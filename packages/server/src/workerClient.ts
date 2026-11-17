import { createVaultScope } from "./crypto/scope.js";
import type { VaultHandle } from "./sessionCache.js";

/**
 * For any process that isn't the API itself (a background worker, say)
 * to reach the vault the same way the API's own request handlers do:
 * over HTTP, gated by the shared secret `createInternalRoutes` checks,
 * never by holding the DEK directly. Mirrors a 404 response (vault
 * locked, nothing to retry yet) as `VaultLockedError` so callers can
 * treat it as "come back later" rather than a hard failure.
 */
export class VaultLockedError extends Error {
  constructor() {
    super("vault locked");
  }
}

export interface VaultWorkerClientConfig {
  /** Base URL of the API process exposing `createInternalRoutes`' routes. */
  baseUrl: string;
  /** Must match the `workerSecret` passed to `createInternalRoutes`. */
  secret: string;
}

export function createVaultWorkerClient(config: VaultWorkerClientConfig) {
  function headers(): Record<string, string> {
    return { "content-type": "application/json", "x-worker-secret": config.secret };
  }

  async function post<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(`${config.baseUrl}${path}`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(body),
    });

    if (response.status === 404) {
      throw new VaultLockedError();
    }
    if (!response.ok) {
      throw new Error(`vault internal service ${path} failed: ${response.status}`);
    }

    return (await response.json()) as T;
  }

  async function decrypt(sessionId: string, ciphertext: Buffer): Promise<string> {
    const { plaintext } = await post<{ plaintext: string }>("/decrypt", {
      sessionId,
      ciphertext: ciphertext.toString("base64"),
    });
    return plaintext;
  }

  async function decryptMany(sessionId: string, blobs: (Buffer | null)[]): Promise<(string | null)[]> {
    const nonNullIndexes: number[] = [];
    const ciphertexts: string[] = [];
    blobs.forEach((blob, i) => {
      if (blob) {
        nonNullIndexes.push(i);
        ciphertexts.push(blob.toString("base64"));
      }
    });

    if (ciphertexts.length === 0) {
      return blobs.map(() => null);
    }

    const { plaintexts } = await post<{ plaintexts: string[] }>("/decrypt-batch", { sessionId, ciphertexts });

    const result: (string | null)[] = blobs.map(() => null);
    nonNullIndexes.forEach((originalIndex, batchIndex) => {
      result[originalIndex] = plaintexts[batchIndex] ?? null;
    });
    return result;
  }

  async function encrypt(sessionId: string, plaintext: string): Promise<Buffer> {
    const { ciphertext } = await post<{ ciphertext: string }>("/encrypt", { sessionId, plaintext });
    return Buffer.from(ciphertext, "base64");
  }

  return { decrypt, decryptMany, encrypt };
}

export type VaultWorkerClient = ReturnType<typeof createVaultWorkerClient>;

export interface RemoteVaultConfig extends VaultWorkerClientConfig {
  /** The named scopes this process needs (e.g. the module ids it runs jobs for). */
  scopes: readonly string[];
  /** How long fetched keys are trusted before re-checking the session. Default 60s. */
  ttlMs?: number;
}

/**
 * A `VaultHandle` source for a process that isn't the API - e.g. a worker
 * running module jobs. `prepare(sessionId)` fetches the configured named
 * scopes' keys from the API's `/scope-keys` (gated by the worker or a
 * per-scope secret) and caches them briefly; `vaultFor(sessionId)` then
 * answers synchronously, like a local session cache would.
 *
 * Only named scopes cross the process boundary. `legacy` throws: pre-scope
 * data needs the DEK, which never leaves the API - keep jobs over legacy
 * data in the API process, or move that data to a named scope.
 */
export function createRemoteVault(config: RemoteVaultConfig) {
  const ttlMs = config.ttlMs ?? 60_000;
  const cache = new Map<string, { handle: VaultHandle; expiresAt: number }>();

  async function prepare(sessionId: string): Promise<void> {
    const cached = cache.get(sessionId);
    if (cached && cached.expiresAt > Date.now()) return;

    const response = await fetch(`${config.baseUrl}/scope-keys`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-worker-secret": config.secret },
      body: JSON.stringify({ sessionId, scopes: config.scopes }),
    });
    if (response.status === 404) {
      cache.delete(sessionId); // locked: vaultFor will say so
      return;
    }
    if (!response.ok) throw new Error(`vault internal service /scope-keys failed: ${response.status}`);

    const body = (await response.json()) as { userId: number; scopes: Record<string, { encryptionKey: string; indexKey: string }> };
    const scopes = new Map(
      Object.entries(body.scopes).map(([name, keys]) => [
        name,
        { encryptionKey: Buffer.from(keys.encryptionKey, "base64"), indexKey: Buffer.from(keys.indexKey, "base64") },
      ]),
    );
    const handle: VaultHandle = {
      userId: body.userId,
      scope<Context extends string = string>(name: string) {
        const keys = scopes.get(name);
        if (!keys) throw new Error(`remote vault: scope "${name}" wasn't requested (add it to scopes)`);
        return createVaultScope<Context>(name, keys);
      },
      get legacy(): never {
        throw new Error("remote vault: the legacy scope needs the DEK, which never leaves the API process");
      },
    };
    cache.set(sessionId, { handle, expiresAt: Date.now() + ttlMs });
  }

  function vaultFor(sessionId: string): VaultHandle | undefined {
    const cached = cache.get(sessionId);
    if (!cached) return undefined;
    if (cached.expiresAt <= Date.now()) {
      cache.delete(sessionId);
      return undefined;
    }
    return cached.handle;
  }

  return { prepare, vaultFor };
}

export type RemoteVault = ReturnType<typeof createRemoteVault>;
