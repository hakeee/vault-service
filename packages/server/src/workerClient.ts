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
