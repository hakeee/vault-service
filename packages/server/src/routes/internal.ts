import type { FastifyInstance } from "fastify";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { decryptField, encryptField } from "../crypto/aes.js";
import { assertScopeName } from "../crypto/scope.js";
import { scopeKeysOf, sessionCacheInternals, type SessionCache } from "../sessionCache.js";

const WORKER_SECRET_HEADER = "x-worker-secret";

const decryptBodySchema = z.object({
  sessionId: z.string(),
  ciphertext: z.string(), // base64
});

const decryptBatchBodySchema = z.object({
  sessionId: z.string(),
  ciphertexts: z.array(z.string()), // base64
});

const encryptBodySchema = z.object({
  sessionId: z.string(),
  plaintext: z.string(), // utf-8
});

const scopeKeysBodySchema = z.object({
  sessionId: z.string(),
  scopes: z.array(z.string()).min(1),
});

export interface InternalRoutesConfig {
  /** Shared secret a non-API process (e.g. a worker) presents to use these routes - the only boundary that matters, not network topology. */
  workerSecret: string;
  sessionCache: SessionCache;
  /**
   * Optional per-scope secrets for `/scope-keys`: a process presenting
   * `scopeSecrets.journal` may fetch the `journal` scope's keys and nothing
   * else. `workerSecret` still grants every named scope (never the DEK or
   * the legacy scope - those don't leave the API process at all).
   */
  scopeSecrets?: Readonly<Record<string, string>>;
}

function sameSecret(provided: unknown, expected: string): boolean {
  if (typeof provided !== "string" || expected.length === 0) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * The generic half of a "worker-safe" crypto service: decrypt/encrypt
 * against a cached session's vault, nothing domain-specific. `/decrypt`,
 * `/decrypt-batch` and `/encrypt` serve the legacy scope (unversioned
 * format, raw DEK, done here in the API); `/scope-keys` hands out named
 * scopes' keys for workers using `createRemoteVault`. An app with
 * its own encrypted-and-indexed domain data (e.g. blind-indexed tag
 * lookups) adds its own routes alongside these, using
 * `sessionCache.getVault(sessionId)`, rather than this package owning
 * domain logic it has no business knowing about.
 */
export function createInternalRoutes(config: InternalRoutesConfig) {
  const { workerSecret, sessionCache, scopeSecrets = {} } = config;
  const { getSession } = sessionCacheInternals(sessionCache);
  const isWorker = (provided: unknown) => sameSecret(provided, workerSecret);

  return async function internalRoutes(app: FastifyInstance) {
    app.addHook("onRequest", async (request, reply) => {
      const provided = request.headers[WORKER_SECRET_HEADER];
      // /scope-keys checks per-scope secrets itself; everything else is worker-secret only.
      const scopeRoute = request.routeOptions.url?.endsWith("/scope-keys");
      const known = isWorker(provided) || (scopeRoute && Object.values(scopeSecrets).some((s) => sameSecret(provided, s)));
      if (!known) {
        reply.code(401).send({ error: "unauthorized" });
      }
    });

    /**
     * A named scope's keys for a session, so a worker process can run a
     * module's jobs with that module's own vault scope - without the DEK,
     * and without the API doing every encrypt/decrypt over HTTP. 404 means
     * the session's vault is locked (come back later), like the routes below.
     */
    app.post("/scope-keys", async (request, reply) => {
      const { sessionId, scopes } = scopeKeysBodySchema.parse(request.body);
      const provided = request.headers[WORKER_SECRET_HEADER];
      for (const scope of scopes) {
        try {
          assertScopeName(scope);
        } catch (error) {
          reply.code(400).send({ error: (error as Error).message });
          return;
        }
        const scopeSecret = scopeSecrets[scope];
        if (!isWorker(provided) && !(scopeSecret && sameSecret(provided, scopeSecret))) {
          reply.code(403).send({ error: `not allowed scope "${scope}"` });
          return;
        }
      }
      const session = getSession(sessionId);
      if (!session) {
        reply.code(404).send({ error: "vault locked" });
        return;
      }
      return {
        userId: session.userId,
        scopes: Object.fromEntries(
          scopes.map((scope) => {
            const keys = scopeKeysOf(session, scope);
            return [scope, { encryptionKey: keys.encryptionKey.toString("base64"), indexKey: keys.indexKey.toString("base64") }];
          }),
        ),
      };
    });

    app.post("/decrypt", async (request, reply) => {
      const { sessionId, ciphertext } = decryptBodySchema.parse(request.body);
      const session = getSession(sessionId);

      if (!session) {
        reply.code(404).send({ error: "vault locked" });
        return;
      }

      const plaintext = decryptField(session.dek, Buffer.from(ciphertext, "base64"));
      return { plaintext: plaintext.toString("utf8") };
    });

    // Batched for context-building workloads that decrypt many rows at
    // once - avoids one HTTP round trip per row.
    app.post("/decrypt-batch", async (request, reply) => {
      const { sessionId, ciphertexts } = decryptBatchBodySchema.parse(request.body);
      const session = getSession(sessionId);

      if (!session) {
        reply.code(404).send({ error: "vault locked" });
        return;
      }

      const plaintexts = ciphertexts.map((ciphertext) =>
        decryptField(session.dek, Buffer.from(ciphertext, "base64")).toString("utf8"),
      );
      return { plaintexts };
    });

    app.post("/encrypt", async (request, reply) => {
      const { sessionId, plaintext } = encryptBodySchema.parse(request.body);
      const session = getSession(sessionId);

      if (!session) {
        reply.code(404).send({ error: "vault locked" });
        return;
      }

      const ciphertext = encryptField(session.dek, Buffer.from(plaintext, "utf8"));
      return { ciphertext: ciphertext.toString("base64") };
    });
  };
}
