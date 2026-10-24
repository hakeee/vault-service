import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { decryptField, encryptField } from "../crypto/aes.js";
import type { SessionCache } from "../sessionCache.js";

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

export interface InternalRoutesConfig {
  /** Shared secret a non-API process (e.g. a worker) presents to use these routes - the only boundary that matters, not network topology. */
  workerSecret: string;
  sessionCache: SessionCache;
}

/**
 * The generic half of a "worker-safe" crypto service: decrypt/encrypt
 * against a cached session's DEK, nothing domain-specific. An app with
 * its own encrypted-and-indexed domain data (e.g. blind-indexed tag
 * lookups) should add its own routes alongside these in its own app,
 * using this package's exported `blindIndex`/`deriveBlindIndexKey` and
 * `sessionCache.getSession` directly, rather than trying to make this
 * package own domain logic it has no business knowing about.
 */
export function createInternalRoutes(config: InternalRoutesConfig) {
  const { workerSecret, sessionCache } = config;

  return async function internalRoutes(app: FastifyInstance) {
    app.addHook("onRequest", async (request, reply) => {
      const provided = request.headers[WORKER_SECRET_HEADER];
      if (provided !== workerSecret) {
        reply.code(401).send({ error: "unauthorized" });
      }
    });

    app.post("/decrypt", async (request, reply) => {
      const { sessionId, ciphertext } = decryptBodySchema.parse(request.body);
      const session = sessionCache.getSession(sessionId);

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
      const session = sessionCache.getSession(sessionId);

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
      const session = sessionCache.getSession(sessionId);

      if (!session) {
        reply.code(404).send({ error: "vault locked" });
        return;
      }

      const ciphertext = encryptField(session.dek, Buffer.from(plaintext, "utf8"));
      return { ciphertext: ciphertext.toString("base64") };
    });
  };
}
