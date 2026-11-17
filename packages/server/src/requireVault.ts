import type { FastifyReply, FastifyRequest } from "fastify";
import { typedSession } from "./session.js";
import type { SessionCache, VaultHandle } from "./sessionCache.js";

export interface UnlockedVaultRequest {
  /** The vault session id - e.g. to enqueue background work a worker can later run against this session. */
  sessionId: string;
  userId: number;
  vault: VaultHandle;
}

export interface RequireVaultOptions {
  /** HTTP status for a locked vault. Default 423 (Locked). */
  lockedStatus?: number;
}

/**
 * The per-request gate for anything that needs the vault: returns the
 * unlocked vault, or replies `lockedStatus` with `{ error: "vault locked" }`
 * and returns undefined - callers return immediately in that case.
 *
 * ```ts
 * const requireVault = createRequireVault(sessionCache);
 * app.get("/notes", async (request, reply) => {
 *   const unlocked = requireVault(request, reply);
 *   if (!unlocked) return;
 *   const notes = unlocked.vault.scope<"note.body">("notes");
 *   ...
 * });
 * ```
 */
export function createRequireVault(sessionCache: SessionCache, options: RequireVaultOptions = {}) {
  const lockedStatus = options.lockedStatus ?? 423;

  return function requireVault(request: FastifyRequest, reply: FastifyReply): UnlockedVaultRequest | undefined {
    const sessionId = typedSession(request).get("id");
    const vault = sessionId !== undefined ? sessionCache.getVault(sessionId) : undefined;

    if (sessionId === undefined || !vault) {
      reply.code(lockedStatus).send({ error: "vault locked" });
      return undefined;
    }

    return { sessionId, userId: vault.userId, vault };
  };
}
