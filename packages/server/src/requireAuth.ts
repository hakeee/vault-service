import type { FastifyReply, FastifyRequest } from "fastify";
import { isAuthorized, type AuthMode } from "./auth/mode.js";
import { typedSession } from "./session.js";

/**
 * One hook, behavior branches on `mode` - everything downstream is
 * identical regardless of mode. Auth and vault unlock are separate
 * concerns: this only decides who can call the API at all, not whether
 * their vault happens to be unlocked. Use the same `requireAuth` for
 * every other protected route group in your app, not just this
 * package's own routes, so the gate is consistent app-wide.
 */
export function createRequireAuth(mode: AuthMode) {
  return async function requireAuth(request: FastifyRequest, reply: FastifyReply) {
    const authUserId = typedSession(request).get("authUserId");

    if (!isAuthorized(mode, authUserId)) {
      reply.code(401).send({ error: "login required" });
    }
  };
}
