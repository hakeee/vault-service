import type { FastifyReply, FastifyRequest } from "fastify";
import { isAuthorized, type AuthMode } from "./auth/mode.js";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { sessionStatus } from "./accountStatus.js";
import { typedSession } from "./session.js";

/**
 * One hook, behavior branches on `mode` - everything downstream is
 * identical regardless of mode. Auth and vault unlock are separate
 * concerns: this only decides who can call the API at all, not whether
 * their vault happens to be unlocked. Use the same `requireAuth` for
 * every other protected route group in your app, not just this
 * package's own routes, so the gate is consistent app-wide.
 */
export function createRequireAuth(mode: AuthMode, options: { db?: BetterSQLite3Database<any> } = {}) {
  return async function requireAuth(request: FastifyRequest, reply: FastifyReply) {
    const session = typedSession(request);
    const authUserId = session.get("authUserId");

    if (!isAuthorized(mode, authUserId)) {
      reply.code(401).send({ error: "login required" });
      return;
    }
    // With the db, disabled accounts and sessions from before "log out
    // everywhere" end here, even though their cookie is still valid.
    if (options.db && mode !== "none" && sessionStatus(options.db, session) === "ended") {
      session.delete();
      reply.code(401).send({ error: "session ended" });
    }
  };
}
