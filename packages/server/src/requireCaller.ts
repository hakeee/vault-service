import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { eq } from "drizzle-orm";
import type { FastifyReply, FastifyRequest } from "fastify";
import type { AuthMode } from "./auth/mode.js";
import { user } from "./schema.js";
import { sessionStatus } from "./accountStatus.js";
import { ensureSessionId, typedSession } from "./session.js";

export interface LoggedInCaller {
  userId: number;
  /** The session id; the same one the vault unlocks under, once it does. */
  sessionId: string;
}

export interface RequireCallerConfig {
  db: BetterSQLite3Database<any>;
  mode: AuthMode;
  /** `none` mode's implicit user, as passed to createVaultRoutes. */
  noneMode: { placeholderEmail: string };
}

/**
 * Who's calling, for things that only need a login - not an unlocked
 * vault. Replies 401 and returns undefined when there's no login. In
 * `none` mode the implicit user only exists after the first unlock, so
 * until then it replies 423 like a locked vault.
 *
 * Anything served this way is readable by whoever holds the session
 * cookie, vault or not: never return vault-encrypted data from it.
 */
export function createRequireCaller(config: RequireCallerConfig) {
  let noneModeUserId: number | undefined;

  return function requireCaller(request: FastifyRequest, reply: FastifyReply): LoggedInCaller | undefined {
    const session = typedSession(request);

    if (config.mode === "none") {
      if (noneModeUserId === undefined) {
        const row = config.db.select({ id: user.id }).from(user).where(eq(user.email, config.noneMode.placeholderEmail)).get();
        noneModeUserId = row?.id;
      }
      if (noneModeUserId === undefined) {
        reply.code(423).send({ error: "vault locked" });
        return undefined;
      }
      return { userId: noneModeUserId, sessionId: ensureSessionId(session) };
    }

    const authUserId = session.get("authUserId");
    if (authUserId === undefined || sessionStatus(config.db, session) === "ended") {
      reply.code(401).send({ error: "login required" });
      return undefined;
    }
    return { userId: Number(authUserId), sessionId: ensureSessionId(session) };
  };
}
