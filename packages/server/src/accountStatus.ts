import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { eq } from "drizzle-orm";
import { user } from "./schema.js";
import type { TypedSession } from "./session.js";

/**
 * Whether a logged-in session still counts. Session cookies are stateless,
 * so disabling an account or "log out everywhere" works by comparing the
 * session's login time with the user's `sessions_valid_after` (and
 * `disabled_at`). One indexed read per request.
 */
export function sessionStatus(db: BetterSQLite3Database<any>, session: TypedSession): "ok" | "ended" | "anonymous" {
  const authUserId = session.get("authUserId");
  if (authUserId === undefined) return "anonymous";
  const row = db
    .select({ disabledAt: user.disabledAt, validAfter: user.sessionsValidAfter })
    .from(user)
    .where(eq(user.id, Number(authUserId)))
    .get();
  if (!row || row.disabledAt) return "ended";
  const loginAt = Number(session.get("loginAt") ?? 0);
  if (row.validAfter && loginAt < row.validAfter.getTime()) return "ended";
  return "ok";
}

/** Self-service actions an app's authorizer may deny (e.g. module-host IAM, as deny-only rules). Lock and logout are never checked. */
export const SELF_SERVICE_ACTIONS = ["vault:registerPasskey", "vault:setRecoveryKey", "vault:changePassphrase", "auth:changePassword"] as const;
export type SelfServiceAction = (typeof SELF_SERVICE_ACTIONS)[number];

/** Optional hook on the auth/vault routes: return false to refuse a self-service action (403). */
export type SelfServiceAuthorizer = (caller: { userId: number; sessionId: string }, action: SelfServiceAction) => boolean | Promise<boolean>;
