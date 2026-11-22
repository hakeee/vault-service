import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { eq, lt } from "drizzle-orm";
import { revokedSession, user } from "./schema.js";
import type { TypedSession } from "./session.js";

/**
 * The longest a login lasts, whatever the cookie says. The session cookie
 * expires sooner (secure-session: a day after it was made); this bound is
 * what lets `revoked_session` rows be pruned safely.
 */
export const MAX_SESSION_AGE_MS = 7 * 24 * 60 * 60_000;

/**
 * Whether a logged-in session still counts. Session cookies are stateless,
 * so disabling an account or "log out everywhere" works by comparing the
 * session's login time with the user's `sessions_valid_after` (and
 * `disabled_at`), and logging out by listing the session id in
 * `revoked_session`. Two indexed reads per request.
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
  if (!(Date.now() - loginAt < MAX_SESSION_AGE_MS)) return "ended";
  const id = session.get("id");
  if (id && db.select({ id: revokedSession.sessionId }).from(revokedSession).where(eq(revokedSession.sessionId, id)).get()) return "ended";
  return "ok";
}

/** Ends one session for good (logout), so a copy of its cookie stops working too. */
export function revokeSession(db: BetterSQLite3Database<any>, sessionId: string): void {
  const now = Date.now();
  db.insert(revokedSession).values({ sessionId, revokedAt: new Date(now) }).onConflictDoNothing().run();
  // Older rows can't match a live session any more (MAX_SESSION_AGE_MS).
  db.delete(revokedSession).where(lt(revokedSession.revokedAt, new Date(now - MAX_SESSION_AGE_MS - 60 * 60_000))).run();
}

/**
 * Ends every other login of the user (after their password changed): cookies
 * from before now stop counting. The caller's own session, if it's theirs,
 * carries on: its login time moves up to the cut-off.
 */
export function endOtherSessions(db: BetterSQLite3Database<any>, session: TypedSession, userId: number): void {
  const now = Date.now();
  db.update(user).set({ sessionsValidAfter: new Date(now) }).where(eq(user.id, userId)).run();
  if (session.get("authUserId") === String(userId)) session.set("loginAt", String(now));
}

/** Self-service actions an app's authorizer may deny (e.g. module-host IAM, as deny-only rules). Lock and logout are never checked. */
export const SELF_SERVICE_ACTIONS = ["vault:registerPasskey", "vault:setRecoveryKey", "vault:changePassphrase", "auth:changePassword"] as const;
export type SelfServiceAction = (typeof SELF_SERVICE_ACTIONS)[number];

/** Optional hook on the auth/vault routes: return false to refuse a self-service action (403). */
export type SelfServiceAuthorizer = (caller: { userId: number; sessionId: string }, action: SelfServiceAction) => boolean | Promise<boolean>;
