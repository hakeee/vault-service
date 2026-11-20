import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, asc, eq, ne } from "drizzle-orm";
import { hashPassword } from "./auth/password.js";
import { user, userIdentity, userMfaFactor, vaultUnlockMethod } from "./schema.js";
import type { SessionCache } from "./sessionCache.js";

/**
 * Accounts made by the app rather than by signing up - e.g. an admin
 * creating one when signup is `"closed"`. Matches module-host IAM's
 * `IamAccounts`. Creating one sets a login password only; the person picks
 * their own vault passphrase on first unlock, so whoever created the
 * account can't read their data.
 */
export function createAccountStore(db: BetterSQLite3Database<any>, options: { sessionCache?: SessionCache } = {}) {
  /** Ends every session of the user: cookies from before now stop counting, and unlocked vaults lock. */
  const endSessions = (userId: number, extra: Partial<typeof user.$inferInsert> = {}) => {
    db.update(user).set({ sessionsValidAfter: new Date(), ...extra }).where(eq(user.id, userId)).run();
    options.sessionCache?.dropUser(userId);
  };

  return {
    /** `mfa`: has an authenticator app or login passkey. */
    async list(): Promise<{ id: number; email: string; displayName: string; disabled: boolean; mfa: boolean }[]> {
      const rows = await db
        .select({ id: user.id, email: user.email, displayName: user.displayName, disabledAt: user.disabledAt })
        .from(user)
        .orderBy(asc(user.id));
      const withMfa = new Set(
        db.select({ userId: userMfaFactor.userId }).from(userMfaFactor).where(ne(userMfaFactor.kind, "recovery")).all().map((r) => r.userId),
      );
      return rows.map(({ disabledAt, ...rest }) => ({ ...rest, disabled: disabledAt !== null, mfa: withMfa.has(rest.id) }));
    },

    /**
     * Removes every second factor (lost phone, lost security key). If two-step
     * login is required, the person sets one up again at their next login.
     * Their sessions end too: whoever has the lost device shouldn't stay in.
     */
    async resetMfa(userId: number): Promise<void> {
      db.delete(userMfaFactor).where(eq(userMfaFactor.userId, userId)).run();
      endSessions(userId);
    },

    /** No logins, and current sessions end (pass `sessionCache` so unlocked vaults lock right away too). */
    async disable(userId: number): Promise<void> {
      endSessions(userId, { disabledAt: new Date() });
    },

    async enable(userId: number): Promise<void> {
      db.update(user).set({ disabledAt: null }).where(eq(user.id, userId)).run();
    },

    /** "Log out everywhere". */
    async revokeSessions(userId: number): Promise<void> {
      endSessions(userId);
    },

    /**
     * A new login password (e.g. temporary, set by an admin). Never touches
     * the vault: its passphrase can't be reset, only recovered with the
     * person's own recovery key. Accounts without a local login (OIDC) can't.
     */
    async resetPassword(userId: number, password: string): Promise<{ ok: true } | { error: "no-local-login" }> {
      const passwordHash = await hashPassword(password);
      const updated = db
        .update(userIdentity)
        .set({ passwordHash })
        .where(and(eq(userIdentity.userId, userId), eq(userIdentity.provider, "local")))
        .returning({ id: userIdentity.id })
        .all();
      return updated.length > 0 ? { ok: true } : { error: "no-local-login" };
    },

    /**
     * Erasure (GDPR): the person is gone, the row stays so the app's foreign
     * keys and history still resolve. Name and email are replaced, every login
     * identity is removed, and every vault unlock method is deleted, which
     * destroys the wrapped keys: data encrypted with their vault becomes
     * unreadable for good. Only for a disabled account, as a deliberate
     * second step after offboarding.
     */
    async erase(userId: number, options: { displayName?: string } = {}): Promise<{ ok: true } | { error: "not-found" | "not-disabled" }> {
      const [row] = await db.select({ disabledAt: user.disabledAt }).from(user).where(eq(user.id, userId));
      if (!row) return { error: "not-found" };
      if (!row.disabledAt) return { error: "not-disabled" };
      db.transaction((tx) => {
        tx.delete(userIdentity).where(eq(userIdentity.userId, userId)).run();
        tx.delete(vaultUnlockMethod).where(eq(vaultUnlockMethod.userId, userId)).run();
        tx.delete(userMfaFactor).where(eq(userMfaFactor.userId, userId)).run();
        tx.update(user)
          .set({ displayName: options.displayName ?? `Erased user #${userId}`, email: `erased-${userId}@erased.invalid`, sessionsValidAfter: new Date() })
          .where(eq(user.id, userId))
          .run();
      });
      endSessions(userId);
      return { ok: true };
    },

    async create(input: { email: string; password: string; displayName: string }): Promise<{ id: number } | { error: "email-taken" }> {
      const [existing] = await db.select({ id: user.id }).from(user).where(eq(user.email, input.email));
      if (existing) return { error: "email-taken" };
      const passwordHash = await hashPassword(input.password);
      const [created] = await db.insert(user).values({ email: input.email, displayName: input.displayName, createdAt: new Date() }).returning();
      if (!created) throw new Error("user insert returned no row");
      await db.insert(userIdentity).values({ userId: created.id, provider: "local", passwordHash });
      return { id: created.id };
    },
  };
}

export type AccountStore = ReturnType<typeof createAccountStore>;
