import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, asc, eq, ne } from "drizzle-orm";
import { hashPassword } from "./auth/password.js";
import { user, userIdentity, userInvite, userMfaFactor, vaultUnlockMethod } from "./schema.js";
import type { SessionCache } from "./sessionCache.js";
import { createInviteStore, type InviteState } from "./invites.js";
import type { IdentityProvisioner } from "./provisioning/index.js";

/**
 * Accounts made by the app rather than by signing up - e.g. an admin
 * creating one when signup is `"closed"`. Matches module-host IAM's
 * `IamAccounts`. Creating one sets a login password only; the person picks
 * their own vault passphrase on first unlock, so whoever created the
 * account can't read their data.
 */
export interface AccountStoreOptions {
  sessionCache?: SessionCache;
  /** OIDC: create invited people at the IdP too (e.g. `createZitadelProvisioner`). */
  provisioner?: IdentityProvisioner;
  /** How long invite links work. Default 7 days. */
  inviteDays?: number;
}

export function createAccountStore(db: BetterSQLite3Database<any>, options: AccountStoreOptions = {}) {
  const invites = createInviteStore(db, { days: options.inviteDays });
  const provisioner = options.provisioner;
  /** The person's subject at the provisioning IdP, if they have one there. */
  const idpSubject = (userId: number) =>
    provisioner
      ? db
          .select({ subject: userIdentity.subject })
          .from(userIdentity)
          .where(and(eq(userIdentity.userId, userId), eq(userIdentity.provider, "oidc"), eq(userIdentity.issuer, provisioner.issuer)))
          .get()?.subject ?? undefined
      : undefined;

  /** Ends every session of the user: cookies from before now stop counting, and unlocked vaults lock. */
  const endSessions = (userId: number, extra: Partial<typeof user.$inferInsert> = {}) => {
    db.update(user).set({ sessionsValidAfter: new Date(), ...extra }).where(eq(user.id, userId)).run();
    options.sessionCache?.dropUser(userId);
  };

  return {
    /**
     * `mfa`: has an authenticator app or login passkey. `login`: has a way
     * to log in (a password or an IdP identity). `invite`: their latest
     * invite, if they ever had one.
     */
    async list(): Promise<{ id: number; email: string; displayName: string; disabled: boolean; mfa: boolean; login: boolean; invite: { state: InviteState; expiresAt: string } | null }[]> {
      const rows = await db
        .select({ id: user.id, email: user.email, displayName: user.displayName, disabledAt: user.disabledAt })
        .from(user)
        .orderBy(asc(user.id));
      const withMfa = new Set(
        db.select({ userId: userMfaFactor.userId }).from(userMfaFactor).where(ne(userMfaFactor.kind, "recovery")).all().map((r) => r.userId),
      );
      const withLogin = new Set(db.select({ userId: userIdentity.userId }).from(userIdentity).all().map((r) => r.userId));
      return rows.map(({ disabledAt, ...rest }) => ({
        ...rest,
        disabled: disabledAt !== null,
        mfa: withMfa.has(rest.id),
        login: withLogin.has(rest.id),
        invite: invites.state(rest.id),
      }));
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
     * Their sessions end: whoever was logged in with the old password is out.
     */
    async resetPassword(userId: number, password: string): Promise<{ ok: true } | { error: "no-local-login" }> {
      const passwordHash = await hashPassword(password);
      const updated = db
        .update(userIdentity)
        .set({ passwordHash })
        .where(and(eq(userIdentity.userId, userId), eq(userIdentity.provider, "local")))
        .returning({ id: userIdentity.id })
        .all();
      if (updated.length === 0) return { error: "no-local-login" };
      // A reset password means whoever was logged in with the old one is out.
      endSessions(userId);
      return { ok: true };
    },

    /**
     * Erasure (GDPR): the person is gone, the row stays so the app's foreign
     * keys and history still resolve. Name and email are replaced, every login
     * identity is removed, and every vault unlock method is deleted, which
     * destroys the wrapped keys: data encrypted with their vault becomes
     * unreadable for good. Only for a disabled account, as a deliberate
     * second step after offboarding.
     */
    async erase(userId: number, options: { displayName?: string } = {}): Promise<{ ok: true; idp?: "removed" | "failed" } | { error: "not-found" | "not-disabled" }> {
      const [row] = await db.select({ disabledAt: user.disabledAt }).from(user).where(eq(user.id, userId));
      if (!row) return { error: "not-found" };
      if (!row.disabledAt) return { error: "not-disabled" };
      // The IdP holds their name and email too. Best effort: erasure here goes ahead either way, and says if it didn't work there.
      const subject = idpSubject(userId);
      let idp: "removed" | "failed" | undefined;
      if (subject && provisioner) idp = await provisioner.removeUser(subject).then(() => "removed" as const, () => "failed" as const);
      db.transaction((tx) => {
        tx.delete(userIdentity).where(eq(userIdentity.userId, userId)).run();
        tx.delete(vaultUnlockMethod).where(eq(vaultUnlockMethod.userId, userId)).run();
        tx.delete(userMfaFactor).where(eq(userMfaFactor.userId, userId)).run();
        tx.delete(userInvite).where(eq(userInvite.userId, userId)).run();
        tx.update(user)
          .set({ displayName: options.displayName ?? `Erased user #${userId}`, email: `erased-${userId}@erased.invalid`, sessionsValidAfter: new Date() })
          .where(eq(user.id, userId))
          .run();
      });
      endSessions(userId);
      return idp ? { ok: true, idp } : { ok: true };
    },

    /**
     * An account waiting for its person, with a one-time link (`token`,
     * shown once; the app emails it). Single mode: the link sets their
     * password. OIDC: it ties their IdP login to this account. With a
     * provisioner, they're created at the IdP too, and `idpInvite` has the
     * IdP email them how to set up their sign-in.
     */
    async invite(input: { email: string; displayName: string; idpInvite?: boolean }): Promise<{ id: number; token: string; expiresAt: Date } | { error: "email-taken" } | { error: "idp"; message: string }> {
      const [existing] = await db.select({ id: user.id }).from(user).where(eq(user.email, input.email));
      if (existing) return { error: "email-taken" };
      let subject: string | undefined;
      if (provisioner) {
        try {
          ({ subject } = await provisioner.createUser({ email: input.email, displayName: input.displayName }));
        } catch (error) {
          return { error: "idp", message: error instanceof Error ? error.message : String(error) };
        }
      }
      const created = db.transaction((tx) => {
        const row = tx.insert(user).values({ email: input.email, displayName: input.displayName, createdAt: new Date() }).returning().get();
        if (subject && provisioner) tx.insert(userIdentity).values({ userId: row.id, provider: "oidc", issuer: provisioner.issuer, subject }).run();
        return row;
      });
      if (subject && input.idpInvite) {
        try {
          await provisioner!.sendInvite(subject);
        } catch (error) {
          return { error: "idp", message: `account created, but the IdP's invite email failed: ${error instanceof Error ? error.message : String(error)}` };
        }
      }
      return { id: created.id, ...invites.issue(created.id) };
    },

    /** A new link for someone who hasn't accepted yet; the old one stops working. With `idpInvite`, the IdP emails them again too. */
    async reinvite(userId: number, opts: { idpInvite?: boolean } = {}): Promise<{ token: string; expiresAt: Date } | { error: "not-found" | "accepted" } | { error: "idp"; message: string }> {
      const [row] = await db.select({ id: user.id }).from(user).where(eq(user.id, userId));
      if (!row) return { error: "not-found" };
      if (invites.state(userId)?.state === "accepted") return { error: "accepted" };
      const subject = idpSubject(userId);
      if (subject && opts.idpInvite) {
        try {
          await provisioner!.sendInvite(subject);
        } catch (error) {
          return { error: "idp", message: error instanceof Error ? error.message : String(error) };
        }
      }
      return invites.issue(userId);
    },

    /** The open invite link stops working (the account stays; disable it to keep them out entirely). */
    /**
     * Replaces the person's roles at the IdP (`provisioner.setRoles`): the
     * role keys their next ID token carries. `no-idp`: they have no login at
     * the provisioning IdP, or it can't grant roles.
     */
    async setIdpRoles(userId: number, roles: readonly string[]): Promise<{ ok: true } | { error: "no-idp" } | { error: "idp"; message: string }> {
      const subject = idpSubject(userId);
      if (!subject || !provisioner?.setRoles) return { error: "no-idp" };
      try {
        await provisioner.setRoles(subject, roles);
        return { ok: true };
      } catch (error) {
        return { error: "idp", message: error instanceof Error ? error.message : String(error) };
      }
    },

    async revokeInvite(userId: number): Promise<void> {
      invites.revoke(userId);
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
