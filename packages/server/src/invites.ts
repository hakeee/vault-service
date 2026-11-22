import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, desc, eq, isNull } from "drizzle-orm";
import { createHash, randomBytes } from "node:crypto";
import { userInvite } from "./schema.js";

export type InviteState = "pending" | "expired" | "accepted" | "revoked";

const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");

/** One-time invite links. Only the token's hash is stored; a new invite for someone replaces their old one. */
export function createInviteStore(db: BetterSQLite3Database<any>, options: { days?: number } = {}) {
  const days = options.days ?? 7;
  return {
    /** A fresh link token for the account (shown once). Earlier open invites for it stop working. */
    issue(userId: number): { token: string; expiresAt: Date } {
      const token = randomBytes(32).toString("base64url");
      const now = new Date();
      const expiresAt = new Date(now.getTime() + days * 86_400_000);
      db.transaction((tx) => {
        tx.update(userInvite).set({ revokedAt: now }).where(and(eq(userInvite.userId, userId), isNull(userInvite.acceptedAt), isNull(userInvite.revokedAt))).run();
        tx.insert(userInvite).values({ userId, tokenHash: hashToken(token), createdAt: now, expiresAt }).run();
      });
      return { token, expiresAt };
    },

    /** The open invite behind a token (not used, revoked or expired), or undefined. */
    find(token: string): { id: number; userId: number; expiresAt: Date } | undefined {
      const row = db.select().from(userInvite).where(eq(userInvite.tokenHash, hashToken(token))).get();
      if (!row || row.acceptedAt || row.revokedAt || row.expiresAt.getTime() <= Date.now()) return undefined;
      return { id: row.id, userId: row.userId, expiresAt: row.expiresAt };
    },

    /** Uses the invite up. False when it was already used or revoked (e.g. by a request racing this one). */
    accept(id: number): boolean {
      const done = db
        .update(userInvite)
        .set({ acceptedAt: new Date() })
        .where(and(eq(userInvite.id, id), isNull(userInvite.acceptedAt), isNull(userInvite.revokedAt)))
        .returning({ id: userInvite.id })
        .all();
      return done.length > 0;
    },

    revoke(userId: number): void {
      db.update(userInvite).set({ revokedAt: new Date() }).where(and(eq(userInvite.userId, userId), isNull(userInvite.acceptedAt), isNull(userInvite.revokedAt))).run();
    },

    /** The state of someone's latest invite, or null if they never had one. */
    state(userId: number): { state: InviteState; expiresAt: string } | null {
      const row = db.select().from(userInvite).where(eq(userInvite.userId, userId)).orderBy(desc(userInvite.id)).limit(1).get();
      if (!row) return null;
      const state: InviteState = row.acceptedAt ? "accepted" : row.revokedAt ? "revoked" : row.expiresAt.getTime() <= Date.now() ? "expired" : "pending";
      return { state, expiresAt: row.expiresAt.toISOString() };
    },

    /** Everything about the account (erasure). */
    removeAll(userId: number): void {
      db.delete(userInvite).where(eq(userInvite.userId, userId)).run();
    },
  };
}

export type InviteStore = ReturnType<typeof createInviteStore>;
