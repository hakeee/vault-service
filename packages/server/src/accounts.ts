import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { asc, eq } from "drizzle-orm";
import { hashPassword } from "./auth/password.js";
import { user, userIdentity } from "./schema.js";

/**
 * Accounts made by the app rather than by signing up - e.g. an admin
 * creating one when signup is `"closed"`. Matches module-host IAM's
 * `IamAccounts`. Creating one sets a login password only; the person picks
 * their own vault passphrase on first unlock, so whoever created the
 * account can't read their data.
 */
export function createAccountStore(db: BetterSQLite3Database<any>) {
  return {
    async list(): Promise<{ id: number; email: string; displayName: string }[]> {
      return db.select({ id: user.id, email: user.email, displayName: user.displayName }).from(user).orderBy(asc(user.id));
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
