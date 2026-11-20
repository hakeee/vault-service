import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { describe, expect, it } from "vitest";
import { createAccountStore } from "./accounts.js";
import { migrateVaultService } from "./migrate.js";

function setup() {
  const sqlite = new Database(":memory:");
  sqlite.pragma("foreign_keys = ON");
  const db = drizzle(sqlite);
  migrateVaultService(db);
  // An app table pointing at the user, which erasure must keep valid.
  sqlite.exec("CREATE TABLE work (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES user(id))");
  const dropped: number[] = [];
  const accounts = createAccountStore(db, { sessionCache: { dropUser: (id: number) => dropped.push(id) } as never });
  return { sqlite, accounts, dropped };
}

describe("account erasure", () => {
  it("only erases a disabled account, keeps the row, and removes logins and vault keys", async () => {
    const { sqlite, accounts, dropped } = setup();
    const created = await accounts.create({ email: "t@example.com", password: "pw123456", displayName: "Tereza" });
    if (!("id" in created)) throw new Error("not created");
    const id = created.id;
    sqlite.prepare("INSERT INTO vault_unlock_method (user_id, method, wrapped_dek, created_at) VALUES (?, 'password', x'00', 0)").run(id);
    sqlite.prepare("INSERT INTO work (user_id) VALUES (?)").run(id);

    expect(await accounts.erase(id)).toEqual({ error: "not-disabled" });
    expect(await accounts.erase(999)).toEqual({ error: "not-found" });
    await accounts.disable(id);
    expect(await accounts.erase(id, { displayName: "Former trainer #2" })).toEqual({ ok: true });

    expect(sqlite.prepare("SELECT display_name AS name, email FROM user WHERE id = ?").get(id)).toEqual({ name: "Former trainer #2", email: `erased-${id}@erased.invalid` });
    expect(sqlite.prepare("SELECT count(*) AS n FROM user_identity WHERE user_id = ?").get(id)).toEqual({ n: 0 });
    expect(sqlite.prepare("SELECT count(*) AS n FROM vault_unlock_method WHERE user_id = ?").get(id)).toEqual({ n: 0 });
    expect(sqlite.prepare("SELECT count(*) AS n FROM work WHERE user_id = ?").get(id)).toEqual({ n: 1 }); // history still points at the row
    expect(dropped).toContain(id); // unlocked vaults are dropped from memory
    // The email is free again for a new account.
    expect(await accounts.create({ email: "t@example.com", password: "pw123456", displayName: "New" })).toHaveProperty("id");
  });
});
