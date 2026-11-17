import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import { getTableConfig, type SQLiteTable } from "drizzle-orm/sqlite-core";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { VAULT_SERVICE_MIGRATIONS_TABLE, migrateVaultService } from "./migrate.js";
import { user, userIdentity, vaultUnlockMethod } from "./schema.js";

const tables: SQLiteTable[] = [user, userIdentity, vaultUnlockMethod];

function openMemoryDb() {
  const sqlite = new Database(":memory:");
  sqlite.pragma("foreign_keys = ON");
  return { sqlite, db: drizzle(sqlite) };
}

type ColumnInfo = { name: string; notnull: number; pk: number };

function columnsOf(sqlite: Database.Database, table: string) {
  return (sqlite.pragma(`table_info(${table})`) as ColumnInfo[])
    .map((c) => ({ name: c.name, notNull: c.notnull === 1 || c.pk === 1, primaryKey: c.pk === 1 }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function trackedCount(sqlite: Database.Database, table: string) {
  return (sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;
}

describe("migrateVaultService", () => {
  it("creates every table in schema.ts with exactly the columns schema.ts declares", () => {
    // The drift guard: if schema.ts changes without `pnpm generate`, the
    // migrated database no longer matches what the code expects.
    const { sqlite, db } = openMemoryDb();
    migrateVaultService(db);

    for (const table of tables) {
      const config = getTableConfig(table);
      const expected = config.columns
        .map((c) => ({ name: c.name, notNull: c.notNull, primaryKey: c.primary }))
        .sort((a, b) => a.name.localeCompare(b.name));
      expect(columnsOf(sqlite, config.name), config.name).toEqual(expected);

      const uniqueColumns = config.columns.filter((c) => c.isUnique).map((c) => c.name);
      const uniqueIndexes = (sqlite.pragma(`index_list(${config.name})`) as { name: string; unique: number }[])
        .filter((i) => i.unique === 1 && !i.name.startsWith("sqlite_autoindex"))
        .flatMap((i) => (sqlite.pragma(`index_info(${i.name})`) as { name: string }[]).map((c) => c.name));
      expect(uniqueIndexes.sort(), `${config.name} unique columns`).toEqual(uniqueColumns.sort());
    }
  });

  it("is a no-op when run again", () => {
    const { sqlite, db } = openMemoryDb();
    migrateVaultService(db);
    const applied = trackedCount(sqlite, VAULT_SERVICE_MIGRATIONS_TABLE);
    migrateVaultService(db);
    expect(trackedCount(sqlite, VAULT_SERVICE_MIGRATIONS_TABLE)).toBe(applied);
  });

  it("adopts a database whose app already created these tables, keeping its rows", () => {
    // The exact DDL Ebba's own migrations produced before this package
    // owned its schema (Ebba 0000 + 0004's two ALTERs, in that order).
    const { sqlite, db } = openMemoryDb();
    sqlite.exec(`
      CREATE TABLE \`user\` (
        \`id\` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        \`display_name\` text NOT NULL,
        \`email\` text NOT NULL,
        \`created_at\` integer NOT NULL
      );
      CREATE UNIQUE INDEX \`user_email_unique\` ON \`user\` (\`email\`);
      CREATE TABLE \`user_identity\` (
        \`id\` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        \`user_id\` integer NOT NULL,
        \`provider\` text NOT NULL,
        \`issuer\` text,
        \`subject\` text,
        \`password_hash\` text,
        FOREIGN KEY (\`user_id\`) REFERENCES \`user\`(\`id\`) ON UPDATE no action ON DELETE no action
      );
      CREATE TABLE \`vault_unlock_method\` (
        \`id\` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        \`user_id\` integer NOT NULL,
        \`method\` text NOT NULL,
        \`label\` blob,
        \`wrapped_dek\` blob NOT NULL,
        \`kdf_salt\` blob,
        \`kdf_params\` text,
        \`credential_id\` text,
        \`prf_salt\` blob,
        \`created_at\` integer NOT NULL,
        \`last_used_at\` integer,
        FOREIGN KEY (\`user_id\`) REFERENCES \`user\`(\`id\`) ON UPDATE no action ON DELETE no action
      );
      ALTER TABLE \`vault_unlock_method\` ADD \`public_key\` blob;
      ALTER TABLE \`vault_unlock_method\` ADD \`counter\` integer;
      INSERT INTO user (display_name, email, created_at) VALUES ('Existing', 'existing@example.com', 1);
    `);

    migrateVaultService(db);

    expect(sqlite.prepare("SELECT email FROM user").all()).toEqual([{ email: "existing@example.com" }]);
    expect(trackedCount(sqlite, VAULT_SERVICE_MIGRATIONS_TABLE)).toBeGreaterThan(0);
    for (const table of tables) {
      const config = getTableConfig(table);
      expect(columnsOf(sqlite, config.name).map((c) => c.name).sort()).toEqual(
        config.columns.map((c) => c.name).sort(),
      );
    }
  });

  it("keeps its own history separate from the consuming app's migrations", () => {
    // A consumer's migrations folder, shaped like drizzle-kit's output,
    // with a table referencing user.id.
    const folder = mkdtempSync(join(tmpdir(), "vault-service-consumer-"));
    mkdirSync(join(folder, "meta"));
    writeFileSync(
      join(folder, "meta/_journal.json"),
      JSON.stringify({
        version: "7",
        dialect: "sqlite",
        entries: [{ idx: 0, version: "6", when: 1, tag: "0000_app", breakpoints: true }],
      }),
    );
    writeFileSync(
      join(folder, "0000_app.sql"),
      "CREATE TABLE `note` (`id` integer PRIMARY KEY, `user_id` integer NOT NULL REFERENCES `user`(`id`));",
    );

    const { sqlite, db } = openMemoryDb();
    migrateVaultService(db);
    migrate(db, { migrationsFolder: folder });

    expect(trackedCount(sqlite, "__drizzle_migrations")).toBe(1);
    const ownApplied = trackedCount(sqlite, VAULT_SERVICE_MIGRATIONS_TABLE);
    migrateVaultService(db);
    expect(trackedCount(sqlite, VAULT_SERVICE_MIGRATIONS_TABLE)).toBe(ownApplied);

    sqlite.prepare("INSERT INTO user (display_name, email, created_at) VALUES ('A', 'a@example.com', 1)").run();
    sqlite.prepare("INSERT INTO note (user_id) VALUES (1)").run();
    expect(() => sqlite.prepare("INSERT INTO note (user_id) VALUES (999)").run()).toThrow(/FOREIGN KEY/);
  });
});
