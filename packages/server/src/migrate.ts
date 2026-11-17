import { fileURLToPath } from "node:url";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";

/**
 * Tracking table for this package's migrations, separate from the
 * consumer's own `__drizzle_migrations` - drizzle's migrator only applies
 * migrations newer than the latest row in its table, so sharing one table
 * between two independent migration histories would make each skip the
 * other's.
 */
export const VAULT_SERVICE_MIGRATIONS_TABLE = "__vault_service_migrations";

/**
 * `src/migrate.ts` and the compiled `dist/migrate.js` both sit one level
 * under the package root, so one relative path works for either.
 */
export const vaultServiceMigrationsFolder = fileURLToPath(new URL("../migrations", import.meta.url));

/**
 * Brings this package's tables (`user`, `user_identity`,
 * `vault_unlock_method`) up to date. Call it before your own app's
 * migrations, on every boot - it's a no-op when nothing is pending, and
 * your own tables reference `user.id`, so ours must exist first.
 *
 * A database that already has these tables from before this package
 * shipped migrations is adopted as-is: the baseline is idempotent.
 */
export function migrateVaultService<TSchema extends Record<string, unknown>>(
  db: BetterSQLite3Database<TSchema>,
): void {
  migrate(db, {
    migrationsFolder: vaultServiceMigrationsFolder,
    migrationsTable: VAULT_SERVICE_MIGRATIONS_TABLE,
  });
}
