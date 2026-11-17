import { defineConfig } from "drizzle-kit";

// Generates this package's own migrations from src/schema.ts. Consumers
// never run drizzle-kit against these tables themselves - they call
// `migrateVaultService(db)` (src/migrate.ts), which applies the SQL in
// ./migrations with its own tracking table. See README "Database".
export default defineConfig({
  schema: "./src/schema.ts",
  out: "./migrations",
  dialect: "sqlite",
});
