import { sqliteTable, integer, text, blob } from "drizzle-orm/sqlite-core";

/**
 * These three tables are the whole of what this library owns in the
 * database: who a user is, how they authenticate, and what unwraps their
 * vault's Data Encryption Key. A consuming app's own tables reference
 * `user.id` via `.references(() => user.id)` the same way any other
 * foreign key would, so this schema is meant to be imported into (not
 * duplicated by) the app's own schema module and migrated together with
 * it as one database - this package does not run its own migrations.
 *
 * `label` and the DEK-wrapping columns below hold application-level
 * ciphertext (iv || ciphertext || authTag) or key material, never
 * plaintext secrets - see ../crypto/aes.ts.
 */

export const user = sqliteTable("user", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  displayName: text("display_name").notNull(),
  email: text("email").notNull().unique(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});

export const userIdentity = sqliteTable("user_identity", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  userId: integer("user_id").notNull().references(() => user.id),
  provider: text("provider", { enum: ["local", "oidc"] }).notNull(),
  issuer: text("issuer"),
  subject: text("subject"),
  passwordHash: text("password_hash"),
});

export const vaultUnlockMethod = sqliteTable("vault_unlock_method", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  userId: integer("user_id").notNull().references(() => user.id),
  method: text("method", { enum: ["password", "passkey", "recovery"] }).notNull(),
  label: blob("label", { mode: "buffer" }), // encrypted
  wrappedDek: blob("wrapped_dek", { mode: "buffer" }).notNull(),
  kdfSalt: blob("kdf_salt", { mode: "buffer" }), // password only
  kdfParams: text("kdf_params"), // password only, JSON string
  credentialId: text("credential_id"), // passkey only
  publicKey: blob("public_key", { mode: "buffer" }), // passkey only - needed to verify a later assertion
  counter: integer("counter"), // passkey only - signature counter, clone detection
  prfSalt: blob("prf_salt", { mode: "buffer" }), // passkey only
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  lastUsedAt: integer("last_used_at", { mode: "timestamp_ms" }),
});
