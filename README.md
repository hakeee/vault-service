# vault-service

A self-hosted "bring your own encrypted vault" user service: password /
passkey / recovery-key unlock over a single Data Encryption Key, `none` /
`single` / `oidc` auth modes, and a headless React frontend with no
styling opinions.

Extracted from [Ebba](https://github.com/), a personal journaling app -
every crypto decision here was made for that app's actual threat model
(self-hosted, single-user-first, AES-256-GCM everywhere, Argon2id for
passwords), not as a generic "crypto library." Read the source comments
before changing a default.

## Packages

- **`packages/server`** (`@hakeee/vault-service`) - Node/Fastify. Crypto
  primitives, auth modes, the `user`/`user_identity`/`vault_unlock_method`
  schema (Drizzle), and route factories you mount into your own Fastify
  app.
- **`packages/react`** (`@hakeee/vault-service-react`) - headless hooks
  (`useLogin`, `useUnlockWithPassword`, `useVaultGate`, ...) and browser
  WebAuthn helpers. No components, no CSS - bring your own UI.

## Status

v0.1 (server package) and v0.2 (headless React package) are done. The
server package also owns its tables' migrations, and since 0.2.0 hands
out per-feature encryption scopes instead of the raw key. See `ROADMAP.md`.

## Using it

Call `migrateVaultService(db)` on boot, before your own migrations (see
"Database" below), then mount the routes:

```ts
import { migrateVaultService, createAuthRoutes, createVaultRoutes, createInternalRoutes, createRequireAuth } from "@hakeee/vault-service";

migrateVaultService(db);
migrate(db, { migrationsFolder: "./migrations" }); // your app's own

const requireAuth = createRequireAuth("single");
app.register(createAuthRoutes({ db, mode: "single", postLoginRedirectUrl: "https://your-app" }), { prefix: "/auth" });
app.register(createInternalRoutes({ workerSecret: process.env.WORKER_SECRET!, sessionCache }), { prefix: "/internal" });
app.register(async (protected_) => {
  protected_.addHook("onRequest", requireAuth);
  protected_.register(createVaultRoutes({ db, mode: "single", webauthn, noneMode, sessionCache }), { prefix: "/vault" });
});
```

## Encrypting your own data

An unlocked session gives your code a `VaultHandle`, never the DEK:

```ts
const requireVault = createRequireVault(sessionCache); // replies 423 while locked

app.post("/notes", async (request, reply) => {
  const unlocked = requireVault(request, reply);
  if (!unlocked) return;

  const notes = unlocked.vault.scope<"note.title" | "note.body">("notes");
  await db.insert(note).values({
    userId: unlocked.userId,
    title: notes.encryptString("note.title", body.title),
    body: notes.encryptString("note.body", body.body),
    titleIndex: notes.blindIndex("note.title", normalize(body.title)), // exact-match lookups
  });
});
```

- **Scopes** (`vault.scope("notes")`) get their own encryption key and
  blind-index key, both derived from the user's DEK with HKDF
  (`vault-service:scope:<name>:enc:v1` / `:blind-index:v1`). One scope
  can't decrypt or link another's data. Give each feature its own scope,
  and hand a feature only its scope, not the whole handle.
- **Contexts** (`"note.body"`) say where a value lives. The context is
  authenticated with the value, so a ciphertext copied into another
  column won't decrypt, and blind indexes for the same value in two
  contexts are unrelated. The type parameter turns a mistyped context
  into a compile error. Use `<table>.<column>`; row ids usually aren't
  known before insert.
- **Format:** `0x01 || iv (12) || ciphertext || authTag (16)`,
  AES-256-GCM, with associated data `0x01 || context`. The leading
  version byte lets a later format sit alongside this one.
- **`vault.legacy`** reads and writes data from before scopes: the old
  unversioned layout under the raw DEK, and blind indexes under
  `LEGACY_BLIND_INDEX_INFO`. It exists so Ebba's existing rows keep
  working. Don't use it for new data. Each scope decides its own format.
  The format is never guessed from the bytes, because a legacy value's
  first byte is random and is `0x01` one time in 256.
- **Background processes** use `createVaultWorkerClient`. Its routes
  currently serve the legacy scope only; scoped worker access is next on
  the roadmap.

All of this is about keeping well-behaved features apart. It isn't a
sandbox: code in the same process could still reach the session cache.
A feature you don't trust has to run in its own process, the way the
worker does.

## Database

This package owns the `user`, `user_identity` and `vault_unlock_method`
tables: their Drizzle definitions (`src/schema.ts`) **and** their
migrations (`packages/server/migrations`). Your app shares the same
SQLite database and owns everything else in it.

**In a consuming app:**

- Call `migrateVaultService(db)` on every boot, before your own
  migrations. Your tables reference `user.id`, so ours come first. It is
  a no-op when nothing is pending. It records its history in
  `__vault_service_migrations`, kept apart from your
  `__drizzle_migrations`, so the two histories never skip each other's
  entries.
- Import `user` from this package for `.references(() => user.id)`, but
  **don't export these three tables from the schema file drizzle-kit
  reads**. drizzle-kit generates migrations for every table it sees
  exported, and these are already migrated here. You can still pass them
  to `drizzle(sqlite, { schema: { ...yours, user, userIdentity,
  vaultUnlockMethod } })` for typed queries.
- Upgrading is just bumping the dependency. New migrations apply on the
  next boot.
- Adopting an existing database is safe. The baseline (`0000_baseline`)
  is `IF NOT EXISTS` throughout, so a database that already had these
  tables (Ebba, from before this package owned them) just gets its
  tracking row. Your own old migrations that created these tables must
  then be stripped, or fresh installs would create them twice. See
  Ebba's `packages/db/migrations/0000` and `0004` for how that was done.

**Changing the schema (in this repo):**

1. Edit `src/schema.ts`, then run `pnpm --filter @hakeee/vault-service
   generate`. `src/migrate.test.ts` fails if you forget: it compares a
   migrated database against `schema.ts` column by column.
2. Never edit or delete a migration that has shipped. Databases that
   already applied it won't re-run it, so an edit silently forks
   consumers' schemas.
3. Keep changes additive: new nullable columns, new tables, new
   indexes. Every consumer has foreign keys pointing at `user`, and a
   drizzle-kit "table rebuild" migration (what you get for changing a
   column's type or constraints in SQLite) drops and recreates the
   table underneath them. If a change truly needs that, it's a major
   version bump, with upgrade notes.
4. Migrations run inside one transaction per `migrateVaultService` call.
   Don't put `PRAGMA` statements in them; they're no-ops inside a
   transaction.
