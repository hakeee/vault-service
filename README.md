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
- **Background processes** have two options:
  - `createVaultWorkerClient`: encrypt/decrypt over HTTP in the legacy
    scope.
  - `createRemoteVault({ baseUrl, secret, scopes })`: fetches *named
    scopes'* keys from `/internal/scope-keys`, caches them briefly, and
    then gives the process a normal synchronous `VaultHandle`. That's what
    `@hakeee/module-host` worker processes use. Give each worker a
    per-scope secret (`createInternalRoutes({ scopeSecrets: { journal:
    "..." } })`) and it can fetch only those scopes. The DEK and the
    legacy scope never leave the API process (`legacy` throws on a remote
    handle).

All of this is about keeping well-behaved features apart. It isn't a
sandbox: code in the same process could still reach the session cache.
A feature you don't trust has to run in its own process, the way the
worker does.

## Logged in but locked

Login and unlock are separate, so an app can show some things after
login and the rest after unlock:

- `createRequireCaller({ db, mode, noneMode })` is a request gate like
  `createRequireVault`, but needs only a login. It returns `{ userId,
  sessionId }`, or replies 401 itself. The session id exists from login
  onward, and the vault unlocks under that same id. Anything served
  through it is readable by whoever holds the cookie, so never return
  vault-encrypted data from it.
- `sessionCache.onChange(listener)` reports `{ sessionId, userId,
  unlocked }` on every unlock, lock, logout and idle timeout. An idle
  timeout is noticed on the next read or sweep, so up to a minute late.
  module-host uses it to tell open tabs right away.
- Lock with `POST /vault/lock` (`useLockVault`). It keeps the login. In
  React, `useRefreshVaultState()` re-checks both states, e.g. when a
  socket reports a lock.
- Logging in starts a fresh session id, so a vault left unlocked by an
  earlier login in the same browser doesn't carry over.

## Accounts and signup

- `createAuthRoutes({ signup: "closed" })`: only the very first account
  signs itself up (it becomes the owner). After that, `single` mode logins
  for unknown emails get the same 401 as a wrong password, and new OIDC
  identities get a 403, unless an invite or (when `linkByEmail` allows) a
  verified email ties them to an existing account. Default `"open"` keeps
  the old behavior.
- `bootstrapEmail` (with closed signup): on an empty database only this
  email (any case) can create the first account; OIDC also needs the IdP's
  `email_verified`. A single-mode login can't prove it owns the email, so
  keep the server private until that account exists.
- Guessing limits (`loginLimits`, 15-minute window): `perAccountIp` 10
  failed logins for one account from one address, `perAccount` 100 from
  everywhere, `perIp` 50 per address; then a 429 with `Retry-After`. A
  success clears only that address's count. Unknown accounts get a dummy
  Argon2 check, so timing doesn't reveal which emails exist.
- Auth and vault routes answer unexpected errors with a bare
  `{"error":"internal error"}` 500 (details in the log). A failed OIDC
  code exchange is a 400 "login failed; please try again".
- `createAccountStore(db)` (`list`, `create`) is for apps that create
  accounts themselves, e.g. module-host's IAM. It sets a login password
  only. The person picks their own vault passphrase on first unlock.
- `onLogin(event)` runs after every login with `{ userId, created,
  provider, claims? }`. OIDC logins include the ID token's claims, e.g.
  for mapping IdP roles.
- `POST /auth/password` (`useChangeLoginPassword`) changes your own login
  password, checking the current one. It's separate from the vault
  passphrase.

## Invites

- `accounts.invite({ email, displayName, idpInvite? })` makes an account
  with no login yet and returns a one-time link `token` (7 days by
  default, `inviteDays`; only its sha256 is stored). The app emails the
  link. `reinvite(userId)` issues a new one (the old stops working),
  `revokeInvite(userId)` cancels it, `list()` shows each account's
  `invite` state (pending / expired / accepted / revoked) and `login`.
- Routes: `GET /auth/invites/:token` (who it's for, for the invite page).
  Single mode: `POST /auth/invites/:token/accept { password }` sets the
  login password and continues like a login (two-step setup when
  required). OIDC: `GET /auth/invites/:token/start` remembers the invite
  and redirects to the IdP; the callback ties that login to the invited
  account whatever email the IdP reports. Misses are limited per address.
- **Provisioning** (`createAccountStore(db, { provisioner })`): inviting
  in OIDC mode also creates the person at the IdP and stores their
  subject, so their first login matches directly. `idpInvite` asks the
  IdP to email them how to set up their sign-in. Erasure removes them at
  the IdP too (best effort, reported as `idp`). `createZitadelProvisioner
  ({ issuerUrl, token, organizationId? })` uses ZITADEL's v2 user API with
  a service user's personal access token (`user.write`).

## OIDC rules

- The app's `isAuthorizedClaims` runs on **every** login, so taking the
  role away at the IdP locks the person out here.
- `oidcRequireMfa`: `true` refuses ID tokens whose `amr` doesn't list
  `"mfa"` (`amrShowsMfa`); a function decides from the claims itself.
- `linkByEmail` (default true): whether a verified email may link to an
  existing account with no identity at that IdP. A function keeps some
  accounts out (e.g. root); `false` means people only join by invite. An
  account never gets a second login at the same IdP, and an email match
  that can't be linked is refused rather than duplicated.

## Two-step login (MFA)

For `single` mode. Pass `mfa` to `createAuthRoutes`:
`{ key, issuer, webauthn, required?, maxFailures? }`.

- `key`: 32 bytes (`openssl rand -hex 32`), encrypts TOTP secrets at
  rest. Losing it means everyone sets up their authenticator again.
- Factors (table `user_mfa_factor`, not the vault, because login comes
  before unlock): **authenticator apps** (TOTP, RFC 6238; each code works
  once), **login passkeys** (WebAuthn without PRF, so password managers
  like Bitwarden work, unlike vault passkeys) and **10 recovery codes**
  (stored hashed, each works once). The first authenticator or passkey
  comes with recovery codes, shown once.
- After the password, someone with a factor (or for whom `required(userId)`
  says yes) gets `{status: "mfa_required", factors}` or
  `{status: "mfa_setup_required"}` instead of a login. The session is then
  half logged in (`mfaUserId`, no `authUserId`) for 10 minutes: requireAuth
  and the vault routes see nobody, and `/auth/status` says
  `mfa: "verify" | "setup"`. Starting a second step ends any earlier login
  on that session.
- Routes under `/auth/mfa`: `GET /` (stage, required, factors),
  `POST /verify/totp | /verify/recovery | /verify/passkey/options |
  /verify/passkey`, `POST /totp/setup` then `/totp/confirm`,
  `POST /passkey/options` then `/passkey`, `POST /recovery` (new codes),
  `POST /remove`. Once fully logged in, adding, removing and new codes need
  the login password again (`password` in the body), so a stolen cookie
  can't change factors. The last factor can't be removed while two-step
  login is required. Wrong codes count like wrong passwords (10 per account
  in 15 minutes, then 429).
- Accounts: `resetMfa(userId)` removes every factor and ends the person's
  sessions (lost phone); `list()` says who has `mfa`; `erase` removes
  factors too. `createMfaStore(db, key)` is exported for server-side tools.
- React (`@hakeee/vault-service-react`): `useLogin` returns the
  `LoginResult`; `useVaultGate` reports `login-required` with `mfa` set
  mid-login; hooks `useMfaStatus`, `useVerifyTotp`, `useVerifyRecoveryCode`,
  `useVerifyLoginPasskey`, `useStartTotpSetup`, `useConfirmTotp`,
  `useRegisterLoginPasskey`, `useNewRecoveryCodes`, `useRemoveMfaFactor`.

## Disabling accounts and ending sessions

- Pass the db to `createRequireAuth(mode, { db })`. Every request then
  checks `user.disabled_at` and `user.sessions_valid_after` against the
  session's login time. Session cookies are stateless, so this is how
  "disable" and "log out everywhere" take effect immediately: the cookie
  is still valid, but the session no longer counts. `/auth/status` and
  `createRequireCaller` check the same thing. Disabled accounts get a 403
  "account disabled" at login, after the password check, so this doesn't
  reveal which accounts exist.
- `createAccountStore(db, { sessionCache })` adds `disable`, `enable`,
  `revokeSessions` and `resetPassword` (login password only). With the
  cache, the person's unlocked vaults lock right away too.
- `erase(userId, { displayName? })` is GDPR erasure for a **disabled**
  account: the `user` row stays (so the app's foreign keys and history
  resolve) with its name and email replaced, and every login identity and
  vault unlock method is deleted. Deleting the unlock methods destroys the
  wrapped keys, so anything encrypted with that vault is unreadable for
  good. The old email is free again.
- Self-service routes take an optional `authorize(caller, action)` on
  `createAuthRoutes` and `createVaultRoutes`, for `SELF_SERVICE_ACTIONS`
  (`vault:registerPasskey`, `vault:setRecoveryKey`, `vault:changePassphrase`,
  `auth:changePassword`). Returning false gives a 403. Lock and logout are
  never checked.

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
