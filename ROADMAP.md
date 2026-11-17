# vault-service roadmap

## v0.1 - server package (done)

Extracted and generalized out of Ebba:

- `packages/server/src/crypto/*` - AES-256-GCM field encryption, DEK
  wrap/unwrap, Argon2id password KEK, passkey-PRF and recovery-key KEKs
  (HKDF), HMAC blind index, WebAuthn registration/authentication
  ceremonies. Lifted verbatim; HKDF domain-separation strings kept
  unchanged from Ebba's so its already-wrapped DEKs keep working, with an
  optional `info` override for anyone else who wants their own
  namespace.
- `packages/server/src/auth/*` - `isAuthorized` (auth-mode gate),
  password hash/verify, `resolveOidcAccount`, and an OIDC client wrapper.
  **Generalized**: the Zitadel-specific "project grant" claim check is
  gone from the library. `OidcConfig.isAuthorizedClaims?: (claims) =>
  boolean` replaces it - defaults to "any verified login is allowed,"
  and a caller can supply their own predicate (Zitadel-shaped or
  otherwise) against the raw ID-token claims.
- `packages/server/src/schema.ts` - the `user` / `user_identity` /
  `vault_unlock_method` Drizzle tables, unchanged in shape.
- `packages/server/migrations` + `migrateVaultService(db)` - this
  package also owns those tables' migrations, tracked in their own
  `__vault_service_migrations` table so consumers can upgrade the library
  without regenerating anything. The idempotent baseline adopts databases
  that created the tables themselves (Ebba). `src/migrate.test.ts` guards
  against `schema.ts` drifting from the migrations. Rules for future
  migrations are in README "Database".
- `packages/server/src/sessionCache.ts` - the in-memory
  `Map<sessionId, {dek, indexKey, expiresAt}>`, parameterized by idle
  timeout instead of reading an env var directly.
- `packages/server/src/routes/{auth,vault,internal}.ts` +
  `requireAuth.ts` - Fastify route factories, each taking an explicit
  config object instead of reading `process.env` or hardcoding
  deployment-specific strings (rpName, the `none`-mode placeholder
  email/display name, the worker secret, etc).
- `packages/server/src/workerClient.ts` - a small fetch client so a
  non-API process (a background worker) can reach the vault the same way
  Ebba's worker does, over HTTP, gated by the shared secret.
- Full unit-test suite ported (crypto, auth, account resolution), plus a
  new Fastify-`inject()` integration suite covering unlock/bootstrap,
  password login, the `isAuthorizedClaims` gate, passkey register+auth,
  and recovery-key register+unlock+replace.

## v0.2 - React package (done)

`packages/react` (`@hakeee/vault-service-react`): `VaultServiceProvider`
+ a fetch client, hooks for every route (`useAuthStatus`, `useLogin`,
`useLogout`, `useOidcLoginUrl`, `useVaultStatus`,
`useUnlockWithPassword/Passkey/RecoveryKey`, `usePasskeyRegistration`,
`useRegisterRecoveryKey`, `useVaultMethods`, `useRevokeVaultMethod`),
`useVaultGate` (the pending/offline/login-required/vault-locked/unlocked
state machine), and browser WebAuthn/recovery-key helpers. No JSX beyond
the provider, no CSS - a consumer brings its own screens.

## v0.2.0 - scoped encryption (done)

- Versioned envelope format (`crypto/envelope.ts`), with the version
  byte and a caller context authenticated as GCM associated data.
- Per-scope keys (`crypto/scope.ts`), with typed contexts.
- The session cache hands out a `VaultHandle` (`userId`, `scope()`,
  `legacy`) instead of `{ dek, indexKey }`. Raw access is private to this
  package's own routes. **Breaking:** `getSession` / `VaultSession` are
  gone; use `getVault` / `isUnlocked`.
- `createRequireVault`: a per-request gate, so apps don't hand-roll it.
- `DEFAULT_BLIND_INDEX_INFO` renamed `LEGACY_BLIND_INDEX_INFO`, used only
  by the legacy scope. The old name remains as a deprecated alias.
- Format and key-derivation pins in `crypto/scope.test.ts`. If they
  break, stored data would break too.

## v0.2.x - scoped worker access (done)

`/internal/scope-keys` plus `createRemoteVault`: a worker fetches named
scopes' keys (never the DEK or the legacy scope), optionally limited by a
secret per scope, and caches them with a TTL. Secrets are compared in
constant time. Tested over a real socket, round-tripping data with the
API's own scopes. `sessionCache.unlockedSessions()` lists who's unlocked
(ids only, without extending idle timeouts), for schedulers such as
module-host's `activeCallers`.

Also still open:
- The vault's own `vault_unlock_method.label` is written in the legacy
  format, and could move to an internal scope. That needs a data
  migration, so it isn't urgent.
- No re-encryption helper (legacy to scope) yet. Ebba can stay legacy
  indefinitely; build the helper when something actually needs to move.

## v0.3 - storage-adapter abstraction (stretch, not started)

Everything above assumes Drizzle + `better-sqlite3`, because that's all
Ebba has ever needed. Worth doing only once a second real consumer needs
a different database - speculatively abstracting it now would mean
designing against a requirement that doesn't exist yet.

## v0.4 - polish (not started)

- Usage docs beyond the README's one example.
- A minimal example app (Fastify + React, no real UI) that exercises
  every route end to end.
- Publish to npm or GitHub Packages under `@hakeee/*` instead of
  consuming this via `link:` from a sibling checkout.

## Open questions carried over from Ebba

- Argon2id parameters (`DEFAULT_PASSWORD_KDF_PARAMS` in `kek.ts`) are a
  starting guess, not a measured one - re-time on your actual deployment
  box.
- The vault session idle timeout has no library-wide default opinion
  beyond "you must pass one" - what's actually comfortable depends on
  the app.
- Recovery-key UX: shown once at setup, but nothing here forces a caller
  to confirm the user actually saved it before moving on. That's a
  `packages/react` concern (a confirmation-gated flow around
  `generateRecoveryKey`), not yet designed.
