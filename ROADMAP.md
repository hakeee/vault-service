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
  `vault_unlock_method` Drizzle tables, unchanged in shape. This package
  owns the schema, not the migrations - import it into your own app's
  schema module and migrate as one database.
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
