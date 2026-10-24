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

v0.1: the server package, extracted and generalized out of Ebba, with its
full test suite ported and a new Fastify-`inject()` integration suite.
v0.2 in progress: the headless React package. See `ROADMAP.md`.

## Using it

This package doesn't run its own migrations - import `schema.ts`'s
tables into your own app's schema module (so your own tables can
`.references(() => user.id)`) and migrate them together as one database,
the same way Ebba does.

```ts
import { createAuthRoutes, createVaultRoutes, createInternalRoutes, createRequireAuth } from "@hakeee/vault-service";

const requireAuth = createRequireAuth("single");
app.register(createAuthRoutes({ db, mode: "single", postLoginRedirectUrl: "https://your-app" }), { prefix: "/auth" });
app.register(createInternalRoutes({ workerSecret: process.env.WORKER_SECRET!, sessionCache }), { prefix: "/internal" });
app.register(async (protected_) => {
  protected_.addHook("onRequest", requireAuth);
  protected_.register(createVaultRoutes({ db, mode: "single", webauthn, noneMode, sessionCache }), { prefix: "/vault" });
});
```
