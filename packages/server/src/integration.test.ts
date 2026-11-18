import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import secureSession from "@fastify/secure-session";
import Fastify from "fastify";
import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock only the WebAuthn-ceremony half of the crypto module, and the
// network-facing half of the oidc module - everything else (the real
// DEK-wrapping round trip, resolveOidcAccount) stays real, so these tests
// exercise the actual route/session/DB wiring without a real
// authenticator or a live IdP.
vi.mock("./crypto/webauthn.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./crypto/webauthn.js")>();
  return {
    ...actual,
    createPasskeyRegistrationChallenge: vi.fn(),
    verifyPasskeyRegistration: vi.fn(),
    createPasskeyAuthenticationChallenge: vi.fn(),
    verifyPasskeyAuthentication: vi.fn(),
  };
});

vi.mock("./auth/oidc.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./auth/oidc.js")>();
  return {
    ...actual,
    createOidcClient: vi.fn(async () => ({}) as never),
    buildAuthorizationRequest: vi.fn(async () => ({
      url: "https://idp.example.com/authorize?state=test-state",
      state: "test-state",
      nonce: "test-nonce",
      codeVerifier: "test-verifier",
    })),
    handleOidcCallback: vi.fn(),
  };
});

import {
  createPasskeyAuthenticationChallenge,
  createPasskeyRegistrationChallenge,
  verifyPasskeyAuthentication,
  verifyPasskeyRegistration,
} from "./crypto/webauthn.js";
import { handleOidcCallback } from "./auth/oidc.js";
import { createRequireAuth } from "./requireAuth.js";
import { createAuthRoutes } from "./routes/auth.js";
import { createInternalRoutes } from "./routes/internal.js";
import { createVaultRoutes } from "./routes/vault.js";
import { migrateVaultService } from "./migrate.js";
import * as schema from "./schema.js";
import { createSessionCache } from "./sessionCache.js";
import type { AuthMode } from "./auth/mode.js";

const WORKER_SECRET = "test-worker-secret";

function createTestDb() {
  const sqlite = new Database(":memory:");
  const db = drizzle(sqlite, { schema });
  migrateVaultService(db);
  return db;
}

function buildTestApp(mode: AuthMode) {
  const db = createTestDb();
  const sessionCache = createSessionCache(30 * 60 * 1000);

  const app = Fastify();
  app.register(secureSession, { key: randomBytes(32), cookie: { path: "/" } });

  const requireAuth = createRequireAuth(mode);

  app.register(
    createAuthRoutes({
      db,
      mode,
      oidc:
        mode === "oidc"
          ? {
              issuerUrl: "https://idp.example.com",
              clientId: "test-client",
              clientSecret: "test-secret",
              redirectUrl: "http://localhost:3000/auth/oidc/callback",
            }
          : undefined,
      postLoginRedirectUrl: "http://localhost:5173",
      sessionCache,
    }),
    { prefix: "/auth" },
  );
  app.register(createInternalRoutes({ workerSecret: WORKER_SECRET, sessionCache }), { prefix: "/internal" });

  app.register(async (protectedRoutes) => {
    protectedRoutes.addHook("onRequest", requireAuth);
    protectedRoutes.register(
      createVaultRoutes({
        db,
        mode,
        webauthn: { rpID: "localhost", rpName: "Test App", origin: "http://localhost:5173" },
        noneMode: { placeholderEmail: "local@test.internal", placeholderDisplayName: "Me" },
        sessionCache,
      }),
      { prefix: "/vault" },
    );
  });

  return { app, db };
}

describe("mode: none - vault unlock + internal crypto service", () => {
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    ({ app } = buildTestApp("none"));
    await app.ready();
  });

  it("bootstraps on first unlock, then round-trips a value through /internal", async () => {
    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      payload: { password: "correct horse battery staple" },
    });

    expect(unlockRes.statusCode).toBe(200);
    const sessionCookie = unlockRes.cookies[0]!;
    const session = app.decodeSecureSession(sessionCookie.value);
    const sessionId = session?.get("id");
    expect(sessionId).toBeTypeOf("string");

    const plaintext = "a secret note";
    const encryptRes = await app.inject({
      method: "POST",
      url: "/internal/encrypt",
      headers: { "x-worker-secret": WORKER_SECRET },
      payload: { sessionId, plaintext },
    });
    expect(encryptRes.statusCode).toBe(200);

    const decryptRes = await app.inject({
      method: "POST",
      url: "/internal/decrypt",
      headers: { "x-worker-secret": WORKER_SECRET },
      payload: { sessionId, ciphertext: encryptRes.json().ciphertext },
    });
    expect(decryptRes.json().plaintext).toBe(plaintext);
  });

  it("rejects the internal crypto service without the worker secret", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/internal/decrypt",
      payload: { sessionId: "anything", ciphertext: "x" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("rejects the wrong password on a later unlock attempt", async () => {
    await app.inject({ method: "POST", url: "/vault/unlock", payload: { password: "correct horse battery staple" } });
    const res = await app.inject({ method: "POST", url: "/vault/unlock", payload: { password: "wrong password" } });
    expect(res.statusCode).toBe(401);
  });
});

describe("mode: single - login", () => {
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    ({ app } = buildTestApp("single"));
    await app.ready();
  });

  it("blocks a protected route before login", async () => {
    const res = await app.inject({ method: "GET", url: "/vault/status" });
    expect(res.statusCode).toBe(401);
  });

  it("bootstraps the first login for a new email, then allows the protected route", async () => {
    const loginRes = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "me@example.com", password: "correct horse battery staple" },
    });
    expect(loginRes.statusCode).toBe(200);
    const cookie = loginRes.cookies[0]!;

    const res = await app.inject({ method: "GET", url: "/vault/status", cookies: { [cookie.name]: cookie.value } });
    expect(res.statusCode).toBe(200);
  });

  it("logs out and re-locks the protected route", async () => {
    const loginRes = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "me@example.com", password: "correct horse battery staple" },
    });
    const cookie = loginRes.cookies[0]!;

    const logoutRes = await app.inject({ method: "POST", url: "/auth/logout", cookies: { [cookie.name]: cookie.value } });
    const clearedCookie = logoutRes.cookies[0]!;

    const statusRes = await app.inject({
      method: "GET",
      url: "/vault/status",
      cookies: { [clearedCookie.name]: clearedCookie.value },
    });
    expect(statusRes.statusCode).toBe(401);
  });
});

describe("mode: single - lock", () => {
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    ({ app } = buildTestApp("single"));
    await app.ready();
  });

  it("locks the vault but keeps the login", async () => {
    const loginRes = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "me@example.com", password: "correct horse battery staple" },
    });
    let cookie = loginRes.cookies[0]!;
    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [cookie.name]: cookie.value },
      payload: { password: "vault passphrase" },
    });
    cookie = unlockRes.cookies[0] ?? cookie;

    const lockRes = await app.inject({ method: "POST", url: "/vault/lock", cookies: { [cookie.name]: cookie.value } });
    expect(lockRes.statusCode).toBe(200);
    cookie = lockRes.cookies[0] ?? cookie;

    const statusRes = await app.inject({ method: "GET", url: "/vault/status", cookies: { [cookie.name]: cookie.value } });
    expect(statusRes.statusCode).toBe(200);
    expect(statusRes.json()).toMatchObject({ unlocked: false, hasVault: true });

    const relockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [cookie.name]: cookie.value },
      payload: { password: "vault passphrase" },
    });
    expect(relockRes.statusCode).toBe(200);
  });
});

describe("mode: single - logout", () => {
  it("drops the vault, so a copy of the old cookie can't use it", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    const loginRes = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "me@example.com", password: "pw" } });
    const cookie = loginRes.cookies[0]!;
    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [cookie.name]: cookie.value },
      payload: { password: "pass" },
    });
    const oldCookie = unlockRes.cookies[0] ?? cookie;

    await app.inject({ method: "POST", url: "/auth/logout", cookies: { [oldCookie.name]: oldCookie.value } });

    // secure-session cookies are stateless: the old one still authenticates.
    const statusRes = await app.inject({ method: "GET", url: "/vault/status", cookies: { [oldCookie.name]: oldCookie.value } });
    expect(statusRes.statusCode).toBe(200);
    expect(statusRes.json()).toMatchObject({ unlocked: false });
  });
});

describe("mode: single - passkey ownership", () => {
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    ({ app } = buildTestApp("single"));
    await app.ready();
  });

  /** Logs in, unlocks, registers one passkey; returns the logged-in cookie. */
  async function userWithPasskey(email: string, credentialId: string) {
    const loginRes = await app.inject({ method: "POST", url: "/auth/login", payload: { email, password: "pw" } });
    let cookie = loginRes.cookies[0]!;
    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [cookie.name]: cookie.value },
      payload: { password: "pass" },
    });
    cookie = unlockRes.cookies[0] ?? cookie;

    vi.mocked(createPasskeyRegistrationChallenge).mockResolvedValueOnce({
      options: { challenge: "reg" } as never,
      challenge: "reg",
      prfSalt: "cHJmLXNhbHQ",
    });
    const optionsRes = await app.inject({
      method: "POST",
      url: "/vault/methods/passkey/register-options",
      cookies: { [cookie.name]: cookie.value },
    });
    cookie = optionsRes.cookies[0] ?? cookie;

    vi.mocked(verifyPasskeyRegistration).mockResolvedValueOnce({
      credentialId,
      publicKey: Buffer.from(`pk-${credentialId}`),
      counter: 0,
    });
    const registerRes = await app.inject({
      method: "POST",
      url: "/vault/methods/passkey",
      cookies: { [cookie.name]: cookie.value },
      payload: { response: {}, prfOutput: "cHJmLW91dA", label: "device" },
    });
    expect(registerRes.statusCode).toBe(200);
    return registerRes.cookies[0] ?? cookie;
  }

  it("rejects another user's passkey", async () => {
    let cookie = await userWithPasskey("a@example.com", "cred-a");
    await userWithPasskey("b@example.com", "cred-b");

    const lockRes = await app.inject({ method: "POST", url: "/vault/lock", cookies: { [cookie.name]: cookie.value } });
    cookie = lockRes.cookies[0] ?? cookie;

    vi.mocked(createPasskeyAuthenticationChallenge).mockResolvedValueOnce({
      options: { challenge: "auth" } as never,
      challenge: "auth",
      prfSaltByCredentialId: { "cred-a": "cHJmLXNhbHQ" },
    });
    const optionsRes = await app.inject({
      method: "GET",
      url: "/vault/methods/passkey/auth-options",
      cookies: { [cookie.name]: cookie.value },
    });
    cookie = optionsRes.cookies[0] ?? cookie;

    vi.mocked(verifyPasskeyAuthentication).mockResolvedValue({ newCounter: 0 });
    const foreignRes = await app.inject({
      method: "POST",
      url: "/vault/methods/passkey/auth-verify",
      cookies: { [cookie.name]: cookie.value },
      payload: { response: { id: "cred-b" }, prfOutput: "cHJmLW91dA" },
    });
    expect(foreignRes.statusCode).toBe(401);

    const ownRes = await app.inject({
      method: "POST",
      url: "/vault/methods/passkey/auth-verify",
      cookies: { [cookie.name]: cookie.value },
      payload: { response: { id: "cred-a" }, prfOutput: "cHJmLW91dA" },
    });
    expect(ownRes.statusCode).toBe(200);
  });
});

describe("mode: oidc - callback resolution", () => {
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    ({ app } = buildTestApp("oidc"));
    await app.ready();
  });

  /** Starts a login, returning the cookie the callback needs to find the stashed state/nonce/verifier. */
  async function startLogin() {
    const res = await app.inject({ method: "GET", url: "/auth/oidc/login" });
    return res.cookies[0]!;
  }

  // `isAuthorizedClaims` itself (default vs. a custom predicate, run
  // against the raw id token claims) is a pure function covered by
  // auth/oidc.test.ts - these only prove the route correctly turns
  // `claims.isAuthorized` into a 403 reject vs. a successful 302 login,
  // which is what the config option is actually for from a caller's view.
  it("rejects the callback when the resolved claims aren't authorized", async () => {
    vi.mocked(handleOidcCallback).mockResolvedValueOnce({
      issuer: "https://idp.example.com",
      subject: "sub-1",
      email: "nope@example.com",
      emailVerified: true,
      isAuthorized: false,
    });
    const cookie = await startLogin();

    const callbackRes = await app.inject({
      method: "GET",
      url: "/auth/oidc/callback?code=test-code&state=test-state",
      cookies: { [cookie.name]: cookie.value },
    });

    expect(callbackRes.statusCode).toBe(403);
  });

  it("logs the browser in when the resolved claims are authorized", async () => {
    vi.mocked(handleOidcCallback).mockResolvedValueOnce({
      issuer: "https://idp.example.com",
      subject: "sub-2",
      email: "yep@example.com",
      emailVerified: true,
      isAuthorized: true,
    });
    const cookie = await startLogin();

    const callbackRes = await app.inject({
      method: "GET",
      url: "/auth/oidc/callback?code=test-code&state=test-state",
      cookies: { [cookie.name]: cookie.value },
    });

    expect(callbackRes.statusCode).toBe(302);
  });
});

describe("passkey and recovery-key unlock methods", () => {
  let app: ReturnType<typeof Fastify>;
  let cookie: { name: string; value: string };

  beforeEach(async () => {
    ({ app } = buildTestApp("none"));
    await app.ready();
    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      payload: { password: "correct horse battery staple" },
    });
    cookie = unlockRes.cookies[0]!;
  });

  it("registers a passkey and unlocks a fresh session with it", async () => {
    vi.mocked(createPasskeyRegistrationChallenge).mockResolvedValueOnce({
      options: { challenge: "reg-challenge-1" } as never,
      challenge: "reg-challenge-1",
      prfSalt: "cHJmLXNhbHQtMQ",
    });

    const optionsRes = await app.inject({
      method: "POST",
      url: "/vault/methods/passkey/register-options",
      cookies: { [cookie.name]: cookie.value },
    });
    cookie = optionsRes.cookies[0] ?? cookie;

    vi.mocked(verifyPasskeyRegistration).mockResolvedValueOnce({
      credentialId: "cred-1",
      publicKey: Buffer.from("fake-public-key-1"),
      counter: 0,
    });

    const registerRes = await app.inject({
      method: "POST",
      url: "/vault/methods/passkey",
      cookies: { [cookie.name]: cookie.value },
      payload: { response: {}, prfOutput: "cHJmLW91dHB1dC0x", label: "Test device" },
    });
    expect(registerRes.statusCode).toBe(200);

    vi.mocked(createPasskeyAuthenticationChallenge).mockResolvedValueOnce({
      options: { challenge: "auth-challenge-1" } as never,
      challenge: "auth-challenge-1",
      prfSaltByCredentialId: { "cred-1": "cHJmLXNhbHQtMQ" },
    });
    const optionsRes2 = await app.inject({ method: "GET", url: "/vault/methods/passkey/auth-options" });
    const freshCookie = optionsRes2.cookies[0]!;

    vi.mocked(verifyPasskeyAuthentication).mockResolvedValueOnce({ newCounter: 1 });
    const verifyRes = await app.inject({
      method: "POST",
      url: "/vault/methods/passkey/auth-verify",
      cookies: { [freshCookie.name]: freshCookie.value },
      payload: { response: { id: "cred-1" }, prfOutput: "cHJmLW91dHB1dC0x" },
    });

    expect(verifyRes.statusCode).toBe(200);
    expect(verifyRes.json()).toEqual({ status: "unlocked" });
  });

  it("registers a recovery key and unlocks a fresh session with it", async () => {
    const RECOVERY_KEY = "Ab3x-K9fZ-Qp7w-Tz1m-Lk5j-Nc8h-Rv2d-Xg4y";

    const registerRes = await app.inject({
      method: "POST",
      url: "/vault/methods/recovery",
      cookies: { [cookie.name]: cookie.value },
      payload: { recoveryKey: RECOVERY_KEY },
    });
    expect(registerRes.statusCode).toBe(200);

    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock-with-recovery",
      payload: { recoveryKey: RECOVERY_KEY },
    });
    expect(unlockRes.statusCode).toBe(200);

    const wrongRes = await app.inject({
      method: "POST",
      url: "/vault/unlock-with-recovery",
      payload: { recoveryKey: "0000-0000-0000-0000-0000-0000-0000-0000" },
    });
    expect(wrongRes.statusCode).toBe(401);
  });

  it("changes the password, after which only the new one unlocks", async () => {
    const changeRes = await app.inject({
      method: "PUT",
      url: "/vault/methods/password",
      cookies: { [cookie.name]: cookie.value },
      payload: { newPassword: "new passphrase" },
    });
    expect(changeRes.statusCode).toBe(200);

    const oldRes = await app.inject({ method: "POST", url: "/vault/unlock", payload: { password: "correct horse battery staple" } });
    expect(oldRes.statusCode).toBe(401);
    const newRes = await app.inject({ method: "POST", url: "/vault/unlock", payload: { password: "new passphrase" } });
    expect(newRes.statusCode).toBe(200);
  });

  it("won't change the password or remove a method while locked", async () => {
    await app.inject({
      method: "POST",
      url: "/vault/methods/recovery",
      cookies: { [cookie.name]: cookie.value },
      payload: { recoveryKey: "Ab3x-K9fZ-Qp7w-Tz1m-Lk5j-Nc8h-Rv2d-Xg4y" },
    });
    const methodsRes = await app.inject({ method: "GET", url: "/vault/methods", cookies: { [cookie.name]: cookie.value } });
    const recovery = (methodsRes.json() as { methods: { id: number; method: string }[] }).methods.find((m) => m.method === "recovery")!;

    const lockRes = await app.inject({ method: "POST", url: "/vault/lock", cookies: { [cookie.name]: cookie.value } });
    const locked = lockRes.cookies[0] ?? cookie;

    const changeRes = await app.inject({
      method: "PUT",
      url: "/vault/methods/password",
      cookies: { [locked.name]: locked.value },
      payload: { newPassword: "attacker" },
    });
    expect(changeRes.statusCode).toBe(404);
    const deleteRes = await app.inject({ method: "DELETE", url: `/vault/methods/${recovery.id}`, cookies: { [locked.name]: locked.value } });
    expect(deleteRes.statusCode).toBe(404);

    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [locked.name]: locked.value },
      payload: { password: "correct horse battery staple" },
    });
    expect(unlockRes.statusCode).toBe(200);
    const unlocked = unlockRes.cookies[0] ?? locked;
    const deleteUnlockedRes = await app.inject({
      method: "DELETE",
      url: `/vault/methods/${recovery.id}`,
      cookies: { [unlocked.name]: unlocked.value },
    });
    expect(deleteUnlockedRes.statusCode).toBe(200);
  });
});
