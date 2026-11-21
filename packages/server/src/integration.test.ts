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
import { createRequireCaller } from "./requireCaller.js";
import { createAccountStore } from "./accounts.js";
import { createRequireVault } from "./requireVault.js";
import { createAuthRoutes } from "./routes/auth.js";
import { createInternalRoutes } from "./routes/internal.js";
import { createVaultRoutes } from "./routes/vault.js";
import { migrateVaultService } from "./migrate.js";
import * as schema from "./schema.js";
import { createSessionCache } from "./sessionCache.js";
import { base32Decode, totpCode, totpStep } from "./auth/totp.js";
import type { AuthMode } from "./auth/mode.js";

const WORKER_SECRET = "test-worker-secret";

function createTestDb() {
  const sqlite = new Database(":memory:");
  const db = drizzle(sqlite, { schema });
  migrateVaultService(db);
  return db;
}

function buildTestApp(
  mode: AuthMode,
  authExtra: Partial<Parameters<typeof createAuthRoutes>[0]> = {},
  vaultExtra: Partial<Parameters<typeof createVaultRoutes>[0]> = {},
) {
  const db = createTestDb();
  const sessionCache = createSessionCache(30 * 60 * 1000);

  const app = Fastify();
  app.register(secureSession, { key: randomBytes(32), cookie: { path: "/" } });

  const requireAuth = createRequireAuth(mode, { db });

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
      ...authExtra,
    }),
    { prefix: "/auth" },
  );
  app.register(createInternalRoutes({ workerSecret: WORKER_SECRET, sessionCache }), { prefix: "/internal" });

  const requireCaller = createRequireCaller({ db, mode, noneMode: { placeholderEmail: "local@test.internal" } });
  const requireVault = createRequireVault(sessionCache);

  app.register(async (protectedRoutes) => {
    protectedRoutes.addHook("onRequest", requireAuth);
    // Stand-ins for an app's own routes: one needing only a login, one the vault.
    protectedRoutes.get("/whoami", async (request, reply) => requireCaller(request, reply));
    protectedRoutes.get("/secret", async (request, reply) => {
      const unlocked = requireVault(request, reply);
      return unlocked && { sessionId: unlocked.sessionId, userId: unlocked.userId };
    });
    protectedRoutes.register(
      createVaultRoutes({
        db,
        mode,
        webauthn: { rpID: "localhost", rpName: "Test App", origin: "http://localhost:5173" },
        noneMode: { placeholderEmail: "local@test.internal", placeholderDisplayName: "Me" },
        sessionCache,
        ...vaultExtra,
      }),
      { prefix: "/vault" },
    );
  });

  return { app, db, sessionCache };
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
    const loginRes = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "me@example.com", password: "password1" } });
    const cookie = loginRes.cookies[0]!;
    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [cookie.name]: cookie.value },
      payload: { password: "passphrase" },
    });
    const oldCookie = unlockRes.cookies[0] ?? cookie;

    await app.inject({ method: "POST", url: "/auth/logout", cookies: { [oldCookie.name]: oldCookie.value } });

    // secure-session cookies are stateless: the old one still authenticates.
    const statusRes = await app.inject({ method: "GET", url: "/vault/status", cookies: { [oldCookie.name]: oldCookie.value } });
    expect(statusRes.statusCode).toBe(200);
    expect(statusRes.json()).toMatchObject({ unlocked: false });
  });
});

describe("mode: single - guessing and weak secrets", () => {
  const login = (app: ReturnType<typeof buildTestApp>["app"], email: string, password: string) =>
    app.inject({ method: "POST", url: "/auth/login", payload: { email, password } });

  it("refuses a short password for the first account, and a short passphrase for a new vault", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    expect((await login(app, "me@example.com", "pw")).statusCode).toBe(400);
    const cookie = (await login(app, "me@example.com", "password1")).cookies[0]!;
    const unlock = (password: string) => app.inject({ method: "POST", url: "/vault/unlock", cookies: { [cookie.name]: cookie.value }, payload: { password } });
    expect((await unlock("pass")).statusCode).toBe(400);
    expect((await unlock("passphrase")).statusCode).toBe(200);
  });

  it("blocks an account after too many wrong passwords, and the right one stays blocked until it clears", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    await login(app, "me@example.com", "password1");
    for (let i = 0; i < 10; i++) expect((await login(app, "me@example.com", "wrong-guess")).statusCode).toBe(401);
    const blocked = await login(app, "me@example.com", "password1");
    expect(blocked.statusCode).toBe(429);
    expect(Number(blocked.headers["retry-after"])).toBeGreaterThan(0);
  });

  it("blocks vault unlocks after too many wrong passphrases", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    const cookie = (await login(app, "me@example.com", "password1")).cookies[0]!;
    const unlock = (password: string) => app.inject({ method: "POST", url: "/vault/unlock", cookies: { [cookie.name]: cookie.value }, payload: { password } });
    expect((await unlock("passphrase")).statusCode).toBe(200);
    for (let i = 0; i < 10; i++) expect((await unlock("wrong-guess")).statusCode).toBe(401);
    expect((await unlock("passphrase")).statusCode).toBe(429);
  });

  it("answers bad input with a 400, not a 500", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    const res = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "not-an-email", password: "password1" } });
    expect(res.statusCode).toBe(400);
  });

  it("blocks guessing from one address without locking the owner out elsewhere", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    const from = (remoteAddress: string, password: string) =>
      app.inject({ method: "POST", url: "/auth/login", remoteAddress, payload: { email: "me@example.com", password } });
    expect((await from("10.0.0.1", "password1")).statusCode).toBe(200);
    for (let i = 0; i < 10; i++) expect((await from("10.0.0.66", "wrong-guess")).statusCode).toBe(401);
    expect((await from("10.0.0.66", "password1")).statusCode).toBe(429);
    expect((await from("10.0.0.1", "password1")).statusCode).toBe(200);
  });

  it("blocks an account guessed at from many addresses, everywhere, and a success elsewhere doesn't reset it", async () => {
    const { app } = buildTestApp("single", { loginLimits: { perAccount: 5 } });
    await app.ready();
    const from = (remoteAddress: string, password: string) =>
      app.inject({ method: "POST", url: "/auth/login", remoteAddress, payload: { email: "me@example.com", password } });
    expect((await from("10.0.0.1", "password1")).statusCode).toBe(200);
    for (let i = 0; i < 4; i++) expect((await from(`10.0.1.${i}`, "wrong-guess")).statusCode).toBe(401);
    expect((await from("10.0.0.1", "password1")).statusCode).toBe(200);
    expect((await from("10.0.2.1", "wrong-guess")).statusCode).toBe(401);
    expect((await from("10.0.0.1", "password1")).statusCode).toBe(429);
  });

  it("checks a password even for unknown accounts, so timing doesn't tell them apart", async () => {
    const { app } = buildTestApp("single", { signup: "closed" });
    await app.ready();
    const login = (email: string) => app.inject({ method: "POST", url: "/auth/login", payload: { email, password: "wrong-guess" } });
    await app.inject({ method: "POST", url: "/auth/login", payload: { email: "me@example.com", password: "password1" } });
    await login("nobody@example.com"); // warms the dummy hash
    const time = async (email: string) => {
      const start = performance.now();
      expect((await login(email)).statusCode).toBe(401);
      return performance.now() - start;
    };
    const known = await time("me@example.com");
    const unknown = await time("nobody@example.com");
    // Both run Argon2 (tens of ms); without the dummy check the unknown one took about 1 ms.
    expect(unknown).toBeGreaterThan(known / 3);
  });

  it("hides unexpected errors behind a bare 500", async () => {
    const { app } = buildTestApp("single", {
      onLogin: () => {
        throw new Error("SQLITE_CORRUPT: secret detail");
      },
    });
    await app.ready();
    const res = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "me@example.com", password: "password1" } });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: "internal error" });
  });
});

describe("bootstrapEmail - only the owner creates the first account", () => {
  it("single mode: other emails can't create it, the owner's can (any case)", async () => {
    const { app } = buildTestApp("single", { signup: "closed", bootstrapEmail: "Owner@Example.com" });
    await app.ready();
    const login = (email: string) => app.inject({ method: "POST", url: "/auth/login", payload: { email, password: "password1" } });
    expect((await login("stranger@example.com")).statusCode).toBe(401);
    expect((await login("owner@example.com")).statusCode).toBe(200);
    expect((await login("stranger@example.com")).statusCode).toBe(401);
  });

  it("oidc: needs the owner's email, verified by the IdP", async () => {
    const { app } = buildTestApp("oidc", { signup: "closed", bootstrapEmail: "owner@example.com" });
    await app.ready();
    const callback = async (subject: string, email: string, emailVerified: boolean) => {
      vi.mocked(handleOidcCallback).mockResolvedValueOnce({ issuer: "https://idp.example.com", subject, email, emailVerified, isAuthorized: true });
      const cookie = (await app.inject({ method: "GET", url: "/auth/oidc/login" })).cookies[0]!;
      return app.inject({ method: "GET", url: "/auth/oidc/callback?code=c&state=test-state", cookies: { [cookie.name]: cookie.value } });
    };
    expect((await callback("s1", "stranger@example.com", true)).statusCode).toBe(403);
    expect((await callback("s2", "owner@example.com", false)).statusCode).toBe(403);
    expect((await callback("s3", "owner@example.com", true)).statusCode).toBe(302);
  });

  it("oidc: a failed code exchange is a 400 to retry, not a 500", async () => {
    const { app } = buildTestApp("oidc");
    await app.ready();
    vi.mocked(handleOidcCallback).mockRejectedValueOnce(new Error("state mismatch: internal detail"));
    const cookie = (await app.inject({ method: "GET", url: "/auth/oidc/login" })).cookies[0]!;
    const res = await app.inject({ method: "GET", url: "/auth/oidc/callback?code=c&state=test-state", cookies: { [cookie.name]: cookie.value } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).not.toContain("internal detail");
  });

  it("oidc: a browser goes back to the app with an error code, not a JSON page", async () => {
    const { app } = buildTestApp("oidc", { signup: "closed", bootstrapEmail: "owner@example.com" });
    await app.ready();
    const browserCallback = async () => {
      const cookie = (await app.inject({ method: "GET", url: "/auth/oidc/login" })).cookies[0]!;
      return app.inject({
        method: "GET",
        url: "/auth/oidc/callback?code=c&state=test-state",
        cookies: { [cookie.name]: cookie.value },
        headers: { accept: "text/html,application/xhtml+xml" },
      });
    };
    vi.mocked(handleOidcCallback).mockResolvedValueOnce({ issuer: "https://idp.example.com", subject: "x", email: "stranger@example.com", emailVerified: true, isAuthorized: true });
    let res = await browserCallback();
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe("http://localhost:5173/?login_error=signup-closed");
    vi.mocked(handleOidcCallback).mockRejectedValueOnce(new Error("bad state"));
    res = await browserCallback();
    expect(res.headers.location).toBe("http://localhost:5173/?login_error=failed");
    vi.mocked(handleOidcCallback).mockResolvedValueOnce({ issuer: "https://idp.example.com", subject: "y", email: "a@example.com", emailVerified: true, isAuthorized: false });
    res = await browserCallback();
    expect(res.headers.location).toBe("http://localhost:5173/?login_error=not-authorized");
  });
});

describe("mode: single - caller without the vault", () => {
  it("identifies a logged-in caller before unlock, under the id the vault later unlocks with", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    expect((await app.inject({ method: "GET", url: "/whoami" })).statusCode).toBe(401);

    const loginRes = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "me@example.com", password: "password1" } });
    let cookie = loginRes.cookies[0]!;
    const whoRes = await app.inject({ method: "GET", url: "/whoami", cookies: { [cookie.name]: cookie.value } });
    expect(whoRes.statusCode).toBe(200);
    const who = whoRes.json() as { userId: number; sessionId: string };
    expect(who.userId).toBeGreaterThan(0);
    expect((await app.inject({ method: "GET", url: "/secret", cookies: { [cookie.name]: cookie.value } })).statusCode).toBe(423);

    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [cookie.name]: cookie.value },
      payload: { password: "passphrase" },
    });
    cookie = unlockRes.cookies[0] ?? cookie;
    const secretRes = await app.inject({ method: "GET", url: "/secret", cookies: { [cookie.name]: cookie.value } });
    expect(secretRes.json()).toEqual(who);
  });

  it("starts a new session id on login, so an unlocked vault doesn't carry over", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    const loginRes = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "a@example.com", password: "password1" } });
    let cookie = loginRes.cookies[0]!;
    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [cookie.name]: cookie.value },
      payload: { password: "passphrase" },
    });
    cookie = unlockRes.cookies[0] ?? cookie;

    // Another account logs in from the same browser without logging out first.
    const secondRes = await app.inject({
      method: "POST",
      url: "/auth/login",
      cookies: { [cookie.name]: cookie.value },
      payload: { email: "b@example.com", password: "password1" },
    });
    cookie = secondRes.cookies[0] ?? cookie;
    expect((await app.inject({ method: "GET", url: "/secret", cookies: { [cookie.name]: cookie.value } })).statusCode).toBe(423);
  });
});

describe("mode: single - closed signup, onLogin, accounts", () => {
  const login = (app: ReturnType<typeof Fastify>, email: string, password = "password1", cookie?: { name: string; value: string }) =>
    app.inject({ method: "POST", url: "/auth/login", payload: { email, password }, cookies: cookie ? { [cookie.name]: cookie.value } : {} });

  it("lets only the first account sign up, then only accounts the app created", async () => {
    const events: unknown[] = [];
    const { app, db } = buildTestApp("single", { signup: "closed", onLogin: (e) => void events.push(e) });
    await app.ready();

    expect((await login(app, "owner@example.com")).statusCode).toBe(200);
    expect((await login(app, "stranger@example.com")).json()).toEqual({ error: "wrong email or password" });

    const accounts = createAccountStore(db);
    const created = await accounts.create({ email: "new@example.com", password: "temporary1", displayName: "New" });
    expect(created).toEqual({ id: 2 });
    expect(await accounts.create({ email: "new@example.com", password: "x", displayName: "x" })).toEqual({ error: "email-taken" });
    expect((await accounts.list()).map((a) => a.email)).toEqual(["owner@example.com", "new@example.com"]);
    expect((await login(app, "new@example.com", "temporary1")).statusCode).toBe(200);

    expect(events).toEqual([
      { userId: 1, created: true, provider: "local" },
      { userId: 2, created: false, provider: "local" },
    ]);
  });

  it("changes the login password, checking the current one", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    const cookie = (await login(app, "me@example.com", "first-password")).cookies[0]!;
    const change = (currentPassword: string) =>
      app.inject({
        method: "POST",
        url: "/auth/password",
        cookies: { [cookie.name]: cookie.value },
        payload: { currentPassword, newPassword: "second-password" },
      });
    expect((await change("wrong")).statusCode).toBe(401);
    expect((await change("first-password")).statusCode).toBe(200);
    expect((await login(app, "me@example.com", "first-password")).statusCode).toBe(401);
    expect((await login(app, "me@example.com", "second-password")).statusCode).toBe(200);
  });
});

describe("mode: single - account status and self-service rules", () => {
  const cookieOf = (res: { cookies: { name: string; value: string }[] }, prev?: { name: string; value: string }) => res.cookies[0] ?? prev!;
  async function loggedIn(app: ReturnType<typeof Fastify>, email: string, password = "password1") {
    let cookie = cookieOf(await app.inject({ method: "POST", url: "/auth/login", payload: { email, password } }));
    cookie = cookieOf(await app.inject({ method: "POST", url: "/vault/unlock", cookies: { [cookie.name]: cookie.value }, payload: { password: "passphrase" } }), cookie);
    return cookie;
  }
  const get = (app: ReturnType<typeof Fastify>, url: string, cookie: { name: string; value: string }) =>
    app.inject({ method: "GET", url, cookies: { [cookie.name]: cookie.value } });

  it("disables an account: its sessions end, it can't log in, and enabling restores it", async () => {
    const { app, db, sessionCache } = buildTestApp("single");
    await app.ready();
    await loggedIn(app, "owner@example.com");
    const cookie = await loggedIn(app, "member@example.com");
    const accounts = createAccountStore(db, { sessionCache });
    const memberId = (await accounts.list()).find((a) => a.email === "member@example.com")!.id;

    await accounts.disable(memberId);
    expect((await accounts.list()).find((a) => a.id === memberId)!.disabled).toBe(true);
    expect(sessionCache.unlockedSessions().some((s) => s.userId === memberId)).toBe(false);
    const ended = await get(app, "/vault/status", cookie);
    expect(ended.statusCode).toBe(401);
    expect(ended.json()).toEqual({ error: "session ended" });
    expect((await get(app, "/auth/status", cookie)).json()).toMatchObject({ authenticated: false });
    const refused = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "member@example.com", password: "password1" } });
    expect(refused.statusCode).toBe(403);
    expect(refused.json()).toEqual({ error: "account disabled" });
    // A wrong password still gets the generic answer, so disabled accounts don't stand out.
    expect((await app.inject({ method: "POST", url: "/auth/login", payload: { email: "member@example.com", password: "x" } })).statusCode).toBe(401);

    await accounts.enable(memberId);
    expect((await app.inject({ method: "POST", url: "/auth/login", payload: { email: "member@example.com", password: "password1" } })).statusCode).toBe(200);
  });

  it("logs someone out everywhere, and resets their login password", async () => {
    const { app, db, sessionCache } = buildTestApp("single");
    await app.ready();
    const old = await loggedIn(app, "me@example.com");
    const accounts = createAccountStore(db, { sessionCache });

    await new Promise((r) => setTimeout(r, 5)); // a login in the same millisecond as the cutoff would still count
    await accounts.revokeSessions(1);
    expect((await get(app, "/vault/status", old)).statusCode).toBe(401);
    const fresh = await loggedIn(app, "me@example.com");
    expect((await get(app, "/vault/status", fresh)).statusCode).toBe(200);

    expect(await accounts.resetPassword(1, "temporary-pass")).toEqual({ ok: true });
    expect((await app.inject({ method: "POST", url: "/auth/login", payload: { email: "me@example.com", password: "password1" } })).statusCode).toBe(401);
    expect((await app.inject({ method: "POST", url: "/auth/login", payload: { email: "me@example.com", password: "temporary-pass" } })).statusCode).toBe(200);
    expect(await accounts.resetPassword(999, "x")).toEqual({ error: "no-local-login" });
  });

  it("lets the app's authorizer refuse self-service actions, and nothing else", async () => {
    const seen: string[] = [];
    const authorize = (_caller: unknown, action: string) => (seen.push(action), action !== "vault:setRecoveryKey" && action !== "auth:changePassword");
    const { app } = buildTestApp("single", { authorize }, { authorize });
    await app.ready();
    const cookie = await loggedIn(app, "me@example.com");
    const send = (method: "POST" | "PUT", url: string, payload: object) => app.inject({ method, url, cookies: { [cookie.name]: cookie.value }, payload });

    const recovery = await send("POST", "/vault/methods/recovery", { recoveryKey: "Ab3x-K9fZ-Qp7w-Tz1m-Lk5j-Nc8h-Rv2d-Xg4y" });
    expect(recovery.statusCode).toBe(403);
    expect(recovery.json()).toEqual({ error: "not allowed: vault:setRecoveryKey" });
    expect((await send("POST", "/auth/password", { currentPassword: "password1", newPassword: "longenough" })).statusCode).toBe(403);
    expect((await send("PUT", "/vault/methods/password", { newPassword: "another-pass" })).statusCode).toBe(200);
    expect(seen).toEqual(["vault:setRecoveryKey", "auth:changePassword", "vault:changePassphrase"]);
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
    const loginRes = await app.inject({ method: "POST", url: "/auth/login", payload: { email, password: "password1" } });
    let cookie = loginRes.cookies[0]!;
    const unlockRes = await app.inject({
      method: "POST",
      url: "/vault/unlock",
      cookies: { [cookie.name]: cookie.value },
      payload: { password: "passphrase" },
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

describe("mode: oidc - closed signup and onLogin", () => {
  it("refuses new identities once an account exists, links existing emails, and hands claims to onLogin", async () => {
    const events: { created: boolean; claims?: Record<string, unknown> }[] = [];
    const { app } = buildTestApp("oidc", { signup: "closed", onLogin: (e) => void events.push(e) });
    await app.ready();
    const callback = async (subject: string, email: string) => {
      vi.mocked(handleOidcCallback).mockResolvedValueOnce({
        issuer: "https://idp.example.com",
        subject,
        email,
        emailVerified: true,
        isAuthorized: true,
        raw: { sub: subject, roles: ["admin"] },
      });
      const cookie = (await app.inject({ method: "GET", url: "/auth/oidc/login" })).cookies[0]!;
      return app.inject({ method: "GET", url: "/auth/oidc/callback?code=c&state=test-state", cookies: { [cookie.name]: cookie.value } });
    };

    expect((await callback("first", "owner@example.com")).statusCode).toBe(302); // the very first account
    expect((await callback("second", "stranger@example.com")).statusCode).toBe(403);
    expect((await callback("first", "owner@example.com")).statusCode).toBe(302); // known identity: fine
    expect(events.map((e) => e.created)).toEqual([true, false]);
    expect(events[0]!.claims).toEqual({ sub: "first", roles: ["admin"] });
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

describe("mode: single - two-step login (MFA)", () => {
  const webauthn = { rpID: "localhost", rpName: "Test App", origin: "http://localhost:5173" };
  const mfa = (required: (userId: number) => boolean) => ({ mfa: { key: randomBytes(32), issuer: "Test App", webauthn, required } });

  /** One browser: keeps the session cookie between requests, like a real one. */
  function browser(app: ReturnType<typeof buildTestApp>["app"]) {
    let cookie: { name: string; value: string } | undefined;
    return async (method: "GET" | "POST", url: string, payload?: unknown, remoteAddress?: string) => {
      const res = await app.inject({ method, url, ...(payload === undefined ? {} : { payload: payload as object }), ...(cookie ? { cookies: { [cookie.name]: cookie.value } } : {}), ...(remoteAddress ? { remoteAddress } : {}) });
      const set = res.cookies.find((c) => c.name === "session");
      if (set) cookie = set.value ? { name: set.name, value: set.value } : undefined;
      return res;
    };
  }
  const codeFor = (secret: string, offsetSteps = 0) => totpCode(base32Decode(secret), totpStep(Date.now()) + offsetSteps);

  it("forces setup when required, then asks for the code at every login; each code works once", async () => {
    const events: { created: boolean }[] = [];
    const { app } = buildTestApp("single", { ...mfa(() => true), onLogin: (e) => void events.push(e) });
    await app.ready();
    const b = browser(app);

    expect((await b("POST", "/auth/login", { email: "me@example.com", password: "password1" })).json()).toEqual({ status: "mfa_setup_required" });
    expect((await b("GET", "/auth/status")).json()).toEqual({ mode: "single", authenticated: false, mfa: "setup" });
    // Half logged in is nobody to the rest of the app.
    expect((await b("GET", "/whoami")).statusCode).toBe(401);
    expect((await b("POST", "/vault/unlock", { password: "passphrase" })).statusCode).toBe(401);
    expect(events).toEqual([]);

    const { secret, uri } = (await b("POST", "/auth/mfa/totp/setup")).json();
    expect(uri).toContain("otpauth://totp/Test%20App%3Ame%40example.com");
    expect((await b("POST", "/auth/mfa/totp/confirm", { code: "000000" })).statusCode).toBe(401);
    const confirmed = await b("POST", "/auth/mfa/totp/confirm", { code: codeFor(secret) });
    expect(confirmed.json().status).toBe("logged_in");
    expect(confirmed.json().recoveryCodes).toHaveLength(10);
    expect((await b("GET", "/whoami")).statusCode).toBe(200);
    expect(events.map((e) => e.created)).toEqual([true]);

    const next = browser(app);
    expect((await next("POST", "/auth/login", { email: "me@example.com", password: "password1" })).json()).toEqual({ status: "mfa_required", factors: ["totp"] });
    expect((await next("GET", "/auth/status")).json().mfa).toBe("verify");
    // The code that confirmed the setup can't be used again.
    expect((await next("POST", "/auth/mfa/verify/totp", { code: codeFor(secret) })).statusCode).toBe(401);
    expect((await next("POST", "/auth/mfa/verify/totp", { code: codeFor(secret, 1) })).json()).toEqual({ status: "logged_in" });
    expect((await next("GET", "/whoami")).statusCode).toBe(200);
    expect(events.map((e) => e.created)).toEqual([true, false]);
  });

  it("logs in with a recovery code once per code", async () => {
    const { app } = buildTestApp("single", mfa(() => true));
    await app.ready();
    const b = browser(app);
    await b("POST", "/auth/login", { email: "me@example.com", password: "password1" });
    const { secret } = (await b("POST", "/auth/mfa/totp/setup")).json();
    const { recoveryCodes } = (await b("POST", "/auth/mfa/totp/confirm", { code: codeFor(secret) })).json();

    const login = async (code: string) => {
      const c = browser(app);
      await c("POST", "/auth/login", { email: "me@example.com", password: "password1" });
      return c("POST", "/auth/mfa/verify/recovery", { code });
    };
    const first = await login(recoveryCodes[0].toUpperCase().replace("-", " "));
    expect(first.json()).toEqual({ status: "logged_in", recoveryCodesLeft: 9 });
    expect((await login(recoveryCodes[0])).statusCode).toBe(401);
  });

  it("blocks after too many wrong codes, and a mid-login session expires", async () => {
    const { app } = buildTestApp("single", mfa(() => true));
    await app.ready();
    const b = browser(app);
    await b("POST", "/auth/login", { email: "me@example.com", password: "password1" });
    const { secret } = (await b("POST", "/auth/mfa/totp/setup")).json();
    await b("POST", "/auth/mfa/totp/confirm", { code: codeFor(secret) });

    const c = browser(app);
    await c("POST", "/auth/login", { email: "me@example.com", password: "password1" });
    for (let i = 0; i < 10; i++) expect((await c("POST", "/auth/mfa/verify/totp", { code: "000000" })).statusCode).toBe(401);
    expect((await c("POST", "/auth/mfa/verify/totp", { code: codeFor(secret, 1) })).statusCode).toBe(429);

    const d = browser(app);
    await d("POST", "/auth/login", { email: "me@example.com", password: "password1" }, "10.0.0.9");
    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now + 11 * 60_000);
    try {
      expect((await d("GET", "/auth/status")).json()).toEqual({ mode: "single", authenticated: false });
      expect((await d("POST", "/auth/mfa/verify/recovery", { code: "x" })).statusCode).toBe(401);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("ends an earlier login in the same browser when the next one stops at the second step", async () => {
    const { app, db } = buildTestApp("single", mfa((userId) => userId === 2));
    await app.ready();
    const b = browser(app);
    await b("POST", "/auth/login", { email: "first@example.com", password: "password1" });
    await createAccountStore(db).create({ email: "second@example.com", password: "password2", displayName: "Second" });
    expect((await b("GET", "/whoami")).json().userId).toBe(1);
    expect((await b("POST", "/auth/login", { email: "second@example.com", password: "password2" })).json().status).toBe("mfa_setup_required");
    expect((await b("GET", "/whoami")).statusCode).toBe(401);
  });

  it("not required: logs straight in until someone sets a factor up, which then needs their password", async () => {
    const { app, db } = buildTestApp("single", mfa(() => false));
    await app.ready();
    const b = browser(app);
    expect((await b("POST", "/auth/login", { email: "me@example.com", password: "password1" })).json()).toEqual({ status: "logged_in" });

    const { secret } = (await b("POST", "/auth/mfa/totp/setup")).json();
    expect((await b("POST", "/auth/mfa/totp/confirm", { code: codeFor(secret) })).statusCode).toBe(401); // no password
    expect((await b("POST", "/auth/mfa/totp/confirm", { code: codeFor(secret), password: "wrong-pass" })).statusCode).toBe(401);
    const added = await b("POST", "/auth/mfa/totp/confirm", { code: codeFor(secret), password: "password1" });
    expect(added.json().status).toBe("added");
    expect(added.json().recoveryCodes).toHaveLength(10);
    expect((await createAccountStore(db).list())[0]!.mfa).toBe(true);

    const status = (await b("GET", "/auth/mfa")).json();
    expect(status.stage).toBe("full");
    const totp = status.factors.find((f: { kind: string }) => f.kind === "totp");
    expect((await b("POST", "/auth/mfa/remove", { id: totp.id, password: "password1" })).json()).toEqual({ status: "removed" });
    // The recovery codes went with the last authenticator.
    expect((await b("GET", "/auth/mfa")).json().factors).toEqual([]);
    expect((await browser(app)("POST", "/auth/login", { email: "me@example.com", password: "password1" })).json()).toEqual({ status: "logged_in" });
  });

  it("required: the last factor can't be removed; an admin reset clears them and ends sessions", async () => {
    const { app, db } = buildTestApp("single", mfa(() => true));
    await app.ready();
    const b = browser(app);
    await b("POST", "/auth/login", { email: "me@example.com", password: "password1" });
    const { secret } = (await b("POST", "/auth/mfa/totp/setup")).json();
    await b("POST", "/auth/mfa/totp/confirm", { code: codeFor(secret) });
    const totp = (await b("GET", "/auth/mfa")).json().factors.find((f: { kind: string }) => f.kind === "totp");
    expect((await b("POST", "/auth/mfa/remove", { id: totp.id, password: "password1" })).statusCode).toBe(409);

    await createAccountStore(db).resetMfa(1);
    expect((await b("GET", "/whoami")).statusCode).toBe(401);
    expect((await browser(app)("POST", "/auth/login", { email: "me@example.com", password: "password1" })).json()).toEqual({ status: "mfa_setup_required" });
  });

  it("sets up a login passkey mid-login and logs in with it", async () => {
    const { app } = buildTestApp("single", mfa(() => true));
    await app.ready();
    const b = browser(app);
    await b("POST", "/auth/login", { email: "me@example.com", password: "password1" });
    expect((await b("POST", "/auth/mfa/passkey/options")).json().options.challenge).toBeTruthy();
    vi.mocked(verifyPasskeyRegistration).mockResolvedValueOnce({ credentialId: "cred-1", publicKey: Buffer.from("pk"), counter: 0 });
    const registered = await b("POST", "/auth/mfa/passkey", { response: { id: "cred-1" }, label: "YubiKey" });
    expect(registered.json().status).toBe("logged_in");

    const c = browser(app);
    expect((await c("POST", "/auth/login", { email: "me@example.com", password: "password1" })).json()).toEqual({ status: "mfa_required", factors: ["passkey"] });
    expect((await c("POST", "/auth/mfa/verify/passkey/options")).json().options.allowCredentials).toEqual([{ id: "cred-1", type: "public-key" }]);
    vi.mocked(verifyPasskeyAuthentication).mockResolvedValueOnce({ newCounter: 0 });
    expect((await c("POST", "/auth/mfa/verify/passkey", { response: { id: "cred-1" } })).json()).toEqual({ status: "logged_in" });
    expect((await c("GET", "/whoami")).statusCode).toBe(200);
  });

  it("refuses a disabled account mid-login, and erasure removes its factors", async () => {
    const { app, db } = buildTestApp("single", mfa(() => true));
    await app.ready();
    const b = browser(app);
    await b("POST", "/auth/login", { email: "me@example.com", password: "password1" });
    const { secret } = (await b("POST", "/auth/mfa/totp/setup")).json();
    await b("POST", "/auth/mfa/totp/confirm", { code: codeFor(secret) });

    const c = browser(app);
    await c("POST", "/auth/login", { email: "me@example.com", password: "password1" });
    const accounts = createAccountStore(db);
    await accounts.disable(1);
    expect((await c("POST", "/auth/mfa/verify/totp", { code: codeFor(secret, 1) })).statusCode).toBe(401);
    await accounts.erase(1);
    expect(db.select().from(schema.userMfaFactor).all()).toEqual([]);
  });
});

describe("invites and OIDC hardening", () => {
  function browser(app: ReturnType<typeof buildTestApp>["app"]) {
    let cookie: { name: string; value: string } | undefined;
    return async (method: "GET" | "POST", url: string, payload?: unknown, remoteAddress?: string) => {
      const res = await app.inject({ method, url, ...(payload === undefined ? {} : { payload: payload as object }), ...(cookie ? { cookies: { [cookie.name]: cookie.value } } : {}), ...(remoteAddress ? { remoteAddress } : {}) });
      const set = res.cookies.find((c) => c.name === "session");
      if (set) cookie = set.value ? { name: set.name, value: set.value } : undefined;
      return res;
    };
  }
  const idpLogin = (subject: string, email: string, extra: Partial<Parameters<typeof vi.mocked<typeof handleOidcCallback>>[0]> & { isAuthorized?: boolean; emailVerified?: boolean; raw?: Record<string, unknown> } = {}) =>
    vi.mocked(handleOidcCallback).mockResolvedValueOnce({ issuer: "https://idp.example.com", subject, email, emailVerified: true, isAuthorized: true, raw: { sub: subject }, ...extra });
  const callback = "/auth/oidc/callback?code=c&state=test-state";

  it("single mode: the link shows who it's for, sets the password once, then works like a normal login", async () => {
    const { app, db } = buildTestApp("single", { signup: "closed" });
    await app.ready();
    await browser(app)("POST", "/auth/login", { email: "owner@example.com", password: "password1" });
    const accounts = createAccountStore(db);
    const invited = await accounts.invite({ email: "jana@example.com", displayName: "Jana" });
    if (!("token" in invited)) throw new Error("no invite");
    // Invited but no password yet: logging in does nothing.
    expect((await browser(app)("POST", "/auth/login", { email: "jana@example.com", password: "password1" })).statusCode).toBe(401);

    const b = browser(app);
    expect((await b("GET", `/auth/invites/${invited.token}`)).json()).toMatchObject({ mode: "single", email: "jana@example.com", displayName: "Jana" });
    expect((await b("POST", `/auth/invites/${invited.token}/accept`, { password: "short" })).statusCode).toBe(400);
    expect((await b("POST", `/auth/invites/${invited.token}/accept`, { password: "janas-password" })).json()).toEqual({ status: "logged_in" });
    expect((await b("GET", "/whoami")).json().userId).toBe(invited.id);
    expect((await browser(app)("GET", `/auth/invites/${invited.token}`)).statusCode).toBe(404);
    expect((await browser(app)("POST", "/auth/login", { email: "jana@example.com", password: "janas-password" })).json()).toEqual({ status: "logged_in" });
    expect((await accounts.list()).find((a) => a.id === invited.id)).toMatchObject({ login: true, invite: { state: "accepted" } });
    expect(await accounts.reinvite(invited.id)).toEqual({ error: "accepted" });
  });

  it("single mode with required MFA: accepting goes on to setting up a factor", async () => {
    const { app, db } = buildTestApp("single", { mfa: { key: randomBytes(32), issuer: "T", webauthn: { rpID: "localhost", rpName: "T", origin: "http://localhost:5173" }, required: () => true } });
    await app.ready();
    const invited = await createAccountStore(db).invite({ email: "jana@example.com", displayName: "Jana" });
    if (!("token" in invited)) throw new Error("no invite");
    const b = browser(app);
    expect((await b("POST", `/auth/invites/${invited.token}/accept`, { password: "janas-password" })).json()).toEqual({ status: "mfa_setup_required" });
    expect((await b("GET", "/whoami")).statusCode).toBe(401);
  });

  it("a new invite replaces the old link; revoked, expired and disabled ones don't work", async () => {
    const { app, db } = buildTestApp("single");
    await app.ready();
    const accounts = createAccountStore(db);
    const first = await accounts.invite({ email: "jana@example.com", displayName: "Jana" });
    if (!("token" in first)) throw new Error("no invite");
    const second = await accounts.reinvite(first.id);
    if (!("token" in second)) throw new Error("no reinvite");
    expect((await browser(app)("GET", `/auth/invites/${first.token}`)).statusCode).toBe(404);
    expect((await browser(app)("GET", `/auth/invites/${second.token}`)).statusCode).toBe(200);

    await accounts.revokeInvite(first.id);
    expect((await browser(app)("GET", `/auth/invites/${second.token}`)).statusCode).toBe(404);
    expect((await accounts.list())[0]!.invite?.state).toBe("revoked");

    const third = await accounts.reinvite(first.id);
    if (!("token" in third)) throw new Error("no reinvite");
    await accounts.disable(first.id);
    expect((await browser(app)("POST", `/auth/invites/${third.token}/accept`, { password: "janas-password" })).statusCode).toBe(403);
    await accounts.enable(first.id);

    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now + 8 * 86_400_000);
    try {
      expect((await browser(app)("GET", `/auth/invites/${third.token}`)).statusCode).toBe(404);
      expect((await accounts.list())[0]!.invite?.state).toBe("expired");
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("limits guessing at invite links per address", async () => {
    const { app } = buildTestApp("single");
    await app.ready();
    for (let i = 0; i < 20; i++) expect((await browser(app)("GET", `/auth/invites/nope-${i}`, undefined, "10.1.1.1")).statusCode).toBe(404);
    expect((await browser(app)("GET", "/auth/invites/nope", undefined, "10.1.1.1")).statusCode).toBe(429);
    expect((await browser(app)("GET", "/auth/invites/nope", undefined, "10.1.1.2")).statusCode).toBe(404);
  });

  it("oidc: an invite ties whatever login the person uses to the invited account, once", async () => {
    const { app, db } = buildTestApp("oidc", { signup: "closed", linkByEmail: false });
    await app.ready();
    const accounts = createAccountStore(db);
    const owner = browser(app);
    await owner("GET", "/auth/oidc/login");
    idpLogin("owner-sub", "owner@example.com");
    expect((await owner("GET", callback)).statusCode).toBe(302);

    const invited = await accounts.invite({ email: "jana@example.com", displayName: "Jana" });
    if (!("token" in invited)) throw new Error("no invite");
    const b = browser(app);
    const start = await b("GET", `/auth/invites/${invited.token}/start`);
    expect(start.statusCode).toBe(302);
    expect(start.headers.location).toContain("idp.example.com");
    // A different (even unverified) address at the IdP is fine: the invite is the proof.
    idpLogin("jana-sub", "jana.private@example.org", { emailVerified: false });
    expect((await b("GET", callback)).statusCode).toBe(302);
    expect((await b("GET", "/whoami")).json().userId).toBe(invited.id);

    const again = browser(app);
    expect((await again("GET", `/auth/invites/${invited.token}/start`)).statusCode).toBe(404);
    await again("GET", "/auth/oidc/login");
    idpLogin("jana-sub", "jana.private@example.org");
    expect((await again("GET", callback)).statusCode).toBe(302);
    expect((await again("GET", "/whoami")).json().userId).toBe(invited.id);
  });

  it("oidc: an invite can't be taken by a login that already belongs to someone", async () => {
    const { app, db } = buildTestApp("oidc", { signup: "closed" });
    await app.ready();
    const owner = browser(app);
    await owner("GET", "/auth/oidc/login");
    idpLogin("owner-sub", "owner@example.com");
    await owner("GET", callback);
    const invited = await createAccountStore(db).invite({ email: "jana@example.com", displayName: "Jana" });
    if (!("token" in invited)) throw new Error("no invite");
    const b = browser(app);
    await b("GET", `/auth/invites/${invited.token}/start`);
    idpLogin("owner-sub", "owner@example.com");
    expect((await b("GET", callback)).statusCode).toBe(403);
    expect((await browser(app)("GET", `/auth/invites/${invited.token}`)).statusCode).toBe(200);
  });

  it("oidc: taking the role away at the IdP locks a known person out", async () => {
    const { app } = buildTestApp("oidc");
    await app.ready();
    const b = browser(app);
    await b("GET", "/auth/oidc/login");
    idpLogin("sub-1", "me@example.com");
    expect((await b("GET", callback)).statusCode).toBe(302);
    const c = browser(app);
    await c("GET", "/auth/oidc/login");
    idpLogin("sub-1", "me@example.com", { isAuthorized: false });
    expect((await c("GET", callback)).statusCode).toBe(403);
  });

  it("oidc: oidcRequireMfa refuses logins whose amr shows no second factor", async () => {
    const { app } = buildTestApp("oidc", { oidcRequireMfa: true });
    await app.ready();
    const b = browser(app);
    await b("GET", "/auth/oidc/login");
    idpLogin("sub-1", "me@example.com", { raw: { sub: "sub-1", amr: ["pwd"] } });
    expect((await b("GET", callback)).statusCode).toBe(403);
    await b("GET", "/auth/oidc/login");
    idpLogin("sub-1", "me@example.com", { raw: { sub: "sub-1", amr: ["pwd", "mfa"] } });
    expect((await b("GET", callback)).statusCode).toBe(302);
  });

  it("oidc: linking by email can be switched off, kept from some accounts, and never doubles up an IdP login", async () => {
    const { app, db } = buildTestApp("oidc", { linkByEmail: (userId) => userId !== 1 });
    await app.ready();
    await createAccountStore(db).create({ email: "root@example.com", password: "password1", displayName: "Root" });
    await createAccountStore(db).create({ email: "jana@example.com", password: "password1", displayName: "Jana" });
    const login = async (subject: string, email: string) => {
      const b = browser(app);
      await b("GET", "/auth/oidc/login");
      idpLogin(subject, email);
      return (await b("GET", callback)).statusCode;
    };
    expect(await login("evil", "root@example.com")).toBe(403);
    expect(await login("jana-1", "jana@example.com")).toBe(302);
    // Same email, another login at the same IdP: someone else, not a second way into Jana's account.
    expect(await login("jana-2", "jana@example.com")).toBe(403);
  });

  it("provisioning: an invited person exists at the IdP and their first login matches them directly; erasure removes them there", async () => {
    const calls: string[] = [];
    const provisioner = {
      issuer: "https://idp.example.com",
      createUser: async ({ email }: { email: string }) => (calls.push(`create ${email}`), { subject: "zit-42" }),
      sendInvite: async (subject: string) => void calls.push(`invite ${subject}`),
      removeUser: async (subject: string) => void calls.push(`remove ${subject}`),
    };
    const { app, db } = buildTestApp("oidc", { signup: "closed", linkByEmail: false });
    await app.ready();
    const accounts = createAccountStore(db, { provisioner });
    const invited = await accounts.invite({ email: "jana@example.com", displayName: "Jana", idpInvite: true });
    if (!("token" in invited)) throw new Error("no invite");
    expect(calls).toEqual(["create jana@example.com", "invite zit-42"]);

    const b = browser(app);
    await b("GET", "/auth/oidc/login");
    idpLogin("zit-42", "jana@example.com");
    expect((await b("GET", callback)).statusCode).toBe(302);
    expect((await b("GET", "/whoami")).json().userId).toBe(invited.id);

    await accounts.disable(invited.id);
    expect(await accounts.erase(invited.id)).toEqual({ ok: true, idp: "removed" });
    expect(calls.at(-1)).toBe("remove zit-42");
  });

  it("provisioning: when the IdP refuses, no account is made here", async () => {
    const provisioner = {
      issuer: "https://idp.example.com",
      createUser: async () => {
        throw new Error("zitadel POST /v2/users/new: 409 User already exists");
      },
      sendInvite: async () => {},
      removeUser: async () => {},
    };
    const { db } = buildTestApp("oidc");
    const accounts = createAccountStore(db, { provisioner });
    expect(await accounts.invite({ email: "jana@example.com", displayName: "Jana" })).toMatchObject({ error: "idp" });
    expect(await accounts.list()).toEqual([]);
  });
});
