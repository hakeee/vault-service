import secureSession from "@fastify/secure-session";
import Fastify from "fastify";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateDek } from "./crypto/dek.js";
import { createRequireVault } from "./requireVault.js";
import { createSessionCache, sessionCacheInternals } from "./sessionCache.js";
import * as packageIndex from "./index.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("session cache", () => {
  it("hands out a vault handle that never exposes the DEK", () => {
    const cache = createSessionCache(60_000);
    const dek = generateDek();
    sessionCacheInternals(cache).cacheSession("s1", 7, dek);

    const vault = cache.getVault("s1")!;
    expect(vault.userId).toBe(7);

    const reachable = JSON.stringify(vault, (_key, value) =>
      Buffer.isBuffer(value) || (value && value.type === "Buffer") ? "<<buffer>>" : value,
    );
    expect(reachable).not.toContain("<<buffer>>");
    expect(Object.keys(vault)).not.toContain("dek");
    expect(Object.keys(cache)).not.toContain("getSession");
  });

  it("doesn't export raw session access from the package", () => {
    expect(packageIndex).not.toHaveProperty("sessionCacheInternals");
  });

  it("gives the same scope the same keys across handles in one session", () => {
    const cache = createSessionCache(60_000);
    sessionCacheInternals(cache).cacheSession("s1", 1, generateDek());
    const sealed = cache.getVault("s1")!.scope("notes").encryptString("c", "x");
    expect(cache.getVault("s1")!.scope("notes").decryptString("c", sealed)).toBe("x");
  });

  it("locks after the idle timeout, and reading extends it", () => {
    vi.useFakeTimers();
    const cache = createSessionCache(1_000);
    sessionCacheInternals(cache).cacheSession("s1", 1, generateDek());

    vi.advanceTimersByTime(800);
    expect(cache.isUnlocked("s1")).toBe(true); // extends to t=1800
    vi.advanceTimersByTime(800);
    expect(cache.getVault("s1")).toBeDefined();
    vi.advanceTimersByTime(1_001);
    expect(cache.getVault("s1")).toBeUndefined();
  });

  it("refuses foreign objects as a cache", () => {
    expect(() => sessionCacheInternals({} as never)).toThrow();
  });
});

describe("requireVault", () => {
  async function appWith(lockedStatus?: number) {
    const cache = createSessionCache(60_000);
    const app = Fastify();
    app.register(secureSession, { key: randomBytes(32), cookie: { path: "/" } });
    const requireVault = createRequireVault(cache, lockedStatus ? { lockedStatus } : {});
    app.post("/unlock", async (request) => {
      (request.session as unknown as { set(k: string, v: string): void }).set("id", "sid");
      sessionCacheInternals(cache).cacheSession("sid", 3, generateDek());
      return {};
    });
    app.get("/secret", async (request, reply) => {
      const unlocked = requireVault(request, reply);
      if (!unlocked) return;
      const notes = unlocked.vault.scope<"note.body">("notes");
      return { userId: unlocked.userId, sessionId: unlocked.sessionId, ok: notes.decryptString("note.body", notes.encryptString("note.body", "hi")) };
    });
    await app.ready();
    return app;
  }

  it("replies 423 while locked, and returns the vault once unlocked", async () => {
    const app = await appWith();
    expect((await app.inject({ method: "GET", url: "/secret" })).statusCode).toBe(423);

    const unlock = await app.inject({ method: "POST", url: "/unlock" });
    const cookie = unlock.headers["set-cookie"] as string;
    const res = await app.inject({ method: "GET", url: "/secret", headers: { cookie } });
    expect(res.json()).toEqual({ userId: 3, sessionId: "sid", ok: "hi" });
  });

  it("uses a custom locked status", async () => {
    const app = await appWith(404);
    expect((await app.inject({ method: "GET", url: "/secret" })).statusCode).toBe(404);
  });
});
