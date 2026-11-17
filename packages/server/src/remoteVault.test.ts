import Fastify from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateDek } from "./crypto/dek.js";
import { createInternalRoutes } from "./routes/internal.js";
import { createSessionCache, sessionCacheInternals } from "./sessionCache.js";
import { createRemoteVault } from "./workerClient.js";

const sessionCache = createSessionCache(60_000);
sessionCacheInternals(sessionCache).cacheSession("s1", 7, generateDek());

const app = Fastify();
app.register(
  createInternalRoutes({ workerSecret: "worker-secret", sessionCache, scopeSecrets: { journal: "journal-secret" } }),
  { prefix: "/internal" },
);
let baseUrl = "";
beforeAll(async () => {
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address() as { port: number };
  baseUrl = `http://127.0.0.1:${address.port}/internal`;
});
afterAll(() => app.close());

const post = (path: string, secret: string, body: unknown) =>
  fetch(`${baseUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", "x-worker-secret": secret }, body: JSON.stringify(body) });

describe("remote vault", () => {
  it("gives a worker the same named-scope keys the API uses, so data round-trips", async () => {
    const remote = createRemoteVault({ baseUrl, secret: "worker-secret", scopes: ["journal", "notes"] });
    expect(remote.vaultFor("s1")).toBeUndefined(); // nothing until prepared
    await remote.prepare("s1");
    const handle = remote.vaultFor("s1")!;
    expect(handle.userId).toBe(7);

    const local = sessionCache.getVault("s1")!;
    const sealed = local.scope("journal").encryptString("entry.text", "written in the API");
    expect(handle.scope("journal").decryptString("entry.text", sealed)).toBe("written in the API");
    expect(local.scope("notes").decryptString("n", handle.scope("notes").encryptString("n", "from the worker"))).toBe("from the worker");
  });

  it("never hands out the legacy scope or unrequested scopes", async () => {
    const remote = createRemoteVault({ baseUrl, secret: "worker-secret", scopes: ["journal"] });
    await remote.prepare("s1");
    const handle = remote.vaultFor("s1")!;
    expect(() => handle.legacy).toThrow(/never leaves the API/);
    expect(() => handle.scope("people")).toThrow(/wasn't requested/);
  });

  it("limits a per-scope secret to its scope, and to /scope-keys", async () => {
    expect((await post("/scope-keys", "journal-secret", { sessionId: "s1", scopes: ["journal"] })).status).toBe(200);
    expect((await post("/scope-keys", "journal-secret", { sessionId: "s1", scopes: ["journal", "people"] })).status).toBe(403);
    expect((await post("/decrypt", "journal-secret", { sessionId: "s1", ciphertext: "" })).status).toBe(401);
    expect((await post("/scope-keys", "wrong", { sessionId: "s1", scopes: ["journal"] })).status).toBe(401);
  });

  it("reports a locked session as no vault, and rejects bad scope names", async () => {
    const remote = createRemoteVault({ baseUrl, secret: "worker-secret", scopes: ["journal"] });
    await remote.prepare("nope");
    expect(remote.vaultFor("nope")).toBeUndefined();
    expect((await post("/scope-keys", "worker-secret", { sessionId: "s1", scopes: ["Bad:Name"] })).status).toBe(400);
  });

  it("expires cached keys after the ttl", async () => {
    const remote = createRemoteVault({ baseUrl, secret: "worker-secret", scopes: ["journal"], ttlMs: 1 });
    await remote.prepare("s1");
    await new Promise((r) => setTimeout(r, 5));
    expect(remote.vaultFor("s1")).toBeUndefined();
  });
});
