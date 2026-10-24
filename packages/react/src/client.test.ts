import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, createVaultServiceClient } from "./client.js";

function mockFetch(response: () => Response) {
  return vi.fn(async (_url: string, _init?: RequestInit) => response());
}

describe("createVaultServiceClient", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("includes credentials and only sets content-type when there's a body", async () => {
    const fetchMock = mockFetch(() => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = createVaultServiceClient("http://api.example.com");
    await client.request("/vault/status");

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("http://api.example.com/vault/status");
    expect((init as RequestInit).credentials).toBe("include");
    expect((init as RequestInit).headers).not.toHaveProperty("content-type");
  });

  it("sets content-type when a body is sent", async () => {
    const fetchMock = mockFetch(() => new Response(JSON.stringify({ status: "unlocked" }), { status: 200 }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = createVaultServiceClient("http://api.example.com");
    await client.request("/vault/unlock", { method: "POST", body: JSON.stringify({ password: "x" }) });

    const [, init] = fetchMock.mock.calls[0]!;
    expect((init as RequestInit & { headers: Record<string, string> }).headers["content-type"]).toBe("application/json");
  });

  it("throws an ApiError carrying the status and server-provided message", async () => {
    const fetchMock = mockFetch(() => new Response(JSON.stringify({ error: "wrong password" }), { status: 401 }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = createVaultServiceClient("http://api.example.com");

    await expect(client.request("/vault/unlock", { method: "POST", body: "{}" })).rejects.toMatchObject(
      new ApiError(401, "wrong password"),
    );
  });

  it("falls back to the status text when the error body isn't JSON", async () => {
    const fetchMock = vi.fn(async () => new Response("not json", { status: 500, statusText: "Internal Server Error" }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = createVaultServiceClient("http://api.example.com");

    await expect(client.request("/vault/status")).rejects.toMatchObject(new ApiError(500, "Internal Server Error"));
  });
});
