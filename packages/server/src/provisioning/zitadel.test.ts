import { describe, expect, it } from "vitest";
import { createZitadelProvisioner } from "./zitadel.js";

function fakeFetch(answers: Record<string, { status: number; body: unknown }>) {
  const calls: { method: string; url: string; headers: Record<string, string>; body?: unknown }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ method: init.method!, url, headers: init.headers as Record<string, string>, body: init.body ? JSON.parse(String(init.body)) : undefined });
    const answer = answers[`${init.method} ${url}`] ?? { status: 404, body: { message: "not found" } };
    return new Response(JSON.stringify(answer.body), { status: answer.status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe("zitadel provisioner", () => {
  it("creates a human user with a verified email and returns its id as the subject", async () => {
    const { impl, calls } = fakeFetch({ "POST https://auth.example.cz/v2/users/new": { status: 200, body: { id: "3141" } } });
    const zitadel = createZitadelProvisioner({ issuerUrl: "https://auth.example.cz/", token: "pat", organizationId: "org1", fetch: impl });
    expect(zitadel.issuer).toBe("https://auth.example.cz");
    expect(await zitadel.createUser({ email: "jana@example.cz", displayName: "Jana Nováková" })).toEqual({ subject: "3141" });
    expect(calls[0]!.headers.authorization).toBe("Bearer pat");
    expect(calls[0]!.body).toEqual({
      organizationId: "org1",
      username: "jana@example.cz",
      human: { profile: { givenName: "Jana", familyName: "Nováková", displayName: "Jana Nováková" }, email: { email: "jana@example.cz", isVerified: true } },
    });
  });

  it("sends invite codes and deletes users", async () => {
    const { impl, calls } = fakeFetch({
      "POST https://auth.example.cz/v2/users/3141/invite_code": { status: 200, body: {} },
      "DELETE https://auth.example.cz/v2/users/3141": { status: 200, body: {} },
    });
    const zitadel = createZitadelProvisioner({ issuerUrl: "https://auth.example.cz", token: "pat", fetch: impl });
    await zitadel.sendInvite("3141");
    await zitadel.removeUser("3141");
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual(["POST https://auth.example.cz/v2/users/3141/invite_code", "DELETE https://auth.example.cz/v2/users/3141"]);
    expect(calls[0]!.body).toEqual({ sendCode: {} });
  });

  it("reports what ZITADEL said when it refuses, without the token", async () => {
    const { impl } = fakeFetch({ "POST https://auth.example.cz/v2/users/new": { status: 409, body: { message: "User already exists" } } });
    const zitadel = createZitadelProvisioner({ issuerUrl: "https://auth.example.cz", token: "secret-pat", fetch: impl });
    const error = await zitadel.createUser({ email: "a@b.cz", displayName: "A" }).catch((e: Error) => e);
    expect(String(error)).toContain("409");
    expect(String(error)).toContain("User already exists");
    expect(String(error)).not.toContain("secret-pat");
  });
});
