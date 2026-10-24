import { describe, expect, it } from "vitest";
import { resolveOidcAccount, type OidcClaims } from "./accountResolution.js";

function claims(overrides: Partial<OidcClaims> = {}): OidcClaims {
  return {
    issuer: "https://idp.example.com",
    subject: "sub-123",
    email: "me@example.com",
    emailVerified: true,
    isAuthorized: true,
    ...overrides,
  };
}

describe("resolveOidcAccount", () => {
  it("logs in when an oidc identity already exists, even without re-checking authorization", () => {
    const resolution = resolveOidcAccount(claims({ isAuthorized: false }), { identityUserId: 7 });

    expect(resolution).toEqual({ action: "login", userId: 7 });
  });

  it("rejects when not authorized and no existing identity", () => {
    const resolution = resolveOidcAccount(claims({ isAuthorized: false }), {});

    expect(resolution.action).toBe("reject");
  });

  it("rejects an unauthorized account even if its email matches an existing local user", () => {
    const resolution = resolveOidcAccount(claims({ isAuthorized: false }), { localUserIdByEmail: 3 });

    expect(resolution.action).toBe("reject");
  });

  it("links to the existing local user when authorized and the verified email matches", () => {
    const resolution = resolveOidcAccount(claims(), { localUserIdByEmail: 3 });

    expect(resolution).toEqual({ action: "link", userId: 3 });
  });

  it("does not link on an unverified email match - creates instead", () => {
    const resolution = resolveOidcAccount(claims({ emailVerified: false }), { localUserIdByEmail: 3 });

    expect(resolution).toEqual({ action: "create" });
  });

  it("creates a new account when authorized and nothing matches", () => {
    const resolution = resolveOidcAccount(claims(), {});

    expect(resolution).toEqual({ action: "create" });
  });
});
