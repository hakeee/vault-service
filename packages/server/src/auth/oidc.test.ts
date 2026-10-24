import { describe, expect, it, vi } from "vitest";

vi.mock("openid-client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("openid-client")>();
  return { ...actual, authorizationCodeGrant: vi.fn() };
});

import { authorizationCodeGrant } from "openid-client";
import { handleOidcCallback, type OidcConfig } from "./oidc.js";

function fakeTokens(claims: Record<string, unknown>) {
  return { claims: () => claims } as never;
}

const baseConfig: OidcConfig = {
  issuerUrl: "https://idp.example.com",
  clientId: "client",
  clientSecret: "secret",
  redirectUrl: "http://localhost:3000/auth/oidc/callback",
};

const baseParams = {
  currentUrl: new URL("http://localhost:3000/auth/oidc/callback?code=x&state=test-state"),
  codeVerifier: "verifier",
  expectedState: "test-state",
  expectedNonce: "test-nonce",
};

describe("handleOidcCallback", () => {
  it("defaults isAuthorized to true when no predicate is supplied", async () => {
    vi.mocked(authorizationCodeGrant).mockResolvedValueOnce(
      fakeTokens({ iss: "https://idp.example.com", sub: "sub-1", email: "a@example.com", email_verified: true }),
    );

    const claims = await handleOidcCallback({} as never, baseConfig, baseParams);

    expect(claims.isAuthorized).toBe(true);
  });

  it("runs the supplied predicate against the raw id token claims", async () => {
    const rawClaims = {
      iss: "https://idp.example.com",
      sub: "sub-2",
      email: "b@example.com",
      email_verified: true,
      "urn:zitadel:iam:org:project:42:roles": { admin: {} },
    };
    vi.mocked(authorizationCodeGrant).mockResolvedValueOnce(fakeTokens(rawClaims));

    const isAuthorizedClaims = vi.fn(
      (c: Record<string, unknown>) =>
        typeof c["urn:zitadel:iam:org:project:42:roles"] === "object" && c["urn:zitadel:iam:org:project:42:roles"] !== null,
    );

    const claims = await handleOidcCallback({} as never, { ...baseConfig, isAuthorizedClaims }, baseParams);

    expect(isAuthorizedClaims).toHaveBeenCalledWith(rawClaims);
    expect(claims.isAuthorized).toBe(true);
  });

  it("rejects when the supplied predicate returns false", async () => {
    vi.mocked(authorizationCodeGrant).mockResolvedValueOnce(
      fakeTokens({ iss: "https://idp.example.com", sub: "sub-3", email: "c@example.com", email_verified: true }),
    );

    const claims = await handleOidcCallback(
      {} as never,
      { ...baseConfig, isAuthorizedClaims: () => false },
      baseParams,
    );

    expect(claims.isAuthorized).toBe(false);
  });
});
