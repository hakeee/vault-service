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
  it("logs in when an oidc identity already exists", () => {
    expect(resolveOidcAccount(claims(), { identityUserId: 7 })).toEqual({ action: "login", userId: 7 });
  });

  it("re-checks authorization on every login, known identity or not", () => {
    expect(resolveOidcAccount(claims({ isAuthorized: false }), { identityUserId: 7 }).action).toBe("reject");
    expect(resolveOidcAccount(claims({ isAuthorized: false }), {}).action).toBe("reject");
    expect(resolveOidcAccount(claims({ isAuthorized: false }), { invitedUserId: 3 }).action).toBe("reject");
    expect(resolveOidcAccount(claims({ isAuthorized: false }), { localUserIdByEmail: 3 }).action).toBe("reject");
  });

  it("links an invited account by the invite, whatever the email says", () => {
    expect(resolveOidcAccount(claims({ email: "other@example.com", emailVerified: false }), { invitedUserId: 3 })).toEqual({ action: "link", userId: 3 });
  });

  it("refuses an invite when this login already belongs to someone else", () => {
    expect(resolveOidcAccount(claims(), { identityUserId: 7, invitedUserId: 3 }).action).toBe("reject");
    expect(resolveOidcAccount(claims(), { identityUserId: 3, invitedUserId: 3 })).toEqual({ action: "login", userId: 3 });
  });

  it("links a verified email match when allowed", () => {
    expect(resolveOidcAccount(claims(), { localUserIdByEmail: 3 })).toEqual({ action: "link", userId: 3 });
  });

  it("refuses an email match it may not link, instead of creating a duplicate", () => {
    expect(resolveOidcAccount(claims({ emailVerified: false }), { localUserIdByEmail: 3 }).action).toBe("reject");
    expect(resolveOidcAccount(claims(), { localUserIdByEmail: 3, emailLinkAllowed: false }).action).toBe("reject");
  });

  it("creates a new account when authorized and nothing matches", () => {
    expect(resolveOidcAccount(claims(), {})).toEqual({ action: "create" });
  });
});
