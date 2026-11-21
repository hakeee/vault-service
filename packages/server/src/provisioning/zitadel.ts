import type { IdentityProvisioner } from "./index.js";

export interface ZitadelProvisionerConfig {
  /** The instance URL, the same as the OIDC issuer (e.g. https://auth.example.cz). */
  issuerUrl: string;
  /** A personal access token of a service user allowed to manage users (`user.write`) in the organization. */
  token: string;
  /** The organization new people go into. Default: the service user's own. */
  organizationId?: string;
  /** For tests. */
  fetch?: typeof fetch;
}

/**
 * ZITADEL's user API (v2). The user id it returns is the `sub` of that
 * person's ID tokens. Request shapes follow the v2 reference (CreateUser,
 * CreateInviteCode, DeleteUser); confirm them against the production
 * instance in the trial run before relying on them.
 */
export function createZitadelProvisioner(config: ZitadelProvisionerConfig): IdentityProvisioner {
  const base = config.issuerUrl.replace(/\/+$/, "");
  const doFetch = config.fetch ?? fetch;

  async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await doFetch(`${base}${path}`, {
      method,
      headers: { authorization: `Bearer ${config.token}`, accept: "application/json", ...(body === undefined ? {} : { "content-type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      // ZITADEL's error body says what's wrong (no secrets in it); keep it for the log, not the token.
      const detail = await response.text().catch(() => "");
      throw new Error(`zitadel ${method} ${path}: ${response.status} ${detail.slice(0, 300)}`);
    }
    return (await response.json()) as T;
  }

  return {
    issuer: base,
    async createUser({ email, displayName }) {
      const [givenName, ...rest] = displayName.trim().split(/\s+/);
      const created = await call<{ id: string }>("POST", "/v2/users/new", {
        ...(config.organizationId ? { organizationId: config.organizationId } : {}),
        username: email,
        human: {
          // ZITADEL wants both names; one-word names go in both.
          profile: { givenName: givenName || email, familyName: rest.join(" ") || givenName || email, displayName },
          // The app invited them to this address, so it counts as known; their sign-in comes with the invite code.
          email: { email, isVerified: true },
        },
      });
      return { subject: created.id };
    },
    async sendInvite(subject) {
      await call("POST", `/v2/users/${encodeURIComponent(subject)}/invite_code`, { sendCode: {} });
    },
    async removeUser(subject) {
      await call("DELETE", `/v2/users/${encodeURIComponent(subject)}`);
    },
  };
}
