import type { IdentityProvisioner } from "./index.js";

export interface ZitadelProvisionerConfig {
  /** The instance URL, the same as the OIDC issuer (e.g. https://auth.example.cz). */
  issuerUrl: string;
  /** A personal access token of a service user allowed to manage users (`user.write`) in the organization. */
  token: string;
  /** The organization new people go into. Default: the service user's own. */
  organizationId?: string;
  /**
   * The app's project: with it (and `organizationId`, which must own the
   * project), `setRoles` grants people its roles. The service user then also
   * needs `user.grant.write` and `user.grant.read`.
   */
  projectId?: string;
  /** For tests. */
  fetch?: typeof fetch;
}

/**
 * ZITADEL's user API (v2). The user id it returns is the `sub` of that
 * person's ID tokens. CreateUser, CreateInviteCode, DeleteUser and the
 * authorization calls below were confirmed against ZITADEL v4.20, with a
 * service user holding only Org User Manager. The invite email links to
 * ZITADEL's Login V2.
 */
export function createZitadelProvisioner(config: ZitadelProvisionerConfig): IdentityProvisioner {
  const base = config.issuerUrl.replace(/\/+$/, "");
  const doFetch = config.fetch ?? fetch;

  async function call<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const response = await doFetch(`${base}${path}`, {
      method,
      headers: { authorization: `Bearer ${config.token}`, accept: "application/json", ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
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
    ...(config.projectId ? { setRoles } : {}),
  };

  /**
   * The person's authorization ("role assignment") on the project: update it
   * if there is one (its role list is replaced as a whole), else create it.
   * AuthorizationService v2 speaks the Connect protocol. The list filter's
   * JSON shape isn't in the reference (it works on v4.20); results are
   * checked here as well, in case a version ignores a filter.
   */
  async function setRoles(subject: string, roles: readonly string[]): Promise<void> {
    const connect = <T>(method: string, body: unknown) =>
      call<T>("POST", `/zitadel.authorization.v2.AuthorizationService/${method}`, body, { "connect-protocol-version": "1" });
    const { authorizations = [] } = await connect<{ authorizations?: { id: string; user?: { id?: string }; project?: { id?: string } }[] }>("ListAuthorizations", {
      filters: [{ inUserIds: { ids: [subject] } }, { projectId: { id: config.projectId } }],
    });
    const existing = authorizations.find((a) => a.user?.id === subject && a.project?.id === config.projectId);
    if (existing) {
      await connect("UpdateAuthorization", { id: existing.id, roleKeys: [...roles] });
    } else if (roles.length > 0) {
      if (!config.organizationId) throw new Error("zitadel: granting roles needs the organization that owns the project (organizationId)");
      await connect("CreateAuthorization", { userId: subject, projectId: config.projectId, organizationId: config.organizationId, roleKeys: [...roles] });
    }
  }
}
