export type AuthMode = "none" | "single" | "oidc";

/**
 * `none` has no login step at all - every request runs as the one
 * implicit user. `single`/`oidc` both gate on the same thing: has this
 * session's cookie already completed a login, regardless of how (local
 * password or an OIDC callback). The two login flows differ; the gate
 * itself doesn't.
 */
export function isAuthorized(mode: AuthMode, authUserId: string | undefined): boolean {
  if (mode === "none") return true;
  return authUserId !== undefined;
}
