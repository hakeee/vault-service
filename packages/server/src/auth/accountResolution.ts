/** Validated claims from an OIDC callback - see oidc.ts for how these are extracted. */
export interface OidcClaims {
  issuer: string;
  subject: string;
  email: string | undefined;
  emailVerified: boolean;
  /**
   * Whether this login is allowed to create or link an account here -
   * decided by the caller's own `isAuthorizedClaims` predicate on
   * `OidcConfig` (see oidc.ts). Defaults to always-true: any verified
   * login is allowed unless the caller supplies a stricter predicate.
   */
  isAuthorized: boolean;
  /** Every claim of the ID token, e.g. for mapping IdP roles in `onLogin`. */
  raw?: Record<string, unknown>;
}

/** What the caller found by querying its own storage before calling resolveOidcAccount. */
export interface ExistingAccountLookup {
  /** A user_identity(provider="oidc", issuer, subject) row already exists - this is its user_id. */
  identityUserId?: number;
  /** No oidc identity yet, but a local user_identity's user.email matches the claimed email. */
  localUserIdByEmail?: number;
}

export type AccountResolution =
  | { action: "login"; userId: number }
  | { action: "link"; userId: number }
  | { action: "create" }
  | { action: "reject"; reason: string };

/**
 * Pure decision, no I/O - the caller does the actual storage reads/writes
 * based on the action returned. Order matters:
 *
 * 1. An existing oidc identity always wins (fast path, no re-check of
 *    `isAuthorized` - revoking authorization after the fact is a separate
 *    concern, not handled here).
 * 2. Not authorized at all -> reject, regardless of anything else. This
 *    gates linking too, not just brand-new accounts.
 * 3. Authorized, verified email matches an existing local user -> link
 *    (switching from a local password to OIDC keeps all data).
 * 4. Authorized, no match -> create a new user.
 */
export function resolveOidcAccount(claims: OidcClaims, existing: ExistingAccountLookup): AccountResolution {
  if (existing.identityUserId !== undefined) {
    return { action: "login", userId: existing.identityUserId };
  }

  if (!claims.isAuthorized) {
    return { action: "reject", reason: "not authorized" };
  }

  if (existing.localUserIdByEmail !== undefined && claims.emailVerified) {
    return { action: "link", userId: existing.localUserIdByEmail };
  }

  return { action: "create" };
}
