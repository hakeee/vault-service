/** Validated claims from an OIDC callback - see oidc.ts for how these are extracted. */
export interface OidcClaims {
  issuer: string;
  subject: string;
  email: string | undefined;
  emailVerified: boolean;
  /**
   * Whether this login is allowed at all - decided by the caller's own
   * `isAuthorizedClaims` predicate on `OidcConfig` (see oidc.ts). Checked
   * on every login, so taking a role away at the IdP locks the person out
   * here too. Defaults to always-true.
   */
  isAuthorized: boolean;
  /** Every claim of the ID token, e.g. for mapping IdP roles in `onLogin`. */
  raw?: Record<string, unknown>;
}

/** What the caller found by querying its own storage before calling resolveOidcAccount. */
export interface ExistingAccountLookup {
  /** A user_identity(provider="oidc", issuer, subject) row already exists - this is its user_id. */
  identityUserId?: number;
  /** This browser opened an invite link before logging in - the invited account. */
  invitedUserId?: number;
  /** No identity yet, but an account with the claimed email exists. */
  localUserIdByEmail?: number;
  /** Whether that email match may be linked (the app's `linkByEmail`, and it has no identity from this IdP yet). Default true. */
  emailLinkAllowed?: boolean;
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
 * 1. Not authorized -> reject, always, known identity or not.
 * 2. A known identity logs in (unless an invite says it's someone else).
 * 3. An invite links this identity to the invited account - no email
 *    needed, the token proves it.
 * 4. A verified email matching an account links to it, when allowed.
 * 5. Otherwise a new account. A match that can't be linked is refused
 *    rather than created twice.
 */
export function resolveOidcAccount(claims: OidcClaims, existing: ExistingAccountLookup): AccountResolution {
  if (!claims.isAuthorized) return { action: "reject", reason: "not authorized" };

  if (existing.identityUserId !== undefined) {
    if (existing.invitedUserId !== undefined && existing.invitedUserId !== existing.identityUserId) {
      return { action: "reject", reason: "this login already belongs to another account" };
    }
    return { action: "login", userId: existing.identityUserId };
  }

  if (existing.invitedUserId !== undefined) return { action: "link", userId: existing.invitedUserId };

  if (existing.localUserIdByEmail !== undefined) {
    if (claims.emailVerified && existing.emailLinkAllowed !== false) return { action: "link", userId: existing.localUserIdByEmail };
    return { action: "reject", reason: "an account with this email exists - log in with the invite link you were sent" };
  }

  return { action: "create" };
}
