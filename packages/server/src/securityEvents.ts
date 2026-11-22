/**
 * Changes to how someone logs in, for the app to tell them about (e.g. by
 * email), so a change they didn't make doesn't go unnoticed.
 *
 * - `password-changed`: they changed their login password (other sessions ended).
 * - `factor-added` / `factor-removed`: an authenticator app or login passkey.
 * - `recovery-codes-replaced`: a new set of recovery codes (old ones stop working).
 * - `mfa-blocked`: too many wrong second-factor codes; someone may have their password.
 */
export interface SecurityEvent {
  userId: number;
  kind: "password-changed" | "factor-added" | "factor-removed" | "recovery-codes-replaced" | "mfa-blocked";
  /** factor-added / factor-removed: which kind of factor. */
  factor?: "totp" | "passkey";
}

/** Runs after the change is saved. Failures are logged, never undo the change. */
export type SecurityEventHandler = (event: SecurityEvent) => void | Promise<void>;

/** Calls the app's handler without letting it break the request. */
export function securityNotifier(handler: SecurityEventHandler | undefined, log: (error: unknown) => void) {
  return (event: SecurityEvent): void => {
    if (!handler) return;
    void Promise.resolve()
      .then(() => handler(event))
      .catch(log);
  };
}

/**
 * Something that happened at the door, for an audit trail (`onAudit` on the
 * auth and vault routes): logins and their failures, second factors,
 * password and passphrase changes, unlocks. Storing them is the app's job.
 */
export interface AuthAuditEvent {
  action:
    | "login" // a finished login (detail: local / oidc)
    | "login.password" // the password step: failed, blocked, refused (disabled), ok (second step follows)
    | "login.mfa" // a wrong or blocked second-factor code
    | "logout"
    | "reauth" // the password re-typed on a logged-in session (changing factors)
    | "password.change"
    | "mfa.factor-added"
    | "mfa.factor-removed"
    | "mfa.recovery-codes"
    | "invite.open" // a link that didn't match an open invite
    | "invite.accept"
    | "oidc.refused" // detail: the refusal code
    | "vault.unlock" // detail: passphrase / recovery / passkey
    | "vault.passphrase-change"
    | "vault.method-added"
    | "vault.method-removed";
  outcome: "ok" | "failed" | "blocked" | "refused";
  /** The account, when known. */
  userId?: number;
  /** Login attempts: the email that was typed (lowercased), also for accounts that don't exist. */
  email?: string;
  /** The client's address (`request.ip`). */
  ip: string;
  detail?: string;
}

export type AuditHandler = (event: AuthAuditEvent) => void;

/** Calls the app's audit handler; a throwing one is logged, never breaks the request. */
export function auditor(handler: AuditHandler | undefined, log: (error: unknown) => void) {
  return (event: AuthAuditEvent): void => {
    if (!handler) return;
    try {
      handler(event);
    } catch (error) {
      log(error);
    }
  };
}
