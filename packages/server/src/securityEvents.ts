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
