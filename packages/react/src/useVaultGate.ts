import { useAuthStatus, useVaultStatus } from "./hooks.js";
import type { AuthMode, MfaStage } from "./types.js";

export type VaultGateState =
  | { status: "pending" }
  /** Can't reach the server to check status at all - a PWA-style app that must work offline may want to render its main shell here anyway. */
  | { status: "offline" }
  /** `mfa`: the password is done; the second step is due (or a factor must be set up first). */
  | { status: "login-required"; mode: AuthMode; mfa?: MfaStage }
  | { status: "vault-locked"; hasVault: boolean; hasPasskey: boolean; hasRecoveryKey: boolean }
  | { status: "unlocked" };

/**
 * Generalizes the "which screen am I on" branching every consumer of
 * this package would otherwise have to re-derive: auth mode gates who
 * can call the API at all; vault unlock is a separate, later concern.
 * Order matters - vault status is only ever queried once auth is settled
 * (`none` mode, or already authenticated), since it would just 401
 * otherwise.
 */
export function useVaultGate(): VaultGateState {
  const authStatus = useAuthStatus();

  const vaultStatusEnabled = authStatus.data?.mode === "none" || (authStatus.data?.authenticated ?? false);
  const vaultStatus = useVaultStatus({ enabled: vaultStatusEnabled });

  if (authStatus.isPending) return { status: "pending" };
  if (authStatus.isError) return { status: "offline" };

  if (authStatus.data.mode !== "none" && !authStatus.data.authenticated) {
    return { status: "login-required", mode: authStatus.data.mode, ...(authStatus.data.mfa ? { mfa: authStatus.data.mfa } : {}) };
  }

  if (vaultStatus.isPending) return { status: "pending" };
  if (vaultStatus.isError) return { status: "offline" };

  if (!vaultStatus.data.unlocked) {
    return {
      status: "vault-locked",
      hasVault: vaultStatus.data.hasVault,
      hasPasskey: vaultStatus.data.hasPasskey,
      hasRecoveryKey: vaultStatus.data.hasRecoveryKey,
    };
  }

  return { status: "unlocked" };
}
