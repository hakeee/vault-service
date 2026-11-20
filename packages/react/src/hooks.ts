import { useMutation, useQuery, useQueryClient, type UseMutationResult, type UseQueryResult } from "@tanstack/react-query";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/browser";
import { registerPasskey as browserRegisterPasskey, unlockWithPasskey as browserUnlockWithPasskey } from "./browser/passkey.js";
import { registerLoginPasskey, verifyLoginPasskey } from "./browser/loginPasskey.js";
import { useVaultServiceClient } from "./VaultServiceProvider.js";
import type { AuthStatus, LoginResult, MfaEnrolled, MfaStatus, VaultMethod, VaultStatus } from "./types.js";

/** The query key prefix of every hook here - invalidate it to re-check login and vault state from outside React. */
export const vaultServiceQueryKey = ["vaultService"] as const;

/**
 * Re-checks login and vault state, e.g. when a live socket reports the
 * vault locked or a request came back 423. `useVaultGate` follows.
 */
export function useRefreshVaultState(): () => void {
  const queryClient = useQueryClient();
  return () => void queryClient.invalidateQueries({ queryKey: vaultServiceQueryKey });
}

/** Checked before vault status - auth mode gates who can call the API at all, independent of vault unlock. */
export function useAuthStatus(): UseQueryResult<AuthStatus> {
  const client = useVaultServiceClient();
  return useQuery({
    queryKey: ["vaultService", "authStatus"],
    queryFn: () => client.request<AuthStatus>("/auth/status"),
    retry: false,
  });
}

export function useLogin(): UseMutationResult<LoginResult, Error, { email: string; password: string }> {
  const client = useVaultServiceClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ email, password }) =>
      client.request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vaultService", "authStatus"] });
    },
  });
}

export function useLogout(): UseMutationResult<{ status: string }, Error, void> {
  const client = useVaultServiceClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => client.request("/auth/logout", { method: "POST" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vaultService"] });
    },
  });
}

/** Changes the login password (single mode) - not the vault passphrase (`useChangePassword`). */
export function useChangeLoginPassword(): UseMutationResult<{ status: string }, Error, { currentPassword: string; newPassword: string }> {
  const client = useVaultServiceClient();
  return useMutation({
    mutationFn: (body) => client.request("/auth/password", { method: "POST", body: JSON.stringify(body) }),
  });
}

/** Full-page navigation, not a fetch - the IdP's login page isn't something the client's request() can handle. */
export function useOidcLoginUrl(): string {
  const client = useVaultServiceClient();
  return `${client.baseUrl}/auth/oidc/login`;
}

export function useVaultStatus(options: { enabled?: boolean } = {}): UseQueryResult<VaultStatus> {
  const client = useVaultServiceClient();
  return useQuery({
    queryKey: ["vaultService", "vaultStatus"],
    queryFn: () => client.request<VaultStatus>("/vault/status"),
    retry: false,
    enabled: options.enabled ?? true,
  });
}

function useInvalidateVaultStatus() {
  const queryClient = useQueryClient();
  return () => void queryClient.invalidateQueries({ queryKey: ["vaultService", "vaultStatus"] });
}

export function useUnlockWithPassword(): UseMutationResult<{ status: string }, Error, string> {
  const client = useVaultServiceClient();
  const invalidate = useInvalidateVaultStatus();
  return useMutation({
    mutationFn: (password: string) => client.request("/vault/unlock", { method: "POST", body: JSON.stringify({ password }) }),
    onSuccess: invalidate,
  });
}

/** Locks the vault but keeps the login; `useLogout` clears both. */
export function useLockVault(): UseMutationResult<{ status: string }, Error, void> {
  const client = useVaultServiceClient();
  const invalidate = useInvalidateVaultStatus();
  return useMutation({
    mutationFn: () => client.request("/vault/lock", { method: "POST" }),
    onSuccess: invalidate,
  });
}

export function useUnlockWithPasskey(): UseMutationResult<void, Error, void> {
  const client = useVaultServiceClient();
  const invalidate = useInvalidateVaultStatus();
  return useMutation({
    mutationFn: () => browserUnlockWithPasskey(client),
    onSuccess: invalidate,
  });
}

export function useUnlockWithRecoveryKey(): UseMutationResult<{ status: string }, Error, string> {
  const client = useVaultServiceClient();
  const invalidate = useInvalidateVaultStatus();
  return useMutation({
    mutationFn: (recoveryKey: string) =>
      client.request("/vault/unlock-with-recovery", { method: "POST", body: JSON.stringify({ recoveryKey }) }),
    onSuccess: invalidate,
  });
}

export function usePasskeyRegistration(): UseMutationResult<void, Error, string> {
  const client = useVaultServiceClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (label: string) => browserRegisterPasskey(client, label),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vaultService"] });
    },
  });
}

export function useRegisterRecoveryKey(): UseMutationResult<{ status: string }, Error, string> {
  const client = useVaultServiceClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (recoveryKey: string) =>
      client.request("/vault/methods/recovery", { method: "POST", body: JSON.stringify({ recoveryKey }) }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vaultService"] });
    },
  });
}

export function useVaultMethods(options: { enabled?: boolean } = {}): UseQueryResult<{ methods: VaultMethod[] }> {
  const client = useVaultServiceClient();
  return useQuery({
    queryKey: ["vaultService", "vaultMethods"],
    queryFn: () => client.request<{ methods: VaultMethod[] }>("/vault/methods"),
    enabled: options.enabled ?? true,
  });
}

export function useRevokeVaultMethod(): UseMutationResult<{ status: string }, Error, number> {
  const client = useVaultServiceClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => client.request(`/vault/methods/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      // Status too: hasPasskey / hasRecoveryKey may have just flipped.
      void queryClient.invalidateQueries({ queryKey: ["vaultService"] });
    },
  });
}

/** Needs an unlocked vault; the old password isn't asked for (see the server route). */
export function useChangePassword(): UseMutationResult<{ status: string }, Error, string> {
  const client = useVaultServiceClient();
  return useMutation({
    mutationFn: (newPassword: string) =>
      client.request("/vault/methods/password", { method: "PUT", body: JSON.stringify({ newPassword }) }),
  });
}

// Re-exported so a consumer never needs to import @simplewebauthn/browser
// itself just to type a passkey ceremony's response.
export type { AuthenticationResponseJSON, RegistrationResponseJSON };

// --- two-step login (MFA, `single` mode) -------------------------------------

const mfaKey = ["vaultService", "mfa"] as const;

/** Where the login stands and, once logged in, your second factors. */
export function useMfaStatus(options: { enabled?: boolean } = {}): UseQueryResult<MfaStatus> {
  const client = useVaultServiceClient();
  return useQuery({ queryKey: mfaKey, queryFn: () => client.request<MfaStatus>("/auth/mfa"), enabled: options.enabled ?? true, retry: false });
}

/** Re-checks login state after a step that may have finished the login. */
function useAfterMfaStep() {
  const queryClient = useQueryClient();
  return () => void queryClient.invalidateQueries({ queryKey: vaultServiceQueryKey });
}

/** The second step of a login: a code from the authenticator app. */
export function useVerifyTotp(): UseMutationResult<{ status: string }, Error, string> {
  const client = useVaultServiceClient();
  const done = useAfterMfaStep();
  return useMutation({ mutationFn: (code) => client.request("/auth/mfa/verify/totp", { method: "POST", body: JSON.stringify({ code }) }), onSuccess: done });
}

/** The second step with a recovery code (each works once). */
export function useVerifyRecoveryCode(): UseMutationResult<{ status: string; recoveryCodesLeft: number }, Error, string> {
  const client = useVaultServiceClient();
  const done = useAfterMfaStep();
  return useMutation({ mutationFn: (code) => client.request("/auth/mfa/verify/recovery", { method: "POST", body: JSON.stringify({ code }) }), onSuccess: done });
}

/** The second step with a login passkey (any authenticator; no PRF needed). */
export function useVerifyLoginPasskey(): UseMutationResult<void, Error, void> {
  const client = useVaultServiceClient();
  const done = useAfterMfaStep();
  return useMutation({ mutationFn: () => verifyLoginPasskey(client), onSuccess: done });
}

/** Starts adding an authenticator app: the secret and the `otpauth://` link for a QR code. */
export function useStartTotpSetup(): UseMutationResult<{ secret: string; uri: string }, Error, void> {
  const client = useVaultServiceClient();
  return useMutation({ mutationFn: () => client.request("/auth/mfa/totp/setup", { method: "POST" }) });
}

/** Finishes adding an authenticator app with a code from it. Once logged in, `password` is required too. */
export function useConfirmTotp(): UseMutationResult<MfaEnrolled, Error, { code: string; label?: string; password?: string }> {
  const client = useVaultServiceClient();
  const done = useAfterMfaStep();
  return useMutation({ mutationFn: (body) => client.request("/auth/mfa/totp/confirm", { method: "POST", body: JSON.stringify(body) }), onSuccess: done });
}

/** Adds a login passkey (Bitwarden and other managers work: no PRF needed). Once logged in, `password` is required too. */
export function useRegisterLoginPasskey(): UseMutationResult<MfaEnrolled, Error, { label?: string; password?: string }> {
  const client = useVaultServiceClient();
  const done = useAfterMfaStep();
  return useMutation({ mutationFn: (body) => registerLoginPasskey(client, body), onSuccess: done });
}

/** A fresh set of recovery codes (the old ones stop working). Show them once. */
export function useNewRecoveryCodes(): UseMutationResult<{ recoveryCodes: string[] }, Error, { password: string }> {
  const client = useVaultServiceClient();
  const done = useAfterMfaStep();
  return useMutation({ mutationFn: (body) => client.request("/auth/mfa/recovery", { method: "POST", body: JSON.stringify(body) }), onSuccess: done });
}

export function useRemoveMfaFactor(): UseMutationResult<{ status: string }, Error, { id: number; password: string }> {
  const client = useVaultServiceClient();
  const done = useAfterMfaStep();
  return useMutation({ mutationFn: (body) => client.request("/auth/mfa/remove", { method: "POST", body: JSON.stringify(body) }), onSuccess: done });
}
