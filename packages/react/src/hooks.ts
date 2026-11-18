import { useMutation, useQuery, useQueryClient, type UseMutationResult, type UseQueryResult } from "@tanstack/react-query";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/browser";
import { registerPasskey as browserRegisterPasskey, unlockWithPasskey as browserUnlockWithPasskey } from "./browser/passkey.js";
import { useVaultServiceClient } from "./VaultServiceProvider.js";
import type { AuthStatus, VaultMethod, VaultStatus } from "./types.js";

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

export function useLogin(): UseMutationResult<{ status: string }, Error, { email: string; password: string }> {
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
