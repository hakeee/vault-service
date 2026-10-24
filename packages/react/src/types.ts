import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

export type AuthMode = "none" | "single" | "oidc";

export interface AuthStatus {
  mode: AuthMode;
  authenticated: boolean;
}

export interface VaultStatus {
  unlocked: boolean;
  hasVault: boolean;
  hasPasskey: boolean;
  hasRecoveryKey: boolean;
}

export interface PasskeyRegisterOptions {
  options: PublicKeyCredentialCreationOptionsJSON;
  prfSalt: string;
}

export interface PasskeyAuthOptions {
  options: PublicKeyCredentialRequestOptionsJSON;
  prfSaltByCredentialId: Record<string, string>;
}

export interface VaultMethod {
  id: number;
  method: "password" | "passkey" | "recovery";
  label: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}
