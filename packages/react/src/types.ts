import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

export type AuthMode = "none" | "single" | "oidc";

/** Mid-login: the password is done and a second factor is due ("verify") or must be set up first ("setup"). */
export type MfaStage = "verify" | "setup";

export interface AuthStatus {
  mode: AuthMode;
  authenticated: boolean;
  mfa?: MfaStage;
}

/** What `POST /auth/login` answers: logged in, or on to the second step. */
export type LoginResult = { status: "logged_in" } | { status: "mfa_required"; factors: ("totp" | "passkey")[] } | { status: "mfa_setup_required" };

export interface MfaFactor {
  id: number;
  kind: "totp" | "passkey" | "recovery";
  label: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  /** Recovery codes: how many are left. */
  remaining?: number;
}

export interface MfaStatus {
  stage: MfaStage | "full";
  /** Whether this person must use two-step login. */
  required: boolean;
  kinds: MfaFactor["kind"][];
  /** Only once fully logged in. */
  factors: MfaFactor[];
}

/** After adding an authenticator or passkey: `recoveryCodes` the first time (show them once). */
export interface MfaEnrolled {
  status: "logged_in" | "added";
  recoveryCodes?: string[];
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
