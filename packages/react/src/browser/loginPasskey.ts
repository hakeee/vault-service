import { startAuthentication, startRegistration, type PublicKeyCredentialCreationOptionsJSON, type PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import type { VaultServiceClient } from "../client.js";
import type { MfaEnrolled } from "../types.js";

/**
 * Login passkeys: a second factor, nothing more. Unlike vault passkeys
 * (`./passkey.ts`) they don't ask for the PRF extension, so any
 * authenticator works, password managers like Bitwarden included.
 */

export async function registerLoginPasskey(client: VaultServiceClient, body: { label?: string; password?: string }): Promise<MfaEnrolled> {
  const { options } = await client.request<{ options: PublicKeyCredentialCreationOptionsJSON }>("/auth/mfa/passkey/options", { method: "POST" });
  const response = await startRegistration({ optionsJSON: options });
  return client.request("/auth/mfa/passkey", { method: "POST", body: JSON.stringify({ response, ...body }) });
}

export async function verifyLoginPasskey(client: VaultServiceClient): Promise<void> {
  const { options } = await client.request<{ options: PublicKeyCredentialRequestOptionsJSON }>("/auth/mfa/verify/passkey/options", { method: "POST" });
  const response = await startAuthentication({ optionsJSON: options });
  await client.request("/auth/mfa/verify/passkey", { method: "POST", body: JSON.stringify({ response }) });
}
