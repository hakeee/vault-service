import {
  base64URLStringToBuffer,
  bufferToBase64URLString,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import type { VaultServiceClient } from "../client.js";
import type { PasskeyAuthOptions, PasskeyRegisterOptions } from "../types.js";

/**
 * `@simplewebauthn/{server,browser}` pass the WebAuthn `extensions` object
 * straight through to/from the real `navigator.credentials.*` call
 * without ever encoding its contents for JSON transport (unlike every
 * other binary field, which both libraries base64url-encode
 * automatically) - the prf salt/output are this package's own
 * responsibility to shuttle over HTTP, as plain base64url strings sitting
 * alongside (not inside) the library's own options/response objects. See
 * `@hakeee/vault-service`'s `crypto/webauthn.ts` for the server-side half
 * of this caveat.
 */
export class PasskeyUnsupportedError extends Error {
  constructor(
    message = "This device/browser can't use a passkey for vault unlock - stick with the password.",
  ) {
    super(message);
  }
}

/**
 * WebAuthn is unavailable in an insecure context (any origin that isn't
 * https:// or http://localhost) - browsers don't even expose
 * `window.PublicKeyCredential` there, so `@simplewebauthn/browser` falls
 * back to its own generic "WebAuthn is not supported in this browser"
 * Error, indistinguishable from a real lack of platform support. Checked
 * explicitly so the one common, fixable case (serving over plain HTTP to
 * a non-localhost hostname) gets a message that says so, not a
 * "try again" that reads like a transient failure.
 */
function assertSecureContext(): void {
  if (typeof window !== "undefined" && !window.isSecureContext) {
    throw new PasskeyUnsupportedError(
      "Passkeys need a secure connection (https://, or http://localhost) - this page is being served over plain HTTP.",
    );
  }
}

async function getPasskeyRegisterOptions(client: VaultServiceClient): Promise<PasskeyRegisterOptions> {
  return client.request("/vault/methods/passkey/register-options", { method: "POST" });
}

async function getPasskeyAuthOptions(client: VaultServiceClient): Promise<PasskeyAuthOptions> {
  return client.request("/vault/methods/passkey/auth-options");
}

/**
 * Registers a new passkey for this device, wrapping the vault's *current*
 * session DEK (the caller must already be unlocked - adding a passkey
 * happens while already unlocked via another method). Requests the
 * `prf` extension directly at creation time; if the browser doesn't
 * return a result from that single step, this throws rather than
 * attempting a second ceremony - the user just keeps using the password
 * on this device instead, same as the no-prf-support case.
 */
export async function registerPasskey(client: VaultServiceClient, label: string): Promise<void> {
  assertSecureContext();

  const { options, prfSalt } = await getPasskeyRegisterOptions(client);

  const optionsWithPrf = {
    ...options,
    extensions: { ...options.extensions, prf: { eval: { first: base64URLStringToBuffer(prfSalt) } } },
  };

  const response = await startRegistration({ optionsJSON: optionsWithPrf });

  // Always a real ArrayBuffer at runtime per the WebAuthn spec - the
  // BufferSource type just also allows an ArrayBufferView in theory.
  const prfResult = response.clientExtensionResults?.prf?.results?.first as ArrayBuffer | undefined;
  if (!prfResult) {
    throw new PasskeyUnsupportedError();
  }

  await client.request("/vault/methods/passkey", {
    method: "POST",
    body: JSON.stringify({ response, prfOutput: bufferToBase64URLString(prfResult), label }),
  });
}

/** Unlocks the vault with a passkey already registered for this user. */
export async function unlockWithPasskey(client: VaultServiceClient): Promise<void> {
  assertSecureContext();

  const { options, prfSaltByCredentialId } = await getPasskeyAuthOptions(client);

  const evalByCredential: Record<string, { first: ArrayBuffer }> = {};
  for (const [credentialId, saltBase64Url] of Object.entries(prfSaltByCredentialId)) {
    evalByCredential[credentialId] = { first: base64URLStringToBuffer(saltBase64Url) };
  }

  const optionsWithPrf = { ...options, extensions: { ...options.extensions, prf: { evalByCredential } } };

  const response = await startAuthentication({ optionsJSON: optionsWithPrf });

  const prfResult = response.clientExtensionResults?.prf?.results?.first as ArrayBuffer | undefined;
  if (!prfResult) {
    throw new PasskeyUnsupportedError();
  }

  await client.request("/vault/methods/passkey/auth-verify", {
    method: "POST",
    body: JSON.stringify({ response, prfOutput: bufferToBase64URLString(prfResult) }),
  });
}
