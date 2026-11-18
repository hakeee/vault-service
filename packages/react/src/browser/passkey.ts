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
export type PasskeyUnsupportedReason =
  /** Plain HTTP on a non-localhost host: the browser hides WebAuthn entirely. */
  | "insecure-context"
  /** The authenticator didn't report PRF support at all (e.g. some password managers). */
  | "no-prf"
  /** It claimed PRF support but never returned an output. */
  | "no-prf-output";

const REASON_MESSAGES: Record<PasskeyUnsupportedReason, string> = {
  "insecure-context":
    "Passkeys need a secure connection (https://, or http://localhost) - this page is being served over plain HTTP.",
  "no-prf":
    "This passkey provider doesn't support the PRF extension, which vault unlock needs (some password managers don't yet). If it just saved a passkey, delete it there; a security key or your phone's passkeys may work instead.",
  "no-prf-output":
    "This passkey said it supports PRF but didn't return a key, so it can't unlock the vault. If it just saved a passkey, delete it there.",
};

export class PasskeyUnsupportedError extends Error {
  readonly reason: PasskeyUnsupportedReason;

  constructor(reason: PasskeyUnsupportedReason = "no-prf", message = REASON_MESSAGES[reason]) {
    super(message);
    this.reason = reason;
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
    throw new PasskeyUnsupportedError("insecure-context");
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
 * `prf` extension at creation time. The spec lets an authenticator answer
 * that with only `prf.enabled: true` and return the actual output on its
 * first assertion instead (some security keys and platforms do), so in
 * that case this runs one assertion against the new credential right away
 * - a second prompt for the user - before giving up.
 */
export async function registerPasskey(client: VaultServiceClient, label: string): Promise<void> {
  assertSecureContext();

  const { options, prfSalt } = await getPasskeyRegisterOptions(client);

  const optionsWithPrf = {
    ...options,
    extensions: { ...options.extensions, prf: { eval: { first: base64URLStringToBuffer(prfSalt) } } },
  };

  const response = await startRegistration({ optionsJSON: optionsWithPrf });

  const prf = response.clientExtensionResults?.prf;
  // Always a real ArrayBuffer at runtime per the WebAuthn spec - the
  // BufferSource type just also allows an ArrayBufferView in theory.
  let prfResult = prf?.results?.first as ArrayBuffer | undefined;
  if (!prfResult) {
    if (prf?.enabled !== true) throw new PasskeyUnsupportedError("no-prf");
    prfResult = await evaluatePrf(options.rp.id ?? window.location.hostname, response.id, prfSalt);
  }

  await client.request("/vault/methods/passkey", {
    method: "POST",
    body: JSON.stringify({ response, prfOutput: bufferToBase64URLString(prfResult), label }),
  });
}

/**
 * One assertion just to read the PRF output for a freshly created
 * credential. The challenge is local and never verified: the server
 * already verifies the registration itself, and it can't check a PRF
 * output anyway - a wrong one only wraps the DEK under a key nobody has.
 */
async function evaluatePrf(rpId: string, credentialId: string, prfSalt: string): Promise<ArrayBuffer> {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  const assertion = await startAuthentication({
    optionsJSON: {
      challenge: bufferToBase64URLString(challenge.buffer),
      rpId,
      allowCredentials: [{ id: credentialId, type: "public-key" }],
      userVerification: "preferred",
      extensions: { prf: { eval: { first: base64URLStringToBuffer(prfSalt) } } },
    },
  });

  const result = assertion.clientExtensionResults?.prf?.results?.first as ArrayBuffer | undefined;
  if (!result) throw new PasskeyUnsupportedError("no-prf-output");
  return result;
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
    throw new PasskeyUnsupportedError("no-prf-output");
  }

  await client.request("/vault/methods/passkey/auth-verify", {
    method: "POST",
    body: JSON.stringify({ response, prfOutput: bufferToBase64URLString(prfResult) }),
  });
}
