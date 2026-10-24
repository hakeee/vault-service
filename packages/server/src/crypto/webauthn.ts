import { randomBytes } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";

/** isoBase64URL.fromBuffer wants a Uint8Array<ArrayBuffer> specifically - a plain Buffer's backing type is wider (ArrayBufferLike). */
function toBase64Url(buffer: Buffer): string {
  return isoBase64URL.fromBuffer(new Uint8Array(buffer));
}

export interface WebauthnConfig {
  rpID: string;
  rpName: string;
  origin: string;
}

/**
 * `@simplewebauthn/{server,browser}` pass `extensions` straight through to
 * the real `navigator.credentials.*` call without ever encoding it for
 * JSON transport (unlike every other binary field, which both libraries
 * base64url-encode for you) - the prf salt/output are therefore the
 * caller's responsibility to shuttle over HTTP as plain base64url
 * strings, sitting alongside (not inside) the library's own
 * options/response objects. See `@hakeee/vault-service-react`'s browser
 * passkey helper for the client-side half of this: decoding a salt into a
 * real BufferSource right before calling startRegistration/
 * startAuthentication, and encoding the returned prf result right after.
 */
export interface PasskeyRegistrationChallenge {
  options: PublicKeyCredentialCreationOptionsJSON;
  challenge: string;
  /** Base64url - the frontend injects this into its own extensions.prf.eval.first. */
  prfSalt: string;
}

export async function createPasskeyRegistrationChallenge(
  config: WebauthnConfig,
  user: { id: number; email: string },
  existingCredentialIds: string[],
): Promise<PasskeyRegistrationChallenge> {
  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userName: user.email,
    userID: Buffer.from(String(user.id), "utf8"),
    excludeCredentials: existingCredentialIds.map((id) => ({ id })),
  });

  return { options, challenge: options.challenge, prfSalt: toBase64Url(randomBytes(32)) };
}

export interface VerifiedPasskeyRegistration {
  credentialId: string;
  publicKey: Buffer;
  counter: number;
}

/** Verifies the registration ceremony itself - nothing prf-related, that's extracted separately by the caller from the response's clientExtensionResults. */
export async function verifyPasskeyRegistration(
  config: WebauthnConfig,
  response: RegistrationResponseJSON,
  expectedChallenge: string,
): Promise<VerifiedPasskeyRegistration> {
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpID,
  });

  if (!verification.verified) {
    throw new Error("passkey registration could not be verified");
  }

  const { credential } = verification.registrationInfo;
  return { credentialId: credential.id, publicKey: Buffer.from(credential.publicKey), counter: credential.counter };
}

export interface PasskeyAuthenticationChallenge {
  options: PublicKeyCredentialRequestOptionsJSON;
  challenge: string;
  /** credentialId (base64url) -> that credential's own prf salt (base64url) - WebAuthn's evalByCredential, for when more than one passkey is registered. */
  prfSaltByCredentialId: Record<string, string>;
}

export async function createPasskeyAuthenticationChallenge(
  config: WebauthnConfig,
  credentials: { credentialId: string; prfSalt: Buffer }[],
): Promise<PasskeyAuthenticationChallenge> {
  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    allowCredentials: credentials.map((c) => ({ id: c.credentialId })),
  });

  const prfSaltByCredentialId: Record<string, string> = {};
  for (const c of credentials) {
    prfSaltByCredentialId[c.credentialId] = toBase64Url(c.prfSalt);
  }

  return { options, challenge: options.challenge, prfSaltByCredentialId };
}

export interface VerifiedPasskeyAuthentication {
  newCounter: number;
}

export async function verifyPasskeyAuthentication(
  config: WebauthnConfig,
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  storedCredential: WebAuthnCredential,
): Promise<VerifiedPasskeyAuthentication> {
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpID,
    credential: storedCredential,
  });

  if (!verification.verified) {
    throw new Error("passkey authentication could not be verified");
  }

  return { newCounter: verification.authenticationInfo.newCounter };
}
