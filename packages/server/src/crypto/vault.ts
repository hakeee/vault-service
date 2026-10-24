import { generateDek, unwrapDek, wrapDek } from "./dek.js";
import { derivePasswordKek, generateSalt, DEFAULT_PASSWORD_KDF_PARAMS, type KdfParams } from "./kek.js";
import { derivePasskeyKek } from "./passkeyKek.js";
import { deriveRecoveryKek } from "./recoveryKek.js";

export interface PasswordUnlockMethod {
  wrappedDek: Buffer;
  kdfSalt: Buffer;
  kdfParams: KdfParams;
}

/**
 * Vault setup: generates a brand-new DEK and wraps it with a
 * password-derived KEK. Used once, the first time a password unlock
 * method is created for a user.
 */
export async function createPasswordUnlockMethod(
  password: string,
  params: KdfParams = DEFAULT_PASSWORD_KDF_PARAMS,
): Promise<{ dek: Buffer; method: PasswordUnlockMethod }> {
  const dek = generateDek();
  const method = await wrapDekForPassword(dek, password, params);
  return { dek, method };
}

/**
 * Adding a second unlock method wraps the *same* DEK again under a new
 * KEK - every method is an independent slot on one DEK, not a
 * re-encryption of the data.
 */
export async function wrapDekForPassword(
  dek: Buffer,
  password: string,
  params: KdfParams = DEFAULT_PASSWORD_KDF_PARAMS,
): Promise<PasswordUnlockMethod> {
  const kdfSalt = generateSalt();
  const kek = await derivePasswordKek(password, kdfSalt, params);
  return { wrappedDek: wrapDek(dek, kek), kdfSalt, kdfParams: params };
}

/**
 * Unlock: re-derive the KEK from the stored salt/params, then unwrap the
 * DEK. Throws if the password is wrong (GCM auth tag fails).
 */
export async function unlockWithPassword(
  password: string,
  method: PasswordUnlockMethod,
): Promise<Buffer> {
  const kek = await derivePasswordKek(password, method.kdfSalt, method.kdfParams);
  return unwrapDek(method.wrappedDek, kek);
}

/**
 * Adding a passkey, mirroring wrapDekForPassword exactly - the only
 * difference is where the KEK comes from (a prf output, already
 * extracted from the WebAuthn ceremony's response by the caller, not a
 * password). Wraps the *same* DEK a password method already unwrapped
 * this session; never generates a new one.
 */
export function wrapDekForPasskey(dek: Buffer, prfOutput: Buffer): Buffer {
  const kek = derivePasskeyKek(prfOutput);
  return wrapDek(dek, kek);
}

/** Unlock with a passkey: same shape as unlockWithPassword, no KDF re-derivation needed. */
export function unlockWithPasskey(prfOutput: Buffer, wrappedDek: Buffer): Buffer {
  const kek = derivePasskeyKek(prfOutput);
  return unwrapDek(wrappedDek, kek);
}

/**
 * Adding a recovery key - same shape as wrapDekForPasskey. Typically only
 * one recovery key per user; the caller is responsible for replacing any
 * existing recovery row rather than accumulating them if that's the
 * desired policy.
 */
export function wrapDekForRecovery(dek: Buffer, recoveryKey: Buffer): Buffer {
  const kek = deriveRecoveryKek(recoveryKey);
  return wrapDek(dek, kek);
}

/** Unlock with a recovery key: same shape as unlockWithPasskey. */
export function unlockWithRecovery(recoveryKey: Buffer, wrappedDek: Buffer): Buffer {
  const kek = deriveRecoveryKek(recoveryKey);
  return unwrapDek(wrappedDek, kek);
}
