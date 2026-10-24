import { hkdfSync } from "node:crypto";

/**
 * Kept unchanged from the Ebba codebase this library was extracted from -
 * changing it would silently invalidate every recovery-key unlock method
 * already wrapped under it. Other consumers should pass their own `info`
 * to namespace their own derivation instead of relying on this default.
 */
export const DEFAULT_RECOVERY_KEK_INFO = "ebba:recovery-kek:v1";

/**
 * Derives a Key Encryption Key from a recovery key. A 192-bit randomly
 * generated recovery key has no low-entropy weakness to compensate for,
 * unlike a human-chosen password, so (like derivePasskeyKek) a fast HKDF
 * is the right, justified choice - not Argon2id's deliberately slow hash.
 */
export function deriveRecoveryKek(recoveryKey: Buffer, info: string = DEFAULT_RECOVERY_KEK_INFO): Buffer {
  return Buffer.from(hkdfSync("sha256", recoveryKey, Buffer.alloc(0), info, 32));
}
