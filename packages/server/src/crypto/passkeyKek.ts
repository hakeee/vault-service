import { hkdfSync } from "node:crypto";

/**
 * Kept unchanged from the Ebba codebase this library was extracted from -
 * changing it would silently invalidate every passkey unlock method
 * already wrapped under it. Other consumers should pass their own `info`
 * to namespace their own derivation instead of relying on this default.
 */
export const DEFAULT_PASSKEY_KEK_INFO = "ebba:passkey-kek:v1";

/**
 * Derives a Key Encryption Key from a WebAuthn `prf` extension output.
 * The prf output is already a per-credential, per-salt deterministic
 * secret only the registered authenticator can reproduce, so (unlike the
 * password path) there's no separate KDF cost parameter to tune here -
 * HKDF is just shaping it into the right length, same idea as
 * blindIndex.ts's `deriveBlindIndexKey`.
 */
export function derivePasskeyKek(prfOutput: Buffer, info: string = DEFAULT_PASSKEY_KEK_INFO): Buffer {
  return Buffer.from(hkdfSync("sha256", prfOutput, Buffer.alloc(0), info, 32));
}
