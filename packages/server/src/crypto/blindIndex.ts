import { createHmac, hkdfSync } from "node:crypto";

/**
 * Kept unchanged from the Ebba codebase this library was extracted from -
 * changing it would silently invalidate every blind index already stored
 * under it. Other consumers of this package should pass their own `info`
 * to namespace their own derivation instead of relying on this default.
 */
export const DEFAULT_BLIND_INDEX_INFO = "ebba:blind-index:v1";

/**
 * Derived from the DEK via HKDF rather than stored as its own wrapped
 * secret - cryptographically equivalent to "DEK-wrapped and only loaded
 * at unlock", without an extra storage row: it's only computable once
 * the DEK itself is unwrapped.
 */
export function deriveBlindIndexKey(dek: Buffer, info: string = DEFAULT_BLIND_INDEX_INFO): Buffer {
  return Buffer.from(hkdfSync("sha256", dek, Buffer.alloc(0), info, 32));
}

/**
 * HMAC blind index for exact-match lookups on encrypted names.
 * Deterministic: the same value always produces the same index under the
 * same key, which is what makes the SQL lookup work and is the accepted
 * trade-off of this approach.
 */
export function blindIndex(indexKey: Buffer, normalizedValue: string): string {
  return createHmac("sha256", indexKey).update(normalizedValue, "utf8").digest("hex");
}
