import { createHmac, hkdfSync } from "node:crypto";

/**
 * The blind-index derivation used before scopes existed. It's kept
 * unchanged from the Ebba codebase this library was extracted from,
 * because changing it would invalidate every blind index already stored
 * under it. Only the legacy scope uses it; named scopes derive their own
 * index keys (see ./scope.ts).
 */
export const LEGACY_BLIND_INDEX_INFO = "ebba:blind-index:v1";

/** @deprecated Renamed to `LEGACY_BLIND_INDEX_INFO`. New code should use a named vault scope. */
export const DEFAULT_BLIND_INDEX_INFO = LEGACY_BLIND_INDEX_INFO;

/**
 * Derived from the DEK via HKDF rather than stored as its own wrapped
 * secret - cryptographically equivalent to "DEK-wrapped and only loaded
 * at unlock", without an extra storage row: it's only computable once
 * the DEK itself is unwrapped.
 */
export function deriveBlindIndexKey(dek: Buffer, info: string = LEGACY_BLIND_INDEX_INFO): Buffer {
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
