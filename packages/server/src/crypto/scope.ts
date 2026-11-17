import { createHmac, hkdfSync } from "node:crypto";
import { decryptField, encryptField } from "./aes.js";
import { LEGACY_BLIND_INDEX_INFO, blindIndex as legacyBlindIndex, deriveBlindIndexKey } from "./blindIndex.js";
import { openEnvelope, sealEnvelope } from "./envelope.js";

/**
 * Lowercase dotted names, e.g. `notes` or `notes.attachments`. Names go
 * into HKDF info strings, so they're kept to a charset that can't collide
 * with the `:` separators used there.
 */
const SCOPE_NAME = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*$/;

export class InvalidScopeError extends Error {}

export function assertScopeName(name: string): void {
  if (!SCOPE_NAME.test(name)) {
    throw new InvalidScopeError(`invalid vault scope name "${name}" - expected e.g. "notes" or "notes.attachments"`);
  }
}

/**
 * Contexts are joined to the value with a NUL byte in blind indexes, so
 * they can't contain one. Empty is rejected too: a context is the caller's
 * deliberate statement of where a value lives (e.g. `"note.body"`).
 */
function assertContext(context: string): void {
  if (context.length === 0 || context.includes("\0")) {
    throw new InvalidScopeError(`invalid vault context ${JSON.stringify(context)} - expected e.g. "note.body"`);
  }
}

export interface ScopeKeys {
  encryptionKey: Buffer;
  indexKey: Buffer;
}

/**
 * Two independent keys per scope, both derived from the user's DEK, so a
 * scope can never decrypt or link another scope's data, and its
 * encryption key and blind-index key never double up. The `:v1` suffix
 * allows rotating a derivation later without touching the DEK.
 */
export function deriveScopeKeys(dek: Buffer, scope: string): ScopeKeys {
  assertScopeName(scope);
  const derive = (purpose: string) =>
    Buffer.from(hkdfSync("sha256", dek, Buffer.alloc(0), `vault-service:scope:${scope}:${purpose}:v1`, 32));
  return { encryptionKey: derive("enc"), indexKey: derive("blind-index") };
}

/**
 * Everything one feature may do with the vault, and nothing more: it never
 * sees the DEK or another scope's keys.
 *
 * `Context` lets a feature pin down where its encrypted values live, e.g.
 * `vault.scope<"note.title" | "note.body">("notes")`, so a typo in a
 * context is a compile error rather than undecryptable data.
 */
export interface VaultScope<Context extends string = string> {
  readonly name: string;
  encrypt(context: Context, plaintext: Buffer): Buffer;
  encryptString(context: Context, plaintext: string): Buffer;
  decrypt(context: Context, envelope: Buffer): Buffer;
  decryptString(context: Context, envelope: Buffer): string;
  /**
   * Deterministic HMAC for exact-match lookups on an encrypted value.
   * Keyed per scope and separated per context, so the same value in two
   * columns (or two scopes) yields unrelated indexes.
   */
  blindIndex(context: Context, value: string): string;
}

export function createVaultScope<Context extends string = string>(name: string, keys: ScopeKeys): VaultScope<Context> {
  const { encryptionKey, indexKey } = keys;
  const open = (context: string, envelope: Buffer) => {
    assertContext(context);
    return openEnvelope(encryptionKey, context, envelope);
  };
  return {
    name,
    encrypt(context, plaintext) {
      assertContext(context);
      return sealEnvelope(encryptionKey, context, plaintext);
    },
    encryptString(context, plaintext) {
      assertContext(context);
      return sealEnvelope(encryptionKey, context, Buffer.from(plaintext, "utf8"));
    },
    decrypt: open,
    decryptString: (context, envelope) => open(context, envelope).toString("utf8"),
    blindIndex(context, value) {
      assertContext(context);
      return createHmac("sha256", indexKey).update(context, "utf8").update("\0").update(value, "utf8").digest("hex");
    },
  };
}

/**
 * Data written before scopes existed: the old unversioned
 * `iv || ciphertext || authTag` layout under the raw DEK, with no context,
 * and blind indexes under `LEGACY_BLIND_INDEX_INFO`. Kept so Ebba's existing
 * rows keep working without re-encryption. New features should use a named
 * scope instead.
 */
export interface LegacyVaultScope {
  encrypt(plaintext: Buffer): Buffer;
  encryptString(plaintext: string): Buffer;
  decrypt(blob: Buffer): Buffer;
  decryptString(blob: Buffer): string;
  blindIndex(value: string): string;
}

export function createLegacyScope(dek: Buffer, indexKey: Buffer = deriveBlindIndexKey(dek, LEGACY_BLIND_INDEX_INFO)): LegacyVaultScope {
  return {
    encrypt: (plaintext) => encryptField(dek, plaintext),
    encryptString: (plaintext) => encryptField(dek, Buffer.from(plaintext, "utf8")),
    decrypt: (blob) => decryptField(dek, blob),
    decryptString: (blob) => decryptField(dek, blob).toString("utf8"),
    blindIndex: (value) => legacyBlindIndex(indexKey, value),
  };
}
