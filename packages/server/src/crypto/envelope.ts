import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // 96 bits
const AUTH_TAG_LENGTH = 16;

/**
 * Version byte at the front of every envelope. Future formats (another
 * cipher, key rotation with a key id, ...) get a new value here, and
 * `openEnvelope` dispatches on it.
 *
 * This byte is only meaningful because a scope decides its format up
 * front: named scopes only ever read and write envelopes, and only the
 * legacy scope reads the old unversioned `iv || ciphertext || authTag`
 * layout. Sniffing would be unsound, because a legacy blob's first byte is
 * a random IV byte and is `0x01` one time in 256.
 */
export const ENVELOPE_V1 = 0x01;

const MIN_V1_LENGTH = 1 + IV_LENGTH + AUTH_TAG_LENGTH;

export class UnsupportedEnvelopeError extends Error {
  constructor(detail: string) {
    super(`unsupported encrypted value: ${detail}`);
  }
}

/**
 * Associated data is `version || utf8(context)`: the header is authenticated
 * along with the caller's context, so a value only decrypts under the exact
 * context it was sealed with. There's only one variable-length field, so
 * this encoding can't be ambiguous.
 */
function associatedData(version: number, context: string): Buffer {
  return Buffer.concat([Buffer.of(version), Buffer.from(context, "utf8")]);
}

/**
 * Seals `plaintext` under `key`, bound to `context`. Layout:
 * `0x01 || iv (12) || ciphertext || authTag (16)`.
 */
export function sealEnvelope(key: Buffer, context: string, plaintext: Buffer): Buffer {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(associatedData(ENVELOPE_V1, context));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.of(ENVELOPE_V1), iv, ciphertext, cipher.getAuthTag()]);
}

/**
 * Reverses `sealEnvelope`. Throws on an unknown version, and fails closed
 * (GCM auth error) if the key, the context or any byte is wrong.
 */
export function openEnvelope(key: Buffer, context: string, envelope: Buffer): Buffer {
  const version = envelope[0];
  if (version !== ENVELOPE_V1) {
    throw new UnsupportedEnvelopeError(`version byte ${version ?? "missing"}`);
  }
  if (envelope.length < MIN_V1_LENGTH) {
    throw new UnsupportedEnvelopeError("too short");
  }

  const iv = envelope.subarray(1, 1 + IV_LENGTH);
  const authTag = envelope.subarray(envelope.length - AUTH_TAG_LENGTH);
  const ciphertext = envelope.subarray(1 + IV_LENGTH, envelope.length - AUTH_TAG_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAAD(associatedData(version, context));
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
