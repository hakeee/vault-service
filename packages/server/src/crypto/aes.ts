import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // 96 bits
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypts one field's plaintext with a 256-bit key. Output layout is
 * `iv || ciphertext || authTag` in a single Buffer, stored as-is in a
 * BLOB column.
 */
export function encryptField(key: Buffer, plaintext: Buffer): Buffer {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, authTag]);
}

/**
 * Reverses encryptField. Throws if the key is wrong or the blob was
 * tampered with - GCM's authTag check fails closed, it never silently
 * returns garbage.
 */
export function decryptField(key: Buffer, blob: Buffer): Buffer {
  const iv = blob.subarray(0, IV_LENGTH);
  const authTag = blob.subarray(blob.length - AUTH_TAG_LENGTH);
  const ciphertext = blob.subarray(IV_LENGTH, blob.length - AUTH_TAG_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
