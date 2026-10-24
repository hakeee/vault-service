import { randomBytes } from "node:crypto";
import { decryptField, encryptField } from "./aes.js";

const DEK_LENGTH = 32; // 256-bit, for AES-256-GCM

/**
 * Generates the one Data Encryption Key - created once, never changes.
 * Each unlock method wraps its own copy of it.
 */
export function generateDek(): Buffer {
  return randomBytes(DEK_LENGTH);
}

/** Wraps the DEK with a KEK - stored as vault_unlock_method.wrapped_dek. */
export function wrapDek(dek: Buffer, kek: Buffer): Buffer {
  return encryptField(kek, dek);
}

/** Unwraps a wrapped DEK with its matching KEK. Throws if the KEK is wrong. */
export function unwrapDek(wrappedDek: Buffer, kek: Buffer): Buffer {
  return decryptField(kek, wrappedDek);
}
