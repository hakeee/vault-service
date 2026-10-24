import { bufferToBase64URLString } from "@simplewebauthn/browser";

/**
 * 24 random bytes (192 bits) via the browser's own CSPRNG, base64url-
 * encoded and chunked with dashes purely for readability - the dashes
 * (and any whitespace) are stripped server-side before decoding
 * (`@hakeee/vault-service`'s `routes/vault.ts`'s `decodeRecoveryKey`).
 */
export function generateRecoveryKey(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const encoded = bufferToBase64URLString(bytes.buffer);
  return encoded.match(/.{1,4}/g)!.join("-");
}
