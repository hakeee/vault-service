import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decryptField, encryptField } from "./aes.js";

describe("encryptField / decryptField", () => {
  it("round-trips plaintext", () => {
    const key = randomBytes(32);
    const plaintext = Buffer.from("Long day, wiped out but dinner with Anna was nice.", "utf8");

    const blob = encryptField(key, plaintext);
    const decrypted = decryptField(key, blob);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it("produces a different ciphertext each time (random IV)", () => {
    const key = randomBytes(32);
    const plaintext = Buffer.from("same text", "utf8");

    const first = encryptField(key, plaintext);
    const second = encryptField(key, plaintext);

    expect(first.equals(second)).toBe(false);
  });

  it("fails closed on the wrong key", () => {
    const plaintext = Buffer.from("secret", "utf8");
    const blob = encryptField(randomBytes(32), plaintext);

    expect(() => decryptField(randomBytes(32), blob)).toThrow();
  });

  it("fails closed when the ciphertext is tampered with", () => {
    const key = randomBytes(32);
    const blob = encryptField(key, Buffer.from("secret", "utf8"));
    const lastByteIndex = blob.length - 1;
    blob.writeUInt8(blob.readUInt8(lastByteIndex) ^ 0xff, lastByteIndex); // flip a byte in the auth tag

    expect(() => decryptField(key, blob)).toThrow();
  });
});
