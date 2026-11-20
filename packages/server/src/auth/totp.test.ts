import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode, generateTotpSecret, totpCode, totpStep, totpUri, verifyTotp } from "./totp.js";

// RFC 6238 appendix B, SHA-1 rows: the secret is ASCII "12345678901234567890".
const RFC_SECRET = Buffer.from("12345678901234567890", "ascii");
const RFC_VECTORS: [number, string][] = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

describe("totp", () => {
  it("matches the RFC 6238 test vectors", () => {
    for (const [seconds, code] of RFC_VECTORS) expect(totpCode(RFC_SECRET, totpStep(seconds * 1000), 8)).toBe(code);
  });

  it("gives the 6-digit code apps show (the last 6 digits of the RFC's)", () => {
    expect(totpCode(RFC_SECRET, totpStep(59_000))).toBe("287082");
  });

  it("round-trips base32 and makes 160-bit secrets", () => {
    const bytes = Buffer.from("hello, authenticator");
    expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
    expect(base32Encode(Buffer.from("12345678901234567890"))).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect(base32Decode(generateTotpSecret())).toHaveLength(20);
  });

  it("accepts one step of drift either way, nothing further", () => {
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step), now)).toBe(step);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 1), now)).toBe(step - 1);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 1), now)).toBe(step + 1);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 2), now)).toBeNull();
    expect(verifyTotp(RFC_SECRET, "12345", now)).toBeNull();
    expect(verifyTotp(RFC_SECRET, "abcdef", now)).toBeNull();
  });

  it("refuses a code from a step already used", () => {
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    const code = totpCode(RFC_SECRET, step);
    expect(verifyTotp(RFC_SECRET, code, now, step)).toBeNull();
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 1), now, step)).toBe(step + 1);
  });

  it("builds an otpauth link", () => {
    const uri = totpUri("ABC", "me@example.com", "Hody Pes");
    expect(uri).toBe("otpauth://totp/Hody%20Pes%3Ame%40example.com?secret=ABC&issuer=Hody+Pes&algorithm=SHA1&digits=6&period=30");
  });
});
