import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { derivePasskeyKek } from "./passkeyKek.js";

describe("derivePasskeyKek", () => {
  it("is deterministic for the same prf output", () => {
    const prfOutput = randomBytes(32);

    expect(derivePasskeyKek(prfOutput).equals(derivePasskeyKek(prfOutput))).toBe(true);
  });

  it("differs for different prf outputs", () => {
    expect(derivePasskeyKek(randomBytes(32)).equals(derivePasskeyKek(randomBytes(32)))).toBe(false);
  });

  it("produces a 256-bit key", () => {
    expect(derivePasskeyKek(randomBytes(32)).length).toBe(32);
  });
});
