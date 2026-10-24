import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { deriveRecoveryKek } from "./recoveryKek.js";

describe("deriveRecoveryKek", () => {
  it("is deterministic for the same recovery key", () => {
    const recoveryKey = randomBytes(24);

    expect(deriveRecoveryKek(recoveryKey).equals(deriveRecoveryKek(recoveryKey))).toBe(true);
  });

  it("differs for different recovery keys", () => {
    expect(deriveRecoveryKek(randomBytes(24)).equals(deriveRecoveryKek(randomBytes(24)))).toBe(false);
  });

  it("produces a 256-bit key", () => {
    expect(deriveRecoveryKek(randomBytes(24)).length).toBe(32);
  });
});
