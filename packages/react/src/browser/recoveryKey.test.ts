import { describe, expect, it } from "vitest";
import { generateRecoveryKey } from "./recoveryKey.js";

describe("generateRecoveryKey", () => {
  it("produces dash-chunked base64url groups", () => {
    const key = generateRecoveryKey();

    expect(key).toMatch(/^[A-Za-z0-9_-]{1,4}(-[A-Za-z0-9_-]{1,4})*$/);
  });

  it("is different every time (random bytes)", () => {
    expect(generateRecoveryKey()).not.toBe(generateRecoveryKey());
  });
});
