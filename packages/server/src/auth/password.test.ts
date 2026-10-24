import { describe, expect, it } from "vitest";
import { hashPassword, verifyPasswordHash } from "./password.js";

describe("hashPassword / verifyPasswordHash", () => {
  it("verifies the correct password", async () => {
    const hash = await hashPassword("correct-password");

    expect(await verifyPasswordHash(hash, "correct-password")).toBe(true);
  });

  it("rejects the wrong password", async () => {
    const hash = await hashPassword("correct-password");

    expect(await verifyPasswordHash(hash, "wrong-password")).toBe(false);
  });

  it("produces a different hash each time (random salt)", async () => {
    const first = await hashPassword("same-password");
    const second = await hashPassword("same-password");

    expect(first).not.toBe(second);
  });
});
