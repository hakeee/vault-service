import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { KdfParams } from "./kek.js";
import {
  createPasswordUnlockMethod,
  unlockWithPasskey,
  unlockWithPassword,
  unlockWithRecovery,
  wrapDekForPasskey,
  wrapDekForPassword,
  wrapDekForRecovery,
} from "./vault.js";

// Deliberately weak params - these tests check correctness, not strength,
// and real Argon2id params (see kek.ts) would make the suite slow for no
// benefit here.
const FAST_PARAMS: KdfParams = { memoryCost: 1024, timeCost: 1, parallelism: 1, outputLen: 32 };

describe("createPasswordUnlockMethod / unlockWithPassword", () => {
  it("unlocks with the correct password", async () => {
    const { dek, method } = await createPasswordUnlockMethod("correct-password", FAST_PARAMS);

    const unlocked = await unlockWithPassword("correct-password", method);

    expect(unlocked.equals(dek)).toBe(true);
  });

  it("rejects the wrong password", async () => {
    const { method } = await createPasswordUnlockMethod("correct-password", FAST_PARAMS);

    await expect(unlockWithPassword("wrong-password", method)).rejects.toThrow();
  });
});

describe("wrapDekForPassword", () => {
  it("wraps the same DEK for a second unlock method without changing it", async () => {
    const { dek, method: firstMethod } = await createPasswordUnlockMethod("first-password", FAST_PARAMS);
    const secondMethod = await wrapDekForPassword(dek, "second-password", FAST_PARAMS);

    const unlockedViaFirst = await unlockWithPassword("first-password", firstMethod);
    const unlockedViaSecond = await unlockWithPassword("second-password", secondMethod);

    expect(unlockedViaFirst.equals(dek)).toBe(true);
    expect(unlockedViaSecond.equals(dek)).toBe(true);
  });
});

describe("wrapDekForPasskey / unlockWithPasskey", () => {
  it("unlocks with the matching prf output", async () => {
    const { dek } = await createPasswordUnlockMethod("a-password", FAST_PARAMS);
    const prfOutput = randomBytes(32); // stands in for a WebAuthn prf extension result

    const wrappedDek = wrapDekForPasskey(dek, prfOutput);
    const unlocked = unlockWithPasskey(prfOutput, wrappedDek);

    expect(unlocked.equals(dek)).toBe(true);
  });

  it("rejects a mismatched prf output", async () => {
    const { dek } = await createPasswordUnlockMethod("a-password", FAST_PARAMS);
    const wrappedDek = wrapDekForPasskey(dek, randomBytes(32));

    expect(() => unlockWithPasskey(randomBytes(32), wrappedDek)).toThrow();
  });

  it("wraps the same DEK a password method already unwrapped, alongside it", async () => {
    const { dek, method: passwordMethod } = await createPasswordUnlockMethod("a-password", FAST_PARAMS);
    const prfOutput = randomBytes(32);
    const wrappedDek = wrapDekForPasskey(dek, prfOutput);

    const unlockedViaPassword = await unlockWithPassword("a-password", passwordMethod);
    const unlockedViaPasskey = unlockWithPasskey(prfOutput, wrappedDek);

    expect(unlockedViaPassword.equals(dek)).toBe(true);
    expect(unlockedViaPasskey.equals(dek)).toBe(true);
  });
});

describe("wrapDekForRecovery / unlockWithRecovery", () => {
  it("unlocks with the matching recovery key", async () => {
    const { dek } = await createPasswordUnlockMethod("a-password", FAST_PARAMS);
    const recoveryKey = randomBytes(24);

    const wrappedDek = wrapDekForRecovery(dek, recoveryKey);
    const unlocked = unlockWithRecovery(recoveryKey, wrappedDek);

    expect(unlocked.equals(dek)).toBe(true);
  });

  it("rejects a mismatched recovery key", async () => {
    const { dek } = await createPasswordUnlockMethod("a-password", FAST_PARAMS);
    const wrappedDek = wrapDekForRecovery(dek, randomBytes(24));

    expect(() => unlockWithRecovery(randomBytes(24), wrappedDek)).toThrow();
  });
});
