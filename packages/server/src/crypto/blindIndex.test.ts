import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { blindIndex, deriveBlindIndexKey } from "./blindIndex.js";

describe("blindIndex", () => {
  it("is deterministic for the same value and key", () => {
    const indexKey = deriveBlindIndexKey(randomBytes(32));

    expect(blindIndex(indexKey, "divorce")).toBe(blindIndex(indexKey, "divorce"));
  });

  it("differs for different values under the same key", () => {
    const indexKey = deriveBlindIndexKey(randomBytes(32));

    expect(blindIndex(indexKey, "divorce")).not.toBe(blindIndex(indexKey, "climbing"));
  });

  it("differs for the same value under different DEKs", () => {
    const indexKeyA = deriveBlindIndexKey(randomBytes(32));
    const indexKeyB = deriveBlindIndexKey(randomBytes(32));

    expect(blindIndex(indexKeyA, "divorce")).not.toBe(blindIndex(indexKeyB, "divorce"));
  });
});

describe("deriveBlindIndexKey", () => {
  it("is deterministic for the same DEK", () => {
    const dek = randomBytes(32);

    expect(deriveBlindIndexKey(dek).equals(deriveBlindIndexKey(dek))).toBe(true);
  });
});
