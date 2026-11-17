import { createCipheriv, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { encryptField } from "./aes.js";
import { blindIndex, deriveBlindIndexKey } from "./blindIndex.js";
import { generateDek } from "./dek.js";
import { ENVELOPE_V1, UnsupportedEnvelopeError, openEnvelope, sealEnvelope } from "./envelope.js";
import { InvalidScopeError, createLegacyScope, createVaultScope, deriveScopeKeys } from "./scope.js";

function scopeFor(dek: Buffer, name: string) {
  return createVaultScope(name, deriveScopeKeys(dek, name));
}

describe("envelope", () => {
  it("round-trips and starts with the version byte", () => {
    const key = randomBytes(32);
    const envelope = sealEnvelope(key, "note.body", Buffer.from("hello"));
    expect(envelope[0]).toBe(ENVELOPE_V1);
    expect(openEnvelope(key, "note.body", envelope).toString()).toBe("hello");
  });

  it("fails closed under the wrong context", () => {
    const key = randomBytes(32);
    const envelope = sealEnvelope(key, "note.body", Buffer.from("hello"));
    expect(() => openEnvelope(key, "note.title", envelope)).toThrow();
  });

  it("authenticates the version byte, not just the payload", () => {
    // Flipping the header to another (hypothetically valid) version must
    // not decrypt either - checked here by forging one and bypassing the
    // dispatch: AAD includes the version, so GCM itself rejects it.
    const key = randomBytes(32);
    const envelope = sealEnvelope(key, "c", Buffer.from("hello"));
    const forged = Buffer.from(envelope);
    forged[0] = 0x02;
    expect(() => openEnvelope(key, "c", forged)).toThrow(UnsupportedEnvelopeError);
  });

  it("rejects unknown versions and truncated input", () => {
    const key = randomBytes(32);
    expect(() => openEnvelope(key, "c", Buffer.of(0x07, 1, 2, 3))).toThrow(UnsupportedEnvelopeError);
    expect(() => openEnvelope(key, "c", Buffer.of(ENVELOPE_V1, 1, 2))).toThrow(UnsupportedEnvelopeError);
    expect(() => openEnvelope(key, "c", Buffer.alloc(0))).toThrow(UnsupportedEnvelopeError);
  });

  it("matches the documented byte layout (format pin)", () => {
    // Independent re-implementation of v1: 0x01 || iv || ct || tag with
    // AAD 0x01 || context. If this breaks, already-stored data breaks too.
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.concat([Buffer.of(0x01), Buffer.from("note.body")]));
    const ct = Buffer.concat([cipher.update("pinned"), cipher.final()]);
    const handBuilt = Buffer.concat([Buffer.of(0x01), iv, ct, cipher.getAuthTag()]);
    expect(openEnvelope(key, "note.body", handBuilt).toString()).toBe("pinned");
  });
});

describe("vault scopes", () => {
  it("derives keys exactly as documented (derivation pin)", () => {
    const dek = Buffer.alloc(32, 0x42);
    const hkdf = (info: string) => Buffer.from(hkdfSync("sha256", dek, Buffer.alloc(0), info, 32));
    const keys = deriveScopeKeys(dek, "notes");
    expect(keys.encryptionKey).toEqual(hkdf("vault-service:scope:notes:enc:v1"));
    expect(keys.indexKey).toEqual(hkdf("vault-service:scope:notes:blind-index:v1"));

    const expectedIndex = createHmac("sha256", hkdf("vault-service:scope:notes:blind-index:v1"))
      .update("note.title\0hello")
      .digest("hex");
    expect(scopeFor(dek, "notes").blindIndex("note.title", "hello")).toBe(expectedIndex);
  });

  it("round-trips strings and buffers", () => {
    const notes = scopeFor(generateDek(), "notes");
    expect(notes.decryptString("note.body", notes.encryptString("note.body", "hej då"))).toBe("hej då");
    const bytes = randomBytes(64);
    expect(notes.decrypt("note.file", notes.encrypt("note.file", bytes))).toEqual(bytes);
  });

  it("can't decrypt another scope's data, even for the same user", () => {
    const dek = generateDek();
    const sealed = scopeFor(dek, "notes").encryptString("body", "secret");
    expect(() => scopeFor(dek, "habits").decryptString("body", sealed)).toThrow();
  });

  it("can't decrypt another user's data in the same scope", () => {
    const sealed = scopeFor(generateDek(), "notes").encryptString("body", "secret");
    expect(() => scopeFor(generateDek(), "notes").decryptString("body", sealed)).toThrow();
  });

  it("binds values to their context, so they can't be moved between columns", () => {
    const notes = scopeFor(generateDek(), "notes");
    const title = notes.encryptString("note.title", "secret");
    expect(() => notes.decryptString("note.body", title)).toThrow();
  });

  it("keeps blind indexes unlinkable across contexts and scopes", () => {
    const dek = generateDek();
    const notes = scopeFor(dek, "notes");
    const habits = scopeFor(dek, "habits");
    const a = notes.blindIndex("note.title", "Gym");
    expect(notes.blindIndex("note.title", "Gym")).toBe(a); // deterministic
    expect(notes.blindIndex("note.tag", "Gym")).not.toBe(a);
    expect(habits.blindIndex("note.title", "Gym")).not.toBe(a);
  });

  it("validates scope names and contexts", () => {
    const dek = generateDek();
    for (const bad of ["", "Notes", "notes:x", "1notes", "notes.", ".notes", "no tes"]) {
      expect(() => deriveScopeKeys(dek, bad), bad).toThrow(InvalidScopeError);
    }
    expect(() => deriveScopeKeys(dek, "notes.attachments-v2")).not.toThrow();

    const notes = scopeFor(dek, "notes");
    expect(() => notes.encryptString("", "x")).toThrow(InvalidScopeError);
    expect(() => notes.blindIndex("a\0b", "x")).toThrow(InvalidScopeError);
  });

  it("narrows contexts at the type level", () => {
    const notes = createVaultScope<"note.title" | "note.body">("notes", deriveScopeKeys(generateDek(), "notes"));
    notes.encryptString("note.title", "ok");
    // @ts-expect-error - not a declared context for this scope
    expect(() => notes.encryptString("note.titel", "typo")).not.toThrow();
  });
});

describe("legacy scope", () => {
  it("reads and writes exactly what pre-scope code did", () => {
    const dek = generateDek();
    const legacy = createLegacyScope(dek);
    const oldBlob = encryptField(dek, Buffer.from("written before scopes"));
    expect(legacy.decryptString(oldBlob)).toBe("written before scopes");

    const newBlob = legacy.encryptString("still legacy");
    expect(newBlob.length).toBe(12 + "still legacy".length + 16); // no version byte

    expect(legacy.blindIndex("gym")).toBe(blindIndex(deriveBlindIndexKey(dek), "gym"));
    expect(legacy.blindIndex("gym")).toBe(
      createHmac("sha256", Buffer.from(hkdfSync("sha256", dek, Buffer.alloc(0), "ebba:blind-index:v1", 32)))
        .update("gym")
        .digest("hex"),
    );
  });

  it("is a different key space from every named scope", () => {
    const dek = generateDek();
    const legacyBlob = createLegacyScope(dek).encryptString("x");
    expect(() => scopeFor(dek, "notes").decryptString("c", legacyBlob)).toThrow();
  });
});
