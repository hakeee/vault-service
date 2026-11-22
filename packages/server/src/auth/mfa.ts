import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, asc, eq } from "drizzle-orm";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { decryptField, encryptField } from "../crypto/aes.js";
import { userMfaFactor } from "../schema.js";
import { base32Decode, verifyTotp } from "./totp.js";

export type MfaFactorKind = "totp" | "passkey" | "recovery";

/** What the person sees about one of their factors - never secrets. */
export interface MfaFactorInfo {
  id: number;
  kind: MfaFactorKind;
  label: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  /** Recovery codes only: how many are left. */
  remaining?: number;
}

const RECOVERY_CODE_COUNT = 10;
const RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"; // no 0/o, 1/i/l

/** Codes like `k7m2p-x9qrt`: 10 characters from 31 (about 50 bits), plenty for single-use codes. */
function newRecoveryCode(): string {
  const bytes = randomBytes(10);
  const chars = [...bytes].map((b) => RECOVERY_ALPHABET[b % RECOVERY_ALPHABET.length]).join("");
  return `${chars.slice(0, 5)}-${chars.slice(5)}`;
}

/** Spaces, dashes and case don't matter when typing a code back. */
const normalizeRecoveryCode = (code: string) => code.toLowerCase().replace(/[\s-]/g, "");
/**
 * Stored recovery codes: an HMAC under the MFA key (`h1:` prefix), so a
 * copy of the database alone can't be searched for them (50 bits is a lot
 * to guess online, but not offline against a plain hash). Rows from before
 * hold plain sha256 hex, and still work until they're replaced.
 */
const RECOVERY_HMAC = "h1:";
const legacyRecoveryHash = (code: string) => createHash("sha256").update(normalizeRecoveryCode(code)).digest("hex");

/**
 * The second factors of email + password logins. `key` (32 bytes) encrypts
 * TOTP secrets and keys the recovery code hashes, so a copy of the database
 * alone doesn't give anyone working codes.
 */
export function createMfaStore(db: BetterSQLite3Database<any>, key: Buffer) {
  if (key.length !== 32) throw new Error("MFA key must be 32 bytes (openssl rand -hex 32)");
  const hashRecoveryCode = (code: string) => RECOVERY_HMAC + createHmac("sha256", key).update(normalizeRecoveryCode(code)).digest("hex");
  const sameHash = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
  const rows = (userId: number) => db.select().from(userMfaFactor).where(eq(userMfaFactor.userId, userId)).orderBy(asc(userMfaFactor.id)).all();
  const now = () => new Date();

  return {
    list(userId: number): MfaFactorInfo[] {
      return rows(userId).map((r) => ({
        id: r.id,
        kind: r.kind,
        label: r.label,
        createdAt: r.createdAt.toISOString(),
        lastUsedAt: r.lastUsedAt?.toISOString() ?? null,
        ...(r.kind === "recovery" ? { remaining: (JSON.parse(r.codes ?? "[]") as string[]).length } : {}),
      }));
    },

    /** Factors that count as a second factor by themselves (recovery codes are only a fallback). */
    primaryKinds(userId: number): ("totp" | "passkey")[] {
      return [...new Set(rows(userId).flatMap((r) => (r.kind === "recovery" ? [] : [r.kind])))];
    },

    addTotp(userId: number, secret: string, label: string | null, acceptedStep: number): void {
      db.insert(userMfaFactor)
        .values({ userId, kind: "totp", label, secret: encryptField(key, Buffer.from(secret, "utf8")), lastStep: acceptedStep, createdAt: now(), lastUsedAt: now() })
        .run();
    },

    /** True when the code matches one of the person's authenticator apps (each step only once). */
    verifyTotp(userId: number, code: string): boolean {
      for (const r of rows(userId)) {
        if (r.kind !== "totp" || !r.secret) continue;
        const secret = base32Decode(decryptField(key, r.secret).toString("utf8"));
        const step = verifyTotp(secret, code, Date.now(), r.lastStep);
        if (step === null) continue;
        db.update(userMfaFactor).set({ lastStep: step, lastUsedAt: now() }).where(eq(userMfaFactor.id, r.id)).run();
        return true;
      }
      return false;
    },

    addPasskey(userId: number, credential: { credentialId: string; publicKey: Buffer; counter: number }, label: string | null): void {
      db.insert(userMfaFactor).values({ userId, kind: "passkey", label, ...credential, createdAt: now() }).run();
    },

    passkeys(userId: number): { id: number; credentialId: string; publicKey: Buffer; counter: number }[] {
      return rows(userId).flatMap((r) => (r.kind === "passkey" && r.credentialId && r.publicKey ? [{ id: r.id, credentialId: r.credentialId, publicKey: r.publicKey, counter: r.counter ?? 0 }] : []));
    },

    passkeyUsed(id: number, counter: number): void {
      db.update(userMfaFactor).set({ counter, lastUsedAt: now() }).where(eq(userMfaFactor.id, id)).run();
    },

    /** A fresh set of recovery codes, replacing any old ones. Returned once; only hashes are kept. */
    newRecoveryCodes(userId: number): string[] {
      const codes = Array.from({ length: RECOVERY_CODE_COUNT }, newRecoveryCode);
      db.transaction((tx) => {
        tx.delete(userMfaFactor).where(and(eq(userMfaFactor.userId, userId), eq(userMfaFactor.kind, "recovery"))).run();
        tx.insert(userMfaFactor).values({ userId, kind: "recovery", label: null, codes: JSON.stringify(codes.map(hashRecoveryCode)), createdAt: now() }).run();
      });
      return codes;
    },

    /** Uses up a recovery code: true if it was one of the unused ones. */
    useRecoveryCode(userId: number, code: string): boolean {
      const typed = hashRecoveryCode(code);
      const legacy = legacyRecoveryHash(code);
      for (const r of rows(userId)) {
        if (r.kind !== "recovery") continue;
        const hashes = JSON.parse(r.codes ?? "[]") as string[];
        const index = hashes.findIndex((h) => sameHash(h, h.startsWith(RECOVERY_HMAC) ? typed : legacy));
        if (index === -1) continue;
        hashes.splice(index, 1);
        db.update(userMfaFactor).set({ codes: JSON.stringify(hashes), lastUsedAt: now() }).where(eq(userMfaFactor.id, r.id)).run();
        return true;
      }
      return false;
    },

    /** Removes one factor. Without any authenticator or passkey left, the recovery codes go too. */
    remove(userId: number, id: number): boolean {
      const removed = db.delete(userMfaFactor).where(and(eq(userMfaFactor.userId, userId), eq(userMfaFactor.id, id))).returning().all();
      if (removed.length > 0 && this.primaryKinds(userId).length === 0) this.reset(userId);
      return removed.length > 0;
    },

    /** Every factor of the person (an admin's "reset MFA", account erasure). */
    reset(userId: number): void {
      db.delete(userMfaFactor).where(eq(userMfaFactor.userId, userId)).run();
    },
  };
}

export type MfaStore = ReturnType<typeof createMfaStore>;
