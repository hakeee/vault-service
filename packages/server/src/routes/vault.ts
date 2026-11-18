import { randomUUID } from "node:crypto";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, eq } from "drizzle-orm";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  createPasskeyAuthenticationChallenge,
  createPasskeyRegistrationChallenge,
  verifyPasskeyAuthentication,
  verifyPasskeyRegistration,
  type WebauthnConfig,
} from "../crypto/webauthn.js";
import { decryptField, encryptField } from "../crypto/aes.js";
import {
  createPasswordUnlockMethod,
  unlockWithPasskey,
  unlockWithPassword,
  unlockWithRecovery,
  wrapDekForPasskey,
  wrapDekForRecovery,
} from "../crypto/vault.js";
import type { KdfParams } from "../crypto/kek.js";
import type { AuthMode } from "../auth/mode.js";
import { user, vaultUnlockMethod } from "../schema.js";
import { typedSession } from "../session.js";
import { sessionCacheInternals, type SessionCache } from "../sessionCache.js";

const unlockBodySchema = z.object({ password: z.string().min(1) });
const registerPasskeyBodySchema = z.object({
  response: z.custom<RegistrationResponseJSON>(),
  prfOutput: z.string().min(1), // base64url
  label: z.string().min(1),
});
const authVerifyPasskeyBodySchema = z.object({
  response: z.custom<AuthenticationResponseJSON>(),
  prfOutput: z.string().min(1), // base64url
});
const recoveryKeyBodySchema = z.object({ recoveryKey: z.string().min(1) });

/** The frontend displays the key chunked with dashes for readability - cosmetic only, stripped before decoding. */
function decodeRecoveryKey(value: string): Buffer {
  return Buffer.from(value.replace(/[\s-]/g, ""), "base64url");
}

export interface VaultRoutesConfig {
  db: BetterSQLite3Database<any>;
  mode: AuthMode;
  webauthn: WebauthnConfig;
  /** `mode: "none"` has no real identity system - this is the one implicit user's placeholder, not meant to be shown anywhere. */
  noneMode: { placeholderEmail: string; placeholderDisplayName: string };
  sessionCache: SessionCache;
}

interface UnlockedVault {
  userId: number;
  dek: Buffer;
}

/**
 * Unlock (deriving the DEK) and managing unlock methods - independent of
 * `mode`, but *which* user's vault gets unlocked does depend on it:
 * `none` always means the one implicit user; `single`/`oidc` mean
 * whoever just logged in via routes/auth.ts (requireAuth.ts already
 * guarantees `authUserId` is set by the time these handlers run, in those
 * modes).
 */
export function createVaultRoutes(config: VaultRoutesConfig) {
  const { db, mode, webauthn, noneMode, sessionCache } = config;
  const { cacheSession, getSession } = sessionCacheInternals(sessionCache);

  /** Caches the session the same way for every unlock path (password, passkey, bootstrap). */
  function startSession(request: FastifyRequest, unlocked: UnlockedVault): void {
    const session = typedSession(request);
    const sessionId = session.get("id") ?? randomUUID();
    session.set("id", sessionId);
    cacheSession(sessionId, unlocked.userId, unlocked.dek);
  }

  /** The vault must already be unlocked to register a passkey - it wraps *this session's* DEK. */
  function getSessionOrReject(request: FastifyRequest, reply: FastifyReply) {
    const sessionId = typedSession(request).get("id");
    const session = sessionId !== undefined ? getSession(sessionId) : undefined;
    if (!session) {
      reply.code(404).send({ error: "vault locked" });
      return undefined;
    }
    return session;
  }

  /** `none` mode's one implicit user; `single`/`oidc` already resolved their user at login. */
  async function resolveUserIdForStatus(request: FastifyRequest): Promise<number | undefined> {
    if (mode === "none") {
      const [existingUser] = await db.select().from(user).where(eq(user.email, noneMode.placeholderEmail));
      return existingUser?.id;
    }
    const authUserId = typedSession(request).get("authUserId");
    return authUserId !== undefined ? Number(authUserId) : undefined;
  }

  /**
   * Same as resolveUserIdForStatus, except `none` mode also creates the
   * implicit user here if this is the very first unlock ever - unlock is
   * the only place `none` mode can create it, since there's no login step
   * to do it earlier.
   */
  async function resolveOrCreateUserIdForUnlock(request: FastifyRequest): Promise<number> {
    if (mode === "none") {
      const [existingUser] = await db.select().from(user).where(eq(user.email, noneMode.placeholderEmail));
      if (existingUser) return existingUser.id;

      const [createdUser] = await db
        .insert(user)
        .values({ displayName: noneMode.placeholderDisplayName, email: noneMode.placeholderEmail, createdAt: new Date() })
        .returning();
      if (!createdUser) throw new Error("user insert returned no row");
      return createdUser.id;
    }

    const authUserId = typedSession(request).get("authUserId");
    if (authUserId === undefined) {
      // requireAuth already guarantees this in single/oidc mode - a missing
      // value here would mean the hook isn't actually wired in front of this
      // route, which is a programming error, not a client error.
      throw new Error("vault unlock reached without an authenticated session");
    }
    return Number(authUserId);
  }

  async function hasPasswordVaultMethod(userId: number): Promise<boolean> {
    const [methodRow] = await db
      .select({ id: vaultUnlockMethod.id })
      .from(vaultUnlockMethod)
      .where(and(eq(vaultUnlockMethod.userId, userId), eq(vaultUnlockMethod.method, "password")));
    return methodRow !== undefined;
  }

  async function getPasskeyMethods(userId: number) {
    return db
      .select()
      .from(vaultUnlockMethod)
      .where(and(eq(vaultUnlockMethod.userId, userId), eq(vaultUnlockMethod.method, "passkey")));
  }

  async function hasRecoveryKeyMethod(userId: number): Promise<boolean> {
    const [methodRow] = await db
      .select({ id: vaultUnlockMethod.id })
      .from(vaultUnlockMethod)
      .where(and(eq(vaultUnlockMethod.userId, userId), eq(vaultUnlockMethod.method, "recovery")));
    return methodRow !== undefined;
  }

  /** First unlock for this user: creates their password unlock method. */
  async function bootstrapFirstVaultForUser(userId: number, password: string): Promise<UnlockedVault> {
    const { dek, method } = await createPasswordUnlockMethod(password);

    await db.insert(vaultUnlockMethod).values({
      userId,
      method: "password",
      wrappedDek: method.wrappedDek,
      kdfSalt: method.kdfSalt,
      kdfParams: JSON.stringify(method.kdfParams),
      createdAt: new Date(),
    });

    return { userId, dek };
  }

  /** Every later unlock: verify the password against the stored method, or bootstrap if there isn't one yet. */
  async function unlockOrBootstrapVault(
    userId: number,
    password: string,
    reply: FastifyReply,
  ): Promise<UnlockedVault | undefined> {
    const [methodRow] = await db
      .select()
      .from(vaultUnlockMethod)
      .where(and(eq(vaultUnlockMethod.userId, userId), eq(vaultUnlockMethod.method, "password")));

    if (!methodRow) {
      return bootstrapFirstVaultForUser(userId, password);
    }

    if (!methodRow.kdfSalt || !methodRow.kdfParams) {
      reply.code(500).send({ error: "no password unlock method found" });
      return undefined;
    }

    try {
      const dek = await unlockWithPassword(password, {
        wrappedDek: methodRow.wrappedDek,
        kdfSalt: methodRow.kdfSalt,
        kdfParams: JSON.parse(methodRow.kdfParams) as KdfParams,
      });
      return { userId, dek };
    } catch {
      reply.code(401).send({ error: "wrong password" });
      return undefined;
    }
  }

  return async function vaultRoutes(app: FastifyInstance) {
    app.get("/status", async (request) => {
      const session = typedSession(request);
      const sessionId = session.get("id");
      const unlocked = sessionId !== undefined && getSession(sessionId) !== undefined;

      const userId = await resolveUserIdForStatus(request);
      const hasVault = userId !== undefined && (await hasPasswordVaultMethod(userId));
      const hasPasskey = userId !== undefined && (await getPasskeyMethods(userId)).length > 0;
      const hasRecoveryKey = userId !== undefined && (await hasRecoveryKeyMethod(userId));

      return { unlocked, hasVault, hasPasskey, hasRecoveryKey };
    });

    app.post("/unlock", async (request, reply) => {
      const { password } = unlockBodySchema.parse(request.body);
      const userId = await resolveOrCreateUserIdForUnlock(request);

      const unlocked = await unlockOrBootstrapVault(userId, password, reply);
      if (unlocked === undefined) return; // reply already sent (wrong password / no method)

      startSession(request, unlocked);
      return { status: "unlocked" };
    });

    // Drops this session's DEK but keeps the login, so the next visit only
    // asks for an unlock method. Logout is the heavier step: it also clears
    // the login.
    app.post("/lock", async (request) => {
      const sessionId = typedSession(request).get("id");
      if (sessionId !== undefined) sessionCache.dropSession(sessionId);
      return { status: "locked" };
    });

    app.post("/unlock-with-recovery", async (request, reply) => {
      const { recoveryKey } = recoveryKeyBodySchema.parse(request.body);
      const userId = await resolveOrCreateUserIdForUnlock(request);

      const [methodRow] = await db
        .select()
        .from(vaultUnlockMethod)
        .where(and(eq(vaultUnlockMethod.userId, userId), eq(vaultUnlockMethod.method, "recovery")));
      if (!methodRow) {
        reply.code(404).send({ error: "no recovery key registered" });
        return;
      }

      let dek: Buffer;
      try {
        dek = unlockWithRecovery(decodeRecoveryKey(recoveryKey), methodRow.wrappedDek);
      } catch {
        reply.code(401).send({ error: "wrong recovery key" });
        return;
      }

      startSession(request, { userId, dek });
      return { status: "unlocked" };
    });

    app.get("/methods", async (request) => {
      const userId = await resolveUserIdForStatus(request);
      if (userId === undefined) return { methods: [] };

      // Labels are encrypted - only decodable while the vault happens to be
      // unlocked this session. Still worth listing the rows while locked,
      // just without a human-readable label.
      const sessionId = typedSession(request).get("id");
      const dek = sessionId !== undefined ? getSession(sessionId)?.dek : undefined;

      const rows = await db.select().from(vaultUnlockMethod).where(eq(vaultUnlockMethod.userId, userId));
      return {
        methods: rows.map((row) => ({
          id: row.id,
          method: row.method,
          label: row.label && dek ? decryptField(dek, row.label).toString("utf8") : null,
          createdAt: row.createdAt,
          lastUsedAt: row.lastUsedAt,
        })),
      };
    });

    app.post("/methods/passkey/register-options", async (request, reply) => {
      const session = getSessionOrReject(request, reply);
      if (!session) return;

      const existing = await getPasskeyMethods(session.userId);
      const [userRow] = await db.select().from(user).where(eq(user.id, session.userId));
      if (!userRow) throw new Error("session userId does not match any user row");

      const challenge = await createPasskeyRegistrationChallenge(
        webauthn,
        { id: userRow.id, email: userRow.email },
        existing.flatMap((m) => (m.credentialId ? [m.credentialId] : [])),
      );

      const typed = typedSession(request);
      typed.set("passkeyChallenge", challenge.challenge);
      typed.set("passkeyPrfSalt", challenge.prfSalt);

      return { options: challenge.options, prfSalt: challenge.prfSalt };
    });

    app.post("/methods/passkey", async (request, reply) => {
      const session = getSessionOrReject(request, reply);
      if (!session) return;

      const { response, prfOutput, label } = registerPasskeyBodySchema.parse(request.body);
      const typed = typedSession(request);
      const expectedChallenge = typed.get("passkeyChallenge");
      const prfSalt = typed.get("passkeyPrfSalt");
      if (!expectedChallenge || !prfSalt) {
        reply.code(400).send({ error: "no pending passkey registration for this session" });
        return;
      }

      const verified = await verifyPasskeyRegistration(webauthn, response, expectedChallenge);
      const wrappedDek = wrapDekForPasskey(session.dek, Buffer.from(prfOutput, "base64url"));

      await db.insert(vaultUnlockMethod).values({
        userId: session.userId,
        method: "passkey",
        label: encryptField(session.dek, Buffer.from(label, "utf8")),
        wrappedDek,
        credentialId: verified.credentialId,
        publicKey: verified.publicKey,
        counter: verified.counter,
        prfSalt: Buffer.from(prfSalt, "base64url"),
        createdAt: new Date(),
      });

      typed.set("passkeyChallenge", "");
      typed.set("passkeyPrfSalt", "");
      return { status: "registered" };
    });

    app.get("/methods/passkey/auth-options", async (request, reply) => {
      const userId = await resolveUserIdForStatus(request);
      const passkeys = userId !== undefined ? await getPasskeyMethods(userId) : [];
      if (passkeys.length === 0) {
        reply.code(404).send({ error: "no passkeys registered" });
        return;
      }

      const challenge = await createPasskeyAuthenticationChallenge(
        webauthn,
        passkeys.flatMap((m) => (m.credentialId && m.prfSalt ? [{ credentialId: m.credentialId, prfSalt: m.prfSalt }] : [])),
      );

      typedSession(request).set("passkeyChallenge", challenge.challenge);
      return { options: challenge.options, prfSaltByCredentialId: challenge.prfSaltByCredentialId };
    });

    app.post("/methods/passkey/auth-verify", async (request, reply) => {
      const { response, prfOutput } = authVerifyPasskeyBodySchema.parse(request.body);
      const typed = typedSession(request);
      const expectedChallenge = typed.get("passkeyChallenge");
      if (!expectedChallenge) {
        reply.code(400).send({ error: "no pending passkey login for this session" });
        return;
      }

      const [methodRow] = await db
        .select()
        .from(vaultUnlockMethod)
        .where(and(eq(vaultUnlockMethod.credentialId, response.id), eq(vaultUnlockMethod.method, "passkey")));

      if (!methodRow?.publicKey) {
        reply.code(401).send({ error: "unknown passkey" });
        return;
      }
      // Looked up by credential id alone, so without this a logged-in user
      // could unlock someone else's vault into their own session.
      const expectedUserId = await resolveUserIdForStatus(request);
      if (expectedUserId !== undefined && methodRow.userId !== expectedUserId) {
        reply.code(401).send({ error: "unknown passkey" });
        return;
      }
      const storedCounter = methodRow.counter ?? 0;

      let verified: { newCounter: number };
      try {
        verified = await verifyPasskeyAuthentication(webauthn, response, expectedChallenge, {
          id: methodRow.credentialId!,
          publicKey: new Uint8Array(methodRow.publicKey),
          counter: storedCounter,
        });
      } catch {
        reply.code(401).send({ error: "passkey verification failed" });
        return;
      }

      // A counter that didn't increase means a cloned authenticator -
      // except the (0, 0) steady state, which is normal for synced/
      // multi-device passkeys that never track a counter at all. A
      // *drop* to 0 from a previously nonzero value is still suspicious,
      // not exempted - that's a real authenticator's counter going
      // backwards.
      const isCounterlessAuthenticator = storedCounter === 0 && verified.newCounter === 0;
      if (!isCounterlessAuthenticator && verified.newCounter <= storedCounter) {
        reply.code(401).send({ error: "passkey counter did not increase - possible cloned authenticator" });
        return;
      }

      let dek: Buffer;
      try {
        dek = unlockWithPasskey(Buffer.from(prfOutput, "base64url"), methodRow.wrappedDek);
      } catch {
        reply.code(401).send({ error: "wrong passkey" });
        return;
      }

      await db
        .update(vaultUnlockMethod)
        .set({ counter: verified.newCounter, lastUsedAt: new Date() })
        .where(eq(vaultUnlockMethod.id, methodRow.id));

      typed.set("passkeyChallenge", "");
      startSession(request, { userId: methodRow.userId, dek });
      return { status: "unlocked" };
    });

    app.post("/methods/recovery", async (request, reply) => {
      const session = getSessionOrReject(request, reply);
      if (!session) return;

      const { recoveryKey } = recoveryKeyBodySchema.parse(request.body);
      const wrappedDek = wrapDekForRecovery(session.dek, decodeRecoveryKey(recoveryKey));

      // Only one recovery key per user by convention - generating a new
      // one replaces any existing row rather than accumulating.
      await db
        .delete(vaultUnlockMethod)
        .where(and(eq(vaultUnlockMethod.userId, session.userId), eq(vaultUnlockMethod.method, "recovery")));

      await db.insert(vaultUnlockMethod).values({
        userId: session.userId,
        method: "recovery",
        label: encryptField(session.dek, Buffer.from("Recovery key", "utf8")),
        wrappedDek,
        createdAt: new Date(),
      });

      return { status: "registered" };
    });

    app.delete("/methods/:id", async (request, reply) => {
      const userId = await resolveUserIdForStatus(request);
      const { id } = z.object({ id: z.coerce.number().int() }).parse(request.params);

      const [methodRow] = await db.select().from(vaultUnlockMethod).where(eq(vaultUnlockMethod.id, id));
      if (!methodRow || methodRow.userId !== userId) {
        reply.code(404).send({ error: "not found" });
        return;
      }

      // The password method is the required baseline - there's always
      // exactly one, never zero.
      if (methodRow.method === "password") {
        reply.code(400).send({ error: "the password unlock method can't be removed" });
        return;
      }

      await db.delete(vaultUnlockMethod).where(eq(vaultUnlockMethod.id, id));
      return { status: "revoked" };
    });
  };
}
