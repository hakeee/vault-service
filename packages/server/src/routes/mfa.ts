import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, eq } from "drizzle-orm";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { generateAuthenticationOptions, generateRegistrationOptions } from "@simplewebauthn/server";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { createAttemptLimiter, type AttemptLimiter } from "../attemptLimiter.js";
import { sessionStatus } from "../accountStatus.js";
import type { DeviceCookies } from "../auth/device.js";
import { createMfaStore, type MfaStore } from "../auth/mfa.js";
import { verifyPasswordHash } from "../auth/password.js";
import { generateTotpSecret, totpUri, verifyTotp, base32Decode } from "../auth/totp.js";
import { verifyPasskeyAuthentication, verifyPasskeyRegistration, type WebauthnConfig } from "../crypto/webauthn.js";
import { user, userIdentity } from "../schema.js";
import type { SecurityEvent } from "../securityEvents.js";
import { typedSession, unsetSessionKeys, type TypedSession } from "../session.js";

export interface MfaConfig {
  /**
   * 32 bytes (`openssl rand -hex 32`): encrypts TOTP secrets and keys recovery code hashes at rest.
   * Losing it means everyone sets up their authenticator again.
   */
  key: Buffer;
  /** The name authenticator apps show next to the account. */
  issuer: string;
  /** For login passkeys (no PRF needed, unlike vault passkeys). Usually the same as the vault routes'. */
  webauthn: WebauthnConfig;
  /**
   * Whether this person must have a second factor. Default: nobody must,
   * but anyone who set one up is always asked for it. When it says yes and
   * they have none yet, the login stops at setting one up.
   */
  required?: (userId: number) => boolean | Promise<boolean>;
  /**
   * Wrong codes per account and browser before a 429. Default 10; the first
   * block lasts 15 minutes, each next one twice as long (up to a day).
   */
  maxFailures?: number;
}

export type MfaStage = "verify" | "setup";

/** A password-checked login waiting for its second factor stays usable this long. */
const PENDING_MS = 10 * 60_000;
/** Every session key of the second step; a finished login clears them. */
export const MFA_SESSION_KEYS = ["mfaUserId", "mfaStage", "mfaAt", "mfaCreated", "mfaTotpSecret", "mfaChallenge"];

const codeBody = z.object({ code: z.string().min(1).max(64) });
const passkeyVerifyBody = z.object({ response: z.custom<AuthenticationResponseJSON>() });
const label = z.string().trim().max(60).optional();
/** On a fully logged-in session, changing factors needs the password again: a stolen cookie alone can't add or remove them. */
const password = z.string().max(1024).optional();
const totpConfirmBody = z.object({ code: z.string().min(1).max(16), label, password });
const passkeyRegisterBody = z.object({ response: z.custom<RegistrationResponseJSON>(), label, password });
const passwordBody = z.object({ password });
const removeBody = z.object({ id: z.number().int(), password });

type Caller = { userId: number; stage: MfaStage | "full"; created: boolean };

export interface MfaRoutesDeps {
  db: BetterSQLite3Database<any>;
  config: MfaConfig;
  /** Finishes the login (fresh session id, `authUserId`, known-device cookie, onLogin) once the second factor is in. */
  completeLogin: (request: FastifyRequest, reply: FastifyReply, userId: number, created: boolean) => Promise<void>;
  /** Known browsers: wrong codes from one don't block the owner's others. */
  devices: DeviceCookies;
  /** Wrong passwords on a logged-in session, per account: shared with changing the password, so a stolen cookie can't guess it. */
  reauthFailures: AttemptLimiter;
  notify: (event: SecurityEvent) => void;
}

/**
 * Second factors for `single` mode. After the password, `begin` puts the
 * session in a half-logged-in state (`mfaUserId`, no `authUserId`), so
 * requireAuth and the vault routes still see nobody. Only these routes
 * accept it, to verify a factor (or set one up when it's required), and
 * then `completeLogin` makes it a real login.
 */
export function createMfaRoutes(deps: MfaRoutesDeps) {
  const { db, config, devices, reauthFailures, notify } = deps;
  const store: MfaStore = createMfaStore(db, config.key);
  // Escalating: 10 tries per 15 minutes would still add up to a fair chance at a 6-digit code over months.
  const failures = createAttemptLimiter({ max: config.maxFailures ?? 10, windowMs: 15 * 60_000, escalate: { maxBlockMs: 24 * 60 * 60_000 } });

  /** Puts the session in the second-factor step: any earlier login on it ends here. */
  function begin(session: TypedSession, userId: number, stage: MfaStage, created: boolean, dropSession: (id: string) => void): void {
    const oldId = session.get("id");
    if (oldId) dropSession(oldId);
    unsetSessionKeys(session, ["id", "authUserId", "loginAt", ...MFA_SESSION_KEYS]);
    session.set("mfaUserId", String(userId));
    session.set("mfaStage", stage);
    session.set("mfaAt", String(Date.now()));
    if (created) session.set("mfaCreated", "1");
  }

  /** The pending second step on this session, if any and still fresh. */
  function pending(session: TypedSession): { userId: number; stage: MfaStage; created: boolean } | undefined {
    const userId = session.get("mfaUserId");
    const stage = session.get("mfaStage");
    if (!userId || (stage !== "verify" && stage !== "setup")) return undefined;
    if (Date.now() - Number(session.get("mfaAt") ?? 0) > PENDING_MS) return undefined;
    const row = db.select({ disabledAt: user.disabledAt }).from(user).where(eq(user.id, Number(userId))).get();
    if (!row || row.disabledAt) return undefined;
    return { userId: Number(userId), stage, created: session.get("mfaCreated") === "1" };
  }

  function caller(request: FastifyRequest, reply: FastifyReply, allowed: Caller["stage"][]): Caller | undefined {
    const session = typedSession(request);
    const authUserId = session.get("authUserId");
    const found: Caller | undefined =
      authUserId !== undefined && sessionStatus(db, session) === "ok" ? { userId: Number(authUserId), stage: "full", created: false } : pending(session);
    if (!found) {
      reply.code(401).send({ error: "login required" });
      return undefined;
    }
    if (!allowed.includes(found.stage)) {
      reply.code(409).send({ error: found.stage === "full" ? "already logged in" : `finish the second step first (${found.stage})` });
      return undefined;
    }
    return found;
  }

  /** Wrong codes count per account and browser: a known browser of the owner has its own count. */
  const codeKey = (request: FastifyRequest, userId: number) => `${userId}:${devices.read(request, userId) ?? "-"}`;
  const tooMany = (limiter: AttemptLimiter, key: string, reply: FastifyReply) => {
    const wait = limiter.blockedFor(key);
    if (wait > 0) reply.code(429).header("retry-after", wait).send({ error: "too many failed attempts; try again later" });
    return wait > 0;
  };
  const codeBlocked = (request: FastifyRequest, who: Caller, reply: FastifyReply) => tooMany(failures, codeKey(request, who.userId), reply);
  const codeFailed = (request: FastifyRequest, who: Caller, reply: FastifyReply, error: string) => {
    if (failures.fail(codeKey(request, who.userId))) notify({ userId: who.userId, kind: "mfa-blocked" });
    reply.code(401).send({ error });
  };
  const loggedIn = async (request: FastifyRequest, reply: FastifyReply, who: Caller) => {
    failures.clear(codeKey(request, who.userId));
    await deps.completeLogin(request, reply, who.userId, who.created);
  };

  /** Fully logged-in sessions re-type the password before changing factors; mid-login ones just did. */
  async function passwordOk(who: Caller, given: string | undefined, reply: FastifyReply): Promise<boolean> {
    if (who.stage !== "full") return true;
    if (tooMany(reauthFailures, String(who.userId), reply)) return false;
    const identity = db
      .select({ hash: userIdentity.passwordHash })
      .from(userIdentity)
      .where(and(eq(userIdentity.userId, who.userId), eq(userIdentity.provider, "local")))
      .get();
    if (!identity?.hash || !given || !(await verifyPasswordHash(identity.hash, given))) {
      reauthFailures.fail(String(who.userId));
      reply.code(401).send({ error: "wrong password" });
      return false;
    }
    return true;
  }

  const isRequired = async (userId: number) => (await config.required?.(userId)) ?? false;

  /** After a new authenticator or passkey: recovery codes the first time, and the login finishes if it was waiting on setup. */
  async function enrolled(request: FastifyRequest, reply: FastifyReply, who: Caller, factor: "totp" | "passkey") {
    const firstFactor = !store.list(who.userId).some((f) => f.kind === "recovery");
    const recoveryCodes = firstFactor ? store.newRecoveryCodes(who.userId) : undefined;
    const session = typedSession(request);
    unsetSessionKeys(session, ["mfaTotpSecret", "mfaChallenge"]);
    if (who.stage === "setup") await deps.completeLogin(request, reply, who.userId, who.created);
    notify({ userId: who.userId, kind: "factor-added", factor });
    return { status: who.stage === "setup" ? "logged_in" : "added", ...(recoveryCodes ? { recoveryCodes } : {}) };
  }

  async function routes(app: FastifyInstance) {
    /** Where this session stands, and (once logged in) the person's factors. */
    app.get("/", async (request, reply) => {
      const who = caller(request, reply, ["verify", "setup", "full"]);
      if (!who) return;
      const factors = store.list(who.userId);
      return {
        stage: who.stage,
        required: await isRequired(who.userId),
        // Mid-login, only which kinds exist: enough to offer the right form.
        kinds: [...new Set(factors.map((f) => f.kind))],
        factors: who.stage === "full" ? factors : [],
      };
    });

    // --- the second step of a login ---------------------------------------

    app.post("/verify/totp", async (request, reply) => {
      const who = caller(request, reply, ["verify"]);
      if (!who || codeBlocked(request, who, reply)) return;
      const { code } = codeBody.parse(request.body);
      if (!store.verifyTotp(who.userId, code)) return codeFailed(request, who, reply, "wrong code");
      await loggedIn(request, reply, who);
      return { status: "logged_in" };
    });

    app.post("/verify/recovery", async (request, reply) => {
      const who = caller(request, reply, ["verify"]);
      if (!who || codeBlocked(request, who, reply)) return;
      const { code } = codeBody.parse(request.body);
      if (!store.useRecoveryCode(who.userId, code)) return codeFailed(request, who, reply, "wrong code");
      await loggedIn(request, reply, who);
      const left = store.list(who.userId).find((f) => f.kind === "recovery")?.remaining ?? 0;
      return { status: "logged_in", recoveryCodesLeft: left };
    });

    app.post("/verify/passkey/options", async (request, reply) => {
      const who = caller(request, reply, ["verify"]);
      if (!who) return;
      const passkeys = store.passkeys(who.userId);
      if (passkeys.length === 0) return reply.code(404).send({ error: "no passkey set up" });
      const options = await generateAuthenticationOptions({
        rpID: config.webauthn.rpID,
        allowCredentials: passkeys.map((p) => ({ id: p.credentialId })),
        userVerification: "preferred",
      });
      typedSession(request).set("mfaChallenge", options.challenge);
      return { options };
    });

    app.post("/verify/passkey", async (request, reply) => {
      const who = caller(request, reply, ["verify"]);
      if (!who || codeBlocked(request, who, reply)) return;
      const { response } = passkeyVerifyBody.parse(request.body);
      const session = typedSession(request);
      const challenge = session.get("mfaChallenge");
      const passkey = store.passkeys(who.userId).find((p) => p.credentialId === response?.id);
      if (!challenge || !passkey) return codeFailed(request, who, reply, "passkey verification failed");
      let newCounter: number;
      try {
        ({ newCounter } = await verifyPasskeyAuthentication(config.webauthn, response, challenge, {
          id: passkey.credentialId,
          publicKey: new Uint8Array(passkey.publicKey),
          counter: passkey.counter,
        }));
      } catch {
        return codeFailed(request, who, reply, "passkey verification failed");
      }
      // A counter that didn't go up means a cloned authenticator, except 0 -> 0 (synced passkeys don't count).
      if (!(newCounter > passkey.counter || (newCounter === 0 && passkey.counter === 0))) return codeFailed(request, who, reply, "passkey verification failed");
      store.passkeyUsed(passkey.id, newCounter);
      await loggedIn(request, reply, who);
      return { status: "logged_in" };
    });

    // --- setting up factors (mid-login when required, or later) -------------

    app.post("/totp/setup", async (request, reply) => {
      const who = caller(request, reply, ["setup", "full"]);
      if (!who) return;
      const secret = generateTotpSecret();
      // Kept in the encrypted session cookie until a code proves the app has it.
      typedSession(request).set("mfaTotpSecret", secret);
      const email = db.select({ email: user.email }).from(user).where(eq(user.id, who.userId)).get()?.email ?? String(who.userId);
      return { secret, uri: totpUri(secret, email, config.issuer) };
    });

    app.post("/totp/confirm", async (request, reply) => {
      const who = caller(request, reply, ["setup", "full"]);
      if (!who || codeBlocked(request, who, reply)) return;
      const body = totpConfirmBody.parse(request.body);
      if (!(await passwordOk(who, body.password, reply))) return;
      const secret = typedSession(request).get("mfaTotpSecret");
      if (!secret) return reply.code(409).send({ error: "start the setup first" });
      const step = verifyTotp(base32Decode(secret), body.code, Date.now());
      if (step === null) return codeFailed(request, who, reply, "wrong code; check the time on your phone");
      store.addTotp(who.userId, secret, body.label || "Authenticator app", step);
      return enrolled(request, reply, who, "totp");
    });

    app.post("/passkey/options", async (request, reply) => {
      const who = caller(request, reply, ["setup", "full"]);
      if (!who) return;
      const email = db.select({ email: user.email }).from(user).where(eq(user.id, who.userId)).get()?.email ?? String(who.userId);
      const options = await generateRegistrationOptions({
        rpName: config.webauthn.rpName,
        rpID: config.webauthn.rpID,
        userName: email,
        userID: Buffer.from(String(who.userId), "utf8"),
        excludeCredentials: store.passkeys(who.userId).map((p) => ({ id: p.credentialId })),
        authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      });
      typedSession(request).set("mfaChallenge", options.challenge);
      return { options };
    });

    app.post("/passkey", async (request, reply) => {
      const who = caller(request, reply, ["setup", "full"]);
      if (!who) return;
      const body = passkeyRegisterBody.parse(request.body);
      if (!(await passwordOk(who, body.password, reply))) return;
      const challenge = typedSession(request).get("mfaChallenge");
      if (!challenge) return reply.code(409).send({ error: "start the setup first" });
      let credential: Awaited<ReturnType<typeof verifyPasskeyRegistration>>;
      try {
        credential = await verifyPasskeyRegistration(config.webauthn, body.response, challenge);
      } catch {
        return reply.code(400).send({ error: "passkey registration could not be verified" });
      }
      store.addPasskey(who.userId, credential, body.label || "Passkey");
      return enrolled(request, reply, who, "passkey");
    });

    app.post("/recovery", async (request, reply) => {
      const who = caller(request, reply, ["full"]);
      if (!who) return;
      const body = passwordBody.parse(request.body);
      if (!(await passwordOk(who, body.password, reply))) return;
      if (store.primaryKinds(who.userId).length === 0) return reply.code(409).send({ error: "set up an authenticator app or passkey first" });
      const recoveryCodes = store.newRecoveryCodes(who.userId);
      notify({ userId: who.userId, kind: "recovery-codes-replaced" });
      return { recoveryCodes };
    });

    app.post("/remove", async (request, reply) => {
      const who = caller(request, reply, ["full"]);
      if (!who) return;
      const body = removeBody.parse(request.body);
      if (!(await passwordOk(who, body.password, reply))) return;
      const factor = store.list(who.userId).find((f) => f.id === body.id);
      if (!factor) return reply.code(404).send({ error: "no such factor" });
      if (factor.kind === "recovery") return reply.code(400).send({ error: "recovery codes are replaced, not removed" });
      const others = store.list(who.userId).filter((f) => f.kind !== "recovery" && f.id !== factor.id);
      if (others.length === 0 && (await isRequired(who.userId))) return reply.code(409).send({ error: "two-step login is required: add another factor first" });
      store.remove(who.userId, factor.id);
      notify({ userId: who.userId, kind: "factor-removed", factor: factor.kind });
      return { status: "removed" };
    });
  }

  return { store, begin, pending, routes };
}
