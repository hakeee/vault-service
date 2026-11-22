import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createInviteStore } from "../invites.js";
import { z } from "zod";
import { createAttemptLimiter, ipBucket, MIN_SECRET_LENGTH, type AttemptLimit } from "../attemptLimiter.js";
import { createDeviceCookies, deriveDeviceKey } from "../auth/device.js";
import { securityNotifier, type SecurityEventHandler } from "../securityEvents.js";
import {
  buildAuthorizationRequest,
  createOidcClient,
  handleOidcCallback,
  type OidcConfig,
} from "../auth/oidc.js";
import { hashPassword, verifyPasswordHash } from "../auth/password.js";
import { resolveOidcAccount, type OidcLoginError } from "../auth/accountResolution.js";
import type { AuthMode } from "../auth/mode.js";
import { user, userIdentity } from "../schema.js";
import { typedSession, unsetSessionKeys, type TypedSession } from "../session.js";
import { randomBytes, randomUUID } from "node:crypto";
import type { SessionCache } from "../sessionCache.js";
import { endOtherSessions, revokeSession, sessionStatus, type SelfServiceAuthorizer } from "../accountStatus.js";
import { routeErrorHandler } from "./errors.js";
import { createMfaRoutes, MFA_SESSION_KEYS, type MfaConfig } from "./mfa.js";

const loginBodySchema = z.object({ email: z.email(), password: z.string().min(1) });
const acceptInviteBodySchema = z.object({ password: z.string().min(MIN_SECRET_LENGTH, `choose a password of at least ${MIN_SECRET_LENGTH} characters`) });
const changePasswordBodySchema = z.object({ currentPassword: z.string().min(1), newPassword: z.string().min(MIN_SECRET_LENGTH, `at least ${MIN_SECRET_LENGTH} characters`) });

/** Handed to `onLogin` after every successful login. */
export interface LoginEvent {
  userId: number;
  /** This login created the account (open signup, a first OIDC login, or the very first account). */
  created: boolean;
  provider: "local" | "oidc";
  /** The ID token's claims, for OIDC logins - e.g. to map IdP roles. */
  claims?: Record<string, unknown>;
}

export interface AuthRoutesConfig {
  db: BetterSQLite3Database<any>;
  mode: AuthMode;
  oidc?: OidcConfig;
  /** Where to send the browser after a successful OIDC login (your web app's own origin). */
  postLoginRedirectUrl: string;
  /**
   * The same cache passed to createVaultRoutes. With it, logout also drops
   * the session's DEK. Without it, the DEK stays in memory until the idle
   * timeout, and a copy of the old cookie (stateless, so still valid) can
   * still use the vault until then.
   */
  sessionCache?: SessionCache;
  /**
   * Whether logging in with an unknown account creates it. `"open"`
   * (default): the first login for an email (or an OIDC identity) creates
   * the account. `"closed"`: only the very first account is created this
   * way - it becomes the owner - and the rest are created by the app (see
   * `createAccountStore`), or linked by email for OIDC. Invite links and
   * other providers can build on `"closed"` later.
   */
  signup?: "open" | "closed";
  /**
   * With closed signup: the only email allowed to create the very first
   * account (case-insensitive). OIDC logins also need the IdP to say the
   * email is verified. Without it, whoever logs in first on an empty
   * database becomes the owner. A single-mode login can't prove it owns
   * the email, so keep the server private until that first account exists.
   */
  bootstrapEmail?: string;
  /** Runs after every successful login, before the response - e.g. IAM role mapping. */
  onLogin?: (event: LoginEvent) => void | Promise<void>;
  /** May refuse self-service actions (here: `auth:changePassword`) with a 403. Default: allowed. */
  authorize?: SelfServiceAuthorizer;
  /**
   * Failed logins allowed within the window before a 429. `perAccountIp`
   * (default 10) counts one account from one IP, so a stranger can't lock
   * the owner out; `perAccount` (default 100) counts an account from
   * everywhere, against guessing spread over many addresses; `perIp`
   * (default 50) counts one address across accounts. Window: 15 minutes.
   * Addresses are counted per IPv4 address or IPv6 /64. Behind a proxy, set
   * Fastify's `trustProxy` so the IP is the client's.
   *
   * A browser the account has fully logged in from before (a "known device"
   * cookie) is counted on its own instead (`perAccountIp` per device), so
   * guessing from elsewhere can't lock the owner out of their own browsers.
   */
  loginLimits?: { perAccountIp?: number; perAccount?: number; perIp?: number; windowMs?: number };
  /**
   * The known-device cookie (see `loginLimits`). `key`: HMAC key; default
   * derived from the MFA key, or a random one per process (devices are then
   * forgotten on restart). `secure`: HTTPS only; default when the request
   * came over HTTPS.
   */
  deviceCookie?: { key?: Buffer; secure?: boolean };
  /**
   * Told about changes to how someone logs in (password changed, factors
   * added or removed, new recovery codes, too many wrong codes), e.g. to
   * email them. Runs after the change; a failure is logged, nothing more.
   */
  onSecurityEvent?: SecurityEventHandler;
  /**
   * Second factors for `single` mode (authenticator apps, login passkeys,
   * recovery codes), served under `/mfa`. Without it, a correct password
   * logs in, as before.
   */
  mfa?: MfaConfig;
  /**
   * OIDC: whether a verified email at the IdP may link to an existing
   * account that has no identity there yet. Default true. Give a function
   * to keep some accounts out (the app's root), or false when people only
   * join by invite (the production setting).
   */
  linkByEmail?: boolean | ((userId: number) => boolean | Promise<boolean>);
  /**
   * OIDC: refuse ID tokens that don't show a second factor. `true` checks
   * that `amr` lists "mfa"; a function decides from the claims itself.
   */
  oidcRequireMfa?: boolean | ((claims: Record<string, unknown>) => boolean);
}

/** The default `oidcRequireMfa` check: the IdP says the login used more than one factor. */
export function amrShowsMfa(claims: Record<string, unknown>): boolean {
  return Array.isArray(claims.amr) && claims.amr.includes("mfa");
}

/**
 * `mode`'s login flows. Independent of vault unlock, which lives in
 * routes/vault.ts - see requireAuth.ts for how the two connect (unlock
 * routes sit behind the same `authUserId` session check these routes
 * set).
 */
export function createAuthRoutes(config: AuthRoutesConfig) {
  const { db, mode, oidc, postLoginRedirectUrl, sessionCache, onLogin } = config;
  const invites = createInviteStore(db);
  // Invite tokens are unguessable; this only keeps someone from hammering the lookup.
  const inviteMisses = createAttemptLimiter({ max: 20, windowMs: 15 * 60_000 });
  const mayLinkByEmail = async (userId: number) =>
    typeof config.linkByEmail === "function" ? await config.linkByEmail(userId) : config.linkByEmail !== false;
  const oidcMfaOk = (claims: Record<string, unknown>) =>
    !config.oidcRequireMfa || (typeof config.oidcRequireMfa === "function" ? config.oidcRequireMfa(claims) : amrShowsMfa(claims));
  const windowMs = config.loginLimits?.windowMs ?? 15 * 60_000;
  const perAccountIp = createAttemptLimiter({ max: config.loginLimits?.perAccountIp ?? 10, windowMs } satisfies AttemptLimit);
  const perAccount = createAttemptLimiter({ max: config.loginLimits?.perAccount ?? 100, windowMs });
  const perIp = createAttemptLimiter({ max: config.loginLimits?.perIp ?? 50, windowMs });
  const perDevice = createAttemptLimiter({ max: config.loginLimits?.perAccountIp ?? 10, windowMs });
  const devices = createDeviceCookies({
    key: config.deviceCookie?.key ?? (config.mfa ? deriveDeviceKey(config.mfa.key) : randomBytes(32)),
    secure: config.deviceCookie?.secure,
  });
  // Wrong passwords on a logged-in session (changing the password or factors), per account: a stolen
  // cookie mustn't be a way to guess the password. Escalating, like second-factor codes.
  const reauthFailures = createAttemptLimiter({ max: 10, windowMs: 15 * 60_000, escalate: { maxBlockMs: 24 * 60 * 60_000 } });
  let logError: (error: unknown) => void = (error) => console.error("vault-service: onSecurityEvent failed", error);
  const notify = securityNotifier(config.onSecurityEvent, (error) => logError(error));
  const bootstrapEmail = config.bootstrapEmail?.trim().toLowerCase() || undefined;
  /** Whether a login for an unknown account may create it. `verified`: the email is known to be the person's (OIDC). */
  const signupOpen = async (email: string | undefined, verified: boolean) => {
    if (config.signup !== "closed") return true;
    if ((await db.select({ id: user.id }).from(user).limit(1)).length > 0) return false;
    return bootstrapEmail === undefined || (verified && email?.toLowerCase() === bootstrapEmail);
  };

  // Unknown accounts still get a full password check, against a hash of
  // nothing anyone knows, so the response time doesn't reveal which emails
  // have an account.
  let dummyHash: Promise<string> | undefined;
  const burnPasswordCheck = async (password: string) => {
    dummyHash ??= hashPassword(randomBytes(32).toString("hex"));
    await verifyPasswordHash(await dummyHash, password);
  };

  // Discovery hits the issuer over the network - cached for the process
  // lifetime, same idea as the DEK cache avoiding redoing expensive setup
  // per request.
  let oidcClientPromise: ReturnType<typeof createOidcClient> | undefined;
  function getOidcClient() {
    if (!oidc) throw new Error("oidc config missing");
    if (!oidcClientPromise) {
      oidcClientPromise = createOidcClient(oidc);
    }
    return oidcClientPromise;
  }

  /**
   * Marks the session logged in with a fresh session id. Rotating it means
   * a vault left unlocked under the old id (another login in this browser)
   * can't carry over to the new one.
   */
  function startLogin(session: TypedSession, userId: number): void {
    const oldId = session.get("id");
    if (oldId) sessionCache?.dropSession(oldId);
    session.set("id", randomUUID());
    session.set("authUserId", String(userId));
    // Compared with the user's sessions_valid_after ("log out everywhere").
    session.set("loginAt", String(Date.now()));
  }

  /** A real login: fresh session id, a known-device cookie for password logins, then the app's onLogin. */
  async function completeLogin(request: FastifyRequest, reply: FastifyReply, userId: number, created: boolean, provider: "local" | "oidc", claims?: Record<string, unknown>) {
    const session = typedSession(request);
    unsetSessionKeys(session, MFA_SESSION_KEYS);
    startLogin(session, userId);
    if (provider === "local") devices.issue(request, reply, userId);
    await onLogin?.({ userId, created, provider, ...(claims ? { claims } : {}) });
  }

  const mfa =
    config.mfa && mode === "single"
      ? createMfaRoutes({
          db,
          config: config.mfa,
          completeLogin: (request, reply, userId, created) => completeLogin(request, reply, userId, created, "local"),
          devices,
          reauthFailures,
          notify,
        })
      : undefined;

  /** After a correct password: logged in, or on to the second step when the person has (or must have) one. */
  async function passwordAccepted(request: FastifyRequest, reply: FastifyReply, userId: number, created: boolean) {
    const session = typedSession(request);
    if (mfa) {
      const kinds = mfa.store.primaryKinds(userId);
      if (kinds.length > 0 || (await config.mfa!.required?.(userId))) {
        mfa.begin(session, userId, kinds.length > 0 ? "verify" : "setup", created, (id) => sessionCache?.dropSession(id));
        return kinds.length > 0 ? { status: "mfa_required", factors: kinds } : { status: "mfa_setup_required" };
      }
    }
    await completeLogin(request, reply, userId, created, "local");
    return { status: "logged_in" };
  }

  /** Disabled accounts can't log in. Checked after the credentials, so it doesn't reveal which accounts exist. */
  const isDisabled = async (userId: number) =>
    Boolean((await db.select({ disabledAt: user.disabledAt }).from(user).where(eq(user.id, userId)))[0]?.disabledAt);

  return async function authRoutes(app: FastifyInstance) {
    app.setErrorHandler(routeErrorHandler);
    logError = (error) => app.log.error({ err: error }, "vault-service: onSecurityEvent failed");

    if (mfa) await app.register(mfa.routes, { prefix: "/mfa" });

    app.get("/status", async (request) => {
      if (mode === "none") return { mode, authenticated: true };
      const session = typedSession(request);
      const status = sessionStatus(db, session);
      if (status === "ended") session.delete();
      // Password done, second factor still to come (or to set up).
      const step = status === "anonymous" ? mfa?.pending(session)?.stage : undefined;
      return { mode, authenticated: status === "ok", ...(step ? { mfa: step } : {}) };
    });

    app.post("/login", async (request, reply) => {
      if (mode !== "single") {
        reply.code(404).send({ error: 'auth mode is not "single"' });
        return;
      }

      const { email, password } = loginBodySchema.parse(request.body);
      const accountKey = email.toLowerCase();
      const ipKey = ipBucket(request.ip);
      const pairKey = `${accountKey} ${ipKey}`;
      const [existingUser] = await db.select().from(user).where(eq(user.email, email));
      // A browser this account logged in from before has its own count, untouched by guessing elsewhere.
      const device = existingUser ? devices.read(request, existingUser.id) : undefined;
      const wait = device
        ? perDevice.blockedFor(device)
        : Math.max(perAccountIp.blockedFor(pairKey), perAccount.blockedFor(accountKey), perIp.blockedFor(ipKey));
      if (wait > 0) {
        reply.code(429).header("retry-after", wait).send({ error: "too many failed attempts; try again later" });
        return;
      }
      const failed = () => {
        if (device) perDevice.fail(device);
        else {
          perAccountIp.fail(pairKey);
          perAccount.fail(accountKey);
          perIp.fail(ipKey);
        }
        reply.code(401).send({ error: "wrong email or password" });
      };

      // First login for this email bootstraps it - mirrors routes/vault.ts's
      // "first unlock creates the vault" shape, one level up the stack.
      if (!existingUser) {
        // Same answer and timing as a wrong password, so closed signup doesn't reveal which emails exist.
        if (!(await signupOpen(email, true))) {
          await burnPasswordCheck(password);
          return failed();
        }
        if (password.length < MIN_SECRET_LENGTH) {
          reply.code(400).send({ error: `choose a password of at least ${MIN_SECRET_LENGTH} characters` });
          return;
        }
        const passwordHash = await hashPassword(password);
        const [createdUser] = await db
          .insert(user)
          .values({ displayName: email, email, createdAt: new Date() })
          .returning();
        if (!createdUser) throw new Error("user insert returned no row");

        await db.insert(userIdentity).values({ userId: createdUser.id, provider: "local", passwordHash });

        return passwordAccepted(request, reply, createdUser.id, true);
      }

      const [identity] = await db
        .select()
        .from(userIdentity)
        .where(and(eq(userIdentity.userId, existingUser.id), eq(userIdentity.provider, "local")));

      if (!identity?.passwordHash) {
        await burnPasswordCheck(password);
        return failed();
      }
      if (!(await verifyPasswordHash(identity.passwordHash, password))) return failed();
      // Only this address's (or browser's) count: guessing from elsewhere keeps counting against the account.
      if (device) perDevice.clear(device);
      else perAccountIp.clear(pairKey);

      if (await isDisabled(existingUser.id)) {
        reply.code(403).send({ error: "account disabled" });
        return;
      }
      return passwordAccepted(request, reply, existingUser.id, false);
    });

    /** Changes the caller's own login password (single mode). Not the vault passphrase - that's `PUT /vault/methods/password`. */
    app.post("/password", async (request, reply) => {
      if (mode !== "single") {
        reply.code(404).send({ error: 'auth mode is not "single"' });
        return;
      }
      const session = typedSession(request);
      const authUserId = session.get("authUserId");
      // Outside requireAuth, so the same checks here: a disabled account's or logged-out session's cookie can't.
      if (authUserId === undefined || sessionStatus(db, session) !== "ok") {
        if (authUserId !== undefined) session.delete();
        reply.code(401).send({ error: "login required" });
        return;
      }
      const userId = Number(authUserId);
      const sessionId = session.get("id") ?? "";
      if (config.authorize && !(await config.authorize({ userId, sessionId }, "auth:changePassword"))) {
        reply.code(403).send({ error: "not allowed: auth:changePassword" });
        return;
      }
      const { currentPassword, newPassword } = changePasswordBodySchema.parse(request.body);
      const wait = reauthFailures.blockedFor(String(userId));
      if (wait > 0) {
        reply.code(429).header("retry-after", wait).send({ error: "too many failed attempts; try again later" });
        return;
      }
      const [identity] = await db
        .select()
        .from(userIdentity)
        .where(and(eq(userIdentity.userId, userId), eq(userIdentity.provider, "local")));
      if (!identity?.passwordHash || !(await verifyPasswordHash(identity.passwordHash, currentPassword))) {
        reauthFailures.fail(String(userId));
        reply.code(401).send({ error: "wrong password" });
        return;
      }
      await db.update(userIdentity).set({ passwordHash: await hashPassword(newPassword) }).where(eq(userIdentity.id, identity.id));
      // Whoever else is logged in with the old password is out; this session carries on.
      endOtherSessions(db, session, userId);
      sessionCache?.dropUser(userId, sessionId);
      notify({ userId, kind: "password-changed" });
      return { status: "changed" };
    });

    /** Sends the browser to the IdP. State, nonce and PKCE verifier wait in the encrypted session cookie until the callback. */
    async function redirectToIdp(request: FastifyRequest, reply: FastifyReply) {
      const oidcClient = await getOidcClient();
      const { url, state, nonce, codeVerifier } = await buildAuthorizationRequest(oidcClient, oidc!);
      const session = typedSession(request);
      session.set("oidcState", state);
      session.set("oidcNonce", nonce);
      session.set("oidcCodeVerifier", codeVerifier);
      return reply.redirect(url);
    }

    app.get("/oidc/login", async (request, reply) => {
      if (mode !== "oidc" || !oidc) {
        reply.code(404).send({ error: 'auth mode is not "oidc"' });
        return;
      }
      // A plain login isn't an invite, even if this browser opened one earlier.
      unsetSessionKeys(typedSession(request), ["inviteToken"]);
      return redirectToIdp(request, reply);
    });

    // --- invites ---------------------------------------------------------------

    /** The open invite behind a link, counting misses per address. */
    const openInvite = (request: FastifyRequest, reply: FastifyReply, token: string) => {
      const wait = inviteMisses.blockedFor(ipBucket(request.ip));
      if (wait > 0) {
        reply.code(429).header("retry-after", wait).send({ error: "too many attempts; try again later" });
        return undefined;
      }
      const invite = invites.find(token);
      if (!invite) {
        inviteMisses.fail(ipBucket(request.ip));
        reply.code(404).send({ error: "this invite link has expired or was already used - ask for a new one" });
        return undefined;
      }
      return invite;
    };

    /** What the invite page shows before the person acts. */
    app.get<{ Params: { token: string } }>("/invites/:token", async (request, reply) => {
      const invite = openInvite(request, reply, request.params.token);
      if (!invite) return;
      const row = db.select({ email: user.email, displayName: user.displayName, disabledAt: user.disabledAt }).from(user).where(eq(user.id, invite.userId)).get();
      if (!row || row.disabledAt) return reply.code(404).send({ error: "this invite link has expired or was already used - ask for a new one" });
      return { mode, email: row.email, displayName: row.displayName, expiresAt: invite.expiresAt.toISOString() };
    });

    /** Single mode: the invited person picks their login password, then goes on like any login (two-step setup when required). */
    app.post<{ Params: { token: string } }>("/invites/:token/accept", async (request, reply) => {
      if (mode !== "single") return reply.code(404).send({ error: 'auth mode is not "single"' });
      const { password } = acceptInviteBodySchema.parse(request.body);
      const invite = openInvite(request, reply, request.params.token);
      if (!invite) return;
      if (await isDisabled(invite.userId)) return reply.code(403).send({ error: "account disabled" });
      const passwordHash = await hashPassword(password);
      // Used up first, atomically: two requests racing with the same link can't both set a password.
      if (!invites.accept(invite.id)) return reply.code(404).send({ error: "this invite link has expired or was already used - ask for a new one" });
      const updated = db
        .update(userIdentity)
        .set({ passwordHash })
        .where(and(eq(userIdentity.userId, invite.userId), eq(userIdentity.provider, "local")))
        .returning({ id: userIdentity.id })
        .all();
      if (updated.length === 0) db.insert(userIdentity).values({ userId: invite.userId, provider: "local", passwordHash }).run();
      // A new password (a re-invite works as a reset): any login from before ends.
      db.update(user).set({ sessionsValidAfter: new Date() }).where(eq(user.id, invite.userId)).run();
      sessionCache?.dropUser(invite.userId);
      return passwordAccepted(request, reply, invite.userId, false);
    });

    /** OIDC: remembers the invite and sends the person to the IdP; the callback ties their login to the invited account. */
    app.get<{ Params: { token: string } }>("/invites/:token/start", async (request, reply) => {
      if (mode !== "oidc" || !oidc) return reply.code(404).send({ error: 'auth mode is not "oidc"' });
      const invite = openInvite(request, reply, request.params.token);
      if (!invite) return;
      typedSession(request).set("inviteToken", request.params.token);
      return redirectToIdp(request, reply);
    });

    /**
     * A refused OIDC login. The browser arrives here by navigation, so it goes
     * back to the app with a code the login screen explains
     * (`?login_error=<code>`); API clients get the JSON error. Codes, not
     * messages: anyone can craft that URL, so it must not carry text.
     */
    const refuseOidc = (request: FastifyRequest, reply: FastifyReply, status: number, code: OidcLoginError, error: string) => {
      if (request.headers.accept?.includes("text/html")) {
        const url = new URL(postLoginRedirectUrl);
        url.searchParams.set("login_error", code);
        return reply.redirect(url.toString());
      }
      return reply.code(status).send({ error });
    };

    app.get("/oidc/callback", async (request, reply) => {
      if (mode !== "oidc" || !oidc) {
        reply.code(404).send({ error: 'auth mode is not "oidc"' });
        return;
      }

      const session = typedSession(request);
      const expectedState = session.get("oidcState");
      const expectedNonce = session.get("oidcNonce");
      const codeVerifier = session.get("oidcCodeVerifier");

      if (!expectedState || !expectedNonce || !codeVerifier) {
        return refuseOidc(request, reply, 400, "failed", "no pending oidc login for this session");
      }

      const oidcClient = await getOidcClient();
      const currentUrl = new URL(request.url, new URL(oidc.redirectUrl).origin);

      let claims: Awaited<ReturnType<typeof handleOidcCallback>>;
      try {
        claims = await handleOidcCallback(oidcClient, oidc, { currentUrl, codeVerifier, expectedState, expectedNonce });
      } catch (error) {
        // A stale or tampered callback, or the IdP refusing the code: the person can simply try again.
        request.log.warn({ err: error }, "oidc callback failed");
        return refuseOidc(request, reply, 400, "failed", "login failed; please try again");
      }

      // Before anything else, on every login: the IdP still lets this person in, and (if required) with a second factor.
      if (!claims.isAuthorized) return refuseOidc(request, reply, 403, "not-authorized", "not authorized");
      if (!oidcMfaOk(claims.raw ?? {})) return refuseOidc(request, reply, 403, "mfa-required", "this app needs two-step login - set it up at your identity provider");

      const inviteToken = session.get("inviteToken");
      unsetSessionKeys(session, ["inviteToken"]);
      const invite = inviteToken ? invites.find(inviteToken) : undefined;
      if (inviteToken && !invite) return refuseOidc(request, reply, 404, "invite-invalid", "this invite link has expired or was already used - ask for a new one");

      const [existingIdentity] = await db
        .select()
        .from(userIdentity)
        .where(
          and(
            eq(userIdentity.provider, "oidc"),
            eq(userIdentity.issuer, claims.issuer),
            eq(userIdentity.subject, claims.subject),
          ),
        );

      // user.email is unique, so a match here is unambiguously "the same
      // person" regardless of which provider created that row - switching
      // from a local password to OIDC keeps all data.
      let localUserIdByEmail: number | undefined;
      let emailLinkAllowed = false;
      if (claims.email && !existingIdentity && !invite) {
        const [matchedUser] = await db.select().from(user).where(eq(user.email, claims.email));
        localUserIdByEmail = matchedUser?.id;
        if (localUserIdByEmail !== undefined) {
          // Never onto an account that already has a login at this IdP: that's someone else's.
          const sameIssuer = db
            .select({ id: userIdentity.id })
            .from(userIdentity)
            .where(and(eq(userIdentity.userId, localUserIdByEmail), eq(userIdentity.provider, "oidc"), eq(userIdentity.issuer, claims.issuer)))
            .get();
          emailLinkAllowed = !sameIssuer && (await mayLinkByEmail(localUserIdByEmail));
        }
      }

      const resolution = resolveOidcAccount(claims, {
        identityUserId: existingIdentity?.userId,
        invitedUserId: invite?.userId,
        localUserIdByEmail,
        emailLinkAllowed,
      });

      if (resolution.action === "reject") {
        return refuseOidc(request, reply, 403, resolution.code, resolution.reason);
      }

      let authUserId: number;
      if (resolution.action === "login") {
        authUserId = resolution.userId;
      } else if (resolution.action === "link") {
        // One login per IdP per account: an invited account already tied to another login there can't take a second.
        const taken = db
          .select({ id: userIdentity.id })
          .from(userIdentity)
          .where(and(eq(userIdentity.userId, resolution.userId), eq(userIdentity.provider, "oidc"), eq(userIdentity.issuer, claims.issuer)))
          .get();
        if (taken) return refuseOidc(request, reply, 409, "identity-taken", "this account already has a different login at this identity provider");
        await db.insert(userIdentity).values({
          userId: resolution.userId,
          provider: "oidc",
          issuer: claims.issuer,
          subject: claims.subject,
        });
        authUserId = resolution.userId;
      } else {
        if (!(await signupOpen(claims.email, claims.emailVerified))) {
          return refuseOidc(request, reply, 403, "signup-closed", "signup is closed - ask for an account");
        }
        const email = claims.email ?? `${claims.subject}@${claims.issuer}`;
        const [createdUser] = await db
          .insert(user)
          .values({ displayName: claims.email ?? "New user", email, createdAt: new Date() })
          .returning();
        if (!createdUser) throw new Error("user insert returned no row");

        await db.insert(userIdentity).values({
          userId: createdUser.id,
          provider: "oidc",
          issuer: claims.issuer,
          subject: claims.subject,
        });
        authUserId = createdUser.id;
      }

      if (await isDisabled(authUserId)) {
        return refuseOidc(request, reply, 403, "disabled", "account disabled");
      }
      if (invite && invite.userId === authUserId) invites.accept(invite.id);
      await completeLogin(request, reply, authUserId, resolution.action === "create", "oidc", claims.raw);
      session.set("oidcState", "");
      session.set("oidcNonce", "");
      session.set("oidcCodeVerifier", "");

      reply.redirect(postLoginRedirectUrl);
    });

    // Available in every mode - a no-op convenience in `none` mode (no
    // `authUserId` was ever set there), but also drops the vault's cached
    // DEK session id, so logging out locks the vault too.
    app.post("/logout", async (request) => {
      const session = typedSession(request);
      const sessionId = session.get("id");
      if (sessionId !== undefined) sessionCache?.dropSession(sessionId);
      // Stateless cookies: without this, a copy of this one would still be logged in.
      if (sessionId && session.get("authUserId") !== undefined) revokeSession(db, sessionId);
      session.delete();
      return { status: "logged_out" };
    });
  };
}
