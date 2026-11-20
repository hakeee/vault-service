import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createAttemptLimiter, MIN_SECRET_LENGTH, type AttemptLimit } from "../attemptLimiter.js";
import {
  buildAuthorizationRequest,
  createOidcClient,
  handleOidcCallback,
  type OidcConfig,
} from "../auth/oidc.js";
import { hashPassword, verifyPasswordHash } from "../auth/password.js";
import { resolveOidcAccount } from "../auth/accountResolution.js";
import type { AuthMode } from "../auth/mode.js";
import { user, userIdentity } from "../schema.js";
import { typedSession, type TypedSession } from "../session.js";
import { randomBytes, randomUUID } from "node:crypto";
import type { SessionCache } from "../sessionCache.js";
import { sessionStatus, type SelfServiceAuthorizer } from "../accountStatus.js";
import { routeErrorHandler } from "./errors.js";

const loginBodySchema = z.object({ email: z.email(), password: z.string().min(1) });
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
   * Behind a proxy, set Fastify's `trustProxy` so the IP is the client's.
   */
  loginLimits?: { perAccountIp?: number; perAccount?: number; perIp?: number; windowMs?: number };
}

/**
 * `mode`'s login flows. Independent of vault unlock, which lives in
 * routes/vault.ts - see requireAuth.ts for how the two connect (unlock
 * routes sit behind the same `authUserId` session check these routes
 * set).
 */
export function createAuthRoutes(config: AuthRoutesConfig) {
  const { db, mode, oidc, postLoginRedirectUrl, sessionCache, onLogin } = config;
  const windowMs = config.loginLimits?.windowMs ?? 15 * 60_000;
  const perAccountIp = createAttemptLimiter({ max: config.loginLimits?.perAccountIp ?? 10, windowMs } satisfies AttemptLimit);
  const perAccount = createAttemptLimiter({ max: config.loginLimits?.perAccount ?? 100, windowMs });
  const perIp = createAttemptLimiter({ max: config.loginLimits?.perIp ?? 50, windowMs });
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

  /** Disabled accounts can't log in. Checked after the credentials, so it doesn't reveal which accounts exist. */
  const isDisabled = async (userId: number) =>
    Boolean((await db.select({ disabledAt: user.disabledAt }).from(user).where(eq(user.id, userId)))[0]?.disabledAt);

  return async function authRoutes(app: FastifyInstance) {
    app.setErrorHandler(routeErrorHandler);

    app.get("/status", async (request) => {
      if (mode === "none") return { mode, authenticated: true };
      const session = typedSession(request);
      const status = sessionStatus(db, session);
      if (status === "ended") session.delete();
      return { mode, authenticated: status === "ok" };
    });

    app.post("/login", async (request, reply) => {
      if (mode !== "single") {
        reply.code(404).send({ error: 'auth mode is not "single"' });
        return;
      }

      const { email, password } = loginBodySchema.parse(request.body);
      const accountKey = email.toLowerCase();
      const pairKey = `${accountKey} ${request.ip}`;
      const wait = Math.max(perAccountIp.blockedFor(pairKey), perAccount.blockedFor(accountKey), perIp.blockedFor(request.ip));
      if (wait > 0) {
        reply.code(429).header("retry-after", wait).send({ error: "too many failed attempts; try again later" });
        return;
      }
      const failed = () => {
        perAccountIp.fail(pairKey);
        perAccount.fail(accountKey);
        perIp.fail(request.ip);
        reply.code(401).send({ error: "wrong email or password" });
      };
      const [existingUser] = await db.select().from(user).where(eq(user.email, email));

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

        startLogin(typedSession(request), createdUser.id);
        await onLogin?.({ userId: createdUser.id, created: true, provider: "local" });
        return { status: "logged_in" };
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
      // Only this address's count: guessing from elsewhere keeps counting against the account.
      perAccountIp.clear(pairKey);

      if (await isDisabled(existingUser.id)) {
        reply.code(403).send({ error: "account disabled" });
        return;
      }
      startLogin(typedSession(request), existingUser.id);
      await onLogin?.({ userId: existingUser.id, created: false, provider: "local" });
      return { status: "logged_in" };
    });

    /** Changes the caller's own login password (single mode). Not the vault passphrase - that's `PUT /vault/methods/password`. */
    app.post("/password", async (request, reply) => {
      if (mode !== "single") {
        reply.code(404).send({ error: 'auth mode is not "single"' });
        return;
      }
      const authUserId = typedSession(request).get("authUserId");
      if (authUserId === undefined) {
        reply.code(401).send({ error: "login required" });
        return;
      }
      const sessionId = typedSession(request).get("id") ?? "";
      if (config.authorize && !(await config.authorize({ userId: Number(authUserId), sessionId }, "auth:changePassword"))) {
        reply.code(403).send({ error: "not allowed: auth:changePassword" });
        return;
      }
      const { currentPassword, newPassword } = changePasswordBodySchema.parse(request.body);
      const [identity] = await db
        .select()
        .from(userIdentity)
        .where(and(eq(userIdentity.userId, Number(authUserId)), eq(userIdentity.provider, "local")));
      if (!identity?.passwordHash || !(await verifyPasswordHash(identity.passwordHash, currentPassword))) {
        reply.code(401).send({ error: "wrong password" });
        return;
      }
      await db.update(userIdentity).set({ passwordHash: await hashPassword(newPassword) }).where(eq(userIdentity.id, identity.id));
      return { status: "changed" };
    });

    app.get("/oidc/login", async (request, reply) => {
      if (mode !== "oidc" || !oidc) {
        reply.code(404).send({ error: 'auth mode is not "oidc"' });
        return;
      }

      const oidcClient = await getOidcClient();
      const { url, state, nonce, codeVerifier } = await buildAuthorizationRequest(oidcClient, oidc);

      // Stashed in the same secure-session cookie already used for vault
      // unlock - no separate storage needed for a value that only needs to
      // survive until the callback a few seconds later.
      const session = typedSession(request);
      session.set("oidcState", state);
      session.set("oidcNonce", nonce);
      session.set("oidcCodeVerifier", codeVerifier);

      reply.redirect(url);
    });

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
        reply.code(400).send({ error: "no pending oidc login for this session" });
        return;
      }

      const oidcClient = await getOidcClient();
      const currentUrl = new URL(request.url, new URL(oidc.redirectUrl).origin);

      let claims: Awaited<ReturnType<typeof handleOidcCallback>>;
      try {
        claims = await handleOidcCallback(oidcClient, oidc, { currentUrl, codeVerifier, expectedState, expectedNonce });
      } catch (error) {
        // A stale or tampered callback, or the IdP refusing the code: the person can simply try again.
        request.log.warn({ err: error }, "oidc callback failed");
        reply.code(400).send({ error: "login failed; please try again" });
        return;
      }

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
      if (claims.email) {
        const [matchedUser] = await db.select().from(user).where(eq(user.email, claims.email));
        localUserIdByEmail = matchedUser?.id;
      }

      const resolution = resolveOidcAccount(claims, {
        identityUserId: existingIdentity?.userId,
        localUserIdByEmail,
      });

      if (resolution.action === "reject") {
        reply.code(403).send({ error: resolution.reason });
        return;
      }

      let authUserId: number;
      if (resolution.action === "login") {
        authUserId = resolution.userId;
      } else if (resolution.action === "link") {
        await db.insert(userIdentity).values({
          userId: resolution.userId,
          provider: "oidc",
          issuer: claims.issuer,
          subject: claims.subject,
        });
        authUserId = resolution.userId;
      } else {
        if (!(await signupOpen(claims.email, claims.emailVerified))) {
          reply.code(403).send({ error: "signup is closed - ask for an account" });
          return;
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
        reply.code(403).send({ error: "account disabled" });
        return;
      }
      startLogin(session, authUserId);
      await onLogin?.({ userId: authUserId, created: resolution.action === "create", provider: "oidc", claims: claims.raw });
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
      session.delete();
      return { status: "logged_out" };
    });
  };
}
