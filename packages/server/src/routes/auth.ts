import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { and, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
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
import { typedSession } from "../session.js";

const loginBodySchema = z.object({ email: z.email(), password: z.string().min(1) });

export interface AuthRoutesConfig {
  db: BetterSQLite3Database<any>;
  mode: AuthMode;
  oidc?: OidcConfig;
  /** Where to send the browser after a successful OIDC login (your web app's own origin). */
  postLoginRedirectUrl: string;
}

/**
 * `mode`'s login flows. Independent of vault unlock, which lives in
 * routes/vault.ts - see requireAuth.ts for how the two connect (unlock
 * routes sit behind the same `authUserId` session check these routes
 * set).
 */
export function createAuthRoutes(config: AuthRoutesConfig) {
  const { db, mode, oidc, postLoginRedirectUrl } = config;

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

  return async function authRoutes(app: FastifyInstance) {
    app.get("/status", async (request) => {
      const authUserId = typedSession(request).get("authUserId");
      return { mode, authenticated: mode === "none" || authUserId !== undefined };
    });

    app.post("/login", async (request, reply) => {
      if (mode !== "single") {
        reply.code(404).send({ error: 'auth mode is not "single"' });
        return;
      }

      const { email, password } = loginBodySchema.parse(request.body);
      const [existingUser] = await db.select().from(user).where(eq(user.email, email));

      // First login for this email bootstraps it - mirrors routes/vault.ts's
      // "first unlock creates the vault" shape, one level up the stack.
      if (!existingUser) {
        const passwordHash = await hashPassword(password);
        const [createdUser] = await db
          .insert(user)
          .values({ displayName: email, email, createdAt: new Date() })
          .returning();
        if (!createdUser) throw new Error("user insert returned no row");

        await db.insert(userIdentity).values({ userId: createdUser.id, provider: "local", passwordHash });

        typedSession(request).set("authUserId", String(createdUser.id));
        return { status: "logged_in" };
      }

      const [identity] = await db
        .select()
        .from(userIdentity)
        .where(and(eq(userIdentity.userId, existingUser.id), eq(userIdentity.provider, "local")));

      if (!identity?.passwordHash || !(await verifyPasswordHash(identity.passwordHash, password))) {
        reply.code(401).send({ error: "wrong email or password" });
        return;
      }

      typedSession(request).set("authUserId", String(existingUser.id));
      return { status: "logged_in" };
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

      const claims = await handleOidcCallback(oidcClient, oidc, {
        currentUrl,
        codeVerifier,
        expectedState,
        expectedNonce,
      });

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

      session.set("authUserId", String(authUserId));
      session.set("oidcState", "");
      session.set("oidcNonce", "");
      session.set("oidcCodeVerifier", "");

      reply.redirect(postLoginRedirectUrl);
    });

    // Available in every mode - a no-op convenience in `none` mode (no
    // `authUserId` was ever set there), but also drops the vault's cached
    // DEK session id, so logging out locks the vault too.
    app.post("/logout", async (request) => {
      typedSession(request).delete();
      return { status: "logged_out" };
    });
  };
}
