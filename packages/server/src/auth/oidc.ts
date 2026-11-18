import * as client from "openid-client";
import type { OidcClaims } from "./accountResolution.js";

export interface OidcConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUrl: string;
  /**
   * Decides whether a verified login is allowed to create or link an
   * account here, given the raw ID-token claims. Defaults to always-true
   * (any verified login is allowed). Pass your own predicate to gate on
   * whatever your IdP encodes - e.g. a Zitadel project grant materializes
   * as a claim named `urn:zitadel:iam:org:project:<id>:roles`; other IdPs
   * use their own shapes entirely, which is why this isn't baked in here.
   */
  isAuthorizedClaims?: (claims: Record<string, unknown>) => boolean;
}

export interface OidcAuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface OidcCallbackParams {
  /** The full callback request URL (path + query), as seen by the server. */
  currentUrl: URL;
  codeVerifier: string;
  expectedState: string;
  expectedNonce: string;
}

/** Discovery hits the issuer over the network - callers should call this once and reuse the result. */
export async function createOidcClient(config: OidcConfig): Promise<client.Configuration> {
  return client.discovery(new URL(config.issuerUrl), config.clientId, config.clientSecret);
}

export async function buildAuthorizationRequest(
  oidcClient: client.Configuration,
  config: OidcConfig,
): Promise<OidcAuthorizationRequest> {
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  const state = client.randomState();
  const nonce = client.randomNonce();

  const url = client.buildAuthorizationUrl(oidcClient, {
    redirect_uri: config.redirectUrl,
    scope: "openid email",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
    nonce,
  });

  return { url: url.toString(), state, nonce, codeVerifier };
}

/**
 * Exchanges the callback's `code` for tokens and extracts the claims
 * needed by accountResolution.ts. `isAuthorized` is computed by the
 * caller-supplied `isAuthorizedClaims` predicate (default: always true) -
 * this function itself has no opinion on what "authorized" means for any
 * particular identity provider.
 */
export async function handleOidcCallback(
  oidcClient: client.Configuration,
  config: OidcConfig,
  params: OidcCallbackParams,
): Promise<OidcClaims> {
  const tokens = await client.authorizationCodeGrant(oidcClient, params.currentUrl, {
    pkceCodeVerifier: params.codeVerifier,
    expectedState: params.expectedState,
    expectedNonce: params.expectedNonce,
  });

  const claims = tokens.claims();
  if (!claims) {
    throw new Error("oidc callback: no id token claims");
  }

  const isAuthorizedClaims = config.isAuthorizedClaims ?? (() => true);

  return {
    issuer: String(claims.iss),
    subject: String(claims.sub),
    email: typeof claims.email === "string" ? claims.email : undefined,
    emailVerified: claims.email_verified === true,
    isAuthorized: isAuthorizedClaims(claims as Record<string, unknown>),
    raw: { ...(claims as Record<string, unknown>) },
  };
}
