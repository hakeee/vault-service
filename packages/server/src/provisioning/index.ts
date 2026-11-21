/**
 * Creating people at the identity provider too, so an admin's "add user"
 * here is all it takes in OIDC mode: the IdP account exists (with
 * self-registration off there), its subject is stored as this account's
 * identity, and the first login matches it directly.
 */
export interface IdentityProvisioner {
  /** The issuer the IdP's ID tokens carry (`iss`), so the stored identity matches the login. */
  issuer: string;
  /** Creates the person at the IdP and returns their subject (`sub`). */
  createUser(input: { email: string; displayName: string }): Promise<{ subject: string }>;
  /** Asks the IdP to email the person how to set up their sign-in (password, passkey). */
  sendInvite(subject: string): Promise<void>;
  /** Removes the person at the IdP (account erasure). */
  removeUser(subject: string): Promise<void>;
}

export { createZitadelProvisioner, type ZitadelProvisionerConfig } from "./zitadel.js";
