import { hash, verify } from "@node-rs/argon2";

/**
 * Login password hashing - a different call shape from ../crypto/kek.ts
 * on purpose. kek.ts derives a *key* from a password (hashRaw, caller
 * manages salt/params alongside the ciphertext it unlocks). Logging in
 * only needs a yes/no answer, so the self-describing string form (salt +
 * params embedded in the hash itself) is the simpler fit - no shared
 * storage row to manage.
 */
export async function hashPassword(password: string): Promise<string> {
  return hash(password);
}

export async function verifyPasswordHash(passwordHash: string, password: string): Promise<boolean> {
  return verify(passwordHash, password);
}
