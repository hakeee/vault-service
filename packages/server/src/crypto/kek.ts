import { randomBytes } from "node:crypto";
import { Algorithm, hashRaw } from "@node-rs/argon2";

export interface KdfParams {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  outputLen: number;
}

/**
 * A reasonable starting point, not a universal recommendation - tune for
 * your deployment box so an unlock feels "noticeably a second," not
 * instant and not annoying. `params` is stored alongside the salt in
 * vault_unlock_method.kdf_params so each row stays decodable even if the
 * defaults below change later.
 */
export const DEFAULT_PASSWORD_KDF_PARAMS: KdfParams = {
  memoryCost: 65536, // KiB = 64 MB
  timeCost: 3,
  parallelism: 1,
  outputLen: 32, // 256-bit KEK, matches AES-256
};

export function generateSalt(): Buffer {
  return randomBytes(16);
}

/** Derives a Key Encryption Key from a password via Argon2id. */
export async function derivePasswordKek(
  password: string,
  salt: Buffer,
  params: KdfParams = DEFAULT_PASSWORD_KDF_PARAMS,
): Promise<Buffer> {
  return hashRaw(password, {
    salt,
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    outputLen: params.outputLen,
    algorithm: Algorithm.Argon2id,
  });
}
