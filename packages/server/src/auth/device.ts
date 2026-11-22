import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";

/**
 * Known devices: after a full login, the browser gets a long-lived signed
 * cookie naming the account. A login that brings one for the account it's
 * logging into is counted on its own (OWASP's "device cookies"), so
 * someone guessing from elsewhere can lock the account out for strangers
 * but not for the owner's own browsers. It proves nothing by itself: the
 * password (and second factor) are still needed.
 *
 * Needs `@fastify/cookie`, which `@fastify/secure-session` registers.
 */
export const DEVICE_COOKIE = "known_device";
const MAX_AGE_MS = 180 * 24 * 60 * 60_000;

export interface DeviceCookieOptions {
  /** HMAC key for the cookie. */
  key: Buffer;
  /** Send the cookie over HTTPS only. Default: when the request came over HTTPS. */
  secure?: boolean;
}

/** A key for device cookies derived from another server secret (e.g. the MFA key), so no new setting is needed. */
export function deriveDeviceKey(secret: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), "vault-service known device cookie", 32));
}

type CookieRequest = FastifyRequest & { cookies?: Record<string, string | undefined> };
type CookieReply = FastifyReply & { setCookie?: (name: string, value: string, options: Record<string, unknown>) => unknown };

export function createDeviceCookies(options: DeviceCookieOptions) {
  const mac = (payload: string) => createHmac("sha256", options.key).update(payload).digest("base64url");

  return {
    /** Marks this browser as a known device of the account (after a full login). */
    issue(request: FastifyRequest, reply: FastifyReply, userId: number): void {
      const setCookie = (reply as CookieReply).setCookie;
      if (!setCookie) return;
      const payload = `${userId}.${Date.now()}.${randomBytes(16).toString("base64url")}`;
      setCookie.call(reply, DEVICE_COOKIE, `${payload}.${mac(payload)}`, {
        path: "/",
        httpOnly: true,
        sameSite: "strict",
        secure: options.secure ?? request.protocol === "https",
        maxAge: MAX_AGE_MS / 1000,
      });
    },

    /** This browser's device id, if it brings a valid cookie for `userId`. */
    read(request: FastifyRequest, userId: number): string | undefined {
      const value = (request as CookieRequest).cookies?.[DEVICE_COOKIE];
      if (!value) return undefined;
      const parts = value.split(".");
      if (parts.length !== 4) return undefined;
      const [user, issuedAt, id, signature] = parts as [string, string, string, string];
      const expected = Buffer.from(mac(`${user}.${issuedAt}.${id}`));
      const given = Buffer.from(signature);
      if (given.length !== expected.length || !timingSafeEqual(given, expected)) return undefined;
      if (Number(user) !== userId || !(Date.now() - Number(issuedAt) < MAX_AGE_MS)) return undefined;
      return id;
    },
  };
}

export type DeviceCookies = ReturnType<typeof createDeviceCookies>;
