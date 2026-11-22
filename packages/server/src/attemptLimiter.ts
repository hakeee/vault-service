import { isIPv6 } from "node:net";

/**
 * Counts failed attempts (logins, unlocks) per key in memory and blocks a
 * key that fails too often within a window, so passwords can't be guessed
 * at full speed. Only failures count; a success clears the key. In-memory
 * on purpose: a restart forgets the counts, which is fine for slowing
 * guessing down, and it needs no table.
 */
export interface AttemptLimiter {
  /** Seconds until `key` may try again, or 0 if it may try now. */
  blockedFor(key: string): number;
  /** Counts a failure. True when this one started a block (e.g. to warn the person). */
  fail(key: string): boolean;
  clear(key: string): void;
}

export interface AttemptLimit {
  /** Failures allowed within the window before the key is blocked. */
  max: number;
  windowMs: number;
  /**
   * Each block after the first lasts twice as long as the one before (up to
   * `maxBlockMs`), until a day passes without one. For short codes (TOTP),
   * where a fixed window still adds up to a real chance over months.
   */
  escalate?: { maxBlockMs: number };
}

/** How long a key's earlier blocks still make the next one longer. */
const STRIKE_MEMORY_MS = 24 * 60 * 60_000;

export function createAttemptLimiter({ max, windowMs, escalate }: AttemptLimit, now: () => number = () => Date.now()): AttemptLimiter {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  /** Escalation: blocks so far, remembered until `until`. */
  const strikes = new Map<string, { n: number; until: number }>();
  const live = (key: string) => {
    const bucket = buckets.get(key);
    if (bucket && bucket.resetAt <= now()) {
      buckets.delete(key);
      return undefined;
    }
    return bucket;
  };
  return {
    blockedFor(key) {
      const bucket = live(key);
      return bucket && bucket.count >= max ? Math.ceil((bucket.resetAt - now()) / 1000) : 0;
    },
    fail(key) {
      let bucket = live(key);
      if (bucket) bucket.count++;
      else buckets.set(key, (bucket = { count: 1, resetAt: now() + windowMs }));
      const blocked = bucket.count === max;
      if (blocked && escalate) {
        const earlier = strikes.get(key);
        const n = earlier && earlier.until > now() ? earlier.n + 1 : 1;
        bucket.resetAt = now() + Math.min(windowMs * 2 ** (n - 1), escalate.maxBlockMs);
        strikes.set(key, { n, until: bucket.resetAt + STRIKE_MEMORY_MS });
      }
      // Keep memory bounded under a flood of distinct keys.
      if (buckets.size > 10_000) for (const k of buckets.keys()) if (!live(k)) buckets.delete(k);
      if (strikes.size > 10_000) for (const [k, s] of strikes) if (s.until <= now()) strikes.delete(k);
      return blocked;
    },
    clear(key) {
      buckets.delete(key);
      strikes.delete(key);
    },
  };
}

/**
 * The key for per-address limits. IPv6 clients usually get a whole /64, so
 * counting single addresses would let one machine pose as billions of
 * clients: they're counted by their /64 instead. IPv4 (also as
 * `::ffff:1.2.3.4`) stays one address.
 */
export function ipBucket(ip: string): string {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return mapped[1]!;
  const address = ip.split("%")[0]!;
  if (!isIPv6(address)) return ip;
  const [head = "", tail] = address.split("::");
  const left = head ? head.split(":") : [];
  // An embedded IPv4 tail (::1.2.3.4) counts as two groups; only the first four groups matter here anyway.
  const right = tail ? tail.split(":").flatMap((g) => (g.includes(".") ? ["0", "0"] : [g])) : [];
  const groups = tail === undefined ? left : [...left, ...Array<string>(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right];
  return `${groups
    .slice(0, 4)
    .map((g) => (parseInt(g, 16) || 0).toString(16))
    .join(":")}::/64`;
}

/** The shortest password or passphrase accepted when one is set (existing shorter ones keep working). */
export const MIN_SECRET_LENGTH = 8;
