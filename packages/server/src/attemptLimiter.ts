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
  fail(key: string): void;
  clear(key: string): void;
}

export interface AttemptLimit {
  /** Failures allowed within the window before the key is blocked. */
  max: number;
  windowMs: number;
}

export function createAttemptLimiter({ max, windowMs }: AttemptLimit, now: () => number = Date.now): AttemptLimiter {
  const buckets = new Map<string, { count: number; resetAt: number }>();
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
      const bucket = live(key);
      if (bucket) bucket.count++;
      else buckets.set(key, { count: 1, resetAt: now() + windowMs });
      // Keep memory bounded under a flood of distinct keys.
      if (buckets.size > 10_000) for (const k of buckets.keys()) if (!live(k)) buckets.delete(k);
    },
    clear(key) {
      buckets.delete(key);
    },
  };
}

/** The shortest password or passphrase accepted when one is set (existing shorter ones keep working). */
export const MIN_SECRET_LENGTH = 8;
