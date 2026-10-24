export interface VaultSession {
  userId: number;
  dek: Buffer;
  indexKey: Buffer;
  expiresAt: number;
}

const SWEEP_INTERVAL_MS = 60_000;

export function createSessionCache(idleTimeoutMs: number) {
  /**
   * `Map<sessionId, { dek, indexKey, expiresAt }>`, one per
   * `createSessionCache` call - never serialized, logged, or sent to the
   * browser; dropped on logout, idle timeout, or process restart. Call
   * this once per running app and share the returned object everywhere
   * a session needs to be read or written, rather than calling it again
   * expecting a fresh store on top of the same process.
   */
  const sessions = new Map<string, VaultSession>();

  function cacheSession(sessionId: string, userId: number, dek: Buffer, indexKey: Buffer): void {
    sessions.set(sessionId, { userId, dek, indexKey, expiresAt: Date.now() + idleTimeoutMs });
  }

  /** Reading a session resets its idle timeout - an active session shouldn't lock mid-use. */
  function getSession(sessionId: string): VaultSession | undefined {
    const session = sessions.get(sessionId);
    if (!session) return undefined;

    if (session.expiresAt < Date.now()) {
      sessions.delete(sessionId);
      return undefined;
    }

    session.expiresAt = Date.now() + idleTimeoutMs;
    return session;
  }

  function dropSession(sessionId: string): void {
    sessions.delete(sessionId);
  }

  /** Sweeps expired sessions periodically, independent of whether anyone reads them. */
  function startSweep(): NodeJS.Timeout {
    return setInterval(() => {
      const now = Date.now();
      for (const [id, session] of sessions) {
        if (session.expiresAt < now) sessions.delete(id);
      }
    }, SWEEP_INTERVAL_MS);
  }

  return { cacheSession, getSession, dropSession, startSweep };
}

export type SessionCache = ReturnType<typeof createSessionCache>;
