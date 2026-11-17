import { createLegacyScope, createVaultScope, deriveScopeKeys, type LegacyVaultScope, type ScopeKeys, type VaultScope } from "./crypto/scope.js";

/**
 * What an app gets for an unlocked session: who it is, and per-feature
 * scopes to encrypt with. Never the DEK - only this package's own routes
 * (wrapping the DEK for a new passkey or recovery key, the worker routes)
 * reach that, through `sessionCacheInternals`, which isn't exported from
 * the package.
 */
export interface VaultHandle {
  readonly userId: number;
  /** A named scope; see `VaultScope`. Keys are derived once per session and cached. */
  scope<Context extends string = string>(name: string): VaultScope<Context>;
  /** Pre-scope data only (see `LegacyVaultScope`). */
  readonly legacy: LegacyVaultScope;
}

/** @internal */
export interface CachedVaultSession {
  userId: number;
  dek: Buffer;
  expiresAt: number;
  scopeKeys: Map<string, ScopeKeys>;
  legacy?: LegacyVaultScope;
}

/** @internal - raw session access for this package's own routes. */
export interface SessionCacheInternals {
  cacheSession(sessionId: string, userId: number, dek: Buffer): void;
  getSession(sessionId: string): CachedVaultSession | undefined;
}

const SWEEP_INTERVAL_MS = 60_000;

const internalsByCache = new WeakMap<object, SessionCacheInternals>();

/** @internal - deliberately not re-exported from the package index. */
export function sessionCacheInternals(cache: SessionCache): SessionCacheInternals {
  const internals = internalsByCache.get(cache);
  if (!internals) throw new Error("not a session cache created by createSessionCache");
  return internals;
}

function toHandle(session: CachedVaultSession): VaultHandle {
  return {
    userId: session.userId,
    scope<Context extends string = string>(name: string) {
      let keys = session.scopeKeys.get(name);
      if (!keys) {
        keys = deriveScopeKeys(session.dek, name);
        session.scopeKeys.set(name, keys);
      }
      return createVaultScope<Context>(name, keys);
    },
    get legacy() {
      session.legacy ??= createLegacyScope(session.dek);
      return session.legacy;
    },
  };
}

export function createSessionCache(idleTimeoutMs: number) {
  /**
   * One entry per unlocked session - never serialized, logged, or sent to
   * the browser; dropped on idle timeout or process restart. Call this
   * once per running app and share the returned object everywhere a
   * session needs to be read, rather than calling it again expecting a
   * fresh store on top of the same process.
   */
  const sessions = new Map<string, CachedVaultSession>();

  function cacheSession(sessionId: string, userId: number, dek: Buffer): void {
    sessions.set(sessionId, { userId, dek, expiresAt: Date.now() + idleTimeoutMs, scopeKeys: new Map() });
  }

  /** Reading a session resets its idle timeout - an active session shouldn't lock mid-use. */
  function getSession(sessionId: string): CachedVaultSession | undefined {
    const session = sessions.get(sessionId);
    if (!session) return undefined;

    if (session.expiresAt < Date.now()) {
      sessions.delete(sessionId);
      return undefined;
    }

    session.expiresAt = Date.now() + idleTimeoutMs;
    return session;
  }

  const cache = {
    /** The unlocked vault for this session id, or undefined if it's locked or expired. */
    getVault(sessionId: string): VaultHandle | undefined {
      const session = getSession(sessionId);
      return session ? toHandle(session) : undefined;
    },

    isUnlocked(sessionId: string): boolean {
      return getSession(sessionId) !== undefined;
    },

    dropSession(sessionId: string): void {
      sessions.delete(sessionId);
    },

    /** Sweeps expired sessions periodically, independent of whether anyone reads them. */
    startSweep(): NodeJS.Timeout {
      return setInterval(() => {
        const now = Date.now();
        for (const [id, session] of sessions) {
          if (session.expiresAt < now) sessions.delete(id);
        }
      }, SWEEP_INTERVAL_MS);
    },
  };

  internalsByCache.set(cache, { cacheSession, getSession });
  return cache;
}

export type SessionCache = ReturnType<typeof createSessionCache>;
