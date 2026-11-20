// Type-only: pulls in `@fastify/secure-session`'s ambient `FastifyRequest.session`
// augmentation so `request.session` typechecks below, without adding a runtime
// dependency on the package - callers register the plugin themselves (this
// package stays agnostic about which session plugin is used, as long as it
// decorates `request.session` with a `get`/`set`/`delete` shape like this one).
import type {} from "@fastify/secure-session";
import { randomUUID } from "node:crypto";

/**
 * `@fastify/secure-session`'s `SessionData` default (`{}`) isn't an
 * exported symbol, so it can't be augmented via declaration merging -
 * this narrow cast is the actual workaround.
 */
export interface TypedSession {
  get(key: string): string | undefined;
  set(key: string, value: string): void;
  /** Clears every key in one call - used by logout to drop both the auth and vault-cache session ids at once. */
  delete(): void;
}

export function typedSession(request: { session: unknown }): TypedSession {
  return request.session as TypedSession;
}

/**
 * The session's id: what the DEK cache, live sockets and background jobs
 * key on. Set at login (and on first status check in `none` mode), so it
 * exists before the vault is unlocked.
 */
export function ensureSessionId(session: TypedSession): string {
  let id = session.get("id");
  if (id === undefined || id === "") {
    id = randomUUID();
    session.set("id", id);
  }
  return id;
}

/** Removes keys from the session (secure-session drops undefined values when it writes the cookie). */
export function unsetSessionKeys(session: TypedSession, keys: readonly string[]): void {
  const loose = session as unknown as { set(key: string, value: undefined): void };
  for (const key of keys) loose.set(key, undefined);
}
