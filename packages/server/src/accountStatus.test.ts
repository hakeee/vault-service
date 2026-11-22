import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { describe, expect, it, vi } from "vitest";
import { endOtherSessions, MAX_SESSION_AGE_MS, revokeSession, sessionStatus } from "./accountStatus.js";
import { migrateVaultService } from "./migrate.js";
import * as schema from "./schema.js";
import type { TypedSession } from "./session.js";

function setup() {
  const db = drizzle(new Database(":memory:"), { schema });
  migrateVaultService(db);
  db.insert(schema.user).values({ displayName: "Me", email: "me@example.com", createdAt: new Date() }).run();
  return db;
}

/** A session as the routes see it, backed by a plain map. */
function fakeSession(values: Record<string, string>): TypedSession {
  const data = new Map(Object.entries(values));
  return { get: (k) => data.get(k), set: (k, v) => void data.set(k, v), delete: () => data.clear() };
}

describe("sessionStatus", () => {
  it("ends a login older than the maximum age, even with a valid cookie", () => {
    const db = setup();
    const loginAt = Date.now();
    const session = fakeSession({ authUserId: "1", id: "s1", loginAt: String(loginAt) });
    expect(sessionStatus(db, session)).toBe("ok");
    vi.spyOn(Date, "now").mockReturnValue(loginAt + MAX_SESSION_AGE_MS + 1);
    try {
      expect(sessionStatus(db, session)).toBe("ended");
    } finally {
      vi.restoreAllMocks();
    }
    expect(sessionStatus(db, fakeSession({ authUserId: "1", id: "s2" }))).toBe("ended");
  });

  it("ends a revoked session (logout), and prunes rows no live session could match", () => {
    const db = setup();
    const session = fakeSession({ authUserId: "1", id: "s1", loginAt: String(Date.now()) });
    revokeSession(db, "s1");
    revokeSession(db, "s1");
    expect(sessionStatus(db, session)).toBe("ended");
    expect(sessionStatus(db, fakeSession({ authUserId: "1", id: "s2", loginAt: String(Date.now()) }))).toBe("ok");

    const later = Date.now() + MAX_SESSION_AGE_MS + 2 * 60 * 60_000;
    vi.spyOn(Date, "now").mockReturnValue(later);
    try {
      revokeSession(db, "s3");
    } finally {
      vi.restoreAllMocks();
    }
    expect(db.select().from(schema.revokedSession).all().map((r) => r.sessionId)).toEqual(["s3"]);
  });

  it("endOtherSessions ends the user's other logins and keeps the caller's", () => {
    const db = setup();
    const loginAt = String(Date.now() - 1000);
    const mine = fakeSession({ authUserId: "1", id: "a", loginAt });
    const other = fakeSession({ authUserId: "1", id: "b", loginAt });
    endOtherSessions(db, mine, 1);
    expect(sessionStatus(db, mine)).toBe("ok");
    expect(sessionStatus(db, other)).toBe("ended");
  });
});
