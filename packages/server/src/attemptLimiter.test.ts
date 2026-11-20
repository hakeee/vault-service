import { describe, expect, it } from "vitest";
import { createAttemptLimiter } from "./attemptLimiter.js";

describe("attempt limiter", () => {
  it("blocks a key after too many failures, until the window passes", () => {
    let t = 0;
    const limiter = createAttemptLimiter({ max: 3, windowMs: 60_000 }, () => t);
    for (let i = 0; i < 3; i++) {
      expect(limiter.blockedFor("a")).toBe(0);
      limiter.fail("a");
    }
    expect(limiter.blockedFor("a")).toBe(60);
    expect(limiter.blockedFor("b")).toBe(0);
    t = 60_000;
    expect(limiter.blockedFor("a")).toBe(0);
  });

  it("forgets a key on success", () => {
    const limiter = createAttemptLimiter({ max: 2, windowMs: 60_000 });
    limiter.fail("a");
    limiter.fail("a");
    expect(limiter.blockedFor("a")).toBeGreaterThan(0);
    limiter.clear("a");
    expect(limiter.blockedFor("a")).toBe(0);
  });
});
