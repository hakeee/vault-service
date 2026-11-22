import { describe, expect, it } from "vitest";
import { createAttemptLimiter, ipBucket } from "./attemptLimiter.js";

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

  it("says when a failure starts a block", () => {
    const limiter = createAttemptLimiter({ max: 2, windowMs: 60_000 });
    expect(limiter.fail("a")).toBe(false);
    expect(limiter.fail("a")).toBe(true);
    expect(limiter.fail("a")).toBe(false);
  });

  it("escalating: each block lasts twice as long, up to the cap, and a quiet day resets it", () => {
    let t = 0;
    const limiter = createAttemptLimiter({ max: 2, windowMs: 60_000, escalate: { maxBlockMs: 240_000 } }, () => t);
    const block = () => {
      limiter.fail("a");
      limiter.fail("a");
      const seconds = limiter.blockedFor("a");
      t += seconds * 1000;
      return seconds;
    };
    expect([block(), block(), block(), block()]).toEqual([60, 120, 240, 240]);
    t += 25 * 60 * 60_000;
    expect(block()).toBe(60);
    limiter.clear("a");
    expect(block()).toBe(60);
  });
});

describe("ipBucket", () => {
  it("keeps IPv4 addresses (plain or mapped) and counts IPv6 by /64", () => {
    expect(ipBucket("203.0.113.7")).toBe("203.0.113.7");
    expect(ipBucket("::ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(ipBucket("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("2001:db8:1:2::1")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("2001:0db8:0001:0002:ffff::9")).toBe("2001:db8:1:2::/64");
    expect(ipBucket("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(ipBucket("::1")).toBe("0:0:0:0::/64");
    expect(ipBucket("fe80::1%eth0")).toBe("fe80:0:0:0::/64");
    expect(ipBucket("not an ip")).toBe("not an ip");
  });
});
