import { describe, expect, it } from "vitest";
import { createRateLimiter, normalizeRateLimitRules } from "../../packages/openclaw/src/rate-limit.js";

describe("rate limiter", () => {
  it("enforces max calls per window", () => {
    const rules = normalizeRateLimitRules([
      { toolName: "write", maxCalls: 1, windowSec: 60, action: "ASK", scope: "session" }
    ]);
    const limiter = createRateLimiter(rules);

    const first = limiter.evaluate("write", "session-1");
    const second = limiter.evaluate("write", "session-1");

    expect(first).toBeNull();
    expect(second).not.toBeNull();
    expect(second?.rule.action).toBe("ASK");
  });

  it("separates session scopes", () => {
    const rules = normalizeRateLimitRules([
      { toolName: "web_fetch", maxCalls: 1, windowSec: 60, action: "DENY", scope: "session" }
    ]);
    const limiter = createRateLimiter(rules);

    expect(limiter.evaluate("web_fetch", "a")).toBeNull();
    expect(limiter.evaluate("web_fetch", "b")).toBeNull();
    expect(limiter.evaluate("web_fetch", "a")).not.toBeNull();
  });
});
