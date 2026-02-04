import { normalizeToolName, type Decision } from "@mindaiproject/firewall-core";

export type RateLimitScope = "session" | "global";

export type RateLimitRule = {
  toolName: string;
  maxCalls: number;
  windowSec: number;
  action?: Decision;
  scope?: RateLimitScope;
};

export type RateLimitHit = {
  rule: NormalizedRateLimitRule;
  count: number;
  key: string;
};

export type RateLimiter = {
  evaluate: (toolName: string, sessionKey?: string) => RateLimitHit | null;
};

type NormalizedRateLimitRule = {
  id: string;
  toolName: string;
  matchAll: boolean;
  maxCalls: number;
  windowMs: number;
  action: Decision;
  scope: RateLimitScope;
};

// Normalize and validate rate limit rules from plugin config.
export function normalizeRateLimitRules(raw: unknown): NormalizedRateLimitRule[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const rules: NormalizedRateLimitRule[] = [];
  raw.forEach((entry, index) => {
    if (!entry || typeof entry !== "object") {
      return;
    }
    const record = entry as Record<string, unknown>;
    const toolNameRaw = typeof record.toolName === "string" ? record.toolName.trim() : "";
    if (!toolNameRaw) {
      return;
    }
    const normalizedToolName = normalizeToolName(toolNameRaw);
    const matchAll = normalizedToolName === "*" || normalizedToolName === "all";
    const maxCalls = Number(record.maxCalls);
    const windowSec = Number(record.windowSec);
    if (!Number.isFinite(maxCalls) || maxCalls <= 0) {
      return;
    }
    if (!Number.isFinite(windowSec) || windowSec <= 0) {
      return;
    }
    const actionRaw = typeof record.action === "string" ? record.action.trim().toUpperCase() : "";
    const action = actionRaw === "DENY" ? "DENY" : "ASK";
    const scope = record.scope === "global" ? "global" : "session";
    rules.push({
      id: `${matchAll ? "*" : normalizedToolName}:${index}`,
      toolName: normalizedToolName,
      matchAll,
      maxCalls,
      windowMs: Math.floor(windowSec * 1000),
      action,
      scope
    });
  });
  return rules;
}

// Create an in-memory rate limiter for tool calls.
export function createRateLimiter(rules: NormalizedRateLimitRule[]): RateLimiter {
  const buckets = new Map<string, number[]>();

  const evaluate = (toolName: string, sessionKey?: string): RateLimitHit | null => {
    if (rules.length === 0) {
      return null;
    }
    const normalizedTool = normalizeToolName(toolName);
    const now = Date.now();
    let hit: RateLimitHit | null = null;

    for (const rule of rules) {
      if (!rule.matchAll && rule.toolName !== normalizedTool) {
        continue;
      }
      const scopeKey = rule.scope === "session" ? sessionKey ?? "no-session" : "global";
      const bucketKey = `${rule.id}:${scopeKey}`;
      const timestamps = buckets.get(bucketKey) ?? [];
      const cutoff = now - rule.windowMs;
      while (timestamps.length > 0) {
        const first = timestamps[0];
        if (first == null || first >= cutoff) {
          break;
        }
        timestamps.shift();
      }
      const count = timestamps.length;
      timestamps.push(now);
      buckets.set(bucketKey, timestamps);

      if (count >= rule.maxCalls) {
        const candidate: RateLimitHit = { rule, count, key: bucketKey };
        hit = pickMoreRestrictive(hit, candidate);
      }
    }

    return hit;
  };

  return { evaluate };
}

function pickMoreRestrictive(current: RateLimitHit | null, next: RateLimitHit): RateLimitHit {
  if (!current) {
    return next;
  }
  const rank = (decision: Decision) => (decision === "DENY" ? 2 : decision === "ASK" ? 1 : 0);
  if (rank(next.rule.action) > rank(current.rule.action)) {
    return next;
  }
  return current;
}
