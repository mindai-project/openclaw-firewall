import type {
  Decision,
  FirewallDecision,
  NormalizedToolRule,
  Policy,
  Risk,
  ToolCall,
  ToolRule
} from "./types.js";

const DEFAULT_REDACT_PARAMS = true;
const DEFAULT_REDACT_RESULT = true;
const DEFAULT_SCAN_INJECTION = true;

// Normalize tool names for consistent policy lookups.
export function normalizeToolName(name: string): string {
  return String(name || "tool").trim().toLowerCase();
}

// Build a normalized rule from an input tool rule and policy defaults.
export function normalizeToolRule(policy: Policy, rule: ToolRule): NormalizedToolRule {
  const risk = rule.risk ?? "unknown";
  const action = resolveDecision(policy, rule, risk);
  const allowPaths = Array.isArray(rule.allowPaths)
    ? rule.allowPaths.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
    : undefined;
  const normalized: NormalizedToolRule = {
    name: normalizeToolName(rule.name),
    risk,
    action,
    redactParams: rule.redactParams ?? DEFAULT_REDACT_PARAMS,
    redactResult: rule.redactResult ?? DEFAULT_REDACT_RESULT,
    scanInjection: rule.scanInjection ?? DEFAULT_SCAN_INJECTION,
    useExecApprovals: rule.useExecApprovals ?? false
  };
  if (allowPaths && allowPaths.length > 0) {
    normalized.allowPaths = allowPaths;
  }
  if (rule.pathAction) {
    normalized.pathAction = rule.pathAction;
  }
  return normalized;
}

// Index tools for quick evaluation.
export function buildPolicyIndex(policy: Policy): Map<string, NormalizedToolRule> {
  const map = new Map<string, NormalizedToolRule>();
  for (const rule of policy.tools) {
    const normalized = normalizeToolRule(policy, rule);
    map.set(normalized.name, normalized);
  }
  return map;
}

// Main policy evaluation entry point.
export function evaluatePolicy(
  policy: Policy,
  toolCall: ToolCall,
  toolIndex: Map<string, NormalizedToolRule> = buildPolicyIndex(policy)
): FirewallDecision {
  const normalizedToolName = normalizeToolName(toolCall.toolName);
  const rule = toolIndex.get(normalizedToolName);

  const risk: Risk = rule?.risk ?? "unknown";
  let decision: Decision;
  if (rule) {
    decision = rule.action;
  } else if (policy.defaults.denyUnknownTools) {
    decision = policy.defaults.unknownToolAction;
  } else {
    decision = policy.risk[risk] ?? policy.defaults.unknownToolAction;
  }

  const redactionPlan = {
    redactParams: rule?.redactParams ?? DEFAULT_REDACT_PARAMS,
    redactResult: rule?.redactResult ?? DEFAULT_REDACT_RESULT
  };

  const scanInjection = rule?.scanInjection ?? DEFAULT_SCAN_INJECTION;
  const useExecApprovals = rule?.useExecApprovals ?? false;

  const result: FirewallDecision = {
    decision,
    reason: buildReason(policy, normalizedToolName, decision, rule, risk),
    risk,
    redactionPlan,
    scanInjection,
    useExecApprovals
  };
  if (rule) {
    result.toolRule = rule;
  }
  return result;
}

function resolveDecision(policy: Policy, rule: ToolRule, risk: Risk): Decision {
  if (rule.action) {
    return rule.action;
  }
  if (typeof rule.allow !== "undefined") {
    if (rule.allow === true) {
      return "ALLOW";
    }
    if (rule.allow === false || rule.allow === "deny") {
      return "DENY";
    }
    if (rule.allow === "ask") {
      return "ASK";
    }
  }
  return policy.risk[risk] ?? policy.defaults.unknownToolAction;
}

function buildReason(
  policy: Policy,
  toolName: string,
  decision: Decision,
  rule: NormalizedToolRule | undefined,
  risk: Risk
): string {
  if (!rule) {
    if (policy.defaults.denyUnknownTools) {
      if (decision === "DENY") {
        return `Unknown tool \"${toolName}\" denied by default policy.`;
      }
      return `Unknown tool \"${toolName}\" resolved to ${decision} by default policy.`;
    }
    return `Unknown tool \"${toolName}\" evaluated by default policy.`;
  }
  return `Tool \"${toolName}\" (${risk}) resolved to ${decision}.`;
}
