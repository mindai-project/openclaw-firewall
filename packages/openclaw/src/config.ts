import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { parse as parseYaml } from "yaml";
import type { Decision, InjectionMode, LogLevel, Policy, RedactionMode, ToolRule } from "@mindaiproject/firewall-core";
import { normalizeToolName } from "@mindaiproject/firewall-core";

export type PresetName = "strict" | "standard" | "dev";

export type LoadedPolicy = {
  policy: Policy;
  warnings: string[];
  source: string;
};

const DEFAULT_POLICY_PATH = path.join(os.homedir(), ".openclaw", "firewall", "firewall.yaml");

// OpenClaw tool baseline mapping from docs/plan.md.
const BASELINE_TOOL_RULES: ToolRule[] = [
  { name: "read", risk: "read" },
  { name: "write", risk: "write" },
  { name: "edit", risk: "write" },
  { name: "apply_patch", risk: "write" },
  { name: "exec", risk: "critical", useExecApprovals: true },
  { name: "process", risk: "critical" },
  { name: "agents_list", risk: "read" },
  { name: "browser", risk: "write" },
  { name: "canvas", risk: "read" },
  { name: "cron", risk: "write" },
  { name: "gateway", risk: "critical" },
  { name: "image", risk: "read" },
  { name: "message", risk: "write" },
  { name: "nodes", risk: "critical" },
  { name: "session_status", risk: "read" },
  { name: "sessions_history", risk: "read" },
  { name: "sessions_list", risk: "read" },
  { name: "sessions_send", risk: "write" },
  { name: "sessions_spawn", risk: "critical" },
  { name: "tts", risk: "read" },
  { name: "web_fetch", risk: "read" },
  { name: "web_search", risk: "read" },
  { name: "memory_search", risk: "read" },
  { name: "memory_get", risk: "read" }
];

const DEFAULT_POLICY: Policy = {
  mode: "standard",
  defaults: {
    denyUnknownTools: true,
    unknownToolAction: "DENY",
    log: "safe",
    redaction: "standard",
    injection: { mode: "alert" }
  },
  risk: {
    read: "ALLOW",
    write: "ASK",
    critical: "DENY",
    unknown: "DENY"
  },
  tools: []
};

// Resolve the default policy path on the local machine.
export function getDefaultPolicyPath(): string {
  return DEFAULT_POLICY_PATH;
}

// Load policy from preset + optional override path.
export function loadPolicyConfig(params: {
  preset?: PresetName;
  policyPath?: string;
}): LoadedPolicy {
  const warnings: string[] = [];
  const presetName = params.preset ?? "standard";
  const presetPolicy = loadPresetPolicy(presetName, warnings);

  const policyPath = params.policyPath ?? DEFAULT_POLICY_PATH;
  const overridePolicy = loadPolicyFile(policyPath, warnings);

  const merged = mergePolicies(presetPolicy, overridePolicy ?? {});
  const normalized = normalizePolicy(merged, warnings);

  return {
    policy: normalized,
    warnings,
    source: overridePolicy ? policyPath : `preset:${presetName}`
  };
}

// Load a preset policy without merging any on-disk policy file.
export function loadPresetPolicyOnly(name: PresetName): Policy {
  const warnings: string[] = [];
  const presetPolicy = loadPresetPolicy(name, warnings);
  return normalizePolicy(presetPolicy, warnings);
}

function loadPresetPolicy(name: PresetName, warnings: string[]): Policy {
  const presetPath = new URL(`../presets/${name}.yaml`, import.meta.url);
  try {
    const raw = fs.readFileSync(presetPath, "utf8");
    const parsed = parseYaml(raw) as Partial<Policy>;
    return mergePolicies(DEFAULT_POLICY, parsed);
  } catch (err) {
    warnings.push(`Failed to load preset ${name}; falling back to default policy.`);
    return { ...DEFAULT_POLICY };
  }
}

function loadPolicyFile(policyPath: string, warnings: string[]): Partial<Policy> | null {
  if (!fs.existsSync(policyPath)) {
    warnings.push(`Policy file not found at ${policyPath}; using preset defaults.`);
    return null;
  }
  try {
    const raw = fs.readFileSync(policyPath, "utf8");
    return parseYaml(raw) as Partial<Policy>;
  } catch (err) {
    warnings.push(`Failed to parse policy file at ${policyPath}; using preset defaults.`);
    return null;
  }
}

function normalizeDecision(value: unknown, fallback: Decision): Decision {
  if (typeof value !== "string") {
    return fallback;
  }
  const normalized = value.trim().toUpperCase();
  if (normalized === "ALLOW" || normalized === "DENY" || normalized === "ASK") {
    return normalized;
  }
  return fallback;
}

function normalizeDecisionOptional(value: unknown): Decision | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toUpperCase();
  if (normalized === "ALLOW" || normalized === "DENY" || normalized === "ASK") {
    return normalized;
  }
  return undefined;
}

function normalizeLogLevel(value: unknown, fallback: LogLevel): LogLevel {
  if (value === "safe" || value === "debug") {
    return value;
  }
  return fallback;
}

function normalizeRedaction(value: unknown, fallback: RedactionMode): RedactionMode {
  if (value === "standard" || value === "strict" || value === "off") {
    return value;
  }
  return fallback;
}

function normalizeInjectionMode(value: unknown, fallback: InjectionMode): InjectionMode {
  if (value === "shadow" || value === "alert" || value === "block") {
    return value;
  }
  return fallback;
}

function mergePolicies(base: Policy, override: Partial<Policy>): Policy {
  return {
    mode: override.mode ?? base.mode,
    defaults: {
      denyUnknownTools: override.defaults?.denyUnknownTools ?? base.defaults.denyUnknownTools,
      unknownToolAction: normalizeDecision(
        override.defaults?.unknownToolAction,
        base.defaults.unknownToolAction
      ),
      log: normalizeLogLevel(override.defaults?.log, base.defaults.log),
      redaction: normalizeRedaction(override.defaults?.redaction, base.defaults.redaction),
      injection: {
        mode: normalizeInjectionMode(override.defaults?.injection?.mode, base.defaults.injection.mode)
      }
    },
    risk: {
      read: normalizeDecision(override.risk?.read, base.risk.read),
      write: normalizeDecision(override.risk?.write, base.risk.write),
      critical: normalizeDecision(override.risk?.critical, base.risk.critical),
      unknown: normalizeDecision(override.risk?.unknown, base.risk.unknown)
    },
    tools: mergeToolRules(base.tools ?? [], override.tools ?? [])
  };
}

function mergeToolRules(base: ToolRule[], override: ToolRule[]): ToolRule[] {
  const map = new Map<string, ToolRule>();
  for (const rule of base) {
    map.set(normalizeToolName(rule.name), { ...rule, name: normalizeToolName(rule.name) });
  }
  for (const rule of override) {
    const normalizedName = normalizeToolName(rule.name);
    map.set(normalizedName, { ...map.get(normalizedName), ...rule, name: normalizedName });
  }
  return Array.from(map.values());
}

function normalizePolicy(policy: Policy, warnings: string[]): Policy {
  const toolMap = new Map<string, ToolRule>();

  for (const rule of BASELINE_TOOL_RULES) {
    const normalizedName = normalizeToolName(rule.name);
    toolMap.set(normalizedName, {
      ...rule,
      name: normalizedName,
      scanInjection: rule.scanInjection ?? true,
      redactParams: rule.redactParams ?? true,
      redactResult: rule.redactResult ?? true
    });
  }

  for (const rule of policy.tools ?? []) {
    if (!rule.name) {
      warnings.push("Encountered tool rule with missing name; skipping.");
      continue;
    }
    const normalizedName = normalizeToolName(rule.name);
    const existing = toolMap.get(normalizedName) ?? {};
    const normalizedPathAction = normalizeDecisionOptional(rule.pathAction);
    const allowPaths = Array.isArray(rule.allowPaths)
      ? rule.allowPaths.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
      : undefined;
    const next = { ...existing, ...rule, name: normalizedName };
    if (normalizedPathAction) {
      next.pathAction = normalizedPathAction;
    }
    if (allowPaths) {
      next.allowPaths = allowPaths;
    }
    toolMap.set(normalizedName, next);
  }

  return {
    ...policy,
    tools: Array.from(toolMap.values())
  };
}
