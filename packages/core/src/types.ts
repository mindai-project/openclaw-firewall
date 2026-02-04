export type Decision = "ALLOW" | "DENY" | "ASK";
export type Risk = "read" | "write" | "critical" | "unknown";
export type RedactionMode = "standard" | "strict" | "off";
export type LogLevel = "safe" | "debug";
export type InjectionMode = "shadow" | "alert" | "block";

// Canonical tool call shape for policy evaluation.
export type ToolCall = {
  toolName: string;
  params: Record<string, unknown>;
  context: {
    agentId?: string;
    sessionKey?: string;
  };
};

// Canonical tool result shape for redaction/scanning.
export type ToolResult = {
  toolName?: string;
  toolCallId?: string;
  message: unknown;
  isSynthetic?: boolean;
};

export type RedactionMatch = {
  type: string;
  count: number;
  hashes: string[];
};

export type RedactionReport = {
  redacted: boolean;
  matches: RedactionMatch[];
};

export type RedactionPlan = {
  redactParams: boolean;
  redactResult: boolean;
};

export type ToolRule = {
  name: string;
  risk?: Risk;
  action?: Decision;
  allow?: boolean | "ask" | "deny";
  /** Optional allowlist of filesystem paths (applies to read/write/edit/apply_patch). */
  allowPaths?: string[];
  /** Action to take when a path falls outside allowPaths. */
  pathAction?: Decision;
  redactParams?: boolean;
  redactResult?: boolean;
  scanInjection?: boolean;
  useExecApprovals?: boolean;
};

export type PolicyDefaults = {
  denyUnknownTools: boolean;
  unknownToolAction: Decision;
  log: LogLevel;
  redaction: RedactionMode;
  injection: {
    mode: InjectionMode;
  };
};

export type Policy = {
  mode: string;
  defaults: PolicyDefaults;
  risk: Record<Risk, Decision>;
  tools: ToolRule[];
};

export type NormalizedToolRule = {
  name: string;
  risk: Risk;
  action: Decision;
  allowPaths?: string[];
  pathAction?: Decision;
  redactParams: boolean;
  redactResult: boolean;
  scanInjection: boolean;
  useExecApprovals: boolean;
};

export type FirewallDecision = {
  decision: Decision;
  reason: string;
  risk: Risk;
  redactionPlan: RedactionPlan;
  scanInjection: boolean;
  useExecApprovals: boolean;
  toolRule?: NormalizedToolRule;
};

export type Receipt = {
  id: string;
  timestamp: string;
  toolName?: string;
  decision?: Decision;
  risk?: Risk;
  reason?: string;
  sessionKey?: string;
  agentId?: string;
  redaction?: RedactionReport;
  injection?: {
    mode: InjectionMode;
    findings: Array<{ id: string; severity: "low" | "medium" | "high"; message: string }>;
  };
  metadata?: Record<string, unknown>;
};
