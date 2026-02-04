import { buildPolicyIndex, evaluatePolicy, normalizeToolName, type FirewallDecision, type NormalizedToolRule } from "@mindai/firewall-core";
import { hashObject, sha256Hex, stableStringify } from "@mindai/firewall-core";
import type { Decision, Policy, Receipt, ToolCall, RedactionMode } from "@mindai/firewall-core";
import { redactValue } from "@mindai/firewall-redaction";
import { scanText } from "@mindai/firewall-scanner";
import type {
  OpenClawPluginApi,
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
  PluginHookToolContext,
  PluginHookToolResultPersistContext,
  PluginHookToolResultPersistEvent,
  PluginHookToolResultPersistResult,
  PluginLogger
} from "./openclaw-types.js";
import { auditOpenClawConfig, formatAuditFindings } from "./audit.js";
import {
  appendReceipt,
  getStateDir,
  loadApprovalStore,
  saveApprovalStore,
  type ApprovalRecord,
  type ApprovalScope,
  writeLastDecision
} from "./storage.js";
import { loadPolicyConfig } from "./config.js";
import { evaluatePathAllowlist } from "./path-guard.js";
import { createRateLimiter, normalizeRateLimitRules, type RateLimiter } from "./rate-limit.js";

export type FirewallState = {
  policy: Policy;
  policySource: string;
  warnings: string[];
  toolIndex: Map<string, NormalizedToolRule>;
  stateDir: string;
  logger?: PluginLogger;
  resolvePath: (input: string) => string;
  maxResultChars?: number;
  maxResultAction: "truncate" | "block";
  rateLimiter?: RateLimiter;
};

// Initialize firewall state using plugin config and preset policies.
export function createFirewallState(api: OpenClawPluginApi): FirewallState {
  const pluginConfig = api.pluginConfig ?? {};
  const policyPath = typeof pluginConfig.policyPath === "string" && pluginConfig.policyPath
    ? api.resolvePath(pluginConfig.policyPath)
    : undefined;
  const preset = typeof pluginConfig.preset === "string" ? pluginConfig.preset : undefined;
  const maxResultChars =
    typeof pluginConfig.maxResultChars === "number" && pluginConfig.maxResultChars > 0
      ? pluginConfig.maxResultChars
      : undefined;
  const maxResultAction = pluginConfig.maxResultAction === "block" ? "block" : "truncate";
  const rateLimitRules = normalizeRateLimitRules(pluginConfig.rateLimits);
  const rateLimiter = rateLimitRules.length > 0 ? createRateLimiter(rateLimitRules) : undefined;
  const auditOnStart = pluginConfig.auditOnStart !== false;

  const loadParams: { preset?: "strict" | "standard" | "dev"; policyPath?: string } = {};
  if (preset === "strict" || preset === "standard" || preset === "dev") {
    loadParams.preset = preset;
  }
  if (policyPath) {
    loadParams.policyPath = policyPath;
  }
  const loaded = loadPolicyConfig(loadParams);

  if (loaded.warnings.length > 0) {
    loaded.warnings.forEach((warning) => api.logger.warn?.(`[firewall] ${warning}`));
  }
  if (auditOnStart) {
    const findings = auditOpenClawConfig(api.config ?? {});
    if (findings.length > 0) {
      api.logger.warn?.(`[firewall] ${formatAuditFindings(findings)}`);
    }
  }

  const state: FirewallState = {
    policy: loaded.policy,
    policySource: loaded.source,
    warnings: loaded.warnings,
    toolIndex: buildPolicyIndex(loaded.policy),
    stateDir: getStateDir(),
    logger: api.logger,
    resolvePath: api.resolvePath,
    maxResultAction
  };
  if (maxResultChars) {
    state.maxResultChars = maxResultChars;
  }
  if (rateLimiter) {
    state.rateLimiter = rateLimiter;
  }
  return state;
}

// Handle before_tool_call hook: policy decision + approval gating.
export async function handleBeforeToolCall(
  state: FirewallState,
  event: PluginHookBeforeToolCallEvent,
  ctx: PluginHookToolContext
): Promise<PluginHookBeforeToolCallResult | void> {
  const toolName = normalizeToolName(event.toolName);
  const toolCall: ToolCall = {
    toolName,
    params: event.params ?? {},
    context: buildContext(ctx)
  };

  let decision = evaluatePolicy(state.policy, toolCall, state.toolIndex);

  // Delegate exec approvals to OpenClaw's built-in system.
  if (toolName === "exec" && decision.useExecApprovals && decision.decision === "ASK") {
    decision = { ...decision, decision: "ALLOW", reason: "Exec approval delegated to OpenClaw." };
  }

  const pathGuard = evaluatePathGuard(state, toolName, event.params ?? {}, decision);
  if (pathGuard.override) {
    decision = pathGuard.override;
  }

  const rateLimit = decision.decision === "DENY"
    ? {}
    : evaluateRateLimit(state, toolName, ctx.sessionKey, decision);
  if (rateLimit.override) {
    decision = rateLimit.override;
  }

  const { preview, paramsHash, redactionReport } = redactParamsPreview(
    event.params,
    decision.redactionPlan.redactParams,
    state.policy.defaults.redaction
  );
  const guardMetadata = mergeGuardMetadata(pathGuard.metadata, rateLimit.metadata);

  if (decision.decision === "ALLOW") {
    recordDecision(
      state,
      decision,
      ctx,
      toolName,
      redactionReport,
      paramsHash,
      buildLogMetadata(state, preview, guardMetadata)
    );
    return { params: event.params };
  }

  if (decision.decision === "DENY") {
    recordDecision(
      state,
      decision,
      ctx,
      toolName,
      redactionReport,
      paramsHash,
      buildLogMetadata(state, preview, guardMetadata)
    );
    return {
      block: true,
      blockReason: `Firewall denied ${toolName}. ${decision.reason}`
    };
  }

  const approval = resolveApproval(state, decision, ctx, toolName, paramsHash, preview);
  if (approval.allowed) {
    const approvedDecision: FirewallDecision = {
      ...decision,
      decision: "ALLOW",
      reason: "Tool call approved by firewall."
    };
    recordDecision(
      state,
      approvedDecision,
      ctx,
      toolName,
      redactionReport,
      paramsHash,
      buildLogMetadata(state, preview, { approvalId: approval.id, approvalScope: approval.scope, ...guardMetadata })
    );
    return { params: event.params };
  }

  recordDecision(
    state,
    decision,
    ctx,
    toolName,
    redactionReport,
    paramsHash,
    buildLogMetadata(state, preview, { approvalId: approval.id, approvalScope: approval.scope, ...guardMetadata })
  );

  return {
    block: true,
    blockReason: buildAskReason(toolName, approval.id, decision.reason, preview)
  };
}

// Handle tool_result_persist hook: redact and scan output synchronously.
export function handleToolResultPersist(
  state: FirewallState,
  event: PluginHookToolResultPersistEvent,
  ctx: PluginHookToolResultPersistContext
): PluginHookToolResultPersistResult | void {
  const toolName = normalizeToolName(event.toolName ?? ctx.toolName ?? "unknown");
  const toolCall: ToolCall = {
    toolName,
    params: {},
    context: buildContext(ctx)
  };
  const decision = evaluatePolicy(state.policy, toolCall, state.toolIndex);

  const redactionMode = state.policy.defaults.redaction;
  const shouldRedact = decision.redactionPlan.redactResult && redactionMode !== "off";
  const redaction = shouldRedact
    ? redactValue(event.message, { mode: redactionMode })
    : { redacted: event.message, report: { redacted: false, matches: [] } };

  let nextMessage = redaction.redacted;
  const outputGuard = applyOutputGuard(
    nextMessage,
    state.maxResultChars,
    state.maxResultAction,
    event
  );
  if (outputGuard.changed) {
    nextMessage = outputGuard.message;
  }
  let injectionFindings: ReturnType<typeof scanText> | null = null;

  if (decision.scanInjection && !outputGuard.blocked) {
    const messageText = extractMessageText(nextMessage);
    if (messageText) {
      injectionFindings = scanText(messageText);
      if (injectionFindings.flagged) {
        if (state.policy.defaults.injection.mode === "block") {
          nextMessage = buildBlockedToolResult(event, injectionFindings.findings);
        } else if (state.policy.defaults.injection.mode === "alert") {
          nextMessage = appendWarningToMessage(nextMessage, injectionFindings.findings);
        }
      }
    }
  }

  recordToolResultReceipt(
    state,
    toolName,
    ctx,
    redaction.report,
    injectionFindings,
    outputGuard.metadata
  );

  if (nextMessage !== event.message) {
    return { message: nextMessage };
  }
  return;
}

function redactParamsPreview(
  params: Record<string, unknown>,
  shouldRedact: boolean,
  redactionMode: RedactionMode
): { preview: string; paramsHash: string; redactionReport: ReturnType<typeof redactValue>["report"] } {
  const fallback = "[unserializable-params]";
  const safePreview = (value: unknown): string => {
    try {
      return stableStringify(value);
    } catch {
      return fallback;
    }
  };
  const safeHash = (value: unknown): string => {
    try {
      return hashObject(value);
    } catch {
      return sha256Hex(fallback);
    }
  };
  if (!shouldRedact || redactionMode === "off") {
    const preview = truncate(safePreview(params), 500);
    return { preview, paramsHash: safeHash(params), redactionReport: { redacted: false, matches: [] } };
  }
  const redaction = redactValue(params, { mode: redactionMode });
  const preview = truncate(safePreview(redaction.redacted), 500);
  return { preview, paramsHash: safeHash(redaction.redacted), redactionReport: redaction.report };
}

function resolveApproval(
  state: FirewallState,
  decision: FirewallDecision,
  ctx: PluginHookToolContext,
  toolName: string,
  paramsHash: string,
  paramsPreview: string
): { allowed: boolean; id: string; scope?: ApprovalScope } {
  const store = loadApprovalStore(state.stateDir);
  const approvalId = buildApprovalId(toolName, ctx.sessionKey, paramsHash, decision.risk);
  const previewForStore = state.policy.defaults.log === "debug" ? paramsPreview : "[redacted]";

  const sessionApproval = store.sessionApprovals.find(
    (approval) =>
      approval.id === approvalId &&
      approval.toolName === toolName &&
      approval.paramsHash === paramsHash &&
      approval.sessionKey === ctx.sessionKey
  );
  if (sessionApproval) {
    return { allowed: true, id: approvalId, scope: "session" };
  }

  const request = store.requests.find(
    (entry) => entry.id === approvalId && entry.toolName === toolName && entry.paramsHash === paramsHash
  );

  if (request?.status === "approved") {
    if (request.scope === "once" && request.used) {
      return { allowed: false, id: approvalId, scope: request.scope };
    }
    if (request.scope === "session") {
      const alreadyApproved = store.sessionApprovals.find(
        (entry) =>
          entry.id === approvalId &&
          entry.toolName === toolName &&
          entry.paramsHash === paramsHash &&
          entry.sessionKey === ctx.sessionKey
      );
      if (!alreadyApproved) {
        const sessionApproval = buildSessionApproval(approvalId, toolName, paramsHash, ctx.sessionKey);
        store.sessionApprovals.push(sessionApproval);
      }
    }
    if (request.scope === "once") {
      request.used = true;
    }
    request.updatedAt = new Date().toISOString();
    saveApprovalStore(store, state.stateDir);
    const response: { allowed: boolean; id: string; scope?: ApprovalScope } = { allowed: true, id: approvalId };
    if (request.scope) {
      response.scope = request.scope;
    }
    return response;
  }

  if (!request) {
    const recordParams: {
      id: string;
      toolName: string;
      paramsHash: string;
      paramsPreview: string;
      risk: string;
      reason: string;
      sessionKey?: string;
      agentId?: string;
    } = {
      id: approvalId,
      toolName,
      paramsHash,
      paramsPreview: previewForStore,
      risk: decision.risk,
      reason: decision.reason
    };
    if (ctx.sessionKey) {
      recordParams.sessionKey = ctx.sessionKey;
    }
    if (ctx.agentId) {
      recordParams.agentId = ctx.agentId;
    }
    const created: ApprovalRecord = buildApprovalRecord(recordParams);
    store.requests.push(created);
    saveApprovalStore(store, state.stateDir);
  }

  return { allowed: false, id: approvalId };
}

function buildApprovalId(toolName: string, sessionKey: string | undefined, paramsHash: string, risk: string): string {
  return sha256Hex(`${toolName}:${sessionKey ?? ""}:${paramsHash}:${risk}`).slice(0, 16);
}

function buildAskReason(toolName: string, approvalId: string, reason: string, preview: string): string {
  return [
    `Firewall approval required for ${toolName}.`,
    `Reason: ${reason}`,
    `Request ID: ${approvalId}`,
    `Args (redacted): ${preview}`,
    `Approve: /firewall approve ${approvalId} once|session`,
    `Deny: /firewall deny ${approvalId}`
  ].join("\n");
}

function recordDecision(
  state: FirewallState,
  decision: FirewallDecision,
  ctx: PluginHookToolContext,
  toolName: string,
  redactionReport: ReturnType<typeof redactValue>["report"],
  paramsHash: string,
  metadata: Record<string, unknown> = {}
): void {
  const receipt: Receipt = {
    id: sha256Hex(`${toolName}:${new Date().toISOString()}`).slice(0, 16),
    timestamp: new Date().toISOString(),
    toolName,
    decision: decision.decision,
    risk: decision.risk,
    reason: decision.reason,
    redaction: redactionReport,
    metadata: {
      policySource: state.policySource,
      paramsHash,
      ...metadata
    }
  };
  const withContext = addContext(receipt, ctx);
  appendReceipt(withContext, state.stateDir);
  writeLastDecision(withContext, state.stateDir);
}

function recordToolResultReceipt(
  state: FirewallState,
  toolName: string,
  ctx: PluginHookToolResultPersistContext,
  redactionReport: ReturnType<typeof redactValue>["report"],
  injection: ReturnType<typeof scanText> | null,
  metadata?: Record<string, unknown>
): void {
  const receipt: Receipt = {
    id: sha256Hex(`${toolName}:${new Date().toISOString()}`).slice(0, 16),
    timestamp: new Date().toISOString(),
    toolName,
    redaction: redactionReport
  };
  if (metadata) {
    receipt.metadata = metadata;
  }
  if (injection) {
    receipt.injection = {
      mode: state.policy.defaults.injection.mode,
      findings: injection.findings.map((finding) => ({
        id: finding.id,
        severity: finding.severity,
        message: finding.message
      }))
    };
  }
  const withContext = addContext(receipt, ctx);
  appendReceipt(withContext, state.stateDir);
}

function evaluatePathGuard(
  state: FirewallState,
  toolName: string,
  params: Record<string, unknown>,
  decision: FirewallDecision
): { override?: FirewallDecision; metadata?: Record<string, unknown> } {
  const allowPaths = decision.toolRule?.allowPaths;
  if (!allowPaths || allowPaths.length === 0) {
    return {};
  }
  const result = evaluatePathAllowlist({
    toolName,
    params,
    allowPaths,
    resolvePath: state.resolvePath
  });
  const metadata = buildPathGuardMetadata(allowPaths, result);
  if (!result.allowed) {
    const action = decision.toolRule?.pathAction ?? "ASK";
    const override = overrideDecision(decision, action, `Path guard: ${result.reason}`);
    return { override, metadata };
  }
  return { metadata };
}

function evaluateRateLimit(
  state: FirewallState,
  toolName: string,
  sessionKey: string | undefined,
  decision: FirewallDecision
): { override?: FirewallDecision; metadata?: Record<string, unknown> } {
  if (!state.rateLimiter) {
    return {};
  }
  const hit = state.rateLimiter.evaluate(toolName, sessionKey);
  if (!hit) {
    return {};
  }
  const windowSec = Math.max(1, Math.round(hit.rule.windowMs / 1000));
  const reason = `Rate limit exceeded (${hit.rule.maxCalls} calls / ${windowSec}s).`;
  const override = overrideDecision(decision, hit.rule.action, reason);
  return {
    override,
    metadata: {
      rateLimit: {
        tool: toolName,
        scope: hit.rule.scope,
        action: hit.rule.action,
        maxCalls: hit.rule.maxCalls,
        windowSec
      }
    }
  };
}

function buildPathGuardMetadata(
  allowPaths: string[],
  result: ReturnType<typeof evaluatePathAllowlist>
): Record<string, unknown> {
  const hashed = result.toolPaths.map((entry) => sha256Hex(entry).slice(0, 8));
  return {
    pathGuard: {
      allowlistCount: allowPaths.length,
      paths: hashed,
      unmatchedCount: result.unmatched.length
    }
  };
}

function overrideDecision(
  current: FirewallDecision,
  override: Decision,
  reason: string
): FirewallDecision {
  if (decisionRank(override) <= decisionRank(current.decision)) {
    return current;
  }
  return { ...current, decision: override, reason };
}

function decisionRank(decision: Decision): number {
  if (decision === "DENY") {
    return 2;
  }
  if (decision === "ASK") {
    return 1;
  }
  return 0;
}

function mergeGuardMetadata(...entries: Array<Record<string, unknown> | undefined>): Record<string, unknown> {
  return entries.reduce<Record<string, unknown>>(
    (acc, entry) => (entry ? { ...acc, ...entry } : acc),
    {}
  );
}

function applyOutputGuard(
  message: unknown,
  maxChars: number | undefined,
  action: "truncate" | "block",
  event: PluginHookToolResultPersistEvent
): { changed: boolean; blocked: boolean; message: unknown; metadata?: Record<string, unknown> } {
  if (!maxChars || maxChars <= 0) {
    return { changed: false, blocked: false, message };
  }
  const messageText = extractMessageText(message);
  if (!messageText) {
    return { changed: false, blocked: false, message };
  }
  if (messageText.length <= maxChars) {
    return { changed: false, blocked: false, message };
  }

  if (action === "block") {
    return {
      changed: true,
      blocked: true,
      message: buildOversizeToolResult(event, messageText.length, maxChars),
      metadata: {
        outputGuard: {
          action,
          originalLength: messageText.length,
          maxChars
        }
      }
    };
  }

  return {
    changed: true,
    blocked: false,
    message: buildTruncatedToolResult(message, messageText, maxChars),
    metadata: {
      outputGuard: {
        action: "truncate",
        originalLength: messageText.length,
        maxChars
      }
    }
  };
}

function buildOversizeToolResult(
  event: PluginHookToolResultPersistEvent,
  length: number,
  maxChars: number
): unknown {
  const base = typeof event.message === "object" && event.message ? (event.message as Record<string, unknown>) : {};
  const toolCallId = event.toolCallId ?? (base.toolCallId as string | undefined);
  const toolName = event.toolName ?? (base.toolName as string | undefined);
  if (typeof event.message === "string" && !toolCallId && !toolName) {
    return `[firewall] Tool output blocked because it exceeded ${maxChars} characters (got ${length}).`;
  }
  return {
    ...base,
    role: "toolResult",
    toolCallId,
    toolName,
    content: [
      {
        type: "text",
        text: `[firewall] Tool output blocked because it exceeded ${maxChars} characters (got ${length}).`
      }
    ],
    isError: true
  };
}

function buildTruncatedToolResult(message: unknown, text: string, maxChars: number): unknown {
  const trimmed = `${text.slice(0, maxChars)}\n[firewall] Output truncated to ${maxChars} characters.`;
  if (typeof message === "string") {
    return trimmed;
  }
  if (!message || typeof message !== "object") {
    return trimmed;
  }
  const base = message as Record<string, unknown>;
  return {
    ...base,
    content: [{ type: "text", text: trimmed }]
  };
}

function extractMessageText(message: unknown): string | null {
  if (!message) {
    return null;
  }
  if (typeof message === "string") {
    return message;
  }
  if (typeof message === "object") {
    const record = message as Record<string, unknown>;
    const content = record.content;
    if (typeof content === "string") {
      return content;
    }
    if (Array.isArray(content)) {
      const parts = content
        .map((entry) => {
          if (!entry || typeof entry !== "object") {
            return "";
          }
          const block = entry as Record<string, unknown>;
          if (typeof block.text === "string") {
            return block.text;
          }
          if (typeof block.content === "string") {
            return block.content;
          }
          return "";
        })
        .filter(Boolean);
      if (parts.length > 0) {
        return parts.join("\n");
      }
    }
  }
  return null;
}

function buildBlockedToolResult(
  event: PluginHookToolResultPersistEvent,
  findings: Array<{ id: string; severity: "low" | "medium" | "high"; message: string }>
): unknown {
  const base = typeof event.message === "object" && event.message ? (event.message as Record<string, unknown>) : {};
  const toolCallId = event.toolCallId ?? (base.toolCallId as string | undefined);
  const toolName = event.toolName ?? (base.toolName as string | undefined);
  if (typeof event.message === "string" && !toolCallId && !toolName) {
    const summary = findings.map((finding) => `${finding.id}:${finding.severity}`).join(", ");
    return `[firewall] Tool output blocked due to potential prompt injection.\nFindings: ${summary}`;
  }
  return {
    ...base,
    role: "toolResult",
    toolCallId,
    toolName,
    content: [
      {
        type: "text",
        text: "[firewall] Tool output blocked due to potential prompt injection."
      },
      {
        type: "text",
        text: `Findings: ${findings.map((finding) => `${finding.id}:${finding.severity}`).join(", ")}`
      }
    ],
    isError: true
  };
}

function appendWarningToMessage(
  message: unknown,
  findings: Array<{ id: string; severity: "low" | "medium" | "high"; message: string }>
): unknown {
  const warning = `[firewall] Potential prompt injection detected: ${findings
    .map((finding) => `${finding.id}:${finding.severity}`)
    .join(", ")}`;
  if (typeof message === "string") {
    return `${message}\n${warning}`;
  }
  if (!message || typeof message !== "object") {
    return message;
  }
  const record = message as Record<string, unknown>;
  const content = Array.isArray(record.content) ? record.content.slice() : [];
  if (!Array.isArray(record.content) && typeof record.content === "string") {
    content.push({ type: "text", text: record.content });
  }
  content.push({ type: "text", text: warning });
  return { ...record, content };
}

function truncate(value: string, max: number): string {
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, max)}...`;
}

function buildLogMetadata(
  state: FirewallState,
  preview: string,
  extra: Record<string, unknown> = {}
): Record<string, unknown> {
  if (state.policy.defaults.log === "debug") {
    return { paramsPreview: preview, ...extra };
  }
  return { ...extra };
}

function buildContext(ctx: { agentId?: string; sessionKey?: string }): { agentId?: string; sessionKey?: string } {
  const context: { agentId?: string; sessionKey?: string } = {};
  if (ctx.agentId) {
    context.agentId = ctx.agentId;
  }
  if (ctx.sessionKey) {
    context.sessionKey = ctx.sessionKey;
  }
  return context;
}

function addContext<T extends Receipt>(
  receipt: T,
  ctx: { agentId?: string; sessionKey?: string }
): T {
  if (!ctx.agentId && !ctx.sessionKey) {
    return receipt;
  }
  const next: T = { ...receipt };
  if (ctx.agentId) {
    next.agentId = ctx.agentId;
  }
  if (ctx.sessionKey) {
    next.sessionKey = ctx.sessionKey;
  }
  return next;
}

function buildApprovalRecord(params: {
  id: string;
  toolName: string;
  paramsHash: string;
  paramsPreview: string;
  risk: string;
  sessionKey?: string;
  agentId?: string;
  reason: string;
}): ApprovalRecord {
  const record: ApprovalRecord = {
    id: params.id,
    toolName: params.toolName,
    paramsHash: params.paramsHash,
    paramsPreview: params.paramsPreview,
    risk: params.risk,
    status: "pending",
    createdAt: new Date().toISOString(),
    reason: params.reason
  };
  if (params.sessionKey) {
    record.sessionKey = params.sessionKey;
  }
  if (params.agentId) {
    record.agentId = params.agentId;
  }
  return record;
}

function buildSessionApproval(
  id: string,
  toolName: string,
  paramsHash: string,
  sessionKey?: string
): { id: string; toolName: string; paramsHash: string; sessionKey?: string; approvedAt: string } {
  const approval: { id: string; toolName: string; paramsHash: string; sessionKey?: string; approvedAt: string } = {
    id,
    toolName,
    paramsHash,
    approvedAt: new Date().toISOString()
  };
  if (sessionKey) {
    approval.sessionKey = sessionKey;
  }
  return approval;
}
