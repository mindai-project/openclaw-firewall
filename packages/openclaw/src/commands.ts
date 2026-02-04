import type { PluginCommandContext, ReplyPayload } from "./openclaw-types.js";
import { auditOpenClawConfig, formatAuditFindings } from "./audit.js";
import {
  appendApprovalHistory,
  updateApprovalRollup,
  loadApprovalStore,
  saveApprovalStore,
  readLastDecision
} from "./storage.js";
import type { FirewallState } from "./handlers.js";

// Handle /firewall command actions (approve/deny/status/explain).
export function handleFirewallCommand(state: FirewallState, ctx: PluginCommandContext): ReplyPayload {
  const args = (ctx.args ?? "").trim();
  if (!args) {
    return { text: formatHelp() };
  }
  const parts = args.split(/\s+/);
  const action = parts[0] ?? "";

  switch (action) {
    case "approve":
      return approveRequest(state, parts[1], parts[2]);
    case "deny":
      return denyRequest(state, parts[1]);
    case "status":
      return status(state);
    case "explain":
      return explainLast(state);
    case "audit":
      return auditConfig(ctx);
    case "help":
    default:
      return { text: formatHelp() };
  }
}

function approveRequest(state: FirewallState, id?: string, scope?: string): ReplyPayload {
  if (!id) {
    return { text: "Usage: /firewall approve <requestId> once|session" };
  }
  const resolvedScope = scope === "session" ? "session" : "once";
  const store = loadApprovalStore(state.stateDir);
  const record = store.requests.find((entry) => entry.id === id);
  if (!record) {
    return { text: `No approval request found for ${id}.` };
  }
  const wasApproved = record.status === "approved";
  record.status = "approved";
  record.scope = resolvedScope;
  record.updatedAt = new Date().toISOString();
  record.used = false;
  saveApprovalStore(store, state.stateDir);
  if (!wasApproved) {
    const event = buildApprovalHistoryEvent(record);
    appendApprovalHistory(event, state.stateDir);
    updateApprovalRollup(event, state.stateDir);
  }
  return { text: `Approved ${id} (${resolvedScope}).` };
}

function denyRequest(state: FirewallState, id?: string): ReplyPayload {
  if (!id) {
    return { text: "Usage: /firewall deny <requestId>" };
  }
  const store = loadApprovalStore(state.stateDir);
  const record = store.requests.find((entry) => entry.id === id);
  if (!record) {
    return { text: `No approval request found for ${id}.` };
  }
  record.status = "denied";
  record.updatedAt = new Date().toISOString();
  saveApprovalStore(store, state.stateDir);
  return { text: `Denied ${id}.` };
}

function status(state: FirewallState): ReplyPayload {
  const store = loadApprovalStore(state.stateDir);
  const pending = store.requests.filter((entry) => entry.status === "pending");
  if (pending.length === 0) {
    return { text: "No pending firewall approvals." };
  }
  const lines = pending.map(
    (entry) =>
      `- ${entry.id} tool=${entry.toolName} risk=${entry.risk} session=${entry.sessionKey ?? "n/a"}`
  );
  return { text: [`Pending approvals (${pending.length}):`, ...lines].join("\n") };
}

function explainLast(state: FirewallState): ReplyPayload {
  const last = readLastDecision(state.stateDir);
  if (!last) {
    return { text: "No firewall decisions recorded yet." };
  }
  const lines = [
    `Last decision: ${last.decision ?? "n/a"}`,
    `Tool: ${last.toolName ?? "unknown"}`,
    `Risk: ${last.risk ?? "n/a"}`,
    `Reason: ${last.reason ?? "n/a"}`,
    `When: ${last.timestamp}`
  ];
  return { text: lines.join("\n") };
}

function auditConfig(ctx: PluginCommandContext): ReplyPayload {
  const findings = auditOpenClawConfig(ctx.config ?? {});
  return { text: formatAuditFindings(findings) };
}

function formatHelp(): string {
  return [
    "Firewall commands:",
    "/firewall status",
    "/firewall approve <requestId> once|session",
    "/firewall deny <requestId>",
    "/firewall explain",
    "/firewall audit"
  ].join("\n");
}

function buildApprovalHistoryEvent(record: {
  id: string;
  toolName: string;
  risk: string;
  scope?: "once" | "session";
  paramsHash?: string;
  sessionKey?: string;
  agentId?: string;
}): {
  ts: string;
  toolName: string;
  risk: string;
  status: "approved";
  scope?: "once" | "session";
  approvalId?: string;
  paramsHash?: string;
  sessionKey?: string;
  agentId?: string;
} {
  const event: {
    ts: string;
    toolName: string;
    risk: string;
    status: "approved";
    scope?: "once" | "session";
    approvalId?: string;
    paramsHash?: string;
    sessionKey?: string;
    agentId?: string;
  } = {
    ts: new Date().toISOString(),
    toolName: record.toolName,
    risk: record.risk,
    status: "approved"
  };
  if (record.scope) {
    event.scope = record.scope;
  }
  if (record.id) {
    event.approvalId = record.id;
  }
  if (record.paramsHash) {
    event.paramsHash = record.paramsHash;
  }
  if (record.sessionKey) {
    event.sessionKey = record.sessionKey;
  }
  if (record.agentId) {
    event.agentId = record.agentId;
  }
  return event;
}
