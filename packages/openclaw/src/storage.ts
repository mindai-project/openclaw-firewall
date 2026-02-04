import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { Receipt } from "@mindaiproject/firewall-core";

export type ApprovalScope = "once" | "session";
export type ApprovalStatus = "pending" | "approved" | "denied";

export type ApprovalRecord = {
  id: string;
  toolName: string;
  paramsHash: string;
  paramsPreview: string;
  risk: string;
  sessionKey?: string;
  agentId?: string;
  status: ApprovalStatus;
  scope?: ApprovalScope;
  createdAt: string;
  updatedAt?: string;
  used?: boolean;
  reason: string;
};

export type SessionApproval = {
  id: string;
  toolName: string;
  paramsHash: string;
  sessionKey?: string;
  approvedAt: string;
};

export type ApprovalStore = {
  version: number;
  requests: ApprovalRecord[];
  sessionApprovals: SessionApproval[];
};

const DEFAULT_STATE_DIR = path.join(os.homedir(), ".openclaw", "firewall");
const APPROVALS_FILE = "approvals.json";
const APPROVAL_HISTORY_FILE = "approvals.history.jsonl";
const APPROVAL_ROLLUP_FILE = "approvals.rollup.json";
const RECEIPTS_FILE = "receipts.jsonl";
const LAST_DECISION_FILE = "last-decision.json";

export type ApprovalHistoryEvent = {
  ts: string;
  toolName: string;
  risk: string;
  status: "approved";
  scope?: ApprovalScope;
  approvalId?: string;
  paramsHash?: string;
  sessionKey?: string;
  agentId?: string;
};

export type ApprovalRollup = {
  version: number;
  updatedAt: string;
  counts: Record<string, { toolName: string; risk: string; count: number }>;
};

// Compute the default storage directory for the firewall.
export function getStateDir(): string {
  return DEFAULT_STATE_DIR;
}

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export function loadApprovalStore(stateDir = DEFAULT_STATE_DIR): ApprovalStore {
  ensureDir(stateDir);
  const filePath = path.join(stateDir, APPROVALS_FILE);
  if (!fs.existsSync(filePath)) {
    return { version: 1, requests: [], sessionApprovals: [] };
  }
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw) as ApprovalStore;
    return {
      version: parsed.version ?? 1,
      requests: parsed.requests ?? [],
      sessionApprovals: parsed.sessionApprovals ?? []
    };
  } catch (err) {
    return { version: 1, requests: [], sessionApprovals: [] };
  }
}

export function saveApprovalStore(store: ApprovalStore, stateDir = DEFAULT_STATE_DIR): void {
  ensureDir(stateDir);
  const filePath = path.join(stateDir, APPROVALS_FILE);
  fs.writeFileSync(filePath, JSON.stringify(store, null, 2));
}

export function appendApprovalHistory(
  event: ApprovalHistoryEvent,
  stateDir = DEFAULT_STATE_DIR
): void {
  ensureDir(stateDir);
  const filePath = path.join(stateDir, APPROVAL_HISTORY_FILE);
  fs.appendFileSync(filePath, `${JSON.stringify(event)}\n`);
}

export function loadApprovalRollup(stateDir = DEFAULT_STATE_DIR): ApprovalRollup | null {
  const filePath = path.join(stateDir, APPROVAL_ROLLUP_FILE);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw) as ApprovalRollup;
    if (!parsed || typeof parsed !== "object") {
      return null;
    }
    return parsed;
  } catch (err) {
    return null;
  }
}

export function saveApprovalRollup(rollup: ApprovalRollup, stateDir = DEFAULT_STATE_DIR): void {
  ensureDir(stateDir);
  const filePath = path.join(stateDir, APPROVAL_ROLLUP_FILE);
  fs.writeFileSync(filePath, JSON.stringify(rollup, null, 2));
}

export function updateApprovalRollup(
  event: ApprovalHistoryEvent,
  stateDir = DEFAULT_STATE_DIR
): ApprovalRollup {
  const rollup = loadApprovalRollup(stateDir) ?? {
    version: 1,
    updatedAt: new Date().toISOString(),
    counts: {}
  };
  const key = `${event.toolName}:${event.risk}`;
  const existing = rollup.counts[key];
  if (existing) {
    existing.count += 1;
  } else {
    rollup.counts[key] = { toolName: event.toolName, risk: event.risk, count: 1 };
  }
  rollup.updatedAt = new Date().toISOString();
  saveApprovalRollup(rollup, stateDir);
  return rollup;
}

export function rebuildApprovalRollupFromHistory(
  stateDir = DEFAULT_STATE_DIR
): ApprovalRollup | null {
  const filePath = path.join(stateDir, APPROVAL_HISTORY_FILE);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const rollup: ApprovalRollup = {
    version: 1,
    updatedAt: new Date().toISOString(),
    counts: {}
  };
  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw.split("\n").filter(Boolean);
  for (const line of lines) {
    try {
      const event = JSON.parse(line) as ApprovalHistoryEvent;
      if (!event || event.status !== "approved") {
        continue;
      }
      const key = `${event.toolName}:${event.risk}`;
      const existing = rollup.counts[key];
      if (existing) {
        existing.count += 1;
      } else {
        rollup.counts[key] = { toolName: event.toolName, risk: event.risk, count: 1 };
      }
    } catch (err) {
      continue;
    }
  }
  saveApprovalRollup(rollup, stateDir);
  return rollup;
}

export function appendReceipt(receipt: Receipt, stateDir = DEFAULT_STATE_DIR): void {
  ensureDir(stateDir);
  const filePath = path.join(stateDir, RECEIPTS_FILE);
  fs.appendFileSync(filePath, `${JSON.stringify(receipt)}\n`);
}

export function writeLastDecision(record: Receipt, stateDir = DEFAULT_STATE_DIR): void {
  ensureDir(stateDir);
  const filePath = path.join(stateDir, LAST_DECISION_FILE);
  fs.writeFileSync(filePath, JSON.stringify(record, null, 2));
}

export function readLastDecision(stateDir = DEFAULT_STATE_DIR): Receipt | null {
  const filePath = path.join(stateDir, LAST_DECISION_FILE);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(raw) as Receipt;
  } catch (err) {
    return null;
  }
}
