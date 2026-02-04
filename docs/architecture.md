# Architecture Overview

This document explains how the MindAI Tool Firewall is put together and how data flows through it.

## Core Components

- Policy engine (`@mindai/firewall-core`): deterministic allow/deny/ask decisions and tool rule normalization.
- Redaction (`@mindai/firewall-redaction`): masks secrets in tool inputs/outputs before logging or persistence.
- Injection scanner (`@mindai/firewall-scanner`): detects prompt-injection patterns in tool output.
- OpenClaw adapter (`@mindai/openclaw-tool-firewall`): hook integration, approvals, receipts, setup wizard.

## Data Flow

### 1) Before a tool runs (`before_tool_call`)

1. Normalize the tool name.
2. Evaluate policy and resolve a decision.
3. Enforce path allowlists (read/write/edit/apply_patch).
4. Apply rate limits (optional).
5. Redact parameters for preview/logging (if enabled).
6. Take action:
   - `ALLOW`: tool executes.
   - `DENY`: tool is blocked with a reason.
   - `ASK`: create an approval request and block until approved.

### 2) After a tool returns (`tool_result_persist`)

1. Redact tool output (if enabled).
2. Enforce output size limits (truncate or block).
3. Scan for prompt-injection patterns.
4. If injection detected:
   - `shadow`: detect only.
   - `alert`: append a warning.
   - `block`: replace output with a warning.
5. Record a receipt (redacted, safe metadata).

## Storage & Receipts

Stored under `~/.openclaw/firewall/`:

- `approvals.json`: pending/approved requests (redacted previews only).
- `approvals.history.jsonl`: append-only approvals history.
- `approvals.rollup.json`: aggregate counts for recommendations.
- `receipts.jsonl`: decision + redaction/injection metadata.
- `last-decision.json`: most recent decision for `explain`.

All stored data is redacted by default. Identifiers are hashed for correlation.

## Determinism

Decisions are deterministic for the same policy + input. Hashing uses a stable JSON serialization to keep approvals and receipts consistent across runs.
