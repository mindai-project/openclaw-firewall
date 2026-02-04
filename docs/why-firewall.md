# Why the MindAI Tool Firewall?

OpenClaw already provides exec approvals and tool execution. The firewall adds a **deterministic, policy-driven safety layer** across *all tools* with privacy-first redaction and prompt-injection defense.

## At-a-glance

| Capability | Standard OpenClaw | MindAI Tool Firewall |
| --- | --- | --- |
| Exec approvals | Yes | Yes (delegates to OpenClaw) |
| Policy gating for all tools (allow/deny/ask) | No | Yes |
| Redact tool inputs/outputs before logs | No | Yes |
| Prompt-injection detection on tool output | No | Yes |
| Explainable deny/ask reasons | Limited | Yes |
| Safe audit receipts | No | Yes |
| Unknown tools denied by default | No | Yes |
| Output size guard (avoid huge context dumps) | No | Yes |
| Rate limiting per tool | No | Yes |
| Path allowlists for file tools | No | Yes |
| Config audit warnings | No | Yes |

## The gaps we solve

### 1) Only exec approvals are not enough
Standard OpenClaw approvals only cover `exec`. Write/edit/apply_patch tools can still make changes without any approval or policy enforcement.

Firewall fix: risk-based policy for **every tool**.

### 2) Tool outputs can poison the model
Tool results can include malicious instructions ("ignore previous instructions"), which are fed back into the model without inspection.

Firewall fix: injection scanning on tool outputs with `shadow`, `alert`, or `block` modes.

### 3) Secrets can leak into logs or context
Tool inputs/outputs may contain secrets (API keys, Authorization headers, seed phrases). If they are logged or persisted, the system becomes a liability.

Firewall fix: redaction before persistence or logging, with hashed correlation.

### 4) Oversized tool outputs can blow up context
Some tools can return massive payloads that crowd out system context or cause truncation elsewhere.

Firewall fix: output size guards (`maxResultChars`) that truncate or block oversized results.

### 5) File writes should be scoped
Without guardrails, agents can modify sensitive parts of the filesystem.

Firewall fix: per-tool path allowlists (`allowPaths`) with `pathAction` fallback.

### 6) Repeated high-risk calls need throttling
Spiky tool activity can overwhelm systems or increase risk of accidental leakage.

Firewall fix: deterministic per-tool rate limits with `ASK`/`DENY` actions.

## Real-world use cases

### Use case A: Low-interaction daily agent
- Goal: minimal prompts
- Policy: allow read/write, ask critical

Result: agent works freely on files, but still requires human approval for `exec` or critical tools.

### Use case B: Human-in-the-loop code changes
- Goal: review all edits
- Policy: allow read, ask write, deny critical

Result: agent can explore and draft, but every change is approved explicitly.

### Use case C: Compliance/readonly mode
- Goal: no writes
- Policy: allow read, deny write/critical

Result: agent audits and reports without modifying anything.

## What the user sees

When a tool is gated:

```
Firewall approval required for <tool>.
Reason: Tool "<tool>" (<risk>) resolved to ASK.
Request ID: <id>
Args (redacted): <preview>
Approve: /firewall approve <id> once|session
Deny: /firewall deny <id>
```

## Summary

If you only need exec approvals, OpenClaw already provides that. If you need **full tool gating, privacy-first redaction, and injection defense**, this firewall is built for that.
