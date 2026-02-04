# OpenClaw Tool Firewall Plugin — Detailed Build Plan (Plugin‑Only V1, Low Interaction)

## Summary (Deep Context)
We are building a **privacy + security firewall** for OpenClaw tool execution. The goal is to protect inexperienced users by enforcing *safe‑by‑default* tool policies while minimizing interaction. This plugin must:
- Intercept **all tool calls** before execution and **all tool results** before they reach the model context.
- Apply **allow/deny/ask** policy decisions with clear reasons and deterministic behavior.
- Redact secrets in tool inputs/outputs before logs or model context are touched.
- Detect and neutralize **prompt‑injection / tool‑poisoning** attempts embedded in tool results.
- Provide **receipts + safe audit logs** that are redacted and non‑sensitive.
- Remain **drop‑in** for beginners: install package, add plugin entry, pick a preset, done.

Constraints and integration realities:
- **No OpenClaw core patches** in this plan; use existing hooks only (`before_tool_call`, `tool_result_persist`).
- **No stochastic approvals** — determinism is required. Approvals are **risk‑based only**.
- `exec` approvals must **reuse OpenClaw’s existing approval system** (do not bypass or reimplement).
- Unknown/dynamic tools are **denied by default** unless explicitly listed in policy.
- If alignment is needed, the agent may read `/home/openclaw` to mirror core OpenClaw architecture and tool behavior.

Threat model alignment:
- Prevent accidental secret leaks (logs + prompts).
- Mitigate tool output prompt injection.
- Guard against misconfiguration and risky tool use.

## 1) Goals and Non‑Goals
Goals:
- Intercept tool calls pre‑execution to enforce policy and redact inputs.
- Intercept tool results pre‑persistence to redact outputs and scan for injection.
- Keep user interaction minimal: approvals only for high‑risk or triggered cases.
- Provide explainable allow/deny/ask decisions with safe audit logs.

Non‑Goals (V1):
- No OpenClaw core patches.
- No random approval sampling.
- No UI dialogs; command‑based approvals only.

## 2) Architecture Overview
Components:
- FirewallEngine: policy evaluation (allow/deny/ask).
- Redaction: detect and mask sensitive data.
- InjectionScanner: detect prompt‑injection patterns.
- Approvals: command‑based approval store.
- Receipts/Logs: redacted audit logs.

Hook integration:
- `before_tool_call`: policy + input redaction + block/ask decisions.
- `tool_result_persist`: output redaction + injection scan + output sanitization.

## 3) Approval Strategy (Low Interaction)
Default behavior:
- Read‑only tools: auto‑allow.
- Write tools: ask only if policy says `ask`.
- Critical tools: deny or ask depending on preset.
- Exec tool: always defer to OpenClaw’s exec approval system.

Ask only when needed:
- Tool risk level is `critical` (preset‑dependent).
- Tool risk is `write` and policy requires ask.
- Injection scan triggers `block` mode on results.
- Policy overrides per tool specify `allow: ask`.

No stochastic sampling:
- Approvals are deterministic, reproducible, and explainable.

## 4) Policy Model (YAML)
Presets:
- `strict`: deny unknown, ask on write, deny critical.
- `standard`: allow read, ask write, deny critical.
- `dev`: allow most, warn+log.

Example:
```yaml
mode: standard

defaults:
  denyUnknownTools: true
  unknownToolAction: deny
  log: safe
  redaction: standard

risk:
  read: allow
  write: ask
  critical: deny

tools:
  - name: "web_fetch"
    risk: read
    allow: true
    redactResult: true
    scanInjection: true

  - name: "browser"
    risk: write
    allow: ask
    scanInjection: true

  - name: "exec"
    risk: critical
    allow: ask
    useExecApprovals: true
```

## 4.1) Complete Tool Coverage (Explicit Mapping)
All known OpenClaw tools are explicitly classified. Unknown tools remain denied by default. This is the baseline list for policy initialization; dynamic plugin tools must be added to the policy before they can run.

Risk mapping table (defaults in `standard` preset):

| Tool | Risk | Default Action | Notes |
| --- | --- | --- | --- |
| `read` | read | allow | File reads. |
| `write` | write | ask | File writes. |
| `edit` | write | ask | File edits. |
| `apply_patch` | write | ask | Multi-file patching. |
| `exec` | critical | ask | Delegates to OpenClaw exec approvals. |
| `process` | critical | ask | Process control and input. |
| `agents_list` | read | allow | List agents. |
| `browser` | write | ask | Web automation. |
| `canvas` | read | allow | UI rendering only. |
| `cron` | write | ask | Schedule and run jobs. |
| `gateway` | critical | deny | Gateway control actions. |
| `image` | read | allow | Image generation. |
| `message` | write | ask | Outbound messaging actions. |
| `nodes` | critical | ask | Device control actions. |
| `session_status` | read | allow | Session status. |
| `sessions_history` | read | allow | Session transcript reads. |
| `sessions_list` | read | allow | Session listing. |
| `sessions_send` | write | ask | Send messages into sessions. |
| `sessions_spawn` | critical | ask | Spawn subagents. |
| `tts` | read | allow | Text-to-speech generation. |
| `web_fetch` | read | allow | Fetch web content. |
| `web_search` | read | allow | Web search. |
| `memory_search` | read | allow | Memory search (plugin tool). |
| `memory_get` | read | allow | Memory fetch (plugin tool). |

Dynamic tools:
- Channel plugin agent tools and third-party plugin tools are **denied by default** unless explicitly added to policy.
- The CLI `init` command will warn if installed plugins expose tools not present in `firewall.yaml`.

## 5) Core Types and Interfaces
Decision:
```ts
type Decision = "ALLOW" | "DENY" | "ASK";
type Risk = "read" | "write" | "critical" | "unknown";
```

Tool call and result:
```ts
type ToolCall = {
  toolName: string;
  params: Record<string, unknown>;
  context: {
    agentId?: string;
    sessionKey?: string;
  };
};

type ToolResult = {
  toolName?: string;
  toolCallId?: string;
  message: AgentMessage;
  isSynthetic?: boolean;
};

type FirewallDecision = {
  decision: Decision;
  reason: string;
  risk: Risk;
  redactionPlan?: RedactionPlan;
};
```

## 6) Hook Flow
`before_tool_call`:
1. Normalize tool name.
2. Evaluate policy.
3. If `DENY`: throw with reason.
4. If `ASK`: create approval request, throw with instruction.
5. If `ALLOW`: redact input args.

`tool_result_persist`:
1. Redact output.
2. Run injection scan.
3. If scan triggers `block` mode: replace result with safe warning.
4. Return sanitized result.

## 7) Ask UX (Command‑Based)
Commands:
- `/firewall approve <requestId> once|session`
- `/firewall deny <requestId>`
- `/firewall status`
- `/firewall explain last`

Storage:
- Approvals stored in `~/.openclaw/firewall/approvals.json` (redacted).

## 8) Redaction
Minimum detectors:
- Email, phone, IP
- Authorization headers
- Common API keys
- Crypto addresses/txids
- Seed phrase heuristic

Behavior:
- Replace with `"[REDACTED:<type>]"`.
- Keep hashes for correlation.

## 9) Injection Scanner
Rules:
- Ignore/forget instructions
- System prompt impersonation
- Tool‑call coercion attempts

Modes:
- `shadow`: log only
- `alert`: warn in output
- `block`: replace output

## 10) CLI
Commands:
- `mindai-firewall init`
- `mindai-firewall validate`
- `mindai-firewall explain last`

## 11) Tests
Unit:
- Policy evaluation
- Redaction snapshots
- Injection scan coverage

Integration:
- Simulated tool calls and tool results
- Approval lifecycle

## 12) Assumptions and Defaults
- Ask model is risk‑based, not stochastic.
- Users see approval prompts only when necessary.
- Preset default is `standard`.

## 13) Acceptance Criteria
- Plugin loads and runs without OpenClaw core changes.
- Minimal user prompts while maintaining safe blocking.
- Redaction and injection scanning validated by tests.
