# MindAI OpenClaw Tool Firewall

Privacy- and safety-first firewall for OpenClaw tool execution. It adds deterministic allow/deny/ask policy gating, redaction, and prompt-injection defense across all tools, with a guided setup wizard and safe audit logs.

## Highlights

- Deterministic policy gating for all tools (allow/deny/ask)
- Privacy-first redaction for tool inputs and outputs
- Prompt-injection detection on tool results (shadow/alert/block)
- Output size guard to truncate or block oversized results
- Path allowlists for file tools (read/write/edit/apply_patch)
- Per-tool rate limits with ASK or DENY actions
- Explainable decisions with request IDs and safe receipts
- Guided setup wizard and standalone CLI

## Quickstart

Install the CLI via npm (recommended):

```bash
npm install -g @mindaiproject/openclaw-tool-firewall
mindai-firewall setup
```

Or install through OpenClaw:

```bash
openclaw plugins install @mindaiproject/openclaw-tool-firewall
openclaw plugins enable openclaw-tool-firewall
openclaw firewall setup
```

Create a default policy and restart OpenClaw:

```bash
openclaw firewall init --preset standard
```

Approve a gated request in chat:

```
/firewall approve <requestId> once|session
```

## How It Works

- `before_tool_call` enforces policy, path allowlists, rate limits, and approvals
- `tool_result_persist` redacts output, applies output guards, and scans for injection

## Commands

- `openclaw firewall setup` or `mindai-firewall setup`
- `openclaw firewall install` or `mindai-firewall install`
- `openclaw firewall init --preset standard`
- `openclaw firewall validate`
- `openclaw firewall explain`
- `openclaw firewall recommend --min 3`
- `openclaw firewall audit`

## Policy Basics

- Defaults: deny unknown tools, safe logging, redaction, injection mode
- Risk levels: `read`, `write`, `critical`, `unknown`
- Tool rules: per-tool `ALLOW`/`ASK`/`DENY`, allow paths, scan flags

See `docs/policies.md` for the schema and examples.

## Architecture

- `@mindaiproject/firewall-core` policy engine
- `@mindaiproject/firewall-redaction` detectors + masking
- `@mindaiproject/firewall-scanner` injection detection
- `@mindaiproject/openclaw-tool-firewall` OpenClaw adapter + approvals + wizard

More detail: `docs/architecture.md`.

## Security Notes

- Output scanning is best-effort and complements policy gating
- OpenClaw gateway `/tools/invoke` bypasses plugin hooks
- Read `docs/threat-model.md` for what is and is not covered

## Documentation

- `docs/quickstart.md`
- `docs/installation.md`
- `docs/non-coder-setup.md`
- `docs/openclaw.md`
- `docs/examples.md`
- `docs/policies.md`
- `docs/troubleshooting.md`
- `docs/threat-model.md`
- `docs/why-firewall.md`
- `docs/release-checklist.md`

## Index

- [Highlights](#highlights)
- [Quickstart](#quickstart)
- [How It Works](#how-it-works)
- [Commands](#commands)
- [Policy Basics](#policy-basics)
- [Architecture](#architecture)
- [Security Notes](#security-notes)
- [Documentation](#documentation)

## Star History

<a href="https://www.star-history.com/#mindai-project/openclaw-firewall&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=mindai-project/openclaw-firewall&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=mindai-project/openclaw-firewall&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=mindai-project/openclaw-firewall&type=date&legend=top-left" />
 </picture>
</a>
