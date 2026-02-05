# AGENTS.md

This file provides guidance to AI coding agents working on the OpenClaw tool-call firewall.

## Project Overview

This repository provides a privacy and safety firewall for OpenClaw tool execution. It intercepts tool calls, enforces policy decisions, redacts sensitive data, and scans tool outputs for injection or poisoning.

## Commands

| Command            | Description                                |
| ------------------ | ------------------------------------------ |
| `npm run build`    | TypeScript build                           |
| `npm run bundle`   | Bundle OpenClaw adapter + copy manifest    |
| `npm test`         | Run test suite (vitest)                    |
| `npm run release`  | Build + bundle                             |
| `npm run clean`    | Clean TypeScript build artifacts           |

## Architecture

```
packages/
├── cli/
│   └── src/
│       ├── cli.ts           # CLI entry + command routing
│       └── index.ts         # Public exports
├── core/
│   └── src/
│       ├── index.ts         # Public exports
│       ├── policy.ts        # Policy evaluation + decisions
│       ├── stable-json.ts   # Deterministic JSON helpers
│       └── types.ts         # Core types
├── redaction/
│   └── src/
│       ├── detectors.ts     # Pattern detection
│       ├── redact.ts        # Masking logic
│       └── index.ts         # Public exports
├── scanner/
│   └── src/
│       ├── rules.ts         # Injection detection rules
│       └── index.ts         # Public exports
└── openclaw/
    └── src/
        ├── audit.ts                      # Safe audit logging
        ├── cli.ts                        # OpenClaw CLI wiring
        ├── commands.ts                   # CLI commands
        ├── config.ts                     # Config + presets
        ├── handlers.ts                   # Tool call handlers
        ├── mindai-firewall.ts            # CLI entry for bundle
        ├── mindai-openclaw-tool-firewall.ts # Adapter entry
        ├── openclaw-types.ts             # Adapter boundary types
        ├── path-guard.ts                 # Path safety
        ├── plugin.ts                     # OpenClaw plugin entry
        ├── rate-limit.ts                 # Tool call rate limiting
        ├── recommend.ts                  # Preset recommendations
        ├── setup.ts                      # Init + setup helpers
        ├── storage.ts                    # Local storage helpers
        ├── wizard.ts                     # Interactive setup
        └── index.ts                      # Public exports

docs/           # Quickstart, policies, integration, troubleshooting
tests/
├── attacks/         # Injection/policy-manipulation payloads
├── integration/     # OpenClaw adapter boundary tests
└── unit/            # Core, redaction, scanner, and adapter unit tests
```

### Data Flow (Tool Call Lifecycle)

1. `openclaw` adapter receives a tool call request and context.
2. `core` evaluates policy for allow/deny/ask, with deterministic decisions.
3. `redaction` masks sensitive fields in request args and audit logs.
4. If allowed, the tool executes; result is treated as untrusted.
5. `scanner` inspects tool output for injection patterns.
6. `redaction` masks sensitive data in tool results before returning to the model.
7. A structured decision receipt is emitted for explainability.

### Package Responsibilities

`packages/core`: policy schema, decision engine, receipts, and explain-why paths.  
`packages/redaction`: detectors, masking strategies, and redaction reports.  
`packages/scanner`: untrusted-output scanning and severity modes (shadow/alert/block).  
`packages/openclaw`: OpenClaw adapter boundary, presets, config loading, and wiring.  
`packages/cli`: init/validate/explain commands with beginner-friendly errors.  

### Tests

`tests/attacks/` contains injection and policy-manipulation payloads.  
Unit tests live alongside features; integration tests cover the OpenClaw adapter boundary.

## Key Docs

- `docs/quickstart.md`
- `docs/openclaw.md`
- `docs/policies.md`
- `docs/troubleshooting.md`
- `docs/threat-model.md`
