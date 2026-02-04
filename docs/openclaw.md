# OpenClaw Integration

## Plugin ID

The OpenClaw plugin id is:

```
openclaw-tool-firewall
```

## Config (OpenClaw)

## Guided setup (wizard)

Run the setup wizard to configure OpenClaw + policy interactively:

```bash
openclaw firewall setup
```

To force non-interactive behavior, pass `--non-interactive`.

If `openclaw firewall` is missing, OpenClaw did not load the plugin CLI.
Use the standalone CLI and confirm OpenClaw is reading the same config path:

```bash
npm install -g @mindaiproject/openclaw-tool-firewall
mindai-firewall setup --config /path/to/openclaw.json
openclaw plugins list --enabled
```

Add to your OpenClaw config:

```yaml
plugins:
  entries:
    openclaw-tool-firewall:
      enabled: true
      config:
        preset: standard
        policyPath: ~/.openclaw/firewall/firewall.yaml
        # Optional guards
        maxResultChars: 8000
        maxResultAction: truncate # or block
        auditOnStart: true
        rateLimits:
          - toolName: web_fetch
            maxCalls: 20
            windowSec: 60
            action: ASK
            scope: session
```

`preset` is optional (`strict`, `standard`, `dev`). If `policyPath` is omitted, the plugin uses the default path above.

`auditOnStart` defaults to `true` and prints warnings at startup. Set it to `false` to silence the audit.

## Hooks used

- `before_tool_call`: enforce allow/deny/ask and create approval requests.
- `tool_result_persist`: redact results and scan for injection before transcript persistence.

Note: OpenClaw gateway `/tools/invoke` bypasses plugin hooks. Keep the gateway bound to loopback or secured with auth, and run `openclaw firewall audit` for guidance.

## Approvals (chat command)

When a tool is gated, approve with:

```
/firewall approve <requestId> once|session
```

Deny with:

```
/firewall deny <requestId>
```

Inspect pending approvals:

```
/firewall status
```

## Audit (CLI)

Run a quick config audit:

```
openclaw firewall audit
```

You can also run it in chat:

```
/firewall audit
```
