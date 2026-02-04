# Policy Schema

## Top-level fields

- `mode`: string label for the policy (example: `standard`).
- `defaults.denyUnknownTools`: boolean. Unknown tools are denied when `true`.
- `defaults.unknownToolAction`: `ALLOW`, `DENY`, or `ASK`.
- `defaults.log`: `safe` or `debug`.
- `defaults.redaction`: `standard` (default detectors), `strict` (adds aggressive token/base64/hex masking), or `off` (disable redaction entirely; not recommended).
- `defaults.injection.mode`: `shadow`, `alert`, or `block`.
- `risk.read|write|critical|unknown`: default action per risk.
- `tools[]`: per-tool overrides.

## Tool rule fields

- `name`: tool name (required).
- `risk`: `read`, `write`, `critical`, `unknown`.
- `action`: `ALLOW`, `DENY`, or `ASK`.
- `allow`: `true`, `false`, `ask`, or `deny` (alias of `action`).
- `redactParams`: boolean.
- `redactResult`: boolean.
- `scanInjection`: boolean.
- `useExecApprovals`: boolean (exec tool only).
- `allowPaths`: list of allowed filesystem path prefixes (write/read/edit/apply_patch).
- `pathAction`: `ALLOW`, `DENY`, or `ASK` when path is outside allowPaths (default: `ASK`).

Note: if `defaults.redaction` is set to `off`, redaction is disabled even if a tool rule sets `redactParams`/`redactResult` to `true`.

## Preset example

```yaml
mode: standard

defaults:
  denyUnknownTools: true
  unknownToolAction: DENY
  log: safe
  redaction: standard
  injection:
    mode: alert

risk:
  read: ALLOW
  write: ASK
  critical: DENY

tools:
  - name: web_fetch
    risk: read
    scanInjection: true

  - name: write
    risk: write
    allowPaths:
      - /home/user/project
    pathAction: ASK
```

## Baseline tool mapping (preloaded)

The loader preloads the following tool names with default risk classification:

- `read` (read)
- `write` (write)
- `edit` (write)
- `apply_patch` (write)
- `exec` (critical, `useExecApprovals=true`)
- `process` (critical)
- `agents_list` (read)
- `browser` (write)
- `canvas` (read)
- `cron` (write)
- `gateway` (critical)
- `image` (read)
- `message` (write)
- `nodes` (critical)
- `session_status` (read)
- `sessions_history` (read)
- `sessions_list` (read)
- `sessions_send` (write)
- `sessions_spawn` (critical)
- `tts` (read)
- `web_fetch` (read)
- `web_search` (read)
- `memory_search` (read)
- `memory_get` (read)

Unknown tools remain denied unless explicitly added to `tools`.

## Path allowlist notes

- `allowPaths` is matched as a prefix against resolved paths.
- `apply_patch` path extraction is best-effort (based on patch markers). If no path is found, the guard falls back to `pathAction`.

## Training recommendations

You can generate a suggested policy diff based on approved requests:

```bash
openclaw firewall recommend --min 3
```

If `openclaw firewall` is missing, use `mindai-firewall recommend --min 3`.

This outputs a YAML snippet you can manually merge into your policy.

### Storage details (training)

To avoid loading large histories into context, approvals are stored in:

- `~/.openclaw/firewall/approvals.history.jsonl` (append-only history)
- `~/.openclaw/firewall/approvals.rollup.json` (aggregated counts)

`recommend` reads the rollup first and falls back to history if needed.
