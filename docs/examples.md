# Examples

This page shows practical, copy-ready examples for common setups. Use the one that matches your risk tolerance.

## Non-coder quick setup (safe default)

Full non-coder guide: `docs/non-coder-setup.md`.

1. Install and enable the plugin:

```bash
openclaw plugins install @mindai/openclaw-tool-firewall
openclaw plugins enable openclaw-tool-firewall
```

2. Add this to your OpenClaw config:

```yaml
plugins:
  entries:
    openclaw-tool-firewall:
      enabled: true
      config:
        preset: standard
        policyPath: ~/.openclaw/firewall/firewall.yaml
        auditOnStart: true
        maxResultChars: 8000
        maxResultAction: truncate
```

3. Generate the policy file:

```bash
openclaw firewall init --preset standard
```

If `openclaw firewall` is missing, use:

```bash
mindai-firewall init --preset standard
```

4. Restart OpenClaw. Approve requests as needed:

```
/firewall approve <requestId> once|session
```

## Example 1: Read-only audit mode

`firewall.yaml`:

```yaml
mode: readonly

defaults:
  denyUnknownTools: true
  unknownToolAction: DENY
  log: safe
  redaction: strict
  injection:
    mode: block

risk:
  read: ALLOW
  write: DENY
  critical: DENY

tools: []
```

## Example 2: Write with approvals

`firewall.yaml`:

```yaml
mode: review-writes

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

tools: []
```

## Example 3: Scoped writes (path allowlist)

Only allow file edits inside `/home/user/project`:

```yaml
mode: scoped-writes

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
  - name: write
    risk: write
    allowPaths:
      - /home/user/project
    pathAction: DENY

  - name: edit
    risk: write
    allowPaths:
      - /home/user/project
    pathAction: DENY

  - name: apply_patch
    risk: write
    allowPaths:
      - /home/user/project
    pathAction: DENY
```

## Example 4: Output size guard

Stop oversized tool outputs from flooding context:

```yaml
plugins:
  entries:
    openclaw-tool-firewall:
      enabled: true
      config:
        maxResultChars: 8000
        maxResultAction: truncate
```

To block instead of truncate:

```yaml
plugins:
  entries:
    openclaw-tool-firewall:
      enabled: true
      config:
        maxResultChars: 8000
        maxResultAction: block
```

## Example 5: Rate limits (per tool)

Throttle web fetches to reduce risk:

```yaml
plugins:
  entries:
    openclaw-tool-firewall:
      enabled: true
      config:
        rateLimits:
          - toolName: web_fetch
            maxCalls: 20
            windowSec: 60
            action: ASK
            scope: session
```

## Example 6: Safe training rollout

1. Start with `standard` (approvals on write/critical).
2. Use the system normally and approve safe requests.
3. Generate recommendations:

```bash
openclaw firewall recommend --min 3
```

4. Manually merge suggested rules into `firewall.yaml`.

## Example 7: Exec approvals remain OpenClaw-native

The firewall defers `exec` approvals to OpenClaw. You still approve exec via the built-in flow when prompted.
