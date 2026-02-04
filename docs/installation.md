# Installation (OpenClaw)

## 1) Install the plugin

```bash
openclaw plugins install @mindai/openclaw-tool-firewall
```

## 2) Enable the plugin

```bash
openclaw plugins enable openclaw-tool-firewall
```

## 3) Add config to OpenClaw

```yaml
plugins:
  entries:
    openclaw-tool-firewall:
      enabled: true
      config:
        preset: standard
        policyPath: ~/.openclaw/firewall/firewall.yaml
        maxResultChars: 8000
        maxResultAction: truncate
        auditOnStart: true
```

JSON config example:

```json
{
  "plugins": {
    "entries": {
      "openclaw-tool-firewall": {
        "enabled": true,
        "config": {
          "preset": "standard",
          "policyPath": "~/.openclaw/firewall/firewall.yaml",
          "maxResultChars": 8000,
          "maxResultAction": "truncate",
          "auditOnStart": true
        }
      }
    }
  }
}
```

No-code wizard (recommended, guided prompts):

```bash
openclaw firewall setup
```

Guided installer (recommended for no-coders):

```bash
openclaw firewall install
```

If you see `unknown command 'firewall'`, OpenClaw did not load the plugin CLI.
Use the standalone CLI below or set `OPENCLAW_CONFIG_PATH`/`OPENCLAW_STATE_DIR`
so OpenClaw can load the plugin, then re-run.

Force the wizard even if you pass flags:

```bash
openclaw firewall setup --interactive
```

For scripts, disable prompts:

```bash
openclaw firewall setup --preset standard --non-interactive
```

Auto-accept defaults in the wizard:

```bash
openclaw firewall setup --interactive --yes
```

No-code alternative (non-interactive):

```bash
openclaw firewall setup --preset standard
```

Standalone CLI setup (included in the main package):

```bash
npm install -g @mindai/openclaw-tool-firewall
mindai-firewall setup
```

Standalone installer:

```bash
npm install -g @mindai/openclaw-tool-firewall
mindai-firewall install
```

If your OpenClaw config lives in a non-default path, pass it explicitly:

```bash
OPENCLAW_CONFIG_PATH=/path/to/openclaw.json openclaw firewall setup
mindai-firewall setup --config /path/to/openclaw.json
```

## 4) Initialize policy

```bash
openclaw firewall init --preset standard
```

Standalone CLI (included in the main package):

```bash
npm install -g @mindai/openclaw-tool-firewall
mindai-firewall init --preset standard
```

## 5) Validate policy

```bash
openclaw firewall validate
```

## 6) Explain last decision

```bash
openclaw firewall explain
```

## 7) Generate recommendations (training)

```bash
openclaw firewall recommend --min 3
```

## 8) Audit OpenClaw security settings

```bash
openclaw firewall audit
```

## Approvals in chat

```
/firewall approve <requestId> once|session
/firewall deny <requestId>
/firewall status
```

Examples: `docs/examples.md`.
