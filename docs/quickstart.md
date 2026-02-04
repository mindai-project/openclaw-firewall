# Quickstart (5 minutes)

Need a non-coder guide? See `docs/non-coder-setup.md`.  
Architecture overview: `docs/architecture.md`.

## 1) Install + enable the plugin

Example (npm install through OpenClaw):

```bash
openclaw plugins install @mindaiproject/openclaw-tool-firewall
openclaw plugins enable openclaw-tool-firewall
```

No-code setup (guided wizard):

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

No-code setup (non-interactive):

```bash
openclaw firewall setup --preset standard
```

Standalone CLI setup (included in the main package):

```bash
npm install -g @mindaiproject/openclaw-tool-firewall
mindai-firewall setup
```

Standalone installer:

```bash
npm install -g @mindaiproject/openclaw-tool-firewall
mindai-firewall install
```

All `openclaw firewall <command>` invocations have an equivalent
`mindai-firewall <command>` if the OpenClaw CLI command is unavailable.

## 1.1) Add config entry (OpenClaw)

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

Full installation guide: `docs/installation.md`.
Examples: `docs/examples.md`.

## 2) Create a default policy file

```bash
openclaw firewall init --preset standard
```

This writes the policy file to:

```
~/.openclaw/firewall/firewall.yaml
```

Standalone CLI (included in the main package):

```bash
npm install -g @mindaiproject/openclaw-tool-firewall
mindai-firewall init --preset standard
```

## 3) Restart OpenClaw

Once restarted, tool calls will be gated by the firewall. If a tool requires approval, you will see a request ID and can approve via:

```
/firewall approve <requestId> once|session
```

## 4) Validate your policy

```bash
openclaw firewall validate
```

## 5) Explain the last decision

```bash
openclaw firewall explain
```

## 6) Generate policy recommendations (training)

```bash
openclaw firewall recommend --min 3
```

## 7) Audit OpenClaw security settings

```bash
openclaw firewall audit
```
