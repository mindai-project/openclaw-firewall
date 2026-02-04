# Troubleshooting

## Plugin not loading

- Confirm the plugin is enabled:

```bash
openclaw plugins list
```

- Ensure the plugin id is `openclaw-tool-firewall`.
- Ensure config is under `plugins.entries.<id>.config` (not directly under `plugins.entries.<id>`).
- Ensure `plugins.entries` is a map/object keyed by plugin id, not a list/array.

## Config invalid: plugin not found (install loop)

If `openclaw` refuses to run because of:

```
plugins.entries.openclaw-tool-firewall: plugin not found: openclaw-tool-firewall
```

OpenClaw validates config **before** running plugin install, so it aborts. Fix by removing stale entries:

```bash
python - <<'PY'
import json, pathlib
p = pathlib.Path("/root/.openclaw/openclaw.json")
cfg = json.loads(p.read_text())
plugins = cfg.get("plugins", {})
entries = plugins.get("entries", {})
entries.pop("openclaw-tool-firewall", None)
entries.pop("mindai-openclaw-tool-firewall", None)
plugins["entries"] = entries
if not entries:
    plugins.pop("entries", None)
load = plugins.get("load", {})
paths = load.get("paths", [])
paths = [x for x in paths if "openclaw-tool-firewall" not in x]
if paths:
    load["paths"] = paths
    plugins["load"] = load
else:
    load.pop("paths", None)
    if not load:
        plugins.pop("load", None)
installs = plugins.get("installs", {})
installs.pop("openclaw-tool-firewall", None)
installs.pop("mindai-openclaw-tool-firewall", None)
if installs:
    plugins["installs"] = installs
else:
    plugins.pop("installs", None)
cfg["plugins"] = plugins
p.write_text(json.dumps(cfg, indent=2) + "\n")
print("Cleaned", p)
PY
```

Then re-run:

```bash
openclaw plugins install /path/to/mindai-openclaw-tool-firewall-0.1.0.tgz
openclaw plugins enable openclaw-tool-firewall
```

## `openclaw firewall` command not found

This means the OpenClaw CLI did not load the plugin commands. Fixes:

```bash
openclaw plugins list --enabled
```

If the plugin is missing, run the standalone wizard and point it at the
OpenClaw config you actually use:

```bash
npm install -g @mindaiproject/openclaw-tool-firewall
mindai-firewall setup --config /path/to/openclaw.json
```

If your config path is non-default, set `OPENCLAW_CONFIG_PATH` or `OPENCLAW_STATE_DIR`
before running `openclaw`.

## Failed to resolve firewall plugin entrypoint

If you see:

```
Failed to resolve firewall plugin entrypoint. Pass --plugin-path.
```

Pass the entrypoint path explicitly:

```bash
openclaw firewall setup --plugin-path ~/.openclaw/extensions/openclaw-tool-firewall
```

If the plugin is installed via npm in the OpenClaw repo, use:

```bash
openclaw firewall setup --plugin-path /home/openclaw/node_modules/@mindaiproject/openclaw-tool-firewall
```

## Wizard prompts hang in CI or scripts

The setup wizard requires a TTY. In non-interactive environments, use:

```bash
openclaw firewall setup --preset standard --non-interactive
```

## Legacy plugin id

If you upgraded from an older release, your config may still reference the legacy id:

```
mindai-openclaw-tool-firewall
```

Update it to:

```
openclaw-tool-firewall
```

Or re-run the wizard:

```bash
openclaw firewall setup
```

The wizard removes legacy entries automatically.

## Policy file not found

The firewall defaults to:

```
~/.openclaw/firewall/firewall.yaml
```

Generate a preset file:

```bash
openclaw firewall init --preset standard
```

## Where is my OpenClaw config?

If you are not sure which config file OpenClaw is using, run:

```bash
openclaw gateway status
```

If you use environment overrides like `OPENCLAW_STATE_DIR` or `OPENCLAW_CONFIG_PATH`, the config location can change per session.

## Approvals not applying

- Verify the request ID matches the one shown in the block reason.
- Approve with:

```
/firewall approve <requestId> once|session
```

- Check pending approvals:

```
/firewall status
```

## Exec approvals

The firewall defers exec tool approvals to OpenClaw's built-in exec approval flow. If exec commands are blocked, confirm you have completed the `/approve` flow for exec.

## Rate limit blocks

If you see "Rate limit exceeded":

- Increase `rateLimits.maxCalls` or `rateLimits.windowSec`.
- Set `action: ASK` instead of `DENY` to allow a manual approval.

## Path allowlist blocks

If you see "Path guard":

- Add the target directory to `allowPaths`.
- Or set `pathAction: ASK` to allow manual approval.
