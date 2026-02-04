# Non-Coder Setup Guide

This guide is for people who want the safest path with minimal terminal work.

## Quick Path (Recommended)

1. Install and enable the plugin:

```bash
openclaw plugins install @mindaiproject/openclaw-tool-firewall
openclaw plugins enable openclaw-tool-firewall
```

2. Run the guided installer:

```bash
openclaw firewall install
```

3. Restart OpenClaw.

That’s it. The firewall will now gate tools.

## What You’ll See During Use

When a tool needs approval, you’ll see a message like:

```
Firewall approval required for <tool>.
Reason: Tool "<tool>" (<risk>) resolved to ASK.
Request ID: <id>
Args (redacted): <preview>
Approve: /firewall approve <id> once|session
Deny: /firewall deny <id>
```

Use one of these commands in chat:

- `/firewall approve <id> once`
- `/firewall approve <id> session`
- `/firewall deny <id>`
- `/firewall status`

## Where the Files Live

- Policy file (default): `~/.openclaw/firewall/firewall.yaml`
- Approvals/receipts: `~/.openclaw/firewall/`

## Changing Your Safety Level

Run the installer again:

```bash
openclaw firewall install --interactive
```

Pick:

- `strict`: most approvals, safest
- `standard`: balanced (recommended)
- `dev`: least strict (not for production)

## If You Don’t See `openclaw firewall`

The plugin CLI wasn’t loaded. Use the standalone CLI instead:

```bash
npm install -g @mindaiproject/openclaw-tool-firewall
mindai-firewall setup
```
