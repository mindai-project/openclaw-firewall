# Task Brief: Firewall Setup Wizard

Goal:
Add a guided, no-code CLI wizard that configures the firewall policy and OpenClaw plugin config.

Success criteria:
- Running `openclaw firewall setup` in a TTY opens a guided wizard.
- The wizard can configure all firewall policy features (defaults, risk, tool rules, redaction, injection).
- The wizard can configure plugin options (max result guard, audit on start, rate limits).
- The wizard writes config + policy when confirmed and preserves existing configs safely.

Non-goals:
- Building a GUI or web interface.
- Changing OpenClaw core behavior or approval flows.

Risk:
- Misconfiguration could relax security defaults; mitigated by clear prompts and safe defaults.
- Accidental overwrites; mitigated by explicit confirmation before writing.

Test plan:
- `npm test`
- `npm run build`
- `npm run bundle`
