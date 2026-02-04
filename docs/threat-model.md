# Threat Model

## What we protect against

- Accidental leakage of secrets in tool inputs and outputs (redaction before logs or persistence).
- Prompt-injection and tool-poisoning attempts embedded in tool results.
- Misconfigured or unknown tools by default-deny policies.
- Unexplained policy decisions (every DENY/ASK has a reason and a request ID).
- Oversized tool outputs that can overwhelm context.
- Out-of-scope file edits when path allowlists are configured.
- Burst tool usage via deterministic per-tool rate limits.

## What we do not protect against

- Compromised OpenClaw host or OS-level malware.
- Unauthorized access to the OpenClaw config directory.
- Malicious tools that exfiltrate data outside of tool outputs.
- LLM reasoning errors unrelated to tool execution.
- OpenClaw surfaces that bypass plugin hooks (e.g., gateway `/tools/invoke`).
- Unredacted raw streams emitted by OpenClaw itself.

## Assumptions

- Users will review approval prompts carefully.
- OpenClaw's built-in exec approvals remain enabled for exec tools.
- Policy files are managed by trusted operators.
- Audit findings are reviewed and remediated by operators.
