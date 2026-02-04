# AGENTS.md — Agent Tool Privacy Firewall (OpenClaw Adapter)

This repository builds a privacy + safety firewall layer for agent tool execution, designed to integrate *drop-in* with OpenClaw via a plugin/adapter, and remain usable by beginners.

## 0) Prime directive
Do not reduce user safety or privacy.  
Every change must preserve (or improve) determinism, explainability, and “least data” handling.

---

## 1) Scope & non-goals

### In scope
- Tool-call interception (pre-call and post-result)
- Policy enforcement: allow / deny / ask
- Redaction: input and output
- Injection/tool-poisoning defenses for untrusted tool outputs
- Safe audit logs (redacted, non-sensitive)
- Beginner-friendly setup: presets + CLI wizard + clear errors

### Out of scope (unless explicitly requested in the task)
- Building a full agent runtime
- Handling financial signing/broadcasting logic (we gate/deny/ask, we don’t implement wallets)
- Circumventing or weakening OpenClaw security primitives (we extend, not bypass)
- Anything that encourages illegal activity or evasion of controls

---

## 2) Core principles (must follow)

### 2.1 Privacy by default
- Never store or emit raw secrets.
- Redact before logging.
- Prefer partial masking and hashing to preserve debugging correlation without leakage.
- Default policies must be conservative (deny/ask for high risk).

### 2.2 Determinism
- The firewall must behave consistently for the same input + policy.
- Avoid non-deterministic behavior in policy decisions.
- Any randomness must be explicitly documented and disabled by default.

### 2.3 Explainability
- Every DENY/ASK must include a human-readable reason.
- Provide an “explain last decision” path (CLI or API).

### 2.4 Defense in depth
- Treat external content as hostile (`source != user`).
- Enforce risk gating on tool calls, not only at prompt level.
- Sanitize tool outputs before feeding them back into the LLM context.

### 2.5 Minimal integration friction
- Integration must be “drop-in”: 1 dependency + 1 config file + minimal wiring.
- Presets must work without editing (strict/standard/dev).
- Errors must be actionable for beginners.

---

## 3) Task workflow rules (for every task)

### 3.1 Start with a task brief
Each task PR/commit must include:
- Goal (one sentence)
- Success criteria (bullet list)
- Non-goals (if any)
- Risk (privacy/security regression risks)
- Test plan (how you validated)

### 3.2 Small steps, always runnable
- Prefer small PRs/commits.
- Keep the project buildable and tests passing.
- No “big bang” refactors unless explicitly requested.

### 3.3 No silent behavior changes
If behavior changes:
- Update docs and presets if needed.
- Add tests that prove the new expected behavior.
- Add migration notes if config fields change.

### 3.4 Backward compatibility
- Avoid breaking policy schema.
- If breaking is necessary, implement a transition period with warnings + documented migration.

---

## 4) Security & privacy rules (non-negotiable)

### 4.1 Secrets handling
- Never commit secrets, tokens, private keys, seed phrases, or real user data.
- Test fixtures must use synthetic values.

### 4.2 Logging
- Logs must be redacted by default.
- Provide log levels:
  - `safe` (default): minimal, redacted, hashed identifiers only
  - `debug` (optional): still redacted; may include more structure but never raw secrets
- Never log full tool args/results unless they are explicitly classified as non-sensitive (rare).

### 4.3 Policy defaults
- Unknown tools: deny (default).
- High-risk tools: ask or deny by default (preset dependent).
- If `source != user`, escalate gating for write/critical actions.

### 4.4 Injection defense
- Treat tool output as untrusted content.
- Do not allow tool output to alter policy, enable tools, or escalate permissions.
- Provide a scanner with severity and modes:
  - `shadow` (detect + log)
  - `alert` (detect + warn)
  - `block` (detect + deny/ask)

### 4.5 Human confirmation UX
- “Ask” must show:
  - What tool is being called
  - Why it’s being asked
  - A redacted preview of relevant args
- Provide clear “approve once / deny / approve for session” options where feasible.

---

## 5) Code standards

### 5.1 TypeScript
- Strict TS recommended (`"strict": true`) unless a task explicitly requires otherwise.
- Expose stable types for:
  - `ToolCall`, `ToolResult`, `Decision`, `Policy`, `RedactionReport`, `Receipt`

### 5.2 Error handling
- No unhandled promise rejections.
- Normalize errors into a predictable shape:
  - `code`, `message`, `details?`
- Provide user-facing messages that do not leak sensitive data.

### 5.3 Performance
- Redaction and scanning must be efficient.
- Avoid heavy dependencies.
- Keep runtime overhead low (goal: small constant overhead per tool call).

---

## 6) Testing rules

### 6.1 Required tests per feature
- Unit tests for policy evaluation branches.
- Snapshot tests for redaction output.
- Integration tests for the OpenClaw adapter boundary (mock tool runner).
- Regression tests for known injection patterns.

### 6.2 Redaction test coverage
Minimum coverage must include:
- email, IP, Authorization header, common API-key patterns
- crypto addresses/txids
- “seed phrase-like” content heuristic

### 6.3 “Attack suite”
Maintain `/tests/attacks/` with:
- payloads that attempt to trigger tool calls via untrusted outputs
- payloads that try to reveal secrets
- payloads that attempt policy manipulation

---

## 7) Documentation rules

### 7.1 Must update docs when
- Policy schema changes
- Presets change
- Integration steps change
- New risk categories or tool rules are introduced

### 7.2 Required docs
- `docs/quickstart.md` (5-minute setup)
- `docs/openclaw.md` (integration)
- `docs/policies.md` (schema + examples)
- `docs/troubleshooting.md` (beginner-friendly fixes)
- `docs/threat-model.md` (what we protect against, what we don’t)

---

## 8) Versioning & releases
- Use SemVer.
- Patch: bug fixes, safe rule tweaks, docs
- Minor: new features, new optional config fields (backward-compatible)
- Major: breaking policy schema or integration changes (must include migration guide)

---

## 9) Pull request checklist (required)
Before merging:
- [ ] Tests pass locally/CI
- [ ] No secrets in diff
- [ ] Logs are redacted by default
- [ ] New behavior has tests
- [ ] Docs updated (if applicable)
- [ ] “Explainability” verified (DENY/ASK reasons are clear)
- [ ] Integration remains beginner-friendly (no extra steps added)

---

## 10) Communication style
- Be direct and practical.
- Prefer “show, don’t tell”: include examples, configs, and test cases.
- Avoid vague statements like “improves security”; specify *how* and *what changed*.

---

## 11) Repository conventions
Suggested structure:
- `/packages/core` — policy engine + decision types
- `/packages/redaction` — detectors + masking
- `/packages/scanner` — injection detection
- `/packages/openclaw` — adapter + integration glue
- `/packages/cli` — init/validate/explain
- `/examples/` — minimal working examples
- `/docs/` — documentation
- `/tests/` — tests + attack suite

---

## 12) Definition of Done (DoD)
A task is “done” only if:
- The change is merged with tests + docs (as needed)
- The system remains buildable and runnable
- No privacy regression is introduced
- The behavior is explainable and validated with a test plan
