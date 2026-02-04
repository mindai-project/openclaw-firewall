export type AuditSeverity = "low" | "medium" | "high";

export type AuditFinding = {
  id: string;
  severity: AuditSeverity;
  message: string;
  path?: string;
  hint?: string;
};

// Scan OpenClaw config for common high-risk settings without touching secrets.
export function auditOpenClawConfig(config: Record<string, unknown>): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const gateway = asRecord(config.gateway);
  const tools = asRecord(config.tools);
  const logging = asRecord(config.logging);
  const env = asRecord(config.env);

  const bind = typeof gateway?.bind === "string" ? gateway.bind : undefined;
  if (bind && bind !== "loopback") {
    findings.push({
      id: "gateway.bind.exposed",
      severity: "medium",
      message: `Gateway bind mode is "${bind}". Remote clients may connect.`,
      path: "gateway.bind",
      hint: "Use loopback for local-only access or ensure strong auth is configured."
    });
  }

  const auth = asRecord(gateway?.auth);
  const hasToken = typeof auth?.token === "string" && auth.token.trim().length > 0;
  const hasPassword = typeof auth?.password === "string" && auth.password.trim().length > 0;
  const hasAuthMode = auth?.mode === "token" || auth?.mode === "password";
  if (bind && bind !== "loopback" && !hasToken && !hasPassword && !hasAuthMode) {
    findings.push({
      id: "gateway.auth.missing",
      severity: "high",
      message: "Gateway is exposed without a configured auth token or password.",
      path: "gateway.auth",
      hint: "Set gateway.auth.token or gateway.auth.password before exposing the gateway."
    });
  }

  const controlUi = asRecord(gateway?.controlUi);
  if (controlUi?.allowInsecureAuth === true) {
    findings.push({
      id: "gateway.controlUi.allowInsecureAuth",
      severity: "high",
      message: "Control UI allows insecure auth over HTTP.",
      path: "gateway.controlUi.allowInsecureAuth",
      hint: "Disable allowInsecureAuth or enable TLS for the gateway."
    });
  }
  if (controlUi?.dangerouslyDisableDeviceAuth === true) {
    findings.push({
      id: "gateway.controlUi.disableDeviceAuth",
      severity: "high",
      message: "Control UI device auth is disabled.",
      path: "gateway.controlUi.dangerouslyDisableDeviceAuth",
      hint: "Re-enable device auth for Control UI access."
    });
  }

  const tailscale = asRecord(gateway?.tailscale);
  if (tailscale?.mode === "funnel") {
    findings.push({
      id: "gateway.tailscale.funnel",
      severity: "high",
      message: "Gateway is exposed via Tailscale Funnel (public).",
      path: "gateway.tailscale.mode",
      hint: "Avoid funnel unless you need public exposure with strong auth."
    });
  }

  if (logging?.redactSensitive === "off") {
    findings.push({
      id: "logging.redactSensitive.off",
      severity: "medium",
      message: "Sensitive log redaction is disabled.",
      path: "logging.redactSensitive",
      hint: "Set logging.redactSensitive to \"tools\" to avoid leaking secrets in logs."
    });
  }

  const exec = asRecord(tools?.exec);
  if (exec?.security === "full") {
    findings.push({
      id: "tools.exec.security.full",
      severity: "high",
      message: "Exec security is set to full (no allowlist).",
      path: "tools.exec.security",
      hint: "Prefer allowlist and approval gating for exec."
    });
  }
  if (exec?.security === "allowlist" && exec?.ask === "off") {
    findings.push({
      id: "tools.exec.ask.off",
      severity: "medium",
      message: "Exec allowlist is enabled but approvals are disabled.",
      path: "tools.exec.ask",
      hint: "Consider tools.exec.ask=\"on-miss\" for human review."
    });
  }

  const profile = typeof tools?.profile === "string" ? tools.profile : undefined;
  if (profile === "full") {
    findings.push({
      id: "tools.profile.full",
      severity: "medium",
      message: "Tool profile is set to full (broad tool access).",
      path: "tools.profile",
      hint: "Use a narrower profile and explicit allowlist where possible."
    });
  }

  const shellEnv = asRecord(env?.shellEnv);
  if (shellEnv?.enabled === true) {
    findings.push({
      id: "env.shellEnv.enabled",
      severity: "medium",
      message: "Shell environment import is enabled.",
      path: "env.shellEnv.enabled",
      hint: "Disable shell env import unless you need it for secrets."
    });
  }

  return findings;
}

export function formatAuditFindings(findings: AuditFinding[]): string {
  if (findings.length === 0) {
    return "Audit: no high-risk configuration findings detected.";
  }
  const lines = [
    `Audit findings (${findings.length}):`
  ];
  for (const finding of findings) {
    const path = finding.path ? ` (${finding.path})` : "";
    const hint = finding.hint ? ` Hint: ${finding.hint}` : "";
    lines.push(`- [${finding.severity}] ${finding.message}${path}.${hint}`);
  }
  return lines.join("\n");
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  return value as Record<string, unknown>;
}
