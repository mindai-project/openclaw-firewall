export type InjectionFinding = {
  id: string;
  severity: "low" | "medium" | "high";
  message: string;
  matchCount: number;
};

export type InjectionScanResult = {
  findings: InjectionFinding[];
  flagged: boolean;
};

type Rule = {
  id: string;
  severity: "low" | "medium" | "high";
  message: string;
  pattern: RegExp;
};

const RULES: Rule[] = [
  {
    id: "ignore_instructions",
    severity: "high",
    message: "Tool output attempts to override instructions.",
    pattern: /\bignore (?:all|previous|above) instructions\b/gi
  },
  {
    id: "system_prompt",
    severity: "high",
    message: "Tool output references system prompt authority.",
    pattern: /\bsystem prompt\b|\byou are chatgpt\b/gi
  },
  {
    id: "tool_call_coercion",
    severity: "high",
    message: "Tool output attempts to coerce a tool call.",
    pattern: /\bcall the tool\b|\binvoke tool\b|\bexecute tool\b/gi
  },
  {
    id: "credential_theft",
    severity: "medium",
    message: "Tool output requests secrets or credentials.",
    pattern: /\b(api key|password|seed phrase|private key)\b/gi
  },
  {
    id: "role_impersonation",
    severity: "medium",
    message: "Tool output impersonates privileged roles.",
    pattern: /\b(system|developer)\s*:\s*/gi
  },
  {
    id: "data_exfiltration",
    severity: "medium",
    message: "Tool output requests uploading or exfiltration.",
    pattern: /\bexfiltrate\b|\bupload to\b|\bsend (?:all|everything)\b/gi
  },
  {
    id: "overrides",
    severity: "low",
    message: "Tool output contains suspicious override language.",
    pattern: /\bdo not refuse\b|\boverride\b|\bmust comply\b/gi
  }
];

// Scan tool output text for known injection patterns.
export function scanText(input: string): InjectionScanResult {
  const findings: InjectionFinding[] = [];
  for (const rule of RULES) {
    const matches = input.match(rule.pattern);
    if (matches && matches.length > 0) {
      findings.push({
        id: rule.id,
        severity: rule.severity,
        message: rule.message,
        matchCount: matches.length
      });
    }
  }
  return { findings, flagged: findings.length > 0 };
}
