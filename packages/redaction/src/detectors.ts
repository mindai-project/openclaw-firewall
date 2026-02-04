import { sha256Hex, type RedactionMode } from "@mindai/firewall-core";
import type { RedactionMatch, RedactionReport } from "@mindai/firewall-core";

export type RedactionResult = {
  redacted: string;
  report: RedactionReport;
};

export type RedactionOptions = {
  mode?: RedactionMode;
  seedPhraseMode?: "heuristic" | "off";
};

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const AUTH_HEADER_RE = /\bAuthorization:\s*(?:Bearer|Basic|Token)?\s*([A-Za-z0-9._~+\-=/]+)\b/gi;
const OPENAI_KEY_RE = /\bsk-[A-Za-z0-9]{20,}\b/g;
const AWS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/g;
const SLACK_TOKEN_RE = /\bxox[baprs]-[A-Za-z0-9-]{10,48}\b/g;
const STRIPE_KEY_RE = /\bsk_live_[0-9a-zA-Z]{24,}\b/g;
const GENERIC_SECRET_RE = /\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*([A-Za-z0-9_\-]{12,})\b/gi;
const ETH_ADDRESS_RE = /\b0x[a-fA-F0-9]{40}\b/g;
const BTC_ADDRESS_RE = /\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b/g;
const TXID_RE = /\b[a-fA-F0-9]{64}\b/g;
const STRICT_TOKEN_RE = /\b(?=[A-Za-z0-9._~-]{24,})(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._~-]+\b/g;
const STRICT_BASE64_RE = /\b[A-Za-z0-9+/]{32,}={0,2}\b/g;
const STRICT_HEX_RE = /\b[a-fA-F0-9]{32,}\b/g;

// Heuristic detector for seed-phrase-like content.
function isSeedPhraseLike(text: string): boolean {
  const normalized = text.trim().toLowerCase();
  const words = normalized.split(/\s+/).filter(Boolean);
  if (words.length < 12 || words.length > 24) {
    return false;
  }
  if (/[^a-z\s]/.test(normalized)) {
    return false;
  }
  return words.every((word) => word.length >= 3 && word.length <= 8);
}

function emptyReport(): RedactionReport {
  return { redacted: false, matches: [] };
}

function recordMatch(report: RedactionReport, type: string, value: string): void {
  const hash = sha256Hex(value).slice(0, 12);
  const existing = report.matches.find((match) => match.type === type);
  if (existing) {
    existing.count += 1;
    existing.hashes.push(hash);
  } else {
    report.matches.push({ type, count: 1, hashes: [hash] } satisfies RedactionMatch);
  }
  report.redacted = true;
}

function redactByPattern(
  input: string,
  report: RedactionReport,
  type: string,
  pattern: RegExp,
  replacer?: (match: string, groups: string[]) => string
): string {
  return input.replace(pattern, (...args) => {
    const match = args[0];
    const groups = args.slice(1, -2) as string[];
    recordMatch(report, type, match);
    if (replacer) {
      return replacer(match, groups);
    }
    return `[REDACTED:${type}:${sha256Hex(match).slice(0, 8)}]`;
  });
}

// Redact sensitive patterns from a string while producing a report.
export function redactString(input: string, options: RedactionOptions = {}): RedactionResult {
  const mode = options.mode ?? "standard";
  if (mode === "off") {
    return { redacted: input, report: emptyReport() };
  }
  let output = input;
  const report = emptyReport();

  output = redactByPattern(output, report, "email", EMAIL_RE);
  output = redactByPattern(output, report, "ip", IPV4_RE);
  output = output.replace(AUTH_HEADER_RE, (...args) => {
    const match = args[0];
    const token = args[1] ?? match;
    recordMatch(report, "auth", token);
    return `Authorization: [REDACTED:auth:${sha256Hex(String(token)).slice(0, 8)}]`;
  });
  output = redactByPattern(output, report, "openai_key", OPENAI_KEY_RE);
  output = redactByPattern(output, report, "aws_key", AWS_KEY_RE);
  output = redactByPattern(output, report, "slack_token", SLACK_TOKEN_RE);
  output = redactByPattern(output, report, "stripe_key", STRIPE_KEY_RE);
  output = output.replace(GENERIC_SECRET_RE, (...args) => {
    const match = args[0];
    const value = (args[1] ?? match) as string;
    recordMatch(report, "secret", value);
    return match.replace(value, `[REDACTED:secret:${sha256Hex(value).slice(0, 8)}]`);
  });
  output = redactByPattern(output, report, "eth_address", ETH_ADDRESS_RE);
  output = redactByPattern(output, report, "btc_address", BTC_ADDRESS_RE);
  output = redactByPattern(output, report, "txid", TXID_RE);

  if (mode === "strict") {
    output = redactByPattern(output, report, "strict_token", STRICT_TOKEN_RE);
    output = redactByPattern(output, report, "strict_base64", STRICT_BASE64_RE);
    output = redactByPattern(output, report, "strict_hex", STRICT_HEX_RE);
  }

  if (options.seedPhraseMode !== "off" && isSeedPhraseLike(output)) {
    recordMatch(report, "seed_phrase", output);
    output = `[REDACTED:seed_phrase:${sha256Hex(output).slice(0, 8)}]`;
  }

  return { redacted: output, report };
}
