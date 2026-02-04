import type { RedactionReport } from "@mindaiproject/firewall-core";
import { redactString, type RedactionOptions } from "./detectors.js";

export type RedactValueResult = {
  redacted: unknown;
  report: RedactionReport;
};

type RedactionState = {
  seen: WeakMap<object, unknown>;
};

function emptyReport(): RedactionReport {
  return { redacted: false, matches: [] };
}

function mergeReports(a: RedactionReport, b: RedactionReport): RedactionReport {
  const merged: RedactionReport = {
    redacted: a.redacted || b.redacted,
    matches: [...a.matches]
  };
  for (const match of b.matches) {
    const existing = merged.matches.find((entry) => entry.type === match.type);
    if (existing) {
      existing.count += match.count;
      existing.hashes.push(...match.hashes);
    } else {
      merged.matches.push({ ...match });
    }
  }
  return merged;
}

// Deep-redact string fields while preserving structure.
export function redactValue(value: unknown, options: RedactionOptions = {}): RedactValueResult {
  const state: RedactionState = { seen: new WeakMap<object, unknown>() };
  return redactValueWithState(value, options, state);
}

function redactValueWithState(
  value: unknown,
  options: RedactionOptions,
  state: RedactionState
): RedactValueResult {
  if (options.mode === "off") {
    return { redacted: value, report: emptyReport() };
  }
  if (typeof value === "string") {
    const result = redactString(value, options);
    return { redacted: result.redacted, report: result.report };
  }

  if (Array.isArray(value)) {
    const cached = state.seen.get(value);
    if (cached) {
      return { redacted: cached, report: emptyReport() };
    }
    let report = emptyReport();
    const redactedArray: unknown[] = [];
    state.seen.set(value, redactedArray);
    for (const item of value) {
      const next = redactValueWithState(item, options, state);
      report = mergeReports(report, next.report);
      redactedArray.push(next.redacted);
    }
    return { redacted: redactedArray, report };
  }

  if (value && typeof value === "object") {
    const cached = state.seen.get(value);
    if (cached) {
      return { redacted: cached, report: emptyReport() };
    }
    let report = emptyReport();
    const record = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};
    state.seen.set(value, output);
    for (const key of Object.keys(record)) {
      const next = redactValueWithState(record[key], options, state);
      output[key] = next.redacted;
      report = mergeReports(report, next.report);
    }
    return { redacted: output, report };
  }

  return { redacted: value, report: emptyReport() };
}
