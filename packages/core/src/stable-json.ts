import crypto from "node:crypto";

// Deterministic JSON stringify for hashing and request IDs.
export function stableStringify(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const next: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      next[key] = sortValue(record[key]);
    }
    return next;
  }
  return value;
}

// Hash helper to avoid storing raw values in approvals or logs.
export function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function hashObject(value: unknown): string {
  return sha256Hex(stableStringify(value));
}
