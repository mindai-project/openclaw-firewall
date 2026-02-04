import path from "node:path";
import { normalizeToolName } from "@mindaiproject/firewall-core";

export type PathGuardResult = {
  allowed: boolean;
  reason: string;
  toolPaths: string[];
  unmatched: string[];
};

type PathGuardInput = {
  toolName: string;
  params: Record<string, unknown>;
  allowPaths: string[];
  resolvePath?: (input: string) => string;
};

// Evaluate tool path usage against a configured allowlist.
export function evaluatePathAllowlist(input: PathGuardInput): PathGuardResult {
  const toolName = normalizeToolName(input.toolName);
  const toolPaths = extractToolPaths(toolName, input.params);
  if (toolPaths.length === 0) {
    return {
      allowed: false,
      reason: "No path argument found for path allowlist enforcement.",
      toolPaths: [],
      unmatched: []
    };
  }

  const allowPaths = input.allowPaths
    .filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
    .map((entry) => resolvePathSafe(input.resolvePath, entry))
    .filter((entry): entry is string => typeof entry === "string" && entry.length > 0);

  const normalizedToolPaths = toolPaths
    .map((entry) => resolvePathSafe(input.resolvePath, entry))
    .filter((entry): entry is string => typeof entry === "string" && entry.length > 0);

  const unmatched = normalizedToolPaths.filter(
    (candidate) => !allowPaths.some((allowed) => isPathAllowed(candidate, allowed))
  );

  if (unmatched.length > 0) {
    return {
      allowed: false,
      reason: "Path is outside the allowed path list.",
      toolPaths: normalizedToolPaths,
      unmatched
    };
  }

  return {
    allowed: true,
    reason: "Path allowlist matched.",
    toolPaths: normalizedToolPaths,
    unmatched: []
  };
}

function extractToolPaths(toolName: string, params: Record<string, unknown>): string[] {
  if (!params || typeof params !== "object") {
    return [];
  }
  const record = params as Record<string, unknown>;
  const normalized = normalizeToolName(toolName);

  if (normalized === "read" || normalized === "write" || normalized === "edit") {
    const pathValue =
      (typeof record.path === "string" && record.path) ||
      (typeof record.file_path === "string" && record.file_path) ||
      (typeof record.filePath === "string" && record.filePath) ||
      "";
    const pathList =
      readStringArray(record.paths) ??
      readStringArray(record.file_paths) ??
      readStringArray(record.filePaths) ??
      [];
    const combined = pathValue ? [pathValue, ...pathList] : pathList;
    return combined.filter(Boolean);
  }

  if (normalized === "apply_patch") {
    const input = typeof record.input === "string" ? record.input : "";
    return extractPatchPaths(input);
  }

  return [];
}

function readStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const entries = value.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0);
  return entries.length > 0 ? entries : [];
}

function extractPatchPaths(input: string): string[] {
  if (!input.trim()) {
    return [];
  }
  const markers = ["*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "];
  const lines = input.split(/\r?\n/);
  const results: string[] = [];
  for (const line of lines) {
    for (const marker of markers) {
      if (line.startsWith(marker)) {
        const value = line.slice(marker.length).trim();
        if (value) {
          results.push(value);
        }
        break;
      }
    }
  }
  return Array.from(new Set(results));
}

function resolvePathSafe(
  resolver: ((input: string) => string) | undefined,
  input: string
): string | null {
  try {
    const resolved = resolver ? resolver(input) : input;
    return path.resolve(resolved);
  } catch {
    return null;
  }
}

function isPathAllowed(candidate: string, allowed: string): boolean {
  if (candidate === allowed) {
    return true;
  }
  return candidate.startsWith(`${allowed}${path.sep}`);
}
