import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import yaml from "yaml";
import type { Policy } from "@mindaiproject/firewall-core";
import { getDefaultPolicyPath, type PresetName } from "./config.js";
import type { RateLimitRule } from "./rate-limit.js";

export type SetupOptions = {
  configPath?: string;
  policyPath?: string;
  preset?: PresetName;
  pluginPath?: string;
  maxResultChars?: number;
  maxResultAction?: "truncate" | "block";
  auditOnStart?: boolean;
  rateLimits?: RateLimitRule[];
};

export type SetupResult = {
  configPath: string;
  policyPath: string;
  pluginPath: string;
  createdPolicy: boolean;
  updatedConfig: boolean;
  warnings: string[];
};

type ConfigFormat = "json" | "yaml";

const DEFAULT_CONFIG_FILENAME = "openclaw.json";
export const FIREWALL_PLUGIN_ID = "openclaw-tool-firewall";
export const LEGACY_PLUGIN_IDS = ["mindai-openclaw-tool-firewall"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

export function getFirewallPluginConfig(config: Record<string, unknown>): Record<string, unknown> | null {
  const plugins = isRecord(config.plugins) ? config.plugins : null;
  if (!plugins) {
    return null;
  }
  const entries = isRecord(plugins.entries) ? plugins.entries : null;
  if (!entries) {
    return null;
  }
  const primary = isRecord(entries[FIREWALL_PLUGIN_ID]) ? entries[FIREWALL_PLUGIN_ID] : null;
  const primaryConfig = primary && isRecord(primary.config) ? primary.config : null;
  if (primaryConfig) {
    return primaryConfig;
  }
  for (const legacyId of LEGACY_PLUGIN_IDS) {
    const legacy = isRecord(entries[legacyId]) ? entries[legacyId] : null;
    const legacyConfig = legacy && isRecord(legacy.config) ? legacy.config : null;
    if (legacyConfig) {
      return legacyConfig;
    }
  }
  return null;
}

export function resolveOpenClawConfigPath(override?: string): string {
  if (override && override.trim()) {
    return override.trim();
  }
  const envConfig = process.env.OPENCLAW_CONFIG_PATH?.trim();
  if (envConfig) {
    return envConfig;
  }
  const envState = process.env.OPENCLAW_STATE_DIR?.trim();
  if (envState) {
    return path.join(envState, DEFAULT_CONFIG_FILENAME);
  }
  return path.join(os.homedir(), ".openclaw", DEFAULT_CONFIG_FILENAME);
}

function resolveExistingPath(candidates: string[]): string | null {
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function findUpwards(startDir: string, filename: string): string | null {
  let current = startDir;
  for (let depth = 0; depth < 6; depth += 1) {
    const candidate = path.join(current, filename);
    if (fs.existsSync(candidate)) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return null;
}

function resolveFromCurrentInstall(): string | null {
  try {
    const currentFile = fileURLToPath(import.meta.url);
    const currentDir = path.dirname(currentFile);
    const root = findUpwards(currentDir, "openclaw.plugin.json");
    if (root) {
      if (path.basename(root) === "dist") {
        const parent = path.dirname(root);
        if (fs.existsSync(path.join(parent, "package.json"))) {
          return parent;
        }
      }
      return root;
    }
    const candidates: string[] = [
      path.join(currentDir, "mindai-openclaw-tool-firewall.js"),
      path.join(currentDir, "index.js"),
      path.resolve(currentDir, "..", "dist", "mindai-openclaw-tool-firewall.js"),
      path.resolve(currentDir, "..", "dist", "index.js")
    ];
    return resolveExistingPath(candidates);
  } catch {
    return null;
  }
}

export function resolvePluginEntrypoint(explicitPath?: string): string | null {
  if (explicitPath && explicitPath.trim()) {
    return explicitPath.trim();
  }

  const localInstall = resolveFromCurrentInstall();
  if (localInstall) {
    return localInstall;
  }

  try {
    const require = createRequire(import.meta.url);
    // Resolve package root via package.json to avoid export map restrictions.
    const pkgPath = require.resolve("@mindaiproject/openclaw-tool-firewall/package.json");
    const pkgDir = path.dirname(pkgPath);
    if (fs.existsSync(pkgDir)) {
      return pkgDir;
    }
  } catch {
    // ignore
  }
  return null;
}

function detectFormat(configPath: string): ConfigFormat {
  const ext = path.extname(configPath).toLowerCase();
  return ext === ".yml" || ext === ".yaml" ? "yaml" : "json";
}

function parseConfig(raw: string, format: ConfigFormat): Record<string, unknown> {
  if (!raw.trim()) {
    return {};
  }
  if (format === "yaml") {
    const parsed = yaml.parse(raw);
    if (!isRecord(parsed)) {
      throw new Error("Config root must be an object.");
    }
    return parsed;
  }
  const parsed = JSON.parse(raw) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("Config root must be an object.");
  }
  return parsed;
}

function stringifyConfig(config: Record<string, unknown>, format: ConfigFormat): string {
  if (format === "yaml") {
    return `${yaml.stringify(config, { indent: 2 })}`.trimEnd() + "\n";
  }
  return `${JSON.stringify(config, null, 2)}\n`;
}

export function loadOpenClawConfig(configPath: string): {
  config: Record<string, unknown>;
  format: ConfigFormat;
  existed: boolean;
} {
  const format = detectFormat(configPath);
  if (!fs.existsSync(configPath)) {
    return { config: {}, format, existed: false };
  }
  const raw = fs.readFileSync(configPath, "utf8");
  return { config: parseConfig(raw, format), format, existed: true };
}

export function writeOpenClawConfig(
  configPath: string,
  config: Record<string, unknown>,
  format: ConfigFormat
): void {
  const dir = path.dirname(configPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(configPath, stringifyConfig(config, format));
}

export function writePolicyFile(policyPath: string, policy: Policy): void {
  const dir = path.dirname(policyPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const raw = yaml.stringify(policy, { indent: 2 });
  fs.writeFileSync(policyPath, raw.trimEnd() + "\n");
}

export function applyFirewallConfig(
  config: Record<string, unknown>,
  params: {
    pluginPath: string;
    policyPath: string;
    preset: PresetName;
    maxResultChars?: number;
    maxResultAction?: "truncate" | "block";
    auditOnStart?: boolean;
    rateLimits?: RateLimitRule[];
  }
): { config: Record<string, unknown>; changed: boolean; warnings: string[] } {
  const warnings: string[] = [];
  const pluginPath = params.pluginPath;
  const normalizedPluginPath = path.normalize(pluginPath);

  const nextConfig: Record<string, unknown> = { ...config };
  const plugins = isRecord(nextConfig.plugins) ? { ...nextConfig.plugins } : {};
  const load = isRecord(plugins.load) ? { ...plugins.load } : {};
  const existingPaths = Array.isArray(load.paths) ? load.paths.slice() : [];

  const filteredPaths = existingPaths.filter((entry) => {
    if (typeof entry !== "string") {
      return false;
    }
    const normalized = path.normalize(entry);
    if (!normalized.includes("@mindaiproject/openclaw-tool-firewall")) {
      return true;
    }
    return normalized === normalizedPluginPath;
  });

  if (!filteredPaths.includes(pluginPath)) {
    filteredPaths.push(pluginPath);
  }

  load.paths = filteredPaths;
  plugins.load = load;

  const entries = isRecord(plugins.entries) ? { ...plugins.entries } : {};
  for (const legacyId of LEGACY_PLUGIN_IDS) {
    if (legacyId in entries) {
      delete entries[legacyId];
      warnings.push(`Removed legacy plugin entry: ${legacyId}.`);
    }
  }
  const existingEntry = isRecord(entries[FIREWALL_PLUGIN_ID])
    ? { ...entries[FIREWALL_PLUGIN_ID] }
    : {};
  const existingConfig = isRecord(existingEntry.config) ? { ...existingEntry.config } : {};
  const rateLimitsProvided = Object.prototype.hasOwnProperty.call(params, "rateLimits");

  const nextEntry = {
    ...existingEntry,
    enabled: true,
    config: {
      ...existingConfig,
      preset: params.preset,
      policyPath: params.policyPath,
      ...(typeof params.maxResultChars === "number" ? { maxResultChars: params.maxResultChars } : {}),
      ...(params.maxResultAction ? { maxResultAction: params.maxResultAction } : {}),
      ...(typeof params.auditOnStart === "boolean" ? { auditOnStart: params.auditOnStart } : {}),
      ...(rateLimitsProvided ? { rateLimits: params.rateLimits ?? [] } : {})
    }
  };

  entries[FIREWALL_PLUGIN_ID] = nextEntry;
  plugins.entries = entries;
  nextConfig.plugins = plugins;

  const changed = JSON.stringify(config) !== JSON.stringify(nextConfig);
  if (!isRecord(config.plugins)) {
    warnings.push("Created plugins config block.");
  }
  return { config: nextConfig, changed, warnings };
}

export function ensurePolicyFile(params: {
  policyPath?: string;
  preset: PresetName;
}): { policyPath: string; created: boolean } {
  const policyPath = params.policyPath?.trim() || getDefaultPolicyPath();
  if (fs.existsSync(policyPath)) {
    return { policyPath, created: false };
  }
  const presetUrl = new URL(`../presets/${params.preset}.yaml`, import.meta.url);
  const raw = fs.readFileSync(presetUrl, "utf8");
  const dir = path.dirname(policyPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(policyPath, raw);
  return { policyPath, created: true };
}

export function runFirewallSetup(options: SetupOptions = {}): SetupResult {
  const preset = options.preset ?? "standard";
  const configPath = resolveOpenClawConfigPath(options.configPath);
  const pluginPath = resolvePluginEntrypoint(options.pluginPath);
  if (!pluginPath) {
    throw new Error("Failed to resolve firewall plugin entrypoint. Pass --plugin-path.");
  }

  const policyParams: { preset: PresetName; policyPath?: string } = { preset };
  if (typeof options.policyPath === "string") {
    policyParams.policyPath = options.policyPath;
  }
  const policy = ensurePolicyFile(policyParams);
  const loaded = loadOpenClawConfig(configPath);
  const applyParams: {
    pluginPath: string;
    policyPath: string;
    preset: PresetName;
    maxResultChars?: number;
    maxResultAction?: "truncate" | "block";
    auditOnStart?: boolean;
    rateLimits?: RateLimitRule[];
  } = { pluginPath, policyPath: policy.policyPath, preset };
  if (typeof options.maxResultChars === "number") {
    applyParams.maxResultChars = options.maxResultChars;
  }
  if (options.maxResultAction) {
    applyParams.maxResultAction = options.maxResultAction;
  }
  if (typeof options.auditOnStart === "boolean") {
    applyParams.auditOnStart = options.auditOnStart;
  }
  if (typeof options.rateLimits !== "undefined") {
    applyParams.rateLimits = options.rateLimits;
  }
  const applied = applyFirewallConfig(loaded.config, applyParams);

  if (applied.changed || !loaded.existed) {
    writeOpenClawConfig(configPath, applied.config, loaded.format);
  }

  return {
    configPath,
    policyPath: policy.policyPath,
    pluginPath,
    createdPolicy: policy.created,
    updatedConfig: applied.changed || !loaded.existed,
    warnings: applied.warnings
  };
}
