import fs from "node:fs";
import path from "node:path";
import { loadPolicyConfig, type PresetName, getDefaultPolicyPath } from "./config.js";
import { runFirewallSetup, type SetupOptions } from "./setup.js";
import { runFirewallSetupWizard, WizardCancelledError, type WizardRunOptions } from "./wizard.js";
import { auditOpenClawConfig, formatAuditFindings } from "./audit.js";
import {
  readLastDecision,
  loadApprovalStore,
  loadApprovalRollup,
  rebuildApprovalRollupFromHistory
} from "./storage.js";
import {
  computeRecommendations,
  computeRecommendationsFromRollup,
  formatRecommendationsYaml
} from "./recommend.js";
import type { CommanderProgram, PluginLogger } from "./openclaw-types.js";

export type FirewallCliOptions = {
  logger?: PluginLogger;
  config?: Record<string, unknown>;
};

// Register firewall CLI commands for OpenClaw or the standalone CLI.
export function registerFirewallCli(program: CommanderProgram, options: FirewallCliOptions = {}): void {
  const logger = options.logger;
  const root = program;

  root
    .command("init")
    .description("Create a firewall policy file from a preset")
    .option("--preset <preset>", "Preset: strict|standard|dev")
    .option("--policy <path>", "Policy file path")
    .action((...args: unknown[]) => {
      const opts = getOptions(args);
      const preset = normalizePreset(opts.preset);
      const policyPath = typeof opts.policy === "string" ? opts.policy : getDefaultPolicyPath();
      const result = writePolicyFromPreset(policyPath, preset);
      if (result.ok) {
        logger?.info?.(`Policy created at ${policyPath} (${preset}).`);
      } else {
        logger?.error?.(`Failed to create policy at ${policyPath}: ${result.error}`);
      }
    });

  root
    .command("setup")
    .description("Configure OpenClaw to load the firewall (no-code setup)")
    .option("--config <path>", "OpenClaw config path")
    .option("--policy <path>", "Policy file path")
    .option("--preset <preset>", "Preset: strict|standard|dev")
    .option("--plugin-path <path>", "Firewall plugin entrypoint path")
    .option("--max-result-chars <n>", "Max tool result characters")
    .option("--max-result-action <action>", "truncate|block")
    .option("--audit-on-start <bool>", "true|false")
    .option("--quick", "Use the quick setup flow")
    .option("--advanced", "Use the advanced setup flow")
    .option("--interactive", "Run the guided wizard")
    .option("--non-interactive", "Disable prompts even in a TTY")
    .option("--yes", "Auto-write config + policy when using the wizard")
    .action(async (...args: unknown[]) => {
      const opts = getOptions(args);
      const isTty = Boolean(process.stdin.isTTY && process.stdout.isTTY);
      if ((opts.interactive === true || opts.yes === true) && !isTty) {
        logger?.error?.("Interactive wizard requires a TTY. Use --non-interactive for scripts.");
        return;
      }
      const shouldRunWizard = resolveWizardMode(opts);
      if (shouldRunWizard) {
        const wizardPrefill: NonNullable<WizardRunOptions["prefill"]> = {
          preset: normalizePreset(opts.preset),
          flow: resolveFlowFlag(opts, "advanced")
        };
        if (typeof opts.config === "string") {
          wizardPrefill.configPath = opts.config;
        }
        if (typeof opts.policy === "string") {
          wizardPrefill.policyPath = opts.policy;
        }
        if (typeof opts.pluginPath === "string") {
          wizardPrefill.pluginPath = opts.pluginPath;
        }
        const maxResultChars = parseNumber(opts.maxResultChars);
        if (typeof maxResultChars === "number") {
          wizardPrefill.maxResultChars = maxResultChars;
        }
        if (opts.maxResultAction === "block" || opts.maxResultAction === "truncate") {
          wizardPrefill.maxResultAction = opts.maxResultAction;
        }
        const auditOnStart = parseBoolean(opts.auditOnStart);
        if (typeof auditOnStart === "boolean") {
          wizardPrefill.auditOnStart = auditOnStart;
        }
        if (opts.yes === true) {
          wizardPrefill.autoWrite = true;
        }
        const wizardOptions: WizardRunOptions = { prefill: wizardPrefill };
        if (logger) {
          wizardOptions.logger = logger;
        }
        let result: Awaited<ReturnType<typeof runFirewallSetupWizard>>;
        try {
          result = await runFirewallSetupWizard(wizardOptions);
        } catch (err) {
          if (err instanceof WizardCancelledError) {
            logger?.info?.("Setup cancelled.");
            return;
          }
          throw err;
        }
        logger?.info?.(`OpenClaw config: ${result.configPath}`);
        logger?.info?.(`Policy path: ${result.policyPath}`);
        logger?.info?.(`Plugin path: ${result.pluginPath}`);
        if (result.wrotePolicy) {
          logger?.info?.("Policy file written.");
        }
        if (result.wroteConfig) {
          logger?.info?.("OpenClaw config updated with firewall settings.");
        }
        result.warnings.forEach((warning) => logger?.warn?.(warning));
        return;
      }
      const preset = normalizePreset(opts.preset);
      const maxResultChars = parseNumber(opts.maxResultChars);
      const maxResultAction =
        opts.maxResultAction === "block" || opts.maxResultAction === "truncate"
          ? (opts.maxResultAction as "block" | "truncate")
          : undefined;
      const auditOnStart = parseBoolean(opts.auditOnStart);
      const setupOptions: SetupOptions = { preset };
      if (typeof opts.config === "string") {
        setupOptions.configPath = opts.config;
      }
      if (typeof opts.policy === "string") {
        setupOptions.policyPath = opts.policy;
      }
      if (typeof opts.pluginPath === "string") {
        setupOptions.pluginPath = opts.pluginPath;
      }
      if (typeof maxResultChars === "number") {
        setupOptions.maxResultChars = maxResultChars;
      }
      if (maxResultAction) {
        setupOptions.maxResultAction = maxResultAction;
      }
      if (typeof auditOnStart === "boolean") {
        setupOptions.auditOnStart = auditOnStart;
      }
      const result = runFirewallSetup(setupOptions);
      logger?.info?.(`OpenClaw config: ${result.configPath}`);
      logger?.info?.(`Policy path: ${result.policyPath}`);
      logger?.info?.(`Plugin path: ${result.pluginPath}`);
      if (result.createdPolicy) {
        logger?.info?.("Policy file created from preset.");
      }
      if (result.updatedConfig) {
        logger?.info?.("OpenClaw config updated with firewall plugin settings.");
      }
      result.warnings.forEach((warning) => logger?.warn?.(warning));
    });

  root
    .command("install")
    .description("Install + configure the firewall plugin (guided installer)")
    .option("--config <path>", "OpenClaw config path")
    .option("--policy <path>", "Policy file path")
    .option("--preset <preset>", "Preset: strict|standard|dev")
    .option("--plugin-path <path>", "Firewall plugin entrypoint path")
    .option("--max-result-chars <n>", "Max tool result characters")
    .option("--max-result-action <action>", "truncate|block")
    .option("--audit-on-start <bool>", "true|false")
    .option("--quick", "Use the quick install flow")
    .option("--advanced", "Use the advanced setup flow")
    .option("--interactive", "Run the guided wizard")
    .option("--non-interactive", "Disable prompts even in a TTY")
    .option("--yes", "Auto-run installation and write config/policy")
    .action(async (...args: unknown[]) => {
      const opts = getOptions(args);
      const isTty = Boolean(process.stdin.isTTY && process.stdout.isTTY);
      if ((opts.interactive === true || opts.yes === true) && !isTty) {
        logger?.error?.("Interactive installer requires a TTY. Use --non-interactive for scripts.");
        return;
      }
      const shouldRunWizard = resolveWizardMode(opts);
      if (shouldRunWizard) {
        const wizardPrefill: NonNullable<WizardRunOptions["prefill"]> = {
          preset: normalizePreset(opts.preset),
          installMode: true,
          flow: resolveFlowFlag(opts, "quick")
        };
        if (typeof opts.config === "string") {
          wizardPrefill.configPath = opts.config;
        }
        if (typeof opts.policy === "string") {
          wizardPrefill.policyPath = opts.policy;
        }
        if (typeof opts.pluginPath === "string") {
          wizardPrefill.pluginPath = opts.pluginPath;
        }
        const maxResultChars = parseNumber(opts.maxResultChars);
        if (typeof maxResultChars === "number") {
          wizardPrefill.maxResultChars = maxResultChars;
        }
        if (opts.maxResultAction === "block" || opts.maxResultAction === "truncate") {
          wizardPrefill.maxResultAction = opts.maxResultAction;
        }
        const auditOnStart = parseBoolean(opts.auditOnStart);
        if (typeof auditOnStart === "boolean") {
          wizardPrefill.auditOnStart = auditOnStart;
        }
        if (opts.yes === true) {
          wizardPrefill.autoWrite = true;
        }
        const wizardOptions: WizardRunOptions = { prefill: wizardPrefill };
        if (logger) {
          wizardOptions.logger = logger;
        }
        let result: Awaited<ReturnType<typeof runFirewallSetupWizard>>;
        try {
          result = await runFirewallSetupWizard(wizardOptions);
        } catch (err) {
          if (err instanceof WizardCancelledError) {
            logger?.info?.("Install cancelled.");
            return;
          }
          throw err;
        }
        logger?.info?.(`OpenClaw config: ${result.configPath}`);
        logger?.info?.(`Policy path: ${result.policyPath}`);
        logger?.info?.(`Plugin path: ${result.pluginPath}`);
        if (result.wrotePolicy) {
          logger?.info?.("Policy file written.");
        }
        if (result.wroteConfig) {
          logger?.info?.("OpenClaw config updated with firewall settings.");
        }
        result.warnings.forEach((warning) => logger?.warn?.(warning));
        return;
      }
      logger?.error?.("Installer requires an interactive TTY. Use --interactive.");
    });

  root
    .command("validate")
    .description("Validate firewall policy configuration")
    .option("--policy <path>", "Policy file path")
    .option("--preset <preset>", "Preset: strict|standard|dev")
    .action((...args: unknown[]) => {
      const opts = getOptions(args);
      const preset = normalizePreset(opts.preset);
      const policyPath = typeof opts.policy === "string" ? opts.policy : getDefaultPolicyPath();
      const loaded = loadPolicyConfig({ policyPath, preset });
      if (loaded.warnings.length > 0) {
        loaded.warnings.forEach((warning) => logger?.warn?.(warning));
      }
      logger?.info?.(`Policy source: ${loaded.source}`);
    });

  root
    .command("explain")
    .description("Explain the last firewall decision")
    .action(() => {
      const last = readLastDecision();
      if (!last) {
        logger?.info?.("No firewall decisions recorded yet.");
        return;
      }
      logger?.info?.(`Last decision: ${last.decision ?? "n/a"}`);
      logger?.info?.(`Tool: ${last.toolName ?? "unknown"}`);
      logger?.info?.(`Risk: ${last.risk ?? "n/a"}`);
      logger?.info?.(`Reason: ${last.reason ?? "n/a"}`);
      logger?.info?.(`When: ${last.timestamp}`);
    });

  root
    .command("recommend")
    .description("Suggest policy changes based on approved requests")
    .option("--min <count>", "Minimum approvals required")
    .action((...args: unknown[]) => {
      const opts = getOptions(args);
      const min = parseMinCount(opts.min);
      const rollup = loadApprovalRollup();
      let recommendations = [];
      if (rollup) {
        recommendations = computeRecommendationsFromRollup(rollup, min);
      } else {
        const rebuilt = rebuildApprovalRollupFromHistory();
        if (rebuilt) {
          recommendations = computeRecommendationsFromRollup(rebuilt, min);
        } else {
          const store = loadApprovalStore();
          recommendations = computeRecommendations(store, min);
        }
      }
      const output = formatRecommendationsYaml(recommendations);
      logger?.info?.(output);
    });

  root
    .command("audit")
    .description("Audit OpenClaw config for common security gaps")
    .action(() => {
      if (!options.config) {
        logger?.info?.("Audit requires OpenClaw config. Run via `openclaw firewall audit`.");
        return;
      }
      const findings = auditOpenClawConfig(options.config);
      logger?.info?.(formatAuditFindings(findings));
    });
}

function normalizePreset(value: unknown): PresetName {
  if (value === "strict" || value === "standard" || value === "dev") {
    return value;
  }
  return "standard";
}

function getOptions(args: unknown[]): Record<string, unknown> {
  const last = args[args.length - 1];
  if (last && typeof last === "object") {
    const maybeCommand = last as { opts?: () => unknown };
    if (typeof maybeCommand.opts === "function") {
      const value = maybeCommand.opts();
      if (value && typeof value === "object") {
        return value as Record<string, unknown>;
      }
    }
    return last as Record<string, unknown>;
  }
  return {};
}

function parseMinCount(value: unknown): number {
  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 3;
}

function parseNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return undefined;
}

function parseBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") {
      return true;
    }
    if (normalized === "false") {
      return false;
    }
  }
  return undefined;
}

function resolveFlowFlag(options: Record<string, unknown>, fallback: "quick" | "advanced"): "quick" | "advanced" {
  if (options.quick === true) {
    return "quick";
  }
  if (options.advanced === true) {
    return "advanced";
  }
  return fallback;
}

function resolveWizardMode(options: Record<string, unknown>): boolean {
  if (options.nonInteractive === true) {
    return false;
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return false;
  }
  if (options.interactive === true || options.yes === true) {
    return true;
  }
  return !hasNonInteractiveFlags(options);
}

function hasNonInteractiveFlags(options: Record<string, unknown>): boolean {
  const keys = [
    "config",
    "policy",
    "preset",
    "pluginPath",
    "maxResultChars",
    "maxResultAction",
    "auditOnStart"
  ];
  return keys.some((key) => typeof options[key] !== "undefined");
}

function writePolicyFromPreset(policyPath: string, preset: PresetName): { ok: boolean; error?: string } {
  try {
    const presetUrl = new URL(`../presets/${preset}.yaml`, import.meta.url);
    const raw = fs.readFileSync(presetUrl, "utf8");
    const dir = path.dirname(policyPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(policyPath, raw);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}
