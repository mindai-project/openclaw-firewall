import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { stdout as output } from "node:process";
import {
  cancel,
  confirm as clackConfirm,
  intro as clackIntro,
  isCancel,
  multiselect as clackMultiselect,
  note as clackNote,
  outro as clackOutro,
  select as clackSelect,
  text as clackText
} from "@clack/prompts";
import {
  normalizeToolName,
  normalizeToolRule,
  type Decision,
  type Policy,
  type Risk,
  type ToolRule
} from "@mindai/firewall-core";
import { getDefaultPolicyPath, loadPolicyConfig, loadPresetPolicyOnly, type PresetName } from "./config.js";
import {
  applyFirewallConfig,
  getFirewallPluginConfig,
  loadOpenClawConfig,
  resolveOpenClawConfigPath,
  resolvePluginEntrypoint,
  writeOpenClawConfig,
  writePolicyFile
} from "./setup.js";
import type { RateLimitRule } from "./rate-limit.js";
import type { PluginLogger } from "./openclaw-types.js";

type WizardPrefill = {
  configPath?: string;
  policyPath?: string;
  preset?: PresetName;
  pluginPath?: string;
  maxResultChars?: number;
  maxResultAction?: "truncate" | "block";
  auditOnStart?: boolean;
  rateLimits?: RateLimitRule[];
  autoWrite?: boolean;
  installMode?: boolean;
  flow?: "quick" | "advanced";
};

export type WizardRunOptions = {
  logger?: PluginLogger;
  prefill?: WizardPrefill;
  prompt?: Prompt;
};

export type WizardRunResult = {
  configPath: string;
  policyPath: string;
  pluginPath: string;
  preset: PresetName;
  policy: Policy;
  flow: "quick" | "advanced";
  install: InstallSummary;
  maxResultChars?: number;
  maxResultAction?: "truncate" | "block";
  auditOnStart?: boolean;
  rateLimits?: RateLimitRule[];
  wrotePolicy: boolean;
  wroteConfig: boolean;
  warnings: string[];
};

type Choice<T extends string> = {
  value: T;
  label: string;
  detail: string;
};

type Prompt = {
  ask: (prompt: string, fallback?: string) => Promise<string>;
  choose: <T extends string>(prompt: string, choices: Choice<T>[], fallback: T) => Promise<T>;
  confirm: (prompt: string, fallback: boolean) => Promise<boolean>;
  number: (prompt: string, fallback: number) => Promise<number>;
  multiselect?: <T extends string>(
    prompt: string,
    choices: Choice<T>[],
    initialValues: T[]
  ) => Promise<T[]>;
  intro?: (title: string) => Promise<void>;
  outro?: (message: string) => Promise<void>;
  note?: (message: string, title?: string) => Promise<void>;
  close: () => void;
};

type Style = {
  bold: (text: string) => string;
  dim: (text: string) => string;
  cyan: (text: string) => string;
};

type RateLimitSelection = {
  rateLimits: RateLimitRule[];
  provided: boolean;
};

type InstallSummary = {
  mode: "skip" | "manual" | "auto";
  steps: Array<{ label: string; command: string; ok?: boolean; error?: string }>;
  warnings: string[];
};

type SetupFlow = "quick" | "advanced";

const DECISION_CHOICES: Choice<Decision>[] = [
  { value: "ALLOW", label: "Allow", detail: "Run automatically without asking." },
  { value: "ASK", label: "Ask", detail: "Require human approval." },
  { value: "DENY", label: "Deny", detail: "Block the tool entirely." }
];

const RISK_CHOICES: Choice<Risk>[] = [
  { value: "read", label: "Read", detail: "Non-destructive or read-only tools." },
  { value: "write", label: "Write", detail: "Creates or edits data." },
  { value: "critical", label: "Critical", detail: "High-impact or system-level actions." },
  { value: "unknown", label: "Unknown", detail: "Unclassified tools." }
];

const REDACTION_CHOICES: Choice<Policy["defaults"]["redaction"]>[] = [
  { value: "standard", label: "Standard", detail: "Recommended for most users." },
  { value: "strict", label: "Strict", detail: "Extra aggressive masking." },
  { value: "off", label: "Off", detail: "No redaction (not recommended)." }
];

const LOG_CHOICES: Choice<Policy["defaults"]["log"]>[] = [
  { value: "safe", label: "Safe", detail: "Redacted, minimal logs." },
  { value: "debug", label: "Debug", detail: "More structure, still redacted." }
];

const INJECTION_CHOICES: Choice<Policy["defaults"]["injection"]["mode"]>[] = [
  { value: "shadow", label: "Shadow", detail: "Detect only, no user-visible warning." },
  { value: "alert", label: "Alert", detail: "Warn the model when injection is detected." },
  { value: "block", label: "Block", detail: "Replace suspicious output with a warning." }
];

const MAX_RESULT_ACTION_CHOICES: Choice<"truncate" | "block">[] = [
  { value: "truncate", label: "Truncate", detail: "Cut tool output to the limit." },
  { value: "block", label: "Block", detail: "Replace with a warning instead." }
];

const RATE_LIMIT_ACTION_CHOICES: Choice<Decision>[] = [
  { value: "ASK", label: "Ask", detail: "Require approval when limit is exceeded." },
  { value: "DENY", label: "Deny", detail: "Block when limit is exceeded." }
];

const RATE_LIMIT_SCOPE_CHOICES: Choice<"session" | "global">[] = [
  { value: "session", label: "Session", detail: "Limit per session (recommended)." },
  { value: "global", label: "Global", detail: "Limit across all sessions." }
];

export async function runFirewallSetupWizard(options: WizardRunOptions = {}): Promise<WizardRunResult> {
  const logger = options.logger ?? console;
  const prompt = options.prompt ?? createPrompt();
  const shouldClosePrompt = !options.prompt;
  const prefill = options.prefill ?? {};
  const installMode = prefill.installMode === true;

  try {
    if (prompt.intro) {
      printWizardHeader(logger, installMode ? "MindAI Firewall Installer" : "MindAI Firewall Setup Wizard");
      await prompt.intro(installMode ? "MindAI Firewall Installer" : "MindAI Firewall Setup Wizard");
    }

    await logSection(prompt, logger, installMode ? "Installer" : "Setup Wizard", [
      "This wizard configures OpenClaw + the firewall policy.",
      "Press Enter to accept defaults shown in brackets."
    ]);

    const flow = await resolveSetupFlow(prompt, prefill);
    const installSummary = installMode ? await configureInstaller(prompt, logger, prefill) : emptyInstallSummary("skip");

    const configPath = await prompt.ask(
      "OpenClaw config path",
      prefill.configPath ?? resolveOpenClawConfigPath()
    );
    const loadedConfig = loadOpenClawConfig(configPath);
    const existingPluginConfig = getFirewallPluginConfig(loadedConfig.config);
    const existingPreset = parsePresetName(existingPluginConfig?.preset);
    const existingPolicyPath = readString(existingPluginConfig?.policyPath);
    const existingMaxResultChars = readNumber(existingPluginConfig?.maxResultChars);
    const existingMaxResultAction = parseMaxResultAction(existingPluginConfig?.maxResultAction);
    const existingAuditOnStart = readBoolean(existingPluginConfig?.auditOnStart);
    const existingRateLimits = coerceRateLimits(existingPluginConfig?.rateLimits);

    const preset = await prompt.choose(
      "Pick a starting preset",
      [
        { value: "strict", label: "Strict", detail: "Deny most risky tools." },
        { value: "standard", label: "Standard", detail: "Balanced defaults (recommended)." },
        { value: "dev", label: "Dev", detail: "Lenient for local development." }
      ],
      prefill.preset ?? existingPreset ?? "standard"
    );

    const policyPath = await prompt.ask(
      "Firewall policy path",
      prefill.policyPath ?? existingPolicyPath ?? getDefaultPolicyPath()
    );

    const policyExists = fs.existsSync(policyPath);
    const useExisting =
      policyExists &&
      (await prompt.confirm(
        "Existing policy found. Use it as the base?",
        false
      ));

    const basePolicy = useExisting
      ? loadPolicyConfig({ preset, policyPath }).policy
      : loadPresetPolicyOnly(preset);

    const policy = structuredClone(basePolicy);
    policy.mode = preset;

    let rateLimits: RateLimitRule[] = [];
    let rateLimitsProvided = false;

    if (flow === "advanced") {
      await logSection(prompt, logger, "Defaults", [
        "These settings apply when a tool does not override them."
      ]);

      policy.defaults.denyUnknownTools = await prompt.confirm(
        "Deny unknown tools by default?",
        policy.defaults.denyUnknownTools
      );

      policy.defaults.unknownToolAction = await prompt.choose(
        "Unknown tool action",
        DECISION_CHOICES,
        policy.defaults.unknownToolAction
      );

      policy.defaults.log = await prompt.choose(
        "Log level",
        LOG_CHOICES,
        policy.defaults.log
      );

      policy.defaults.redaction = await prompt.choose(
        "Redaction mode",
        REDACTION_CHOICES,
        policy.defaults.redaction
      );

      policy.defaults.injection.mode = await prompt.choose(
        "Injection scanner mode",
        INJECTION_CHOICES,
        policy.defaults.injection.mode
      );

      await logSection(prompt, logger, "Risk Defaults", [
        "Used when a tool does not specify its own action."
      ]);

      policy.risk.read = await prompt.choose(
        "Default action for READ tools",
        DECISION_CHOICES,
        policy.risk.read
      );
      policy.risk.write = await prompt.choose(
        "Default action for WRITE tools",
        DECISION_CHOICES,
        policy.risk.write
      );
      policy.risk.critical = await prompt.choose(
        "Default action for CRITICAL tools",
        DECISION_CHOICES,
        policy.risk.critical
      );
      policy.risk.unknown = await prompt.choose(
        "Default action for UNKNOWN tools",
        DECISION_CHOICES,
        policy.risk.unknown
      );

      await configureToolRules(prompt, logger, policy);

      const rateLimitSelection = await configureRateLimits(
        prompt,
        logger,
        prefill.rateLimits ?? existingRateLimits
      );
      rateLimits = rateLimitSelection.rateLimits;
      rateLimitsProvided = rateLimitSelection.provided;
    } else {
      rateLimits = existingRateLimits;
      rateLimitsProvided = false;
    }

    await logSection(prompt, logger, "Output Guard", [
      "Limit large tool results to reduce prompt injection surface."
    ]);

    const enableMaxResult = await prompt.confirm(
      "Enable output size guard?",
      Boolean(prefill.maxResultChars ?? existingMaxResultChars)
    );
    const maxResultChars = enableMaxResult
      ? await prompt.number("Max result characters", prefill.maxResultChars ?? existingMaxResultChars ?? 8000)
      : undefined;
    const maxResultAction = enableMaxResult
      ? await prompt.choose(
          "When the limit is exceeded",
          MAX_RESULT_ACTION_CHOICES,
          prefill.maxResultAction ?? existingMaxResultAction ?? "truncate"
        )
      : undefined;

    const auditOnStart = await prompt.confirm(
      "Run OpenClaw config audit on startup?",
      prefill.auditOnStart ?? existingAuditOnStart ?? true
    );

    const pluginPath = resolvePluginEntrypoint(prefill.pluginPath);
    if (!pluginPath) {
      throw new Error(
        "Failed to resolve firewall plugin entrypoint. Pass --plugin-path (for example: ~/.openclaw/extensions/openclaw-tool-firewall/dist/index.js)."
      );
    }

    const rateLimitSummary = rateLimitsProvided
      ? (rateLimits.length > 0 ? `${rateLimits.length} rule(s)` : "cleared")
      : (existingRateLimits.length > 0 ? `${existingRateLimits.length} rule(s) (unchanged)` : "none");

    await logSection(prompt, logger, "Summary", [
      `Flow: ${flow === "quick" ? "Quick (recommended)" : "Advanced"}`,
      `Config path: ${configPath}`,
      `Policy path: ${policyPath}`,
      `Preset: ${preset}`,
      `Plugin entrypoint: ${pluginPath}`,
      `Rate limits: ${rateLimitSummary}`,
      `Output guard: ${maxResultChars ? `${maxResultChars} chars (${maxResultAction})` : "disabled"}`,
      `Audit on start: ${auditOnStart ? "enabled" : "disabled"}`,
      ...renderInstallSummary(installSummary)
    ]);

    const shouldWrite =
      prefill.autoWrite ??
      (await prompt.confirm(installMode ? "Proceed with installation?" : "Write config + policy now?", true));

    let wrotePolicy = false;
    let wroteConfig = false;
    const warnings: string[] = [];

    if (shouldWrite) {
      if (installMode) {
        const installWarnings = await runInstallerSteps(installSummary, logger);
        warnings.push(...installWarnings);
      }
      writePolicyFile(policyPath, policy);
      wrotePolicy = true;

      const loaded = loadOpenClawConfig(configPath);
      const applyParams: {
        pluginPath: string;
        policyPath: string;
        preset: PresetName;
        maxResultChars?: number;
        maxResultAction?: "truncate" | "block";
        auditOnStart?: boolean;
        rateLimits?: RateLimitRule[];
      } = { pluginPath, policyPath, preset };
      if (typeof maxResultChars === "number") {
        applyParams.maxResultChars = maxResultChars;
      }
      if (maxResultAction) {
        applyParams.maxResultAction = maxResultAction;
      }
      if (typeof auditOnStart === "boolean") {
        applyParams.auditOnStart = auditOnStart;
      }
      if (rateLimitsProvided) {
        applyParams.rateLimits = rateLimits;
      }
      const applied = applyFirewallConfig(loaded.config, applyParams);
      warnings.push(...applied.warnings);
      if (applied.changed || !loaded.existed) {
        writeOpenClawConfig(configPath, applied.config, loaded.format);
        wroteConfig = true;
      }
    }

    const result: WizardRunResult = {
      configPath,
      policyPath,
      pluginPath,
      preset,
      policy,
      flow,
      install: installSummary,
      ...(typeof maxResultChars === "number" ? { maxResultChars } : {}),
      ...(maxResultAction ? { maxResultAction } : {}),
      ...(typeof auditOnStart === "boolean" ? { auditOnStart } : {}),
      ...(rateLimitsProvided ? { rateLimits } : {}),
      wrotePolicy,
      wroteConfig,
      warnings
    };
    if (prompt.outro) {
      const summary =
        wrotePolicy || wroteConfig
          ? "Setup complete. Configuration updated."
          : "Setup complete. No files were written.";
      await prompt.outro(summary);
    }
    return result;
  } finally {
    if (shouldClosePrompt) {
      prompt.close();
    }
  }
}

async function configureToolRules(prompt: Prompt, logger: PluginLogger, policy: Policy): Promise<void> {
  await logSection(prompt, logger, "Tool Rules", [
    "Decide how specific tools behave. Press Enter to keep defaults."
  ]);

  const toolNames = policy.tools.map((rule) => rule.name);
  const mode = await prompt.choose(
    "Customize tool rules?",
    [
      { value: "none", label: "No", detail: "Keep preset tool rules." },
      { value: "some", label: "Select", detail: "Pick specific tools to customize." },
      { value: "all", label: "All", detail: "Review every tool rule." }
    ],
    "none"
  );

  const selected =
    mode === "all" ? toolNames : mode === "some" ? await selectTools(prompt, toolNames) : [];

  const toolMap = new Map<string, ToolRule>();
  policy.tools.forEach((rule) => toolMap.set(normalizeToolName(rule.name), { ...rule }));

  for (const toolName of selected) {
    const normalized = normalizeToolName(toolName);
    const existing = toolMap.get(normalized) ?? { name: normalized };
    const updated = await promptToolRule(prompt, logger, policy, existing);
    toolMap.set(normalized, updated);
  }

  const addCustom = await prompt.confirm("Add a custom tool rule?", false);
  if (addCustom) {
    let addMore = true;
    while (addMore) {
      const rawName = await prompt.ask("Tool name", "");
      const trimmed = rawName.trim();
      if (trimmed) {
        const name = normalizeToolName(trimmed);
        const existing = toolMap.get(name) ?? { name };
        const updated = await promptToolRule(prompt, logger, policy, existing);
        toolMap.set(name, updated);
      }
      addMore = await prompt.confirm("Add another custom tool?", false);
    }
  }

  policy.tools = Array.from(toolMap.values());
}

async function promptToolRule(
  prompt: Prompt,
  logger: PluginLogger,
  policy: Policy,
  rule: ToolRule
): Promise<ToolRule> {
  const toolName = normalizeToolName(rule.name);
  await logSection(prompt, logger, `Tool: ${toolName}`, [
    "Configure action and safety checks for this tool."
  ]);

  const risk = await prompt.choose(
    `Risk level for ${toolName}`,
    RISK_CHOICES,
    rule.risk ?? "unknown"
  );

  const defaultAction = normalizeToolRule(policy, { ...rule, risk }).action;
  const action = await prompt.choose(
    `Decision for ${toolName}`,
    DECISION_CHOICES,
    defaultAction
  );

  const redactParams = await prompt.confirm(
    `Redact params for ${toolName}?`,
    rule.redactParams ?? true
  );
  const redactResult = await prompt.confirm(
    `Redact results for ${toolName}?`,
    rule.redactResult ?? true
  );
  const scanInjection = await prompt.confirm(
    `Scan output for prompt injection for ${toolName}?`,
    rule.scanInjection ?? true
  );

  const updated: ToolRule = {
    ...rule,
    name: toolName,
    risk,
    action,
    redactParams,
    redactResult,
    scanInjection
  };

  if (toolName === "exec") {
    updated.useExecApprovals = await prompt.confirm(
      "Delegate exec approvals to OpenClaw?",
      rule.useExecApprovals ?? true
    );
  }

  if (isPathTool(toolName)) {
    const setAllowPaths = await prompt.confirm(
      `Configure allowed paths for ${toolName}?`,
      Boolean(rule.allowPaths && rule.allowPaths.length > 0)
    );
    if (setAllowPaths) {
      const existing = rule.allowPaths?.join(", ") ?? "";
      const raw = await prompt.ask("Allowed paths (comma-separated, or 'none' to clear)", existing);
      const trimmed = raw.trim();
      if (trimmed.toLowerCase() === "none") {
        delete updated.allowPaths;
        delete updated.pathAction;
      } else {
        const paths = trimmed
          .split(",")
          .map((entry) => entry.trim())
          .filter((entry) => entry.length > 0);
        if (paths.length > 0) {
          updated.allowPaths = paths;
          updated.pathAction = await prompt.choose(
            "Action when a path is outside the allowlist",
            DECISION_CHOICES,
            rule.pathAction ?? "ASK"
          );
        }
      }
    }
  }

  return updated;
}

async function configureRateLimits(
  prompt: Prompt,
  logger: PluginLogger,
  existing?: RateLimitRule[]
): Promise<RateLimitSelection> {
  await logSection(prompt, logger, "Rate Limits", [
    "Optional per-tool limits to slow down bursty or risky calls."
  ]);

  const hasExisting = Boolean(existing && existing.length > 0);
  if (hasExisting) {
    const mode = await prompt.choose(
      "Rate limits",
      [
        { value: "keep", label: "Keep", detail: "Keep existing rate limits." },
        { value: "edit", label: "Edit", detail: "Replace with new limits." },
        { value: "clear", label: "Clear", detail: "Remove all rate limits." }
      ],
      "keep"
    );
    if (mode === "keep") {
      return { rateLimits: existing ?? [], provided: true };
    }
    if (mode === "clear") {
      return { rateLimits: [], provided: true };
    }
  } else {
    const useLimits = await prompt.confirm("Configure rate limits?", false);
    if (!useLimits) {
      return { rateLimits: [], provided: false };
    }
  }

  const rules: RateLimitRule[] = [];
  let addMore = true;
  while (addMore) {
    const toolName = normalizeToolName(
      await prompt.ask("Tool name (* for all tools)", existing?.[0]?.toolName ?? "*")
    );
    const maxCalls = await prompt.number("Max calls within window", 20);
    const windowSec = await prompt.number("Window size in seconds", 60);
    const action = await prompt.choose(
      "When the limit is exceeded",
      RATE_LIMIT_ACTION_CHOICES,
      "ASK"
    );
    const scope = await prompt.choose(
      "Limit scope",
      RATE_LIMIT_SCOPE_CHOICES,
      "session"
    );
    rules.push({ toolName, maxCalls, windowSec, action, scope });
    addMore = await prompt.confirm("Add another rate limit?", false);
  }
  return { rateLimits: rules, provided: true };
}

async function selectTools(prompt: Prompt, tools: string[]): Promise<string[]> {
  if (tools.length === 0) {
    return [];
  }
  if (prompt.multiselect) {
    const choices = tools.map((tool) => ({ value: tool, label: tool, detail: "" }));
    const selected = await prompt.multiselect(
      "Select tools to customize",
      choices,
      []
    );
    return selected;
  }
  const lines = tools.map((tool, index) => `${index + 1}. ${tool}`);
  const selection = await prompt.ask(
    `Select tools by number (comma-separated) or type "all"\n${lines.join("\n")}`,
    ""
  );
  const normalized = selection.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return [];
  }
  if (normalized === "all") {
    return tools;
  }
  const indexes = normalized
    .split(",")
    .map((entry) => Number.parseInt(entry.trim(), 10))
    .filter((value) => Number.isFinite(value) && value > 0 && value <= tools.length);
  return indexes
    .map((index) => tools[index - 1])
    .filter((tool): tool is string => typeof tool === "string");
}

function isPathTool(toolName: string): boolean {
  return toolName === "read" || toolName === "write" || toolName === "edit" || toolName === "apply_patch";
}

async function resolveSetupFlow(prompt: Prompt, prefill: WizardPrefill): Promise<SetupFlow> {
  if (prefill.flow === "quick" || prefill.flow === "advanced") {
    return prefill.flow;
  }
  return await prompt.choose(
    "Setup style",
    [
      { value: "quick", label: "Quick (Recommended)", detail: "Minimal prompts, safe defaults." },
      { value: "advanced", label: "Advanced", detail: "Customize policies and tool rules." }
    ],
    "quick"
  );
}

function emptyInstallSummary(mode: InstallSummary["mode"]): InstallSummary {
  return { mode, steps: [], warnings: [] };
}

async function configureInstaller(
  prompt: Prompt,
  logger: PluginLogger,
  prefill: WizardPrefill
): Promise<InstallSummary> {
  await logSection(prompt, logger, "Installer Actions", [
    "Install + enable the firewall plugin in OpenClaw.",
    "These steps are optional; you can skip and run them manually later."
  ]);

  if (!isOpenClawAvailable()) {
    if (prompt.note) {
      await prompt.note(
        "OpenClaw CLI was not found in PATH. We'll skip auto-install and only write config + policy.",
        "OpenClaw CLI not found"
      );
    }
    return emptyInstallSummary("manual");
  }

  const shouldInstall = await prompt.confirm(
    "Install and enable the plugin with OpenClaw now?",
    prefill.autoWrite ?? true
  );
  if (!shouldInstall) {
    return emptyInstallSummary("manual");
  }

  return {
    mode: "auto",
    warnings: [],
    steps: [
      {
        label: "Install plugin",
        command: "openclaw plugins install @mindai/openclaw-tool-firewall"
      },
      {
        label: "Enable plugin",
        command: "openclaw plugins enable openclaw-tool-firewall"
      }
    ]
  };
}

function renderInstallSummary(summary: InstallSummary): string[] {
  if (summary.mode === "skip") {
    return [];
  }
  if (summary.mode === "manual") {
    return ["Installer: skipped (run openclaw plugins install/enable manually if needed)"];
  }
  const lines = ["Installer: auto"];
  for (const step of summary.steps) {
    lines.push(`${step.label}: ${step.command}`);
  }
  return lines;
}

async function runInstallerSteps(
  summary: InstallSummary,
  logger: PluginLogger
): Promise<string[]> {
  if (summary.mode !== "auto") {
    return summary.warnings;
  }
  for (const step of summary.steps) {
    const result = runOpenClawCommand(step.command);
    step.ok = result.ok;
    if (!result.ok) {
      step.error = result.error ?? "Command failed";
      summary.warnings.push(`${step.label} failed: ${step.error}`);
    }
    if (result.output) {
      logger.info?.(result.output.trim());
    }
  }
  return summary.warnings;
}

function isOpenClawAvailable(): boolean {
  const result = spawnSync("openclaw", ["--version"], { stdio: "ignore" });
  return !result.error && result.status === 0;
}

function runOpenClawCommand(command: string): { ok: boolean; output: string; error?: string } {
  const parts = command.split(" ").filter(Boolean);
  if (parts.length === 0) {
    return { ok: false, output: "", error: "Empty command" };
  }
  const bin = parts[0];
  if (!bin) {
    return { ok: false, output: "", error: "Empty command" };
  }
  const args = parts.slice(1);
  const result = spawnSync(bin, args, { encoding: "utf8" });
  if (result.error) {
    return { ok: false, output: "", error: result.error.message };
  }
  const output = [result.stdout, result.stderr].filter(Boolean).join("\n");
  if (result.status === 0) {
    return { ok: true, output };
  }
  return { ok: false, output, error: output.trim() || "Command failed" };
}

function createStyle(stream: NodeJS.WriteStream): Style {
  const force = process.env.FORCE_COLOR;
  const forceEnabled = typeof force === "string" && force !== "0";
  const useColor = forceEnabled ? true : Boolean(stream.isTTY) && !process.env.NO_COLOR;
  const wrap = (code: string) => (text: string) =>
    useColor ? `\x1b[${code}m${text}\x1b[0m` : text;
  return {
    bold: wrap("1"),
    dim: wrap("2"),
    cyan: wrap("36")
  };
}

function parsePresetName(value: unknown): PresetName | undefined {
  if (value === "strict" || value === "standard" || value === "dev") {
    return value;
  }
  return undefined;
}

function parseMaxResultAction(value: unknown): "truncate" | "block" | undefined {
  if (value === "truncate" || value === "block") {
    return value;
  }
  return undefined;
}

function readString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? trimmed : undefined;
  }
  return undefined;
}

function readNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return value;
  }
  return undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  return undefined;
}

function coerceRateLimits(value: unknown): RateLimitRule[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const rules: RateLimitRule[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const record = entry as Record<string, unknown>;
    const toolName = readString(record.toolName);
    const maxCalls = Number(record.maxCalls);
    const windowSec = Number(record.windowSec);
    if (!toolName || !Number.isFinite(maxCalls) || maxCalls <= 0) {
      continue;
    }
    if (!Number.isFinite(windowSec) || windowSec <= 0) {
      continue;
    }
    const actionRaw = typeof record.action === "string" ? record.action.trim().toUpperCase() : "";
    const action = actionRaw === "ASK" || actionRaw === "DENY" ? actionRaw : undefined;
    const scope = record.scope === "global" || record.scope === "session" ? record.scope : undefined;
    const next: RateLimitRule = { toolName, maxCalls, windowSec };
    if (action) {
      next.action = action;
    }
    if (scope) {
      next.scope = scope;
    }
    rules.push(next);
  }
  return rules;
}

function createPrompt(): Prompt {
  const style = createStyle(output);

  const stylePromptMessage = (message: string): string => style.cyan(message);
  const stylePromptTitle = (title?: string): string | undefined =>
    title ? style.bold(style.cyan(title)) : title;
  const stylePromptHint = (hint?: string): string | undefined => (hint ? style.dim(hint) : hint);

  const guardCancel = <T>(value: T | symbol): T => {
    if (isCancel(value)) {
      cancel(stylePromptTitle("Setup cancelled.") ?? "Setup cancelled.");
      throw new WizardCancelledError();
    }
    return value;
  };

  const ask = async (question: string, fallback?: string): Promise<string> => {
    const textParams: Parameters<typeof clackText>[0] = {
      message: stylePromptMessage(question)
    };
    if (typeof fallback === "string") {
      textParams.initialValue = fallback;
    }
    const answer = guardCancel(await clackText(textParams));
    const trimmed = String(answer ?? "").trim();
    return trimmed.length > 0 ? trimmed : fallback ?? "";
  };

  const choose = async <T extends string>(
    question: string,
    choices: Choice<T>[],
    fallback: T
  ): Promise<T> => {
    const options = choices.map((choice) => {
      const option: { value: T; label?: string; hint?: string; disabled?: boolean } = {
        value: choice.value,
        label: choice.label
      };
      const hint = stylePromptHint(choice.detail);
      if (hint) {
        option.hint = hint;
      }
      return option;
    }) as unknown as Parameters<typeof clackSelect<T>>[0]["options"];
    const selected = guardCancel(
      await clackSelect({
        message: stylePromptMessage(question),
        options,
        initialValue: fallback
      })
    );
    return selected as T;
  };

  const confirm = async (question: string, fallback: boolean): Promise<boolean> => {
    const value = guardCancel(
      await clackConfirm({
        message: stylePromptMessage(question),
        initialValue: fallback
      })
    );
    return Boolean(value);
  };

  const number = async (question: string, fallback: number): Promise<number> => {
    const value = guardCancel(
      await clackText({
        message: stylePromptMessage(question),
        initialValue: String(fallback),
        validate: (inputValue) => {
          const parsed = Number.parseInt(String(inputValue ?? "").trim(), 10);
          if (!Number.isFinite(parsed) || parsed <= 0) {
            return "Enter a positive number.";
          }
          return undefined;
        }
      })
    );
    const parsed = Number.parseInt(String(value ?? "").trim(), 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
  };

  const multiselect = async <T extends string>(
    question: string,
    choices: Choice<T>[],
    initialValues: T[]
  ): Promise<T[]> => {
    const options = choices.map((choice) => {
      const option: { value: T; label?: string; hint?: string; disabled?: boolean } = {
        value: choice.value,
        label: choice.label
      };
      const hint = stylePromptHint(choice.detail);
      if (hint) {
        option.hint = hint;
      }
      return option;
    }) as unknown as Parameters<typeof clackMultiselect<T>>[0]["options"];
    const selected = guardCancel(
      await clackMultiselect({
        message: stylePromptMessage(question),
        options,
        initialValues
      })
    );
    return selected as T[];
  };

  const intro = async (title: string): Promise<void> => {
    clackIntro(stylePromptTitle(title) ?? title);
  };

  const outro = async (message: string): Promise<void> => {
    clackOutro(stylePromptTitle(message) ?? message);
  };

  const note = async (message: string, title?: string): Promise<void> => {
    clackNote(message, stylePromptTitle(title));
  };

  const close = (): void => {
    void output;
  };

  return { ask, choose, confirm, number, multiselect, intro, outro, note, close };
}

async function logSection(
  prompt: Prompt,
  logger: PluginLogger,
  title: string,
  lines: string[]
): Promise<void> {
  if (prompt.note) {
    await prompt.note(lines.map((line) => `- ${line}`).join("\n"), title);
    return;
  }
  const style = createStyle(output);
  const formattedLines = lines.map((line) => `- ${line}`);
  const boxLines = renderBox(title, formattedLines, style);
  logger.info?.("");
  boxLines.forEach((line) => logger.info?.(line));
}

function renderBox(title: string, lines: string[], style: Style): string[] {
  const content = [title, ...lines];
  const innerWidth = Math.max(0, ...content.map((line) => line.length));
  const border = `+${"-".repeat(innerWidth + 2)}+`;
  const renderLine = (text: string, emphasis = false): string => {
    const padded = text.padEnd(innerWidth);
    const rendered = emphasis ? style.bold(padded) : padded;
    return `| ${rendered} |`;
  };
  return [border, renderLine(title, true), ...lines.map((line) => renderLine(line)), border];
}

function printWizardHeader(logger: PluginLogger, title: string): void {
  const text = title.toUpperCase();
  const bar = "=".repeat(Math.max(24, text.length));
  const header = [
    bar,
    text,
    bar,
    ""
  ].join("\n");
  logger.info?.(header);
}

export class WizardCancelledError extends Error {
  constructor(message = "wizard cancelled") {
    super(message);
    this.name = "WizardCancelledError";
  }
}
