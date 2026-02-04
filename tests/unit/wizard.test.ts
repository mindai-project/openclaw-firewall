import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { runFirewallSetupWizard, type WizardRunOptions } from "../../packages/openclaw/src/wizard.js";

describe("firewall setup wizard", () => {
  it("returns defaults without writing when autoWrite is false", async () => {
    const prompt: NonNullable<WizardRunOptions["prompt"]> = {
      ask: async (_prompt: string, fallback?: string) => fallback ?? "",
      choose: async <T extends string>(
        _prompt: string,
        _choices: Array<{ value: T; label: string; detail: string }>,
        fallback: T
      ) => fallback,
      confirm: async (_prompt: string, fallback: boolean) => fallback,
      number: async (_prompt: string, fallback: number) => fallback,
      close: () => {}
    };

    const result = await runFirewallSetupWizard({
      prefill: {
        configPath: "/tmp/openclaw-wizard/openclaw.json",
        policyPath: "/tmp/openclaw-wizard/firewall.yaml",
        preset: "standard",
        pluginPath: "/tmp/openclaw-wizard/plugin.js",
        flow: "advanced",
        autoWrite: false
      },
      prompt
    });

    expect(result.configPath).toBe("/tmp/openclaw-wizard/openclaw.json");
    expect(result.policyPath).toBe("/tmp/openclaw-wizard/firewall.yaml");
    expect(result.pluginPath).toBe("/tmp/openclaw-wizard/plugin.js");
    expect(result.preset).toBe("standard");
    expect(result.wroteConfig).toBe(false);
    expect(result.wrotePolicy).toBe(false);
  });

  it("respects allow alias when choosing default actions", async () => {
    const tempDir = "/tmp/openclaw-wizard-allow";
    fs.mkdirSync(tempDir, { recursive: true });
    const policyPath = path.join(tempDir, "firewall.yaml");
    fs.writeFileSync(
      policyPath,
      [
        "mode: standard",
        "tools:",
        "  - name: web_fetch",
        "    allow: false",
        "    risk: read"
      ].join("\n") + "\n"
    );

    const prompt: NonNullable<WizardRunOptions["prompt"]> = {
      ask: async (_prompt: string, fallback?: string) => fallback ?? "",
      choose: async <T extends string>(
        promptText: string,
        _choices: Array<{ value: T; label: string; detail: string }>,
        fallback: T
      ) => {
        if (promptText.startsWith("Customize tool rules?")) {
          return "all" as T;
        }
        return fallback;
      },
      confirm: async (promptText: string, fallback: boolean) => {
        if (promptText.startsWith("Existing policy found")) {
          return true;
        }
        return fallback;
      },
      number: async (_prompt: string, fallback: number) => fallback,
      close: () => {}
    };

    const result = await runFirewallSetupWizard({
      prefill: {
        configPath: path.join(tempDir, "openclaw.json"),
        policyPath,
        preset: "standard",
        pluginPath: path.join(tempDir, "plugin.js"),
        flow: "advanced",
        autoWrite: false
      },
      prompt
    });

    const webFetch = result.policy.tools.find((rule) => rule.name === "web_fetch");
    expect(webFetch?.action).toBe("DENY");
  });

  it("can clear existing rate limits", async () => {
    const prompt: NonNullable<WizardRunOptions["prompt"]> = {
      ask: async (_prompt: string, fallback?: string) => fallback ?? "",
      choose: async <T extends string>(
        promptText: string,
        _choices: Array<{ value: T; label: string; detail: string }>,
        fallback: T
      ) => {
        if (promptText === "Rate limits") {
          return "clear" as T;
        }
        return fallback;
      },
      confirm: async (_prompt: string, fallback: boolean) => fallback,
      number: async (_prompt: string, fallback: number) => fallback,
      close: () => {}
    };

    const result = await runFirewallSetupWizard({
      prefill: {
        configPath: "/tmp/openclaw-wizard/openclaw.json",
        policyPath: "/tmp/openclaw-wizard/firewall.yaml",
        preset: "standard",
        pluginPath: "/tmp/openclaw-wizard/plugin.js",
        flow: "advanced",
        autoWrite: false,
        rateLimits: [{ toolName: "web_fetch", maxCalls: 2, windowSec: 60, action: "ASK", scope: "session" }]
      },
      prompt
    });

    expect(result.rateLimits).toEqual([]);
  });
});
