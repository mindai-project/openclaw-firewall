import { describe, expect, it } from "vitest";
import { applyFirewallConfig, resolveOpenClawConfigPath } from "../../packages/openclaw/src/setup.js";

describe("firewall setup helpers", () => {
  it("prefers explicit config path overrides", () => {
    const resolved = resolveOpenClawConfigPath("/tmp/custom/openclaw.json");
    expect(resolved).toBe("/tmp/custom/openclaw.json");
  });

  it("updates plugin load paths and entry config", () => {
    const pluginPath =
      "/home/openclaw/node_modules/@mindaiproject/openclaw-tool-firewall/dist/mindai-openclaw-tool-firewall.js";
    const config = {
      plugins: {
        load: {
          paths: [
            "/home/openclaw/node_modules/@mindaiproject/openclaw-tool-firewall",
            "/home/openclaw/extensions/other/index.js"
          ]
        },
        entries: {
          "mindai-openclaw-tool-firewall": { enabled: false }
        }
      }
    };
    const applied = applyFirewallConfig(config, {
      pluginPath,
      policyPath: "/tmp/firewall.yaml",
      preset: "standard",
      maxResultChars: 8000,
      maxResultAction: "truncate",
      auditOnStart: true,
      rateLimits: [
        { toolName: "web_fetch", maxCalls: 10, windowSec: 60, action: "ASK", scope: "session" }
      ]
    });

    const paths = (applied.config.plugins as { load?: { paths?: string[] } }).load?.paths ?? [];
    expect(paths).toContain(pluginPath);
    expect(paths).toContain("/home/openclaw/extensions/other/index.js");
    expect(paths).not.toContain("/home/openclaw/node_modules/@mindaiproject/openclaw-tool-firewall");

    const entry = (applied.config.plugins as { entries?: Record<string, unknown> }).entries?.[
      "openclaw-tool-firewall"
    ] as { enabled?: boolean; config?: Record<string, unknown> } | undefined;
    expect(
      (applied.config.plugins as { entries?: Record<string, unknown> }).entries?.[
        "mindai-openclaw-tool-firewall"
      ]
    ).toBeUndefined();
    expect(entry?.enabled).toBe(true);
    expect(entry?.config?.preset).toBe("standard");
    expect(entry?.config?.policyPath).toBe("/tmp/firewall.yaml");
    expect(entry?.config?.maxResultChars).toBe(8000);
    expect(entry?.config?.maxResultAction).toBe("truncate");
    expect(entry?.config?.auditOnStart).toBe(true);
    expect(entry?.config?.rateLimits).toEqual([
      { toolName: "web_fetch", maxCalls: 10, windowSec: 60, action: "ASK", scope: "session" }
    ]);
  });
});
