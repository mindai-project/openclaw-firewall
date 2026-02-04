import type { OpenClawPluginApi } from "./openclaw-types.js";
import { createFirewallState, handleBeforeToolCall, handleToolResultPersist } from "./handlers.js";
import { handleFirewallCommand } from "./commands.js";
import { registerFirewallCli } from "./cli.js";

const plugin = {
  id: "openclaw-tool-firewall",
  name: "MindAI Tool Firewall",
  description: "Privacy and safety firewall for OpenClaw tool execution.",
  register(api: OpenClawPluginApi) {
    const state = createFirewallState(api);

    api.on("before_tool_call", async (event, ctx) => {
      return await handleBeforeToolCall(state, event, ctx);
    });

    api.on("tool_result_persist", (event, ctx) => {
      return handleToolResultPersist(state, event, ctx);
    });

    api.registerCommand({
      name: "firewall",
      description: "Approve or inspect firewall tool decisions",
      acceptsArgs: true,
      requireAuth: true,
      handler: async (ctx) => handleFirewallCommand(state, ctx)
    });

    api.registerCli(
      ({ program, logger, config }) => {
        const root = program.command("firewall").description("MindAI tool firewall commands");
        registerFirewallCli(root, { logger, config });
      },
      { commands: ["firewall"] }
    );
  }
};

export default plugin;
