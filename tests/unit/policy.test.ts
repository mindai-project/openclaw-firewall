import { describe, expect, it } from "vitest";
import type { Policy, ToolCall } from "../../packages/core/src/index.js";
import { evaluatePolicy } from "../../packages/core/src/index.js";

const policy: Policy = {
  mode: "standard",
  defaults: {
    denyUnknownTools: true,
    unknownToolAction: "DENY",
    log: "safe",
    redaction: "standard",
    injection: { mode: "alert" }
  },
  risk: {
    read: "ALLOW",
    write: "ASK",
    critical: "DENY",
    unknown: "DENY"
  },
  tools: [
    { name: "read", risk: "read" },
    { name: "write", risk: "write" },
    { name: "exec", risk: "critical", useExecApprovals: true }
  ]
};

describe("policy evaluation", () => {
  it("allows read tools by default risk", () => {
    const toolCall: ToolCall = {
      toolName: "read",
      params: {},
      context: {}
    };
    const decision = evaluatePolicy(policy, toolCall);
    expect(decision.decision).toBe("ALLOW");
  });

  it("asks on write tools", () => {
    const toolCall: ToolCall = {
      toolName: "write",
      params: {},
      context: {}
    };
    const decision = evaluatePolicy(policy, toolCall);
    expect(decision.decision).toBe("ASK");
  });

  it("denies unknown tools when configured", () => {
    const toolCall: ToolCall = {
      toolName: "unknown_tool",
      params: {},
      context: {}
    };
    const decision = evaluatePolicy(policy, toolCall);
    expect(decision.decision).toBe("DENY");
  });

  it("explains unknown tool ASK decisions clearly", () => {
    const askPolicy: Policy = {
      ...policy,
      defaults: { ...policy.defaults, unknownToolAction: "ASK" },
      risk: { ...policy.risk, unknown: "ASK" }
    };
    const toolCall: ToolCall = {
      toolName: "mystery_tool",
      params: {},
      context: {}
    };
    const decision = evaluatePolicy(askPolicy, toolCall);
    expect(decision.decision).toBe("ASK");
    expect(decision.reason).toContain("ASK");
  });
});
