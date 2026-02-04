import { describe, expect, it } from "vitest";
import { computeRecommendations, formatRecommendationsYaml } from "../../packages/openclaw/src/recommend.js";
import type { ApprovalStore } from "../../packages/openclaw/src/storage.js";

function makeStore(): ApprovalStore {
  return {
    version: 1,
    requests: [],
    sessionApprovals: []
  };
}

describe("recommendations", () => {
  it("returns recommendations when approvals meet threshold", () => {
    const store = makeStore();
    store.requests.push({
      id: "a",
      toolName: "write",
      paramsHash: "x",
      paramsPreview: "[redacted]",
      risk: "write",
      status: "approved",
      createdAt: new Date().toISOString(),
      reason: "test"
    });
    store.requests.push({
      id: "b",
      toolName: "write",
      paramsHash: "y",
      paramsPreview: "[redacted]",
      risk: "write",
      status: "approved",
      createdAt: new Date().toISOString(),
      reason: "test"
    });
    const recommendations = computeRecommendations(store, 2);
    expect(recommendations.length).toBe(1);
    expect(recommendations[0]?.toolName).toBe("write");
  });

  it("formats YAML output", () => {
    const output = formatRecommendationsYaml([
      { toolName: "write", risk: "write", count: 3 }
    ]);
    expect(output).toContain("tools:");
    expect(output).toContain("name: write");
  });
});
