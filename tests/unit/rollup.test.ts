import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  appendApprovalHistory,
  rebuildApprovalRollupFromHistory,
  loadApprovalRollup
} from "../../packages/openclaw/src/storage.js";
import { computeRecommendationsFromRollup } from "../../packages/openclaw/src/recommend.js";

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "firewall-rollup-"));
}

describe("approval rollup", () => {
  it("rebuilds rollup from approval history", () => {
    const stateDir = createTempDir();
    appendApprovalHistory(
      {
        ts: new Date().toISOString(),
        toolName: "write",
        risk: "write",
        status: "approved"
      },
      stateDir
    );
    appendApprovalHistory(
      {
        ts: new Date().toISOString(),
        toolName: "write",
        risk: "write",
        status: "approved"
      },
      stateDir
    );

    const rollup = rebuildApprovalRollupFromHistory(stateDir);
    expect(rollup).not.toBeNull();

    const loaded = loadApprovalRollup(stateDir);
    expect(loaded?.counts["write:write"]?.count).toBe(2);

    const recommendations = computeRecommendationsFromRollup(loaded!, 2);
    expect(recommendations.length).toBe(1);
  });
});
