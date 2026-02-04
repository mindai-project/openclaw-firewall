import type { ApprovalRollup, ApprovalStore } from "./storage.js";

export type Recommendation = {
  toolName: string;
  risk: string;
  count: number;
};

export type RecommendationCounts = Record<
  string,
  {
    toolName: string;
    risk: string;
    count: number;
  }
>;

export function computeRecommendationsFromCounts(
  counts: RecommendationCounts,
  minCount: number
): Recommendation[] {
  return Object.values(counts).filter((rec) => rec.count >= minCount);
}

export function computeRecommendationsFromRollup(
  rollup: ApprovalRollup,
  minCount: number
): Recommendation[] {
  return computeRecommendationsFromCounts(rollup.counts, minCount);
}

// Compute recommendations based on approved requests.
export function computeRecommendations(
  store: ApprovalStore,
  minCount: number
): Recommendation[] {
  const counts = new Map<string, Recommendation>();
  for (const request of store.requests) {
    if (request.status !== "approved") {
      continue;
    }
    const key = `${request.toolName}:${request.risk}`;
    const existing = counts.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      counts.set(key, {
        toolName: request.toolName,
        risk: request.risk,
        count: 1
      });
    }
  }

  const asCounts: RecommendationCounts = {};
  for (const [key, value] of counts.entries()) {
    asCounts[key] = value;
  }
  return computeRecommendationsFromCounts(asCounts, minCount);
}

export function formatRecommendationsYaml(recommendations: Recommendation[]): string {
  if (recommendations.length === 0) {
    return "# No recommendations meet the threshold.";
  }
  const lines: string[] = ["# Suggested policy changes", "tools:"];
  for (const rec of recommendations) {
    lines.push(`  - name: ${rec.toolName}`);
    lines.push(`    risk: ${rec.risk}`);
    lines.push("    action: ALLOW");
    lines.push(`    # approvals: ${rec.count}`);
  }
  return lines.join("\n");
}
