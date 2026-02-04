import path from "node:path";
import { defineConfig } from "vitest/config";

const rootDir = path.resolve(__dirname);

// Centralized test config for root tests/*.test.ts.
export default defineConfig({
  resolve: {
    alias: {
      "@mindaiproject/firewall-core": path.join(rootDir, "packages/core/src/index.ts"),
      "@mindaiproject/firewall-redaction": path.join(rootDir, "packages/redaction/src/index.ts"),
      "@mindaiproject/firewall-scanner": path.join(rootDir, "packages/scanner/src/index.ts"),
      "@mindaiproject/openclaw-tool-firewall": path.join(rootDir, "packages/openclaw/src/index.ts")
    }
  },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node"
  }
});
