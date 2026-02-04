import path from "node:path";
import { defineConfig } from "vitest/config";

const rootDir = path.resolve(__dirname);

// Centralized test config for root tests/*.test.ts.
export default defineConfig({
  resolve: {
    alias: {
      "@mindai/firewall-core": path.join(rootDir, "packages/core/src/index.ts"),
      "@mindai/firewall-redaction": path.join(rootDir, "packages/redaction/src/index.ts"),
      "@mindai/firewall-scanner": path.join(rootDir, "packages/scanner/src/index.ts"),
      "@mindai/openclaw-tool-firewall": path.join(rootDir, "packages/openclaw/src/index.ts")
    }
  },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node"
  }
});
