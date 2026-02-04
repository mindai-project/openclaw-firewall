import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "tsup";

const packageDir = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  entry: [
    path.join(packageDir, "src/index.ts"),
    path.join(packageDir, "src/mindai-firewall.ts"),
    path.join(packageDir, "src/mindai-openclaw-tool-firewall.ts")
  ],
  format: ["esm"],
  platform: "node",
  target: "node18",
  splitting: false,
  sourcemap: true,
  clean: false,
  dts: false,
  noExternal: [
    "@mindai/firewall-core",
    "@mindai/firewall-redaction",
    "@mindai/firewall-scanner"
  ],
  external: ["yaml", "commander", "@clack/prompts"],
  outDir: path.join(packageDir, "dist")
});
