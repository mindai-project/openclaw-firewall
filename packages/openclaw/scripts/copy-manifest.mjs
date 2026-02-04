import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(scriptsDir, "..");
const source = path.join(packageDir, "openclaw.plugin.json");
const target = path.join(packageDir, "dist", "openclaw.plugin.json");

if (!fs.existsSync(source)) {
  throw new Error(`openclaw.plugin.json not found at ${source}`);
}

fs.mkdirSync(path.dirname(target), { recursive: true });
fs.copyFileSync(source, target);
