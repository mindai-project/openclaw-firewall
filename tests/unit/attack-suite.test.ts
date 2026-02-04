import { describe, expect, it } from "vitest";
import fs from "node:fs";
import { scanText } from "../../packages/scanner/src/index.js";
import { redactString } from "../../packages/redaction/src/index.js";

const ATTACK_DIR = new URL("../attacks/", import.meta.url);

function readAttack(name: string): string {
  return fs.readFileSync(new URL(name, ATTACK_DIR), "utf8");
}

describe("attack suite", () => {
  it("flags injection payloads", () => {
    const payloads = [
      readAttack("prompt-injection.txt"),
      readAttack("policy-manipulation.txt")
    ];

    for (const payload of payloads) {
      const result = scanText(payload);
      expect(result.flagged).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
    }
  });

  it("redacts secret leak payloads", () => {
    const payload = readAttack("secret-leak.txt");
    const result = redactString(payload);
    expect(result.report.redacted).toBe(true);
    expect(result.redacted).toContain("[REDACTED");
  });
});
