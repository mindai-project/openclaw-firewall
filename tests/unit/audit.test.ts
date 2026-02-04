import { describe, expect, it } from "vitest";
import { auditOpenClawConfig } from "../../packages/openclaw/src/audit.js";

describe("openclaw audit", () => {
  it("flags exposed gateway without auth", () => {
    const findings = auditOpenClawConfig({
      gateway: {
        bind: "lan"
      }
    });

    const ids = findings.map((finding) => finding.id);
    expect(ids).toContain("gateway.bind.exposed");
    expect(ids).toContain("gateway.auth.missing");
  });

  it("flags logging redaction off", () => {
    const findings = auditOpenClawConfig({
      logging: {
        redactSensitive: "off"
      }
    });

    const ids = findings.map((finding) => finding.id);
    expect(ids).toContain("logging.redactSensitive.off");
  });
});
