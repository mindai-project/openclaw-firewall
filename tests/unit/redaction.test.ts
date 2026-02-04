import { describe, expect, it } from "vitest";
import { redactString, redactValue } from "../../packages/redaction/src/index.js";

const SAMPLE = "Email test@example.com IP 192.168.0.1 Authorization: Bearer sk-abc1234567890123456789 0x0123456789abcdef0123456789abcdef01234567";

describe("redaction", () => {
  it("redacts common sensitive patterns", () => {
    const result = redactString(SAMPLE);
    expect(result.redacted).toMatchSnapshot();
    expect(result.report.redacted).toBe(true);
  });

  it("redacts seed-phrase-like content", () => {
    const phrase = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu";
    const result = redactString(phrase);
    expect(result.redacted).toMatchSnapshot();
  });

  it("redacts btc addresses and txids", () => {
    const btc = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    const txid = "a".repeat(64);
    const result = redactString(`BTC ${btc} TX ${txid}`);
    expect(result.redacted).toContain("[REDACTED:btc_address");
    expect(result.redacted).toContain("[REDACTED:txid");
  });

  it("supports redaction mode off", () => {
    const input = "Authorization: Bearer sk-abc1234567890123456789";
    const result = redactString(input, { mode: "off" });
    expect(result.redacted).toBe(input);
    expect(result.report.redacted).toBe(false);
  });

  it("redacts extra patterns in strict mode", () => {
    const input = "strict token abcdef1234567890abcdef1234567890";
    const standard = redactString(input);
    const strict = redactString(input, { mode: "strict" });
    expect(standard.redacted).toBe(input);
    expect(strict.redacted).not.toBe(input);
  });

  it("redacts nested values", () => {
    const stripeKey = ["sk_live_", "aaaaaaaaaaaaaaaaaaaaaaaa"].join("");
    const input = { token: stripeKey, nested: ["user@example.com"] };
    const result = redactValue(input);
    expect(result.redacted).toMatchSnapshot();
  });

  it("handles circular references safely", () => {
    const input: { name: string; self?: unknown } = { name: "root" };
    input.self = input;
    const result = redactValue(input);
    const redacted = result.redacted as { self?: unknown };
    expect(redacted.self).toBe(redacted);
  });
});
