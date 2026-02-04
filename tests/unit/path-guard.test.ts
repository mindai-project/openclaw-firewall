import { describe, expect, it } from "vitest";
import path from "node:path";
import { evaluatePathAllowlist } from "../../packages/openclaw/src/path-guard.js";

describe("path allowlist guard", () => {
  it("allows read paths inside the allowlist", () => {
    const result = evaluatePathAllowlist({
      toolName: "read",
      params: { path: "/tmp/file.txt" },
      allowPaths: ["/tmp"],
      resolvePath: (input) => path.resolve(input)
    });

    expect(result.allowed).toBe(true);
  });

  it("blocks write paths outside the allowlist", () => {
    const result = evaluatePathAllowlist({
      toolName: "write",
      params: { path: "/etc/passwd" },
      allowPaths: ["/tmp"],
      resolvePath: (input) => path.resolve(input)
    });

    expect(result.allowed).toBe(false);
    expect(result.unmatched.length).toBe(1);
  });

  it("supports array path arguments", () => {
    const result = evaluatePathAllowlist({
      toolName: "read",
      params: { paths: ["/tmp/a.txt", "/tmp/b.txt"] },
      allowPaths: ["/tmp"],
      resolvePath: (input) => path.resolve(input)
    });

    expect(result.allowed).toBe(true);
    expect(result.toolPaths.length).toBe(2);
  });

  it("extracts apply_patch paths from patch input", () => {
    const patch = [
      "*** Begin Patch",
      "*** Update File: docs/readme.md",
      "@@",
      "-old",
      "+new",
      "*** End Patch"
    ].join("\n");

    const result = evaluatePathAllowlist({
      toolName: "apply_patch",
      params: { input: patch },
      allowPaths: ["docs"],
      resolvePath: (input) => path.resolve(input)
    });

    expect(result.allowed).toBe(true);
    expect(result.toolPaths.length).toBe(1);
  });
});
