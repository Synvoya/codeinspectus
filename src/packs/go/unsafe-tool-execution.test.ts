import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { runGoUnsafeToolExecution } from "./unsafe-tool-execution.js";

const CORPUS = resolve(process.cwd(), "fixtures/go-ai-corpus");

describe("Go unsafe model-tool execution", () => {
  it("finds the exact TP corpus with security metadata", async () => {
    const findings = await runGoUnsafeToolExecution(resolve(CORPUS, "tp"));
    expect(findings).toHaveLength(3);
    expect(findings.map((finding) => finding.location.file)).toEqual([
      "src/main.go",
      "src/main.go",
      "src/main.go",
    ]);
    expect(findings.map((finding) => finding.location.start_line)).toEqual([36, 50, 22]);
    for (const finding of findings) {
      expect(finding.rule_id).toBe("ci-go-llm-tool-argument-command-execution");
      expect(finding.severity).toBe("high");
      expect(finding.confidence).toBe("medium");
      expect(finding.cwe).toEqual(["CWE-78", "CWE-1426"]);
      expect(finding.owasp_llm).toEqual(["LLM05:2025", "LLM06:2025"]);
      expect(finding.location.snippet).toContain("[VALUE REDACTED]");
    }
  });

  it("keeps the FP corpus silent", async () => {
    await expect(runGoUnsafeToolExecution(resolve(CORPUS, "fp"))).resolves.toEqual([]);
  });

  it("keeps the fixed corpus silent", async () => {
    await expect(runGoUnsafeToolExecution(resolve(CORPUS, "fixed"))).resolves.toEqual([]);
  });

  it("supports a direct file target", async () => {
    const findings = await runGoUnsafeToolExecution(resolve(CORPUS, "tp/src/main.go"));
    expect(findings).toHaveLength(3);
  });
});
