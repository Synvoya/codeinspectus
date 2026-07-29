import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { runPhpUnsafeToolExecution } from "./unsafe-tool-execution.js";

const CORPUS = resolve(process.cwd(), "fixtures/php-ai-corpus");

describe("PHP unsafe model-tool execution", () => {
  it("finds the exact TP corpus with security metadata", async () => {
    const findings = await runPhpUnsafeToolExecution(resolve(CORPUS, "tp"));
    expect(findings).toHaveLength(3);
    expect(findings.map((finding) => finding.location.file)).toEqual(["Agent.php", "Agent.php", "Agent.php"]);
    expect(findings.map((finding) => finding.location.start_line)).toEqual([7, 19, 42]);
    for (const finding of findings) {
      expect(finding.rule_id).toBe("ci-php-llm-tool-argument-command-execution");
      expect(finding.severity).toBe("high");
      expect(finding.confidence).toBe("medium");
      expect(finding.cwe).toEqual(["CWE-78", "CWE-1426"]);
      expect(finding.owasp_llm).toEqual(["LLM05:2025", "LLM06:2025"]);
      expect(finding.location.snippet).toContain("[VALUE REDACTED]");
    }
  });

  it("keeps the FP corpus silent", async () => {
    await expect(runPhpUnsafeToolExecution(resolve(CORPUS, "fp"))).resolves.toEqual([]);
  });

  it("keeps the fixed corpus silent", async () => {
    await expect(runPhpUnsafeToolExecution(resolve(CORPUS, "fixed"))).resolves.toEqual([]);
  });

  it("supports a direct file target", async () => {
    await expect(runPhpUnsafeToolExecution(resolve(CORPUS, "tp/Agent.php"))).resolves.toHaveLength(3);
  });
});
