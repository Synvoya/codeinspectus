import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { runJavaUnsafeToolExecution } from "./unsafe-tool-execution.js";

const CORPUS = resolve(process.cwd(), "fixtures/java-ai-corpus");

describe("Java unsafe model-tool execution", () => {
  it("finds the exact TP corpus with security metadata", async () => {
    const findings = await runJavaUnsafeToolExecution(resolve(CORPUS, "tp"));
    expect(findings).toHaveLength(3);
    expect(findings.map((finding) => finding.location.file)).toEqual([
      "src/main/java/example/Agent.java",
      "src/main/java/example/Agent.java",
      "src/main/java/example/Agent.java",
    ]);
    expect(findings.map((finding) => finding.location.start_line).sort((a, b) => a - b)).toEqual([12, 17, 23]);
    for (const finding of findings) {
      expect(finding.rule_id).toBe("ci-java-llm-tool-argument-command-execution");
      expect(finding.severity).toBe("high");
      expect(finding.confidence).toBe("medium");
      expect(finding.cwe).toEqual(["CWE-78", "CWE-1426"]);
      expect(finding.owasp_llm).toEqual(["LLM05:2025", "LLM06:2025"]);
      expect(finding.location.snippet).toContain("[VALUE REDACTED]");
    }
  });

  it("keeps the FP corpus silent", async () => {
    await expect(runJavaUnsafeToolExecution(resolve(CORPUS, "fp"))).resolves.toEqual([]);
  });

  it("keeps the fixed corpus silent", async () => {
    await expect(runJavaUnsafeToolExecution(resolve(CORPUS, "fixed"))).resolves.toEqual([]);
  });

  it("supports a direct file target", async () => {
    const findings = await runJavaUnsafeToolExecution(
      resolve(CORPUS, "tp/src/main/java/example/Agent.java"),
    );
    expect(findings).toHaveLength(3);
  });
});
