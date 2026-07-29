import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { runRubyUnsafeToolExecution } from "./unsafe-tool-execution.js";

const CORPUS = resolve(process.cwd(), "fixtures/ruby-ai-corpus");

describe("Ruby unsafe model-tool execution", () => {
  it("finds the exact TP corpus with security metadata", async () => {
    const findings = await runRubyUnsafeToolExecution(resolve(CORPUS, "tp"));
    expect(findings).toHaveLength(3);
    expect(findings.map((finding) => finding.location.file)).toEqual(["agent.rb", "agent.rb", "agent.rb"]);
    expect(findings.map((finding) => finding.location.start_line)).toEqual([8, 12, 30]);
    for (const finding of findings) {
      expect(finding.rule_id).toBe("ci-ruby-llm-tool-argument-command-execution");
      expect(finding.severity).toBe("high");
      expect(finding.confidence).toBe("medium");
      expect(finding.cwe).toEqual(["CWE-78", "CWE-1426"]);
      expect(finding.owasp_llm).toEqual(["LLM05:2025", "LLM06:2025"]);
      expect(finding.location.snippet).toContain("[VALUE REDACTED]");
    }
  });

  it("keeps the FP corpus silent", async () => {
    await expect(runRubyUnsafeToolExecution(resolve(CORPUS, "fp"))).resolves.toEqual([]);
  });

  it("keeps the fixed corpus silent", async () => {
    await expect(runRubyUnsafeToolExecution(resolve(CORPUS, "fixed"))).resolves.toEqual([]);
  });

  it("supports a direct file target", async () => {
    await expect(runRubyUnsafeToolExecution(resolve(CORPUS, "tp/agent.rb"))).resolves.toHaveLength(3);
  });

  it("fails closed on unsupported heredocs", async () => {
    await expect(runRubyUnsafeToolExecution({
      target: "/fixture",
      root: "/fixture",
      files: [{
        path: "agent.rb",
        content: 'prompt = <<~PROMPT\nhello\nPROMPT\nsystem(tool_call.function.arguments)\n',
      }],
    })).resolves.toEqual([]);
  });

  it("tracks executable Ruby interpolation while keeping plain string decoys silent", async () => {
    await expect(runRubyUnsafeToolExecution({
      target: "/fixture",
      root: "/fixture",
      files: [{
        path: "agent.rb",
        content: `
def execute(tool_call)
  command = "run #{tool_call.function.arguments}"
  system(command)
end
`,
      }],
    })).resolves.toHaveLength(1);
  });
});
