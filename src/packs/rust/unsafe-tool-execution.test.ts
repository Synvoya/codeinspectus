import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { runRustUnsafeToolExecution } from "./unsafe-tool-execution.js";

const CORPUS = resolve(process.cwd(), "fixtures/rust-ai-corpus");

describe("Rust unsafe model-tool execution", () => {
  it("finds the exact TP corpus with security metadata", async () => {
    const findings = await runRustUnsafeToolExecution(resolve(CORPUS, "tp"));
    expect(findings).toHaveLength(3);
    expect(findings.map((finding) => finding.location.file)).toEqual([
      "src/main.rs",
      "src/main.rs",
      "src/main.rs",
    ]);
    for (const finding of findings) {
      expect(finding.rule_id).toBe("ci-rust-llm-tool-argument-command-execution");
      expect(finding.severity).toBe("high");
      expect(finding.confidence).toBe("medium");
      expect(finding.cwe).toEqual(["CWE-78", "CWE-1426"]);
      expect(finding.owasp_llm).toEqual(["LLM05:2025", "LLM06:2025"]);
      expect(finding.location.snippet).toContain("[VALUE REDACTED]");
    }
  });

  it("keeps the FP corpus silent", async () => {
    await expect(runRustUnsafeToolExecution(resolve(CORPUS, "fp"))).resolves.toEqual([]);
  });

  it("keeps the fixed corpus silent", async () => {
    await expect(runRustUnsafeToolExecution(resolve(CORPUS, "fixed"))).resolves.toEqual([]);
  });

  it("supports a direct file target", async () => {
    await expect(runRustUnsafeToolExecution(resolve(CORPUS, "tp/src/main.rs"))).resolves.toHaveLength(3);
  });

  it("accepts valid multiline Rust strings before the tainted flow", async () => {
    await expect(runRustUnsafeToolExecution({
      target: "/fixture",
      root: "/fixture",
      files: [{
        path: "src/main.rs",
        content: `
use async_openai::types::ChatCompletionMessageToolCall;
use std::process::Command;

fn execute(call: ChatCompletionMessageToolCall) {
    let prompt = "first line
second line";
    let command = call.function.arguments;
    Command::new("bash").arg("-c").arg(command).status().unwrap();
}
`,
      }],
    })).resolves.toHaveLength(1);
  });
});
