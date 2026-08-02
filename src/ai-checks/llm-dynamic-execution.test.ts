import { beforeAll, describe, expect, test } from "vitest";
import { join } from "node:path";

import type { Finding } from "../types.js";
import { runLlmDynamicExecutionCheck } from "./llm-dynamic-execution.js";

const CORPUS = join(process.cwd(), "fixtures", "llm-dynamic-execution-corpus");
const RULE = "ci-ai-llm-output-dynamic-execution";
const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((finding) => finding.location.file.endsWith(suffix) && finding.rule_id === RULE);

describe("model output to dynamic execution", () => {
  let findings: Finding[];
  beforeAll(async () => {
    findings = await runLlmDynamicExecutionCheck(CORPUS);
  });

  test.each([
    ["tp/01-direct-eval.ts", 6, "CWE-94"],
    ["tp/02-split-function.ts", 7, "CWE-94"],
    ["tp/03-child-process-exec.ts", 7, "CWE-78"],
    ["tp/04-anthropic-exec-sync.ts", 8, "CWE-78"],
    ["tp/05-vercel-execa-command.ts", 6, "CWE-78"],
  ])("TP %s fires once with sink-specific metadata", (file, line, cwe) => {
    const hits = atFile(findings, file as string);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      severity: "high",
      confidence: "medium",
      location: { start_line: line },
      engine: "codeinspectus-ai",
    });
    expect(hits[0]!.cwe).toContain(cwe);
    expect(hits[0]!.cwe).toContain("CWE-1426");
    expect(hits[0]!.owasp_llm).toContain("LLM05:2025");
  });

  test.each([
    "fp/01-constants.ts",
    "fp/02-allowlisted-dispatch.ts",
    "fp/03-non-shell-array.ts",
    "fp/04-request-not-model.ts",
    "fp/05-shadowed-eval.ts",
    "fp/06-unrelated-text-property.ts",
    "fixed/01-validated-model-code.ts",
  ])("FP/fixed %s stays silent", (file) => {
    expect(atFile(findings, file)).toHaveLength(0);
  });

  test("emits exactly the five planted findings", () => {
    expect(findings).toHaveLength(5);
    expect(findings.every((finding) => finding.rule_id === RULE)).toBe(true);
  });
});
