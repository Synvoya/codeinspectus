import { beforeAll, describe, expect, test } from "vitest";
import { join } from "node:path";

import type { Finding } from "../types.js";
import { runUnsafeToolExecutionCheck } from "./unsafe-tool-execution.js";

const CORPUS = join(process.cwd(), "fixtures", "unsafe-tool-execution-corpus");
const RULE = "ci-ai-llm-tool-argument-command-execution";

const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((finding) => finding.location.file.endsWith(suffix) && finding.rule_id === RULE);

describe("model tool-argument shell execution", () => {
  let findings: Finding[];

  beforeAll(async () => {
    findings = await runUnsafeToolExecutionCheck(CORPUS);
  });

  test.each([
    ["tp/01-openai-legacy-wrapper.js", 1, 4],
    ["tp/02-openai-modern-direct.ts", 1, 9],
    ["tp/03-promisified-exec.ts", 1, 9],
  ])("TP %s emits exact metadata", (file, count, line) => {
    const hits = atFile(findings, file as string);
    expect(hits).toHaveLength(count as number);
    expect(hits[0]).toMatchObject({
      severity: "high",
      confidence: "medium",
      cwe: ["CWE-78", "CWE-1426"],
      owasp_llm: ["LLM05:2025", "LLM06:2025"],
      location: { start_line: line },
      engine: "codeinspectus-ai",
    });
    expect(hits[0]!.message).toContain("bounded static evidence");
  });

  test.each([
    "fp/01-checked-human-approval.ts",
    "fp/02-allowlisted-command.ts",
    "fp/03-child-process-lookalike.ts",
    "fp/04-tool-args-no-shell.ts",
    "fp/05-request-command-not-model.ts",
    "fp/06-static-command.ts",
    "fp/07-shadowed-exec.ts",
    "fp/08-validated-replacement.ts",
    "fixed/01-openai-fixed-execfile.ts",
  ])("FP/fixed %s stays silent", (file) => {
    expect(atFile(findings, file)).toHaveLength(0);
  });

  test("emits exactly the three planted findings and ignores comments", () => {
    expect(findings).toHaveLength(3);
    expect(findings.every((finding) => finding.rule_id === RULE)).toBe(true);
  });
});
