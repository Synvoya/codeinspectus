import { describe, expect, test } from "vitest";
import { evaluateCiPolicy } from "./ci-policy.js";
import type { JsonExport } from "./export/schemas.js";

function document(coverage: "complete" | "partial" | "unknown", severities: Array<"critical" | "high" | "medium" | "low" | "info">): Pick<JsonExport, "coverage" | "findings"> {
  return {
    coverage: { aggregate: coverage, evidence: [] },
    findings: severities.map((severity, index) => ({ severity } as JsonExport["findings"][number])),
  };
}

describe("CI policy exit contract", () => {
  test("report-only returns 0 with complete coverage even when findings exist", () => {
    expect(evaluateCiPolicy(document("complete", ["critical", "high"]))).toMatchObject({ mode: "report_only", exit_code: 0 });
  });

  test("enforcement returns 0 when no finding meets the threshold", () => {
    expect(evaluateCiPolicy(document("complete", ["medium", "low"]), "high")).toMatchObject({ exit_code: 0, findings_at_or_above_threshold: 0 });
  });

  test("enforcement returns 1 when a finding meets or exceeds the threshold", () => {
    expect(evaluateCiPolicy(document("complete", ["critical", "high", "medium"]), "high")).toMatchObject({ exit_code: 1, findings_at_or_above_threshold: 2 });
  });

  test("Git-scoped enforcement counts primary findings and retains supporting context without gating it", () => {
    const scoped = document("complete", ["critical", "high"]);
    scoped.findings[0]!.scope_role = "supporting_context";
    scoped.findings[1]!.scope_role = "primary";
    expect(evaluateCiPolicy(scoped, "high")).toMatchObject({ exit_code: 1, findings_at_or_above_threshold: 1 });
    scoped.findings[1]!.scope_role = "supporting_context";
    expect(evaluateCiPolicy(scoped, "high")).toMatchObject({ exit_code: 0, findings_at_or_above_threshold: 0 });
  });

  test.each(["partial", "unknown"] as const)("%s coverage returns 2 without a severity policy", (coverage) => {
    expect(evaluateCiPolicy(document(coverage, []))).toMatchObject({ exit_code: 2, coverage });
  });

  test("incomplete coverage takes precedence over threshold findings and returns 2", () => {
    expect(evaluateCiPolicy(document("partial", ["critical"]), "high")).toMatchObject({ exit_code: 2, findings_at_or_above_threshold: 1 });
  });
});
