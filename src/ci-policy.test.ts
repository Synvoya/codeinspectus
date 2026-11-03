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

  // Task 5 (Hibi, 2026-10-31): declared gaps make coverage partial; a named opt-in lets CI pass them.
  describe("accepted coverage gaps", () => {
    const evidence = (...items: Array<[string, "partial" | "unknown" | "excluded" | "covered" | "informational"]>) =>
      items.map(([component, state]) => ({ category: "declared_scope" as const, component, state, detail: "d" }));
    const gapped = (items: ReturnType<typeof evidence>, severities: Array<"critical" | "high"> = []) => ({
      ...document("partial", severities),
      coverage: { aggregate: "partial" as const, evidence: items },
    });

    test("passes coverage when every non-complete cause is an accepted gap, still reporting partial", () => {
      const result = evaluateCiPolicy(gapped(evidence(["gap:php-sast", "partial"], ["engine:opengrep", "covered"])), undefined, ["php-sast", "deno-lock"]);
      expect(result).toMatchObject({ exit_code: 0, coverage: "partial", accepted_gaps: ["php-sast", "deno-lock"] });
      expect(evaluateCiPolicy(gapped(evidence(["gap:php-sast", "partial"]), ["critical"]), "high", ["php-sast"]))
        .toMatchObject({ exit_code: 1, coverage: "partial" });
    });

    test.each([
      ["an unaccepted gap", evidence(["gap:php-sast", "partial"], ["gap:deno-lock", "partial"])],
      ["another partial cause", evidence(["gap:php-sast", "partial"], ["scan-pipeline", "partial"])],
      ["an excluded scanner", evidence(["gap:php-sast", "partial"], ["scanner:sast", "excluded"])],
      ["an unknown component", evidence(["gap:php-sast", "partial"], ["engine:trivy", "unknown"])],
      ["no gap evidence at all", evidence()],
    ])("still returns 2 with %s", (_label, items) => {
      expect(evaluateCiPolicy(gapped(items), undefined, ["php-sast"])).toMatchObject({ exit_code: 2 });
    });

    test("unknown aggregate coverage never passes", () => {
      const unknown = { ...document("unknown", []), coverage: { aggregate: "unknown" as const, evidence: evidence(["gap:php-sast", "partial"]) } };
      expect(evaluateCiPolicy(unknown, undefined, ["php-sast"])).toMatchObject({ exit_code: 2 });
    });
  });
});
