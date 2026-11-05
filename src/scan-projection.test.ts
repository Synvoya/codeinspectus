import { describe, expect, test } from "vitest";
import { projectScanForDisplay, routingNotes } from "./scan.js";
import type { Finding, ScanResult } from "./types.js";
import { createUnavailableRepositoryTrust } from "./repository-trust/schemas.js";

function finding(id: string, severity: Finding["severity"]): Finding {
  return { id, fingerprint: `fp-${id}`, title: id, severity, engine: "opengrep", engines: ["opengrep"], rule_id: id,
    cwe: ["CWE-1"], location: { file: "x", start_line: 1, end_line: 1 }, message: id,
    remediation: { summary: "fix", steps: [], references: [] }, frameworks: [], confidence: "high" };
}

function canonical(): ScanResult {
  return { scan_id: "scan-00000000-0000-4000-8000-000000000000", target: "/repo", started_at: "now", duration_ms: 1,
    engines_run: [], engine_details: [], offline: true, detected_technologies: [], pack_coverage: [],
    repository_trust: createUnavailableRepositoryTrust(),
    summary: { critical: 0, high: 1, medium: 0, low: 2, info: 0, total: 3 },
    findings: [finding("high", "high"), finding("low-1", "low"), finding("low-2", "low")],
    truncated: false, total_findings_before_limit: 3, disclaimer: "test", warnings: [], git_safety: { state: "clean" },
    compliance_overview: { posture_score: 1, frameworks: [], disclaimer: "test" } };
}

describe("canonical scan display projection", () => {
  test("threshold/max do not mutate raw count or canonical stable IDs", async () => {
    const raw = canonical();
    const display = await projectScanForDisplay(raw, { severity_threshold: "low", max_findings: 1, include_compliance: false });
    expect(display.findings.map((item) => item.id)).toEqual(["high"]);
    expect(display.truncated).toBe(true);
    expect(raw.findings.map((item) => item.id)).toEqual(["high", "low-1", "low-2"]);
    expect(raw.total_findings_before_limit).toBe(3);
    expect(raw.truncated).toBe(false);
    expect(display.repository_trust).toEqual(raw.repository_trust);
  });

  test("compliance omission is display-only", async () => {
    const raw = canonical();
    const display = await projectScanForDisplay(raw, { include_compliance: false });
    expect(display.compliance_overview).toBeUndefined();
    expect(raw.compliance_overview).toBeDefined();
  });
});

describe("routingNotes — test/example context (design 4.6)", () => {
  const none = { third_party_code: 0, third_party_files: [], third_party_lowered: 0, third_party_lowered_files: [] };

  test("no note when nothing was lowered", () => {
    expect(routingNotes({ ...none, context_lowered: 0, context_lowered_rules: {} })).toEqual([]);
  });

  test("the note counts the lowered findings per rule and says what keeps its severity", () => {
    const [note] = routingNotes({ ...none, context_lowered: 3, context_lowered_rules: { "generic-api-key": 2, "ci-baseline-dangerous-eval": 1 } });
    expect(note!.component).toBe("routing:test-example-context");
    expect(note!.detail).toContain("3 finding(s)");
    expect(note!.detail).toContain("ci-baseline-dangerous-eval 1, generic-api-key 2");
    expect(note!.detail).toContain("every named-provider secret");
  });

  test("the note reports how many were kept at full severity because the value is used elsewhere", () => {
    const [note] = routingNotes({ ...none, context_lowered: 1, context_lowered_rules: { "generic-api-key": 1 }, context_kept_reused: 2 });
    expect(note!.component).toBe("routing:test-example-context");
    expect(note!.detail).toContain("2 test or example secret(s) kept their severity because the same value also appears in a non-test file");
    const [only] = routingNotes({ ...none, context_lowered: 0, context_lowered_rules: {}, context_kept_reused: 1 });
    expect(only!.component).toBe("routing:test-example-context");
    expect(only!.detail).toContain("1 test or example secret(s) kept");
    expect(only!.detail).not.toContain("0 finding(s)");
  });
});
