import { describe, expect, test } from "vitest";
import { projectScanForDisplay } from "./scan.js";
import type { Finding, ScanResult } from "./types.js";

function finding(id: string, severity: Finding["severity"]): Finding {
  return { id, fingerprint: `fp-${id}`, title: id, severity, engine: "opengrep", engines: ["opengrep"], rule_id: id,
    cwe: ["CWE-1"], location: { file: "x", start_line: 1, end_line: 1 }, message: id,
    remediation: { summary: "fix", steps: [], references: [] }, frameworks: [], confidence: "high" };
}

function canonical(): ScanResult {
  return { scan_id: "scan-00000000-0000-4000-8000-000000000000", target: "/repo", started_at: "now", duration_ms: 1,
    engines_run: [], engine_details: [], offline: true, detected_technologies: [], pack_coverage: [],
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
  });

  test("compliance omission is display-only", async () => {
    const raw = canonical();
    const display = await projectScanForDisplay(raw, { include_compliance: false });
    expect(display.compliance_overview).toBeUndefined();
    expect(raw.compliance_overview).toBeDefined();
  });
});
