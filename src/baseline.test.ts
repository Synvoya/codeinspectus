import { describe, expect, test } from "vitest";
import { compareAgainstBaseline, evaluateNewFindingPolicy } from "./baseline.js";
import { listNativePacks } from "./packs/registry.js";
import type { Finding } from "./types.js";
import type { StoredScanResult } from "./store.js";

function finding(fp: string, severity: Finding["severity"] = "high", component = "rule:a"): Finding {
  return { id: `CI-${fp}`, fingerprint: fp, title: fp, severity, engine: "opengrep", engines: ["opengrep"],
    rule_id: `rule-${fp}`, cwe: ["CWE-1"], location: { file: `src/${fp}.ts`, start_line: 1, end_line: 1 },
    message: fp, remediation: { summary: "fix", steps: [], references: [] }, frameworks: [], confidence: "high",
    producer_components: [component], finding_kind: "sast" };
}

function scan(id: number, findings: Finding[], overrides: Partial<StoredScanResult> = {}): StoredScanResult {
  const engines = ["opengrep", "gitleaks", "trivy", "codeinspectus-ai"] as const;
  return { scan_id: `scan-00000000-0000-4000-8000-${String(id).padStart(12, "0")}`, target: "/repo", repository_root: "/repo",
    started_at: `2026-07-0${id}T00:00:00.000Z`, duration_ms: 1, engines_run: engines.map((engine) => `${engine}@1`),
    engine_details: engines.map((engine) => ({ engine, version: "1", available: true, ran: true, finding_count: findings.filter((f) => f.engines.includes(engine)).length, duration_ms: 1 })),
    offline: true, detected_technologies: [], pack_coverage: listNativePacks().map((pack) => ({ pack_id: pack.id, version: pack.version,
      scanner_kind: pack.scannerKind, state: "not_applicable" as const, languages: [], frameworks: [], platforms: [],
      analyzers: { registered: 0, ran: 0 }, rules: { registered: 0, ran: 0 }, limitations: [] })),
    summary: { critical: findings.filter((f) => f.severity === "critical").length, high: findings.filter((f) => f.severity === "high").length,
      medium: 0, low: findings.filter((f) => f.severity === "low").length, info: 0, total: findings.length }, findings,
    truncated: false, total_findings_before_limit: findings.length, disclaimer: "test", warnings: [], secret_coverage: "verified",
    component_signatures: { "rule:a": "v1", "rule:new": "v1" }, git_safety: { state: "clean" },
    scan_config: { scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 200 },
    storage_schema_version: "2.0.0", canonical_findings: true, ...overrides };
}

describe("pairwise baseline comparison", () => {
  test("classifies existing and proven new findings without global history", () => {
    const old = scan(1, [finding("same")]);
    const fresh = scan(2, [finding("same"), finding("new", "critical", "rule:new")]);
    const result = compareAgainstBaseline(old, fresh);
    expect(result.summary).toEqual({ New: 1, Existing: 1, "Not rechecked / unknown": 0 });
    expect(result.coverage).toBe("complete");
    expect(evaluateNewFindingPolicy(result, "high")).toMatchObject({ exit_code: 1, findings_at_or_above_threshold: 1 });
  });

  test("changed producer signatures make baseline absence unknown and exit 2", () => {
    const old = scan(1, [], { component_signatures: { "rule:new": "v1" } });
    const fresh = scan(2, [finding("new", "high", "rule:new")], { component_signatures: { "rule:new": "v2" } });
    const result = compareAgainstBaseline(old, fresh);
    expect(result.items[0]?.state).toBe("Not rechecked / unknown");
    expect(evaluateNewFindingPolicy(result, "high").exit_code).toBe(2);
  });

  test.each([
    { target: "/other" },
    { repository_root: "/other" },
    { canonical_findings: undefined },
    { truncated: true },
  ])("incompatible baseline fails closed: %o", (overrides) => {
    const old = scan(1, [], overrides as Partial<StoredScanResult>);
    const result = compareAgainstBaseline(old, scan(2, [finding("new")]));
    expect(result.partial).toBe(true);
    expect(evaluateNewFindingPolicy(result, "high").exit_code).toBe(2);
  });

  test("new-only policy ignores existing high findings and retains every item", () => {
    const old = scan(1, [finding("existing", "critical")]);
    const fresh = scan(2, [finding("existing", "critical"), finding("new-low", "low", "rule:new")]);
    const result = compareAgainstBaseline(old, fresh);
    expect(result.items).toHaveLength(fresh.findings.length);
    expect(evaluateNewFindingPolicy(result, "high")).toMatchObject({ exit_code: 0, findings_at_or_above_threshold: 0 });
  });
});
