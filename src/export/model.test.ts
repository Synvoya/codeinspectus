import { describe, expect, test } from "vitest";
import type { StoredScanResult } from "../store.js";
import type { Finding } from "../types.js";
import { assessAggregateCoverage, createJsonExport } from "./model.js";
import { listNativePacks } from "../packs/registry.js";
import { createSarifExport } from "./sarif.js";
import { jsonExportSchema } from "./schemas.js";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1", fingerprint: "fp-1", title: "Test", severity: "high",
    engine: "opengrep", engines: ["opengrep"], rule_id: "test-rule", cwe: ["CWE-79"],
    location: { file: "src/app.ts", start_line: 1, end_line: 1, snippet: "safe" },
    message: "safe", remediation: { summary: "fix", steps: ["fix"], references: [] },
    frameworks: [], confidence: "high", producer_components: ["opengrep@1"], finding_kind: "sast",
    ...overrides,
  };
}

function scan(overrides: Partial<StoredScanResult> = {}): StoredScanResult {
  return {
    scan_id: "scan-00000000-0000-4000-8000-000000000000", target: "/repo",
    started_at: "2026-07-29T00:00:00.000Z", duration_ms: 1,
    engines_run: ["opengrep@1"],
    engine_details: ["opengrep", "gitleaks", "trivy"].map((engine) => ({ engine: engine as "opengrep" | "gitleaks" | "trivy", version: "1", available: true, ran: true, finding_count: engine === "opengrep" ? 1 : 0, duration_ms: 1 })),
    offline: true, detected_technologies: [], pack_coverage: listNativePacks().map((pack) => ({
      pack_id: pack.id, version: pack.version, scanner_kind: pack.scannerKind, state: "not_applicable" as const,
      languages: [], frameworks: [], platforms: [], analyzers: { registered: 0, ran: 0 }, rules: { registered: 0, ran: 0 }, limitations: [],
    })),
    summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
    findings: [finding()], truncated: false, total_findings_before_limit: 1,
    disclaimer: "test", warnings: [], git_safety: { state: "clean" },
    scan_config: { scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 1 },
    secret_coverage: "verified", storage_schema_version: "2.0.0", canonical_findings: true,
    ...overrides,
  };
}

describe("V3 aggregate coverage", () => {
  test("is exactly complete only when the canonical full-product execution has no observed gap", () => {
    expect(assessAggregateCoverage(scan()).aggregate).toBe("complete");
  });

  test("explicit scanner exclusions are partial under whole-product scope", () => {
    const result = assessAggregateCoverage(scan({ scan_config: { scanners: ["sast"], max_findings: 200 } }));
    expect(result.aggregate).toBe("partial");
    expect(result.evidence).toContainEqual(expect.objectContaining({ category: "excluded_input", component: "scanner:secret", state: "excluded" }));
  });

  test("observed bounded/skipped dependency inputs force partial", () => {
    const result = assessAggregateCoverage(scan({ dependency_coverage: [{
      ecosystem: "Pub", engine: "codeinspectus-pub", state: "ran",
      lockfiles: { discovered: 2, analyzed: 1 }, packages: { resolved: 4, eligible: 3, skipped: 1 },
      matching: "exact-enumerated-versions", limitations: [],
    }] }));
    expect(result.aggregate).toBe("partial");
    expect(result.evidence).toContainEqual(expect.objectContaining({ category: "bounded_input", state: "partial" }));
  });

  test("a native pack with skipped-input notes forces aggregate partial", () => {
    const packs = scan().pack_coverage;
    const result = assessAggregateCoverage(scan({
      pack_coverage: packs.map((pack, index) => index === 0
        ? { ...pack, state: "partial", note: "Skipped parser-invalid source src/app.py." }
        : pack),
    }));

    expect(result.aggregate).toBe("partial");
    expect(result.evidence).toContainEqual(expect.objectContaining({
      component: expect.stringMatching(/^pack:/),
      state: "partial",
      detail: "Skipped parser-invalid source src/app.py.",
    }));
  });

  test("a legacy stored scan without the canonical marker is unknown", () => {
    const legacy = scan();
    delete legacy.canonical_findings;
    delete legacy.storage_schema_version;
    expect(assessAggregateCoverage(legacy).aggregate).toBe("unknown");
  });

  test("missing expected component evidence can never serialize as complete", () => {
    const result = assessAggregateCoverage(scan({ engine_details: [{ engine: "opengrep", version: "1", available: true, ran: true, finding_count: 1, duration_ms: 1 }], pack_coverage: [] }));
    expect(result.aggregate).not.toBe("complete");
    expect(result.evidence).toContainEqual(expect.objectContaining({ component: "engine:gitleaks", state: "unknown" }));
    expect(result.evidence).toContainEqual(expect.objectContaining({ component: expect.stringMatching(/^pack:/), state: "unknown" }));
  });
});

describe("V3 JSON export", () => {
  test("includes producer and aggregate coverage on every finding and validates at runtime", () => {
    expect(createJsonExport(scan())).toMatchObject({
      schema_version: "3.0.0", scan: { canonical_findings: true }, coverage: { aggregate: "complete" },
      repository_trust: { schema_version: "1.0.0", coverage: { state: "unavailable" } },
      findings: [{ producer_components: ["opengrep@1"], coverage_context: { aggregate: "complete" } }],
    });
  });

  test("projects identical typed Git scope and finding roles into JSON and SARIF", () => {
    const scoped = scan({
      git_scope: { schema_version: "1.0.0", mode: "commit_diff", repository: "/repo",
        base: { requested: "main", commit: "a".repeat(40) }, head: { requested: "HEAD", commit: "b".repeat(40) },
        entries: [{ status: "modified", path: "src/app.ts", binary: false, generated: false, submodule: false, inspected: true }],
        primary_paths: ["src/app.ts"], primary_finding_count: 1, supporting_context_finding_count: 0, supporting_context_scanned: true, completeness: "complete", limitations: [] },
      findings: [finding({ scope_role: "primary" })],
    });
    const json = createJsonExport(scoped);
    const sarif = createSarifExport(json);
    expect(json.scan.git_scope).toEqual(scoped.git_scope);
    expect(json.findings[0]?.scope_role).toBe("primary");
    expect(sarif.runs[0]?.properties.git_scope).toEqual(scoped.git_scope);
    expect(sarif.runs[0]?.invocations[0]?.properties.git_scope).toEqual(scoped.git_scope);
    expect(sarif.runs[0]?.results[0]?.properties.scope_role).toBe("primary");
  });

  test("retains exact historical versus selected-head context in JSON and SARIF", () => {
    const history = {
      schema_version: "1.0.0" as const, repository: "/repo", commit: "c".repeat(40),
      committer_at: "2026-07-01T00:00:00.000Z", temporal_scope: "historical" as const,
      snapshot_completeness: "complete" as const, limitations: [],
    };
    const json = createJsonExport(scan({ history_revision: history }));
    const sarif = createSarifExport(json);
    expect(json.scan.history_revision).toEqual(history);
    expect(json.coverage.evidence).toContainEqual(expect.objectContaining({ component: "repository-history", state: "covered" }));
    expect(sarif.runs[0]?.properties.history_revision).toEqual(history);
    expect(sarif.runs[0]?.invocations[0]?.properties.history_revision).toEqual(history);
  });

  test("rejects missing or mismatched baseline projections and invalid policy combinations", () => {
    const base = createJsonExport(scan()) as unknown as Record<string, any>;
    const baselineId = "scan-00000000-0000-4000-8000-000000000001";
    const missing = structuredClone(base);
    missing.scan.configuration = { policy_mode: "new_findings_enforcement", baseline_scan_id: baselineId, fail_on_new_severity: "high" };
    expect(jsonExportSchema.safeParse(missing).success).toBe(false);

    const mismatch = structuredClone(base);
    mismatch.scan.configuration = { policy_mode: "report_only", baseline_scan_id: baselineId };
    mismatch.baseline = { schema_version: "1.0.0", baseline_scan_id: "scan-00000000-0000-4000-8000-000000000002", scan_id: base.scan.id,
      target: "/repo", repository: "/repo", summary: { New: 0, Existing: 1, "Not rechecked / unknown": 0 }, coverage: "complete", partial: false, notes: [], items: [] };
    expect(jsonExportSchema.safeParse(mismatch).success).toBe(false);

    const conflicting = structuredClone(base);
    conflicting.scan.configuration = { policy_mode: "new_findings_enforcement", baseline_scan_id: baselineId, fail_on_new_severity: "high", fail_on_severity: "high" };
    conflicting.baseline = { ...mismatch.baseline, baseline_scan_id: baselineId };
    expect(jsonExportSchema.safeParse(conflicting).success).toBe(false);
  });

  test("defensively redacts arbitrary raw text on a secret finding", () => {
    const sentinel = "RAW-UNRECOGNIZED-SECRET-9081726354";
    const document = createJsonExport(scan({ findings: [finding({
      is_secret: true, engine: "gitleaks", engines: ["gitleaks"], rule_id: "generic-secret",
      message: sentinel, location: { file: "x", start_line: 1, end_line: 1, snippet: sentinel },
    })] }));
    expect(JSON.stringify(document)).not.toContain(sentinel);
    expect(document.findings[0]?.message).toMatch(/redacted/i);
    expect(document.findings[0]?.remediation.summary).toBe("fix");
  });

  test("recognized secret tokens cannot survive in any JSON or SARIF-bound free text", () => {
    const token = "sk_live_1234567890ABCDEFGHIJ";
    const document = createJsonExport(scan({ findings: [finding({
      title: `title ${token}`, message: `message ${token}`,
      remediation: { summary: `summary ${token}`, steps: [`step ${token}`], code_suggestion: `code ${token}`, references: [`https://example.test/${token}`] },
      frameworks: [{ framework: `framework ${token}`, controls: [`control ${token}`] }],
    })] }));
    expect(JSON.stringify(document)).not.toContain(token);
    expect(JSON.stringify(createSarifExport(document))).not.toContain(token);
  });
});
