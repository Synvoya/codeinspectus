import { describe, expect, test } from "vitest";
import { compareAgainstBaseline, evaluateNewFindingPolicy } from "./baseline.js";
import { assessAggregateCoverage } from "./export/model.js";
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

describe("baseline comparison for findings that only moved lines", () => {
  const moved = (fp: string, line: number): Finding => {
    const base = finding("same");
    return { ...base, fingerprint: fp, location: { file: "src/same.ts", start_line: line, end_line: line, snippet: "db.query(`SELECT ${id}`)" } };
  };

  test("a baselined finding shifted down by inserted lines stays Existing", () => {
    const result = compareAgainstBaseline(scan(1, [moved("fp-line-3", 3)]), scan(2, [moved("fp-line-13", 13)]));

    expect(result.summary).toEqual({ New: 0, Existing: 1, "Not rechecked / unknown": 0 });
    expect(evaluateNewFindingPolicy(result, "medium").exit_code).toBe(0);
  });

  test("a second copy of a baselined line is New", () => {
    const result = compareAgainstBaseline(scan(1, [moved("fp-3", 3)]), scan(2, [moved("fp-13", 13), moved("fp-23", 23)]));

    expect(result.summary).toMatchObject({ New: 1, Existing: 1 });
  });
});

describe("baseline content anchors never absorb exact matches", () => {
  test("a new identical line beside an unchanged baselined one is New", () => {
    const base = finding("same");
    const at = (fp: string, line: number): Finding => ({ ...base, fingerprint: fp, location: { file: "src/same.ts", start_line: line, end_line: line, snippet: "el.innerHTML = reply;" } });

    const result = compareAgainstBaseline(scan(1, [at("fp-10", 10)]), scan(2, [at("fp-5", 5), at("fp-10", 10)]));

    expect(result.summary).toMatchObject({ New: 1, Existing: 1 });
  });
});

describe("baseline matching cannot be satisfied by location alone", () => {
  const at = (overrides: Partial<Finding>): Finding => ({ ...finding("x"), location: { file: "src/app.ts", start_line: 10, end_line: 10 }, ...overrides });

  test("a new finding from a different engine at a moved finding's old location is New", () => {
    const baselined = at({ fingerprint: "old-medium", severity: "medium", engine: "opengrep", engines: ["opengrep"], rule_id: "sast-rule", cwe: ["CWE-79"] });
    const moved = { ...baselined, fingerprint: "moved-medium", location: { file: "src/app.ts", start_line: 20, end_line: 20 } };
    const introduced = at({ fingerprint: "new-critical", severity: "critical", engine: "codeinspectus-ai", engines: ["codeinspectus-ai"], rule_id: "ai-rule", cwe: ["CWE-79"], producer_components: ["rule:new"] });

    const result = compareAgainstBaseline(scan(1, [baselined]), scan(2, [introduced, moved]));

    expect(result.items.find((item) => item.finding.fingerprint === "new-critical")?.state).toBe("New");
    expect(evaluateNewFindingPolicy(result, "critical").exit_code).toBe(1);
  });

  test("a different secret replacing one on the same line is New", () => {
    const secret = (fingerprint: string, hash: string): Finding => at({
      fingerprint, is_secret: true, secret_value_hash: hash, engine: "gitleaks", engines: ["gitleaks"], rule_id: "generic-api-key", cwe: ["CWE-798"],
    });

    const result = compareAgainstBaseline(scan(1, [secret("s1", "sha256:aaa")]), scan(2, [secret("s2", "sha256:bbb")]));

    expect(result.summary).toMatchObject({ New: 1, Existing: 0 });
  });
});

describe("routing and name-collision notes are context, not coverage gaps", () => {
  test("the file-routing and Trivy Pub collision warnings keep aggregate coverage complete", () => {
    const stored = scan(1, [], { warnings: [
      "File routing: 1 git-ignored finding(s) reframed as local hygiene (lower urgency — present on local disk but not committed); 0 finding(s) in node_modules and 0 non-bundle finding(s) in build output are not reported. The §6.1 client-bundle secret check still covers build output.",
      "2 Trivy Pub advisory match(es) were package-name collisions with git-sourced, custom-hosted, path or SDK packages and are not reported.",
    ] });

    expect(assessAggregateCoverage(stored).aggregate).toBe("complete");
  });
});

describe("findings the file router drops are still a coverage gap", () => {
  test("a routing warning that dropped findings keeps aggregate coverage partial", () => {
    const stored = scan(1, [], { warnings: [
      "File routing dropped 0 finding(s) in node_modules and 1 non-bundle finding(s) in build output; they are not reported.",
    ] });

    expect(assessAggregateCoverage(stored).aggregate).toBe("partial");
  });
});
