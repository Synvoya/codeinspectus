/**
 * CG-42 — the git-safety advisory renders under its OWN "Before you fix:" line in the
 * human-readable scan summary, NOT under "Warnings:" (a non-expert reads "Warnings" as
 * "problems in my code"; the checkpoint nudge is a pre-fix safety note, not a finding).
 * CG-30 routing warnings still render under "Warnings:".
 */

import { describe, test, expect } from "vitest";
import { summarizeScan, summarizeRescan } from "./summarize.js";
import { NO_GIT_RECOMMENDATION, DIRTY_RECOMMENDATION } from "./git-safety.js";
import type { ScanResult, GitSafety, RescanResult, Finding } from "./types.js";
import { createUnavailableRepositoryTrust } from "./repository-trust/schemas.js";
import { createEmptyRepositoryTrustChanges } from "./repository-trust/diff.js";

function mkResult(over: Partial<ScanResult> = {}): ScanResult {
  return {
    scan_id: "scan-test",
    target: "/tmp/x",
    started_at: "2026-07-01T00:00:00.000Z",
    duration_ms: 1,
    engines_run: ["codeinspectus-ai@1"],
    engine_details: [],
    offline: true,
    detected_technologies: [],
    pack_coverage: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findings: [],
    truncated: false,
    total_findings_before_limit: 0,
    disclaimer: "This is not an audit or certification.",
    warnings: [],
    git_safety: { state: "clean" } as GitSafety,
    ...over,
    repository_trust: over.repository_trust ?? createUnavailableRepositoryTrust(),
  };
}

describe("summarizeScan — git-safety advisory placement (CG-42)", () => {
  test("surfaces detected technologies and exact native-pack execution counts", () => {
    const out = summarizeScan(
      mkResult({
        detected_technologies: [
          { id: "typescript", kind: "language", confidence: "high", evidence: ["src/app.ts"] },
          { id: "react", kind: "framework", confidence: "high", evidence: ["package.json"] },
        ],
        pack_coverage: [
          {
            pack_id: "javascript-typescript",
            version: "1.2.0",
            scanner_kind: "ai",
            state: "partial",
            languages: ["javascript", "typescript"],
            frameworks: ["react"],
            platforms: [],
            analyzers: { registered: 7, ran: 6 },
            rules: { registered: 21, ran: 17 },
            limitations: ["Rule-defined coverage only."],
            note: "1 analyzer failed.",
          },
        ],
      }),
    );

    expect(out).toContain("Detected technologies: typescript, react");
    expect(out).toContain("javascript-typescript=partial (6/7 analyzers, 17/21 rules)");
    expect(out).toContain("1 analyzer failed.");
  });

  test("surfaces native Pub dependency scope and skipped packages", () => {
    const out = summarizeScan(
      mkResult({
        dependency_coverage: [
          {
            ecosystem: "Pub",
            engine: "codeinspectus-pub",
            state: "partial",
            lockfiles: { discovered: 2, analyzed: 1 },
            packages: { resolved: 12, eligible: 10, skipped: 2 },
            database_version: "2026-07-26",
            matching: "exact-enumerated-versions",
            limitations: ["One lockfile was malformed."],
            note: "One lockfile was malformed.",
          },
        ],
      }),
    );

    expect(out).toContain("Dependency coverage (exact locked-version matching only):");
    expect(out).toContain("Pub/codeinspectus-pub=partial (1/2 lockfiles, 10/12 eligible packages, 2 unverifiable git/custom-hosted, snapshot 2026-07-26)");
    expect(out).toContain("One lockfile was malformed.");
  });

  test("renders osv-scanner dependency coverage without native Pub wording", () => {
    const out = summarizeScan(
      mkResult({
        dependency_coverage: [
          {
            ecosystem: "PyPI",
            engine: "osv-scanner",
            state: "ran",
            lockfiles: { discovered: 1, analyzed: 1 },
            packages: { resolved: 3, eligible: 3, skipped: 0 },
            database_version: "2026-10-30T08:00:00.000Z",
            matching: "osv-scanner-offline",
            limitations: [],
          },
          {
            ecosystem: "npm",
            engine: "osv-scanner",
            state: "unavailable",
            lockfiles: { discovered: 1, analyzed: 0 },
            packages: { resolved: 12, eligible: 0, skipped: 12 },
            matching: "osv-scanner-offline",
            limitations: ["npm database not installed."],
            note: "npm database not installed.",
          },
        ],
      }),
    );

    expect(out).toContain("PyPI/osv-scanner=ran (1/1 lockfiles, 3/3 eligible packages, 0 not checked, database 2026-10-30T08:00:00.000Z)");
    expect(out).toContain("npm/osv-scanner=unavailable (0/1 lockfiles, 0/12 eligible packages, 12 not checked) — npm database not installed.");
    expect(out).not.toMatch(/osv-scanner=[^\n]*unverifiable git\/custom-hosted/);
  });

  // `summary` counts the displayed set; under `--severity high` the headline used to print "0 medium"
  // while medium findings existed and were only hidden.
  test("a severity display filter lists only the included levels and says lower ones are hidden", () => {
    const filtered = summarizeScan(mkResult({
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
      scan_config: { severity_threshold: "high", max_findings: 200 },
    }));
    expect(filtered).toContain("1 findings at or above high — 0 critical, 1 high. Lower severities are hidden by the display filter");
    expect(filtered).not.toContain("0 medium");

    const unfiltered = summarizeScan(mkResult({ summary: { critical: 0, high: 1, medium: 1, low: 0, info: 0, total: 2 } }));
    expect(unfiltered).toContain("2 findings — 0 critical, 1 high, 1 medium, 0 low, 0 info.");
  });

  test("no_git → recommendation under 'Before you fix:', and NO 'Warnings:' section", () => {
    const out = summarizeScan(
      mkResult({ git_safety: { state: "no_git", recommendation: NO_GIT_RECOMMENDATION }, warnings: [] }),
    );
    expect(out).toContain(`Before you fix:\n  ${NO_GIT_RECOMMENDATION}`);
    expect(out).not.toContain("Warnings:");
  });

  test("dirty + CG-30 routing warning → advice under 'Before you fix:', routing under 'Warnings:'", () => {
    const routing =
      "File routing: reframed 2 git-ignored finding(s) as local-hygiene (lower urgency).";
    const out = summarizeScan(
      mkResult({
        git_safety: { state: "dirty", recommendation: DIRTY_RECOMMENDATION },
        warnings: [routing],
      }),
    );
    expect(out).toContain(`Before you fix:\n  ${DIRTY_RECOMMENDATION}`);
    expect(out).toContain(`Warnings:\n  - ${routing}`);
    // the git recommendation must NOT leak into the Warnings section
    const warningsSection = out.slice(out.indexOf("Warnings:"));
    expect(warningsSection).not.toContain(DIRTY_RECOMMENDATION);
  });

  test("clean → no 'Before you fix:' line", () => {
    const out = summarizeScan(mkResult({ git_safety: { state: "clean" }, warnings: [] }));
    expect(out).not.toContain("Before you fix:");
  });

  test("unknown → no 'Before you fix:' line (degrade silently)", () => {
    const out = summarizeScan(mkResult({ git_safety: { state: "unknown" }, warnings: [] }));
    expect(out).not.toContain("Before you fix:");
  });

  test("three-state security-control evidence is summarized as metadata without absence framing", () => {
    const out = summarizeScan(
      mkResult({
        security_control_evidence: [
          {
            control_id: "a",
            state: "verified_in_repository",
            providers: ["nextjs"],
            evidence_locations: [],
            limitation: "l",
          },
          {
            control_id: "b",
            state: "insecure_configuration_found",
            providers: ["helmet"],
            evidence_locations: [],
            limitation: "l",
          },
          {
            control_id: "c",
            state: "not_verifiable_from_repository",
            providers: [],
            evidence_locations: [],
            limitation: "l",
          },
        ],
      }),
    );
    expect(out).toContain("Runtime-control evidence (metadata; no absence penalty):");
    expect(out).toContain("1 verified in repository");
    expect(out).toContain("1 explicit insecure configuration");
    expect(out).toContain("1 not verifiable from repository");
  });
});

// ── CG-75 / Claim 1: rescan text must surface not_rechecked honestly ─────────
function mkFinding(fp: string): Finding {
  return {
    id: "CI-0001",
    fingerprint: fp,
    title: "SQL injection",
    severity: "high",
    engine: "opengrep",
    engines: ["opengrep"],
    rule_id: "R",
    cwe: ["CWE-89"],
    location: { file: "a.ts", start_line: 1, end_line: 1 },
    message: "m",
    remediation: { summary: "s", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
  };
}

function mkRescan(over: Partial<RescanResult> = {}): RescanResult {
  return {
    scan_id: "scan-1",
    prior_scan_id: "scan-0",
    target: "/repo",
    detected_technologies: [],
    pack_coverage: [],
    repository_trust: createUnavailableRepositoryTrust(),
    repository_trust_changes: createEmptyRepositoryTrustChanges(),
    resolved: [],
    remaining: [],
    introduced: [],
    not_rechecked: [],
    summary: { resolved: 0, remaining: 0, introduced: 0, not_rechecked: 0 },
    partial: false,
    disclaimer: "This is not an audit or certification.",
    ...over,
  };
}

describe("summarizeRescan — not_rechecked surfaced in human text (CG-75 Claim 1)", () => {
  test("retains fresh technology and not-run pack coverage", () => {
    const out = summarizeRescan(
      mkRescan({
        detected_technologies: [
          { id: "dart", kind: "language", confidence: "high", evidence: ["lib/main.dart"] },
        ],
        pack_coverage: [
          {
            pack_id: "javascript-typescript",
            version: "1.2.0",
            scanner_kind: "ai",
            state: "not_run",
            languages: ["javascript", "typescript"],
            frameworks: [],
            platforms: [],
            analyzers: { registered: 7, ran: 0 },
            rules: { registered: 21, ran: 0 },
            limitations: ["The ai scanner class was excluded."],
          },
        ],
      }),
    );

    expect(out).toContain("Detected technologies: dart");
    expect(out).toContain("javascript-typescript=not_run (0/7 analyzers, 0/21 rules)");
  });

  test("retains fresh native dependency coverage", () => {
    const out = summarizeRescan(
      mkRescan({
        dependency_coverage: [
          {
            ecosystem: "Pub",
            engine: "codeinspectus-pub",
            state: "ran",
            lockfiles: { discovered: 1, analyzed: 1 },
            packages: { resolved: 4, eligible: 4, skipped: 0 },
            database_version: "2026-07-26",
            matching: "exact-enumerated-versions",
            limitations: [],
          },
        ],
      }),
    );

    expect(out).toContain("Pub/codeinspectus-pub=ran (1/1 lockfiles, 4/4 eligible packages, 0 unverifiable git/custom-hosted, snapshot 2026-07-26)");
  });

  test("not_rechecked findings appear under a dedicated NOT-confirmed-resolved section with count + note", () => {
    const out = summarizeRescan(
      mkRescan({
        not_rechecked: [mkFinding("t")],
        summary: { resolved: 0, remaining: 0, introduced: 0, not_rechecked: 1 },
        partial: true,
        not_rechecked_note: "1 finding(s) could not be re-checked and are NOT confirmed resolved — the trivy engine did not run in the rescan.",
      }),
    );
    // count on the header line
    expect(out).toMatch(/Not re-?checked:\s*1/i);
    // an explicit "not confirmed resolved" caveat
    expect(out).toMatch(/NOT confirmed resolved/i);
    // the offending finding is listed
    expect(out).toContain("SQL injection");
    // the reason note is present
    expect(out).toMatch(/trivy engine did not run/i);
  });

  test("clean like-for-like rescan → no not_rechecked section", () => {
    const out = summarizeRescan(mkRescan({ remaining: [mkFinding("a")], summary: { resolved: 0, remaining: 1, introduced: 0, not_rechecked: 0 } }));
    expect(out).not.toMatch(/could not be re-?checked/i);
    expect(out).not.toMatch(/NOT confirmed resolved/i);
  });
});

describe("summarizeScan - Synvoya (CodeInspectus) family wording", () => {
  const finding = (over: Partial<Finding>): Finding => ({
    id: "CI-0001", fingerprint: "fp", title: "Hardcoded key", severity: "high", engine: "codeinspectus-ai", engines: ["codeinspectus-ai"],
    rule_id: "ci-ai-client-hardcoded-secret", cwe: ["CWE-798"], location: { file: "a.ts", start_line: 3, end_line: 3 }, message: "m",
    remediation: { summary: "s", steps: [], references: [] }, frameworks: [], confidence: "high", ...over,
  });

  test("family members read Synvoya (CodeInspectus) with the raw engine kept; upstream engines are unchanged", () => {
    const out = summarizeScan(mkResult({
      engines_run: ["opengrep@1.33.1", "codeinspectus-ai@1", "codeinspectus-pub@2"],
      findings: [
        finding({ engine_family: "synvoya" }),
        finding({ id: "CI-0002", title: "Upstream", engine: "trivy", engines: ["trivy"], rule_id: "CVE-2024-1" }),
      ],
      summary: { critical: 0, high: 2, medium: 0, low: 0, info: 0, total: 2 },
    }));
    expect(out).toContain("Engines: opengrep@1.33.1, Synvoya (CodeInspectus) [codeinspectus-ai@1, codeinspectus-pub@2]");
    expect(out).toContain("(CWE-798, Synvoya (CodeInspectus): codeinspectus-ai)");
    expect(out).toContain("(CWE-798, trivy)");
  });

  test("a family member without the display field (an export-shaped scan, as in a bundle report) still reads the family", () => {
    const out = summarizeScan(mkResult({
      findings: [finding({ engine: "synvoya", engines: ["synvoya"], rule_id: "SYN-2026-001", cwe: ["CWE-1104"] })],
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
    }));
    expect(out).toContain("(CWE-1104, Synvoya (CodeInspectus): synvoya)");
  });

  test("a scan with no family member prints the engine list exactly as before", () => {
    expect(summarizeScan(mkResult({ engines_run: ["opengrep@1", "trivy@2"] }))).toContain("Engines: opengrep@1, trivy@2 |");
  });
});
