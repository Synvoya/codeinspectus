/**
 * CG-75 / Claim 1 — rescan correctness (Approach C). The diff logic is the pure function
 * `diffRescan(prior, fresh)` so every mode is deterministic without invoking real engines.
 * A prior finding is `resolved` ONLY when its resolution is PROVABLE: prior captured config,
 * every producing engine ran, and neither scan was truncated. Otherwise `not_rechecked`.
 *
 * CG-76 — severity_threshold is now DISPLAY-ONLY: diffRescan operates on the COMPLETE fresh
 * finding set (no threshold gating), and `filterRescanForDisplay(result, threshold)` hides
 * sub-threshold findings from the rendered resolved/remaining/introduced (not_rechecked is
 * always shown). This recovers precision the CG-75 `>low` band-aid gave up.
 */

import { describe, test, expect } from "vitest";
import { diffRescan, filterRescanForDisplay } from "./rescan.js";
import type {
  Finding,
  ScanResult,
  RescanResult,
  EngineRunInfo,
  Engine,
  Severity,
  ScannerKind,
} from "./types.js";

let fpCounter = 0;
function mkFinding(over: Partial<Finding> = {}): Finding {
  const fp = over.fingerprint ?? `fp-${fpCounter++}`;
  return {
    id: "CI-0001",
    fingerprint: fp,
    title: "Test finding",
    severity: "high",
    engine: "opengrep",
    engines: over.engine ? [over.engine] : ["opengrep"],
    rule_id: "TEST-RULE",
    cwe: ["CWE-000"],
    location: { file: "a.ts", start_line: 1, end_line: 1 },
    message: "m",
    remediation: { summary: "s", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    ...over,
  };
}

function engineInfo(engine: Engine, ran: boolean): EngineRunInfo {
  return { engine, version: "1", available: ran, ran, finding_count: 0, duration_ms: 1 };
}

function mkScan(over: Partial<ScanResult> = {}): ScanResult {
  return {
    scan_id: over.scan_id ?? "scan-00000000-0000-4000-8000-000000000000",
    target: "/repo",
    started_at: "2026-07-12T00:00:00.000Z",
    duration_ms: 1,
    engines_run: [],
    engine_details: over.engine_details ?? [engineInfo("opengrep", true)],
    offline: true,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findings: [],
    truncated: false,
    total_findings_before_limit: 0,
    disclaimer: "d",
    warnings: [],
    git_safety: { state: "clean" },
    // CG-75: a captured config marks the scan as provable-scope (present on CG-75+ scans).
    scan_config: { max_findings: 200 },
    ...over,
  };
}

const A = () => mkFinding({ fingerprint: "a", engine: "opengrep", severity: "high" });

describe("diffRescan — provable resolution (Claim 1 Part B)", () => {
  test("MODE 1: same-config, all engines ran, finding genuinely gone → resolved", () => {
    const prior = mkScan({ findings: [A()] });
    const fresh = mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", findings: [] });
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(1);
    expect(r.summary.not_rechecked).toBe(0);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["a"]);
    expect(r.partial).toBe(false);
  });

  test("MODE 6: still-present finding on like-for-like rescan → remaining, NEVER resolved", () => {
    const prior = mkScan({ findings: [A()] });
    const fresh = mkScan({ findings: [A()] });
    const r = diffRescan(prior, fresh);
    expect(r.summary.remaining).toBe(1);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(0);
  });
});

describe("diffRescan — narrower engine scope / truncation routes to not_rechecked (Claim 1)", () => {
  test("fewer scanners: prior finding's engine not in the rescan → not_rechecked", () => {
    // Prior had a Trivy finding; the rescan ran only opengrep (trivy de-scoped → absent).
    const prior = mkScan({ findings: [mkFinding({ fingerprint: "t", engine: "trivy", severity: "critical" })] });
    const fresh = mkScan({ engine_details: [engineInfo("opengrep", true)], findings: [] });
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(1);
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["t"]);
    expect(r.partial).toBe(true);
    expect(r.not_rechecked_note).toMatch(/trivy/i);
  });

  test("smaller max_findings: rescan truncated → absent prior → not_rechecked", () => {
    const prior = mkScan({ findings: [A()] });
    const fresh = mkScan({ engine_details: [engineInfo("opengrep", true)], findings: [], truncated: true });
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(1);
    expect(r.not_rechecked_note).toMatch(/truncat/i);
  });
});

describe("diffRescan — engine failed/skipped (Claim 1 mode 2)", () => {
  test("engine that produced the prior finding did NOT run → not_rechecked, NOT resolved", () => {
    const prior = mkScan({ findings: [A()] });
    // opengrep is present but ran:false (binary missing / SHA mismatch / timeout).
    const fresh = mkScan({ engine_details: [engineInfo("opengrep", false)], findings: [] });
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(1);
    expect(r.not_rechecked_note).toMatch(/opengrep did not run/i);
  });
});

describe("diffRescan — truncation (Claim 1 mode: truncated original OR rescan)", () => {
  test("prior scan was truncated → absent prior → not_rechecked", () => {
    const prior = mkScan({ findings: [A()], truncated: true });
    const fresh = mkScan({ engine_details: [engineInfo("opengrep", true)], findings: [] });
    const r = diffRescan(prior, fresh);
    expect(r.summary.not_rechecked).toBe(1);
    expect(r.summary.resolved).toBe(0);
  });
});

describe("diffRescan — old-scan fallback (Claim 1: pre-CG-75 prior, no captured config)", () => {
  test("prior lacking scan_config → absent prior → not_rechecked, no crash, clear note", () => {
    const prior = mkScan({ findings: [A()], scan_config: undefined });
    const fresh = mkScan({ engine_details: [engineInfo("opengrep", true)], findings: [] });
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(1);
    expect(r.not_rechecked_note).toMatch(/predates|older|config/i);
  });
});

describe("diffRescan — multi-engine finding needs ALL producers to have run (review MAJOR #2)", () => {
  test("a finding merged from opengrep+ai is NOT resolved when the ai co-producer did not run", () => {
    // engines:[opengrep, ai], representative engine opengrep. Rescan ran opengrep but not ai.
    const merged = mkFinding({ fingerprint: "m", engine: "opengrep", severity: "high" });
    merged.engines = ["opengrep", "codeinspectus-ai"];
    const prior = mkScan({ findings: [merged] });
    const fresh = mkScan({ engine_details: [engineInfo("opengrep", true)], findings: [] }); // ai absent
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(1);
    expect(r.not_rechecked_note).toMatch(/codeinspectus-ai did not run/i);
  });
});

describe("diffRescan — CG-76: threshold is display-only, diffs on the COMPLETE fresh set", () => {
  test("a genuinely-removed finding is RESOLVED even when fresh carried a threshold ≥ medium (precision recovered)", () => {
    // Under the CG-75 band-aid this was routed to not_rechecked; CG-76 diffs on the full set
    // (fresh is run without a threshold), so an absent finding with engine-ran + not-truncated resolves.
    const prior = mkScan({ findings: [mkFinding({ fingerprint: "h", engine: "opengrep", severity: "high" })] });
    const fresh = mkScan({
      engine_details: [engineInfo("opengrep", true)],
      findings: [], // genuinely gone — absent from the COMPLETE fresh set
      scan_config: { max_findings: 200, severity_threshold: "high" },
    });
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(1);
    expect(r.summary.not_rechecked).toBe(0);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["h"]);
  });

  test("a still-present finding REFRAMED to low (same fingerprint) is REMAINING, never resolved/not_rechecked", () => {
    // The MAJOR #2 case: a high prior finding is git-ignored → reframed to `low` in fresh, same
    // fingerprint. Because fresh is complete (all severities), the fingerprint matches → remaining.
    const prior = mkScan({ findings: [mkFinding({ fingerprint: "h", engine: "opengrep", severity: "high" })] });
    const freshReframed = mkFinding({ fingerprint: "h", engine: "opengrep", severity: "low" });
    const fresh = mkScan({ engine_details: [engineInfo("opengrep", true)], findings: [freshReframed] });
    const r = diffRescan(prior, fresh);
    expect(r.summary.remaining).toBe(1);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(0);
    expect(r.remaining.map((f) => f.fingerprint)).toEqual(["h"]);
  });

  test("BLOCKER regression: a co-located secret whose surviving fingerprint FLIPS across a git-status transition is NOT falsely resolved", () => {
    // Prior: Gitleaks(high) + AI(critical) at one location merged to the CRITICAL representative FP_A.
    const priorSecret = mkFinding({
      fingerprint: "FP_A",
      severity: "critical",
      engine: "codeinspectus-ai",
      is_secret: true,
      location: { file: "src/lib/api.ts", start_line: 10, end_line: 10 },
    });
    priorSecret.engines = ["gitleaks", "codeinspectus-ai"];
    const prior = mkScan({
      findings: [priorSecret],
      engine_details: [engineInfo("gitleaks", true), engineInfo("codeinspectus-ai", true)],
    });
    // Fresh: file git-ignored → both reframed to `low`, the tie lets Gitleaks survive dedup →
    // surviving fingerprint FLIPS to FP_G. Same secret, same location, still live on disk.
    const freshSecret = mkFinding({
      fingerprint: "FP_G",
      severity: "low",
      engine: "gitleaks",
      is_secret: true,
      location: { file: "src/lib/api.ts", start_line: 10, end_line: 10 },
    });
    const fresh = mkScan({
      findings: [freshSecret],
      engine_details: [engineInfo("gitleaks", true), engineInfo("codeinspectus-ai", true)],
    });
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(0); // MUST NOT falsely report a live critical secret as fixed
    expect(r.resolved).toEqual([]);
    // The same-identity fresh finding is "still present", not "introduced".
    expect(r.summary.introduced).toBe(0);
  });
});

describe("filterRescanForDisplay — CG-76: threshold hides sub-threshold in display, counts recomputed", () => {
  function mkResult(over: Partial<RescanResult> = {}): RescanResult {
    return {
      scan_id: "scan-1",
      prior_scan_id: "scan-0",
      target: "/repo",
      resolved: [],
      remaining: [],
      introduced: [],
      not_rechecked: [],
      summary: { resolved: 0, remaining: 0, introduced: 0, not_rechecked: 0 },
      partial: false,
      disclaimer: "d",
      ...over,
    };
  }
  const hi = (fp: string) => mkFinding({ fingerprint: fp, severity: "high" });
  const lo = (fp: string) => mkFinding({ fingerprint: fp, severity: "low" });

  test("threshold=medium hides low findings from resolved/remaining/introduced and recomputes counts", () => {
    const full = mkResult({
      resolved: [hi("r1"), lo("r2")],
      remaining: [hi("m1"), lo("m2")],
      introduced: [lo("i1")],
      summary: { resolved: 2, remaining: 2, introduced: 1, not_rechecked: 0 },
    });
    const d = filterRescanForDisplay(full, "medium");
    expect(d.resolved.map((f) => f.fingerprint)).toEqual(["r1"]);
    expect(d.remaining.map((f) => f.fingerprint)).toEqual(["m1"]);
    expect(d.introduced).toEqual([]);
    expect(d.summary).toEqual({ resolved: 1, remaining: 1, introduced: 0, not_rechecked: 0 });
  });

  test("not_rechecked is shown in FULL regardless of threshold (transparency)", () => {
    const full = mkResult({
      not_rechecked: [hi("n1"), lo("n2")],
      summary: { resolved: 0, remaining: 0, introduced: 0, not_rechecked: 2 },
      partial: true,
      not_rechecked_note: "2 finding(s) could not be re-checked.",
    });
    const d = filterRescanForDisplay(full, "medium");
    expect(d.not_rechecked.map((f) => f.fingerprint)).toEqual(["n1", "n2"]);
    expect(d.summary.not_rechecked).toBe(2);
    expect(d.partial).toBe(true);
  });

  test("no threshold → result returned unchanged", () => {
    const full = mkResult({ remaining: [hi("a"), lo("b")], summary: { resolved: 0, remaining: 2, introduced: 0, not_rechecked: 0 } });
    const d = filterRescanForDisplay(full, undefined);
    expect(d.remaining.map((f) => f.fingerprint)).toEqual(["a", "b"]);
    expect(d.summary.remaining).toBe(2);
  });
});

describe("diffRescan — introduced + mixed buckets are correct", () => {
  test("new finding only in fresh → introduced; buckets are disjoint and total-consistent", () => {
    // Distinct locations → distinct dedup keys (as they'd be post-dedup in a real scan).
    const prior = mkScan({
      findings: [
        A(),
        mkFinding({ fingerprint: "gone", engine: "opengrep", severity: "high", location: { file: "gone.ts", start_line: 1, end_line: 1 } }),
      ],
    });
    const fresh = mkScan({
      findings: [
        A(),
        mkFinding({ fingerprint: "new", engine: "opengrep", severity: "low", location: { file: "new.ts", start_line: 1, end_line: 1 } }),
      ],
    });
    const r = diffRescan(prior, fresh);
    expect(r.remaining.map((f) => f.fingerprint)).toEqual(["a"]);
    expect(r.introduced.map((f) => f.fingerprint)).toEqual(["new"]);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["gone"]); // engine ran, in scope, not truncated
    expect(r.summary.not_rechecked).toBe(0);
  });
});
