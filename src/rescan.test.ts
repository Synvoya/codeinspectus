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
import { createUnavailableRepositoryTrust } from "./repository-trust/schemas.js";
import { createEmptyRepositoryTrustChanges } from "./repository-trust/diff.js";
import { DEDUP_COMPONENT, staticComponentSignatures } from "./provenance.js";

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
    producer_components: ["codeinspectus:pipeline", `test:${over.engine ?? "opengrep"}`],
    finding_kind: over.engine === "trivy" ? "vulnerability" : "other",
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
    detected_technologies: [],
    pack_coverage: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findings: [],
    truncated: false,
    total_findings_before_limit: 0,
    disclaimer: "d",
    warnings: [],
    git_safety: { state: "clean" },
    component_signatures: {
      "codeinspectus:pipeline": "pipeline-v1",
      "test:opengrep": "opengrep-v1",
      "test:gitleaks": "gitleaks-v1",
      "test:trivy": "trivy-v1",
      "test:codeinspectus-ai": "ai-v1",
    },
    // CG-75: a captured config marks the scan as provable-scope (present on CG-75+ scans).
    scan_config: { max_findings: 200 },
    // M6 fix rounds 1-2: a current scan records, per pass, what it could not fully analyze (nothing here).
    engine_unchecked: { "opengrep:baseline": { files: [] }, "opengrep:pack": { files: [] }, native: { files: [] }, "osv-scanner": { files: [] } },
    ...over,
    repository_trust: over.repository_trust ?? createUnavailableRepositoryTrust(),
  };
}

const A = () => mkFinding({ fingerprint: "a", engine: "opengrep", severity: "high" });

describe("diffRescan — provable resolution (Claim 1 Part B)", () => {
  test("MODE 1: same-config, all engines ran, finding genuinely gone → resolved", () => {
    const prior = mkScan({ findings: [A()] });
    const fresh = mkScan({
      scan_id: "scan-11111111-1111-4111-8111-111111111111",
      findings: [],
      detected_technologies: [
        { id: "typescript", kind: "language", confidence: "high", evidence: ["src/app.ts"] },
      ],
      pack_coverage: [
        {
          pack_id: "javascript-typescript",
          version: "1.2.0",
          scanner_kind: "ai",
          state: "ran",
          languages: ["javascript", "typescript"],
          frameworks: [],
          platforms: [],
          analyzers: { registered: 7, ran: 7 },
          rules: { registered: 21, ran: 21 },
          limitations: ["Rule-specific coverage only."],
        },
      ],
    });
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(1);
    expect(r.summary.not_rechecked).toBe(0);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["a"]);
    expect(r.partial).toBe(false);
    expect(r.detected_technologies).toEqual(fresh.detected_technologies);
    expect(r.pack_coverage).toEqual(fresh.pack_coverage);
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

  test.each([
    ["GHSA primary survives", "GHSA-test-0000-0001"],
    ["CVE alias survives", "CVE-2026-0001"],
  ])("BLOCKER regression: Pub/Trivy representative change matches when %s", (_label, freshRule) => {
    const priorVulnerability = mkFinding({
      fingerprint: "FP_PUB",
      engine: "codeinspectus-pub",
      engines: ["codeinspectus-pub"],
      rule_id: "GHSA-test-0000-0001",
      vulnerability_aliases: ["CVE-2026-0001"],
      finding_kind: "vulnerability",
      location: { file: "pubspec.lock", start_line: 12, end_line: 12 },
    });
    const freshVulnerability = mkFinding({
      fingerprint: "FP_TRIVY",
      engine: "trivy",
      engines: ["trivy"],
      rule_id: freshRule,
      finding_kind: "vulnerability",
      location: { file: "pubspec.lock", start_line: 1, end_line: 1 },
    });
    const result = diffRescan(
      mkScan({ findings: [priorVulnerability] }),
      mkScan({
        findings: [freshVulnerability],
        engine_details: [engineInfo("trivy", true), engineInfo("codeinspectus-pub", true)],
      }),
    );

    expect(result.summary).toMatchObject({ remaining: 1, introduced: 0, resolved: 0 });
    expect(result.resolved).toEqual([]);
  });
});

describe("diffRescan — 4.1 one finding per secret", () => {
  test("a rescan after the merge reports the absorbed prior remaining, resolved 0", () => {
    // 4.0 stored Gitleaks private-key (1-30) and Trivy private-key (2-29) on one PEM file as two findings.
    const pem = { file: "keys/server.pem" };
    const priorGitleaks = mkFinding({ fingerprint: "FP_GL", engine: "gitleaks", rule_id: "private-key", is_secret: true, cwe: ["CWE-798"], finding_kind: "secret", location: { ...pem, start_line: 1, end_line: 30 } });
    const priorTrivy = mkFinding({ fingerprint: "FP_TR", engine: "trivy", rule_id: "private-key", is_secret: true, cwe: ["CWE-798"], finding_kind: "secret", location: { ...pem, start_line: 2, end_line: 29 } });
    const engines = [engineInfo("gitleaks", true), engineInfo("trivy", true)];
    const prior = mkScan({ findings: [priorGitleaks, priorTrivy], engine_details: engines });
    // 4.1 merges them: the Gitleaks finding survives with both engines.
    const survivor = { ...priorGitleaks, engines: ["gitleaks", "trivy"] as Engine[], producer_components: ["codeinspectus:pipeline", "test:gitleaks", "test:trivy"] };
    const fresh = mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", findings: [survivor], engine_details: engines });
    fresh.component_signatures = { ...fresh.component_signatures, ...staticComponentSignatures([DEDUP_COMPONENT]) }; // made by 4.1
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(0);
    expect(r.summary.introduced).toBe(0);
    expect(r.remaining.map((f) => f.fingerprint)).toEqual(["FP_GL"]);
  });

  test("EmailThing: a 4.0 Gitleaks key block absorbed by a 4.1 native survivor inside it is never resolved", () => {
    const file = "src/mail.ts";
    const priorBlock = mkFinding({ fingerprint: "FP_BLOCK", engine: "gitleaks", rule_id: "private-key", is_secret: true, cwe: ["CWE-798"], finding_kind: "secret", location: { file, start_line: 645, end_line: 648 } });
    const priorNative = mkFinding({ fingerprint: "FP_AI", engine: "codeinspectus-ai", rule_id: "ci-ai-client-hardcoded-secret", severity: "critical", is_secret: true, cwe: ["CWE-798"], finding_kind: "secret", secret_value_hash: "sha256:abc", location: { file, start_line: 645, end_line: 645 } });
    const survivor = { ...priorNative, engines: ["codeinspectus-ai", "gitleaks"] as Engine[], producer_components: ["codeinspectus:pipeline", "test:codeinspectus-ai", "test:gitleaks"] };
    const engines = [engineInfo("gitleaks", true), engineInfo("codeinspectus-ai", true)];
    const prior = mkScan({ findings: [priorBlock, priorNative], engine_details: engines });
    const fresh = mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", findings: [survivor], engine_details: engines });
    fresh.component_signatures = { ...fresh.component_signatures, ...staticComponentSignatures([DEDUP_COMPONENT]) }; // made by 4.1
    const r = diffRescan(prior, fresh);
    expect(r.summary.resolved).toBe(0);
    expect(r.summary.not_rechecked).toBe(0);
    expect(r.summary.introduced).toBe(0);
    expect(r.remaining.map((f) => f.fingerprint)).toEqual(["FP_AI"]);
  });

  test("two 4.0 scans never use the containment match (fix round 3)", () => {
    const pem = { file: "keys/server.pem" };
    const priorTrivy = mkFinding({ fingerprint: "FP_TR", engine: "trivy", rule_id: "private-key", is_secret: true, cwe: ["CWE-798"], finding_kind: "secret", location: { ...pem, start_line: 2, end_line: 29 } });
    const survivor = mkFinding({ fingerprint: "FP_GL", engine: "gitleaks", rule_id: "private-key", is_secret: true, cwe: ["CWE-798"], finding_kind: "secret", location: { ...pem, start_line: 1, end_line: 30 } });
    survivor.engines = ["gitleaks", "trivy"];
    const engines = [engineInfo("gitleaks", true), engineInfo("trivy", true)];
    const r = diffRescan(mkScan({ findings: [priorTrivy], engine_details: engines }),
      mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", findings: [survivor], engine_details: engines }));
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["FP_TR"]);
    expect(r.introduced.map((f) => f.fingerprint)).toEqual(["FP_GL"]);
  });

  test("a 4.1 prior scan never uses the containment match (M5 fix round 2)", () => {
    const pem = { file: "keys/server.pem" };
    const priorTrivy = mkFinding({ fingerprint: "FP_TR", engine: "trivy", rule_id: "private-key", is_secret: true, cwe: ["CWE-798"], finding_kind: "secret", location: { ...pem, start_line: 2, end_line: 29 } });
    const survivor = mkFinding({ fingerprint: "FP_GL", engine: "gitleaks", rule_id: "private-key", is_secret: true, cwe: ["CWE-798"], finding_kind: "secret", location: { ...pem, start_line: 1, end_line: 30 } });
    survivor.engines = ["gitleaks", "trivy"];
    const engines = [engineInfo("gitleaks", true), engineInfo("trivy", true)];
    const marker = staticComponentSignatures([DEDUP_COMPONENT]);
    const prior = mkScan({ findings: [priorTrivy], engine_details: engines });
    prior.component_signatures = { ...prior.component_signatures, ...marker };
    const fresh = mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", findings: [survivor], engine_details: engines });
    fresh.component_signatures = { ...fresh.component_signatures, ...marker };
    const r = diffRescan(prior, fresh);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["FP_TR"]);
    expect(r.introduced.map((f) => f.fingerprint)).toEqual(["FP_GL"]);
  });
});

describe("filterRescanForDisplay — CG-76: threshold hides sub-threshold in display, counts recomputed", () => {
  function mkResult(over: Partial<RescanResult> = {}): RescanResult {
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

describe("diffRescan — findings that only moved lines", () => {
  const at = (fingerprint: string, line: number, snippet = "el.innerHTML = reply;") =>
    mkFinding({ fingerprint, location: { file: "a.ts", start_line: line, end_line: line, snippet } });

  test("a finding whose unchanged code moved down is remaining, not resolved + introduced", () => {
    const prior = mkScan({ findings: [at("fp-line-2", 2)] });
    const fresh = mkScan({ scan_id: "scan-22222222-2222-4222-8222-222222222222", findings: [at("fp-line-4", 4)] });

    const result = diffRescan(prior, fresh);

    expect(result.summary).toMatchObject({ resolved: 0, remaining: 1, introduced: 0 });
  });

  test("a duplicated vulnerable line is still introduced; multiplicity is preserved", () => {
    const prior = mkScan({ findings: [at("p1", 10), at("p2", 20)] });
    const fresh = mkScan({ scan_id: "scan-33333333-3333-4333-8333-333333333333", findings: [at("f1", 12), at("f2", 22), at("f3", 32)] });

    const result = diffRescan(prior, fresh);

    expect(result.summary).toMatchObject({ resolved: 0, remaining: 2, introduced: 1 });
  });

  test("changed code at a moved line is not matched", () => {
    const prior = mkScan({ findings: [at("fp-old", 2)] });
    const fresh = mkScan({ scan_id: "scan-44444444-4444-4444-8444-444444444444", findings: [at("fp-new", 4, "el.innerHTML = other;")] });

    const result = diffRescan(prior, fresh);

    expect(result.summary.introduced).toBe(1);
  });
});

describe("diffRescan — content anchors never absorb exact matches", () => {
  const at = (fingerprint: string, line: number) =>
    mkFinding({ fingerprint, location: { file: "a.ts", start_line: line, end_line: line, snippet: "el.innerHTML = reply;" } });

  test("a new identical line added without shifting others is introduced", () => {
    const prior = mkScan({ findings: [at("fp-10", 10)] });
    const fresh = mkScan({ scan_id: "scan-55555555-5555-4555-8555-555555555555", findings: [at("fp-5", 5), at("fp-10", 10)] });

    expect(diffRescan(prior, fresh).summary).toMatchObject({ remaining: 1, introduced: 1 });
  });

  test("fixing one of two identical lines is resolved", () => {
    const prior = mkScan({ findings: [at("fp-10", 10), at("fp-50", 50)] });
    const fresh = mkScan({ scan_id: "scan-66666666-6666-4666-8666-666666666666", findings: [at("fp-50", 50)] });

    expect(diffRescan(prior, fresh).summary).toMatchObject({ resolved: 1, remaining: 1 });
  });
});

describe("diffRescan — osv-scanner findings and their OSV database signature", () => {
  // Findings always list osv-scanner:vulnerability-db:<Eco>. In the wrapper's `partial` state (archive
  // present, install record absent) no signature is emitted for it; a refresh changes the signature.
  const OSV_COMPONENTS = [
    "codeinspectus:pipeline",
    "osv-scanner:binary",
    "osv-scanner:invocation",
    "osv-scanner:config",
    "osv-scanner:vulnerability-db:PyPI",
  ];
  const signatures = (database?: string): Record<string, string> => ({
    "codeinspectus:pipeline": "pipeline-v1",
    "osv-scanner:binary": "sha256:binary",
    "osv-scanner:invocation": "sha256:invocation",
    "osv-scanner:config": "sha256:config",
    ...(database ? { "osv-scanner:vulnerability-db:PyPI": database } : {}),
  });
  const osv = () => mkFinding({
    fingerprint: "osv-litellm",
    engine: "osv-scanner",
    rule_id: "MAL-2026-2144",
    finding_kind: "vulnerability",
    location: { file: "requirements.txt", start_line: 1, end_line: 1 },
    producer_components: OSV_COMPONENTS,
    package: { ecosystem: "PyPI", name: "litellm", version: "1.107.0" },
  });

  test.each([
    ["neither scan recorded the database", undefined, undefined],
    ["the database was installed with a record before the rescan", undefined, "sha256:pypi-db"],
    ["the record disappeared before the rescan", "sha256:pypi-db", undefined],
  ])("an absent osv finding is not_rechecked, never resolved, when %s", (_label, priorDb, freshDb) => {
    const prior = mkScan({
      engine_details: [engineInfo("osv-scanner", true)],
      component_signatures: signatures(priorDb),
      findings: [osv()],
    });
    const fresh = mkScan({
      scan_id: "scan-11111111-1111-4111-8111-111111111111",
      engine_details: [engineInfo("osv-scanner", true)],
      component_signatures: signatures(freshDb),
      findings: [],
    });
    const result = diffRescan(prior, fresh);
    expect(result.resolved).toEqual([]);
    expect(result.not_rechecked.map((finding) => finding.fingerprint)).toEqual(["osv-litellm"]);
    expect(result.not_rechecked[0]!.package).toEqual({ ecosystem: "PyPI", name: "litellm", version: "1.107.0" });
  });

  test("an OSV DB refresh makes osv findings not_rechecked, never resolved", () => {
    const prior = mkScan({
      engine_details: [engineInfo("osv-scanner", true)],
      component_signatures: signatures("sha256:pypi-db-2026-10-01"),
      findings: [osv()],
    });
    const rescan = (database: string) => mkScan({
      scan_id: "scan-22222222-2222-4222-8222-222222222222",
      engine_details: [engineInfo("osv-scanner", true)],
      component_signatures: signatures(database),
      findings: [],
    });

    const refreshed = diffRescan(prior, rescan("sha256:pypi-db-2026-10-30"));
    expect(refreshed.resolved).toEqual([]);
    expect(refreshed.not_rechecked.map((finding) => finding.fingerprint)).toEqual(["osv-litellm"]);
    expect(refreshed.not_rechecked_note).toMatch(/checks changed/);

    // Control: with the same PyPI database the absence is provable, so the refresh alone made it unprovable.
    expect(diffRescan(prior, rescan("sha256:pypi-db-2026-10-01")).resolved.map((finding) => finding.fingerprint)).toEqual(["osv-litellm"]);
  });

  test("a still-present osv finding stays remaining and keeps its package", () => {
    const prior = mkScan({ engine_details: [engineInfo("osv-scanner", true)], component_signatures: signatures(), findings: [osv()] });
    const fresh = mkScan({ engine_details: [engineInfo("osv-scanner", true)], component_signatures: signatures(), findings: [osv()] });
    const result = diffRescan(prior, fresh);
    expect(result.summary).toMatchObject({ remaining: 1, resolved: 0, not_rechecked: 0 });
    expect(result.remaining[0]!.package?.name).toBe("litellm");
  });
});

describe("diffRescan — native JavaScript file selection changed in the coverage-honesty patch (review I2)", () => {
  // Signatures CodeInspectus 3.3.2 recorded for the two parser components. The JSX retry, the
  // Yarn-tooling skip and the token bound change which files are analyzed, so a finding absent after
  // upgrading may sit in a file the new build skips: it must read not re-checked, never resolved.
  const RELEASED_3_3_2 = {
    "javascript:bounded-structural-parser": "sha256:19126721d10ba84605e343ba3155b93d65b3ddd072fcf8f7b8c7c6e7ee296e69",
    "react-native:javascript-structural-parser": "sha256:fa67e54b2d3f6ed7a24da1817d43c2f51cde97393c1953f9cb30c84e7449a055",
  };

  test.each(Object.keys(RELEASED_3_3_2))("a prior native finding produced by %s is not re-checked after the upgrade", async (component) => {
    const { staticComponentSignatures, PIPELINE_COMPONENT } = await import("./provenance.js");
    const finding = mkFinding({
      fingerprint: "yarn-plugin-finding",
      engine: "codeinspectus-ai",
      engines: ["codeinspectus-ai"],
      location: { file: ".yarn/plugins/@yarnpkg/plugin.cjs", start_line: 4, end_line: 4 },
      producer_components: [PIPELINE_COMPONENT, component],
    });
    const current = staticComponentSignatures([PIPELINE_COMPONENT, component]);
    const prior = mkScan({
      engine_details: [engineInfo("codeinspectus-ai", true)],
      findings: [finding],
      component_signatures: { ...current, [component]: RELEASED_3_3_2[component as keyof typeof RELEASED_3_3_2] },
    });
    const fresh = mkScan({
      scan_id: "scan-22222222-2222-4222-8222-222222222222",
      engine_details: [engineInfo("codeinspectus-ai", true)],
      findings: [],
      component_signatures: current,
    });
    const result = diffRescan(prior, fresh);
    expect(result.summary.resolved).toBe(0);
    expect(result.not_rechecked.map((f) => f.fingerprint)).toEqual(["yarn-plugin-finding"]);
  });
});

// M6 fix round 1 (review MAJOR, pre-existing): an engine that could not fully analyze a file in the rescan
// (an Opengrep per-file timeout, engine error, parse error or size skip; a native parse or size limit) proves
// nothing about the findings it had there.
describe("diffRescan — per-file analysis failures in the rescan", () => {
  const fresh = (unchecked: ScanResult["engine_unchecked"]) =>
    mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", findings: [], engine_unchecked: { ...mkScan().engine_unchecked, ...unchecked } });

  test("an Opengrep baseline finding whose file timed out in the rescan is not_rechecked, not resolved", () => {
    const prior = mkScan({ findings: [mkFinding({ fingerprint: "b", rule_id: "ci-baseline-dangerous-eval", location: { file: "lib/d3.js", start_line: 3, end_line: 3 } })] });
    const r = diffRescan(prior, fresh({ "opengrep:baseline": { files: ["lib/d3.js"] } }));
    expect(r.resolved).toEqual([]);
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["b"]);
    expect(r.not_rechecked_note).toContain("could not fully analyze this finding's file or rule in the rescan");
  });

  test("the pass matters: a pack-rule finding reads the pack set, a baseline finding the baseline set", () => {
    const pack = mkFinding({ fingerprint: "p", rule_id: "syn-node-command-injection", producer_components: ["codeinspectus:pipeline", "test:opengrep"] });
    const baseline = mkFinding({ fingerprint: "q", rule_id: "ci-baseline-dangerous-eval" });
    const prior = mkScan({ findings: [pack, baseline] });
    const r = diffRescan(prior, fresh({ "opengrep:pack": { files: ["a.ts"] } }));
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["p"]);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["q"]);
    // Producer components name the pass when present.
    const byComponent = mkFinding({ fingerprint: "r", rule_id: "x", producer_components: ["codeinspectus:pipeline", "opengrep:pack-invocation"] });
    const r2 = diffRescan(mkScan({ findings: [byComponent], component_signatures: { "codeinspectus:pipeline": "pipeline-v1", "opengrep:pack-invocation": "p1" } }),
      mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", component_signatures: { "codeinspectus:pipeline": "pipeline-v1", "opengrep:pack-invocation": "p1" }, engine_unchecked: { "opengrep:pack": { files: ["a.ts"] } } }));
    expect(r2.not_rechecked.map((f) => f.fingerprint)).toEqual(["r"]);
  });

  test("a native finding whose file the native packs could not read in the rescan is not_rechecked", () => {
    const prior = mkScan({ engine_details: [engineInfo("codeinspectus-ai", true)], findings: [mkFinding({ fingerprint: "n", engine: "codeinspectus-ai" })] });
    const r = diffRescan(prior, mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", engine_details: [engineInfo("codeinspectus-ai", true)], engine_unchecked: { native: { files: ["a.ts"] } } }));
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["n"]);
  });

  test("a set too large to record ('all') re-checks nothing; another file's failure changes nothing", () => {
    const prior = mkScan({ findings: [A()] });
    expect(diffRescan(prior, fresh({ "opengrep:baseline": "all" })).not_rechecked.map((f) => f.fingerprint)).toEqual(["a"]);
    expect(diffRescan(prior, fresh({ "opengrep:baseline": { files: ["other.ts"] } })).resolved.map((f) => f.fingerprint)).toEqual(["a"]);
  });

  test("a rule that failed outright re-checks none of its findings, in any file; other rules are unaffected", () => {
    const failed = mkFinding({ fingerprint: "f", rule_id: "ci-baseline-xss", location: { file: "x.ts", start_line: 1, end_line: 1 } });
    const other = mkFinding({ fingerprint: "o", rule_id: "ci-baseline-dangerous-eval", location: { file: "x.ts", start_line: 2, end_line: 2 } });
    const r = diffRescan(mkScan({ findings: [failed, other] }), fresh({ "opengrep:baseline": { files: [], rules: ["ci-baseline-xss"] } }));
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["f"]);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["o"]);
  });
});

// M6 fix round 2: two more false-resolved paths, and a missing record means nothing was proven.
describe("diffRescan — native packs that ran partially, osv-scanner lockfiles it could not extract", () => {
  const packState = (pack_id: string, state: "ran" | "partial" | "unavailable") => ({
    pack_id, version: "1", scanner_kind: "ai" as const, state, languages: [], frameworks: [], platforms: [],
    analyzers: { registered: 1, ran: 1 }, rules: { registered: 1, ran: 1 }, limitations: [], ...(state === "ran" ? {} : { note: "bound reached" }),
  });
  const nativeScan = (over: Partial<ScanResult>) => mkScan({ engine_details: [engineInfo("codeinspectus-ai", true)], ...over });
  const native = (fingerprint: string, rule_id: string) => mkFinding({ fingerprint, engine: "codeinspectus-ai", rule_id });

  test("the JavaScript baseline pack stopped at its project bound: its findings are not_rechecked; a complete pack's resolve", () => {
    const prior = nativeScan({ findings: [native("w", "ci-baseline-weak-hash"), native("py", "ci-python-hardcoded-signing-secret")] });
    const fresh = nativeScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111",
      pack_coverage: [packState("javascript-baseline", "partial"), packState("python-ai-api", "ran")] });
    const r = diffRescan(prior, fresh);
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["w"]);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["py"]);
    expect(r.not_rechecked_note).toContain("native pack that produced it ran only partially");
  });

  test("Supabase RLS loading stopped (incompleteAll: the JavaScript/TypeScript pack is partial): its RLS finding is not_rechecked", () => {
    const prior = nativeScan({ findings: [native("rls", "ci-ai-rls-missing")] });
    const r = diffRescan(prior, nativeScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", pack_coverage: [packState("javascript-typescript", "partial")] }));
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["rls"]);
    const unavailable = diffRescan(prior, nativeScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", pack_coverage: [packState("javascript-typescript", "unavailable")] }));
    expect(unavailable.not_rechecked.map((f) => f.fingerprint)).toEqual(["rls"]);
  });

  test("a native finding no pack owns is not_rechecked whenever any pack ran partially", () => {
    const prior = nativeScan({ findings: [native("u", "ci-ai-unknown-rule")] });
    const fresh = (state: "ran" | "partial") => nativeScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", pack_coverage: [packState("firebase", state)] });
    expect(diffRescan(prior, fresh("partial")).not_rechecked.map((f) => f.fingerprint)).toEqual(["u"]);
    expect(diffRescan(prior, fresh("ran")).resolved.map((f) => f.fingerprint)).toEqual(["u"]);
  });

  const osvFinding = (file: string) => mkFinding({
    fingerprint: `osv-${file}`, engine: "osv-scanner", rule_id: "CVE-2026-1000", finding_kind: "vulnerability",
    location: { file, start_line: 5, end_line: 5 }, package: { ecosystem: "npm", name: "lodash", version: "4.17.4" },
    producer_components: ["codeinspectus:pipeline", "test:osv-scanner"],
  });
  const osvScan = (over: Partial<ScanResult>) => mkScan({
    engine_details: [engineInfo("osv-scanner", true)],
    component_signatures: { "codeinspectus:pipeline": "pipeline-v1", "test:osv-scanner": "osv-v1" },
    ...over,
  });

  test("a finding at a lockfile osv-scanner found but could not extract in the rescan is not_rechecked", () => {
    const prior = osvScan({ findings: [osvFinding("package-lock.json"), osvFinding("app/package-lock.json")] });
    const fresh = osvScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", engine_unchecked: { "osv-scanner": { files: ["package-lock.json"] } } });
    const r = diffRescan(prior, fresh);
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["osv-package-lock.json"]);
    expect(r.resolved.map((f) => f.fingerprint)).toEqual(["osv-app/package-lock.json"]);
  });

  test("an ecosystem osv-scanner checked only partially without naming files gates all of its findings", () => {
    const prior = osvScan({ findings: [osvFinding("package-lock.json")] });
    const fresh = osvScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", engine_unchecked: { "osv-scanner": { files: [], ecosystems: ["npm"] } } });
    expect(diffRescan(prior, fresh).not_rechecked.map((f) => f.fingerprint)).toEqual(["osv-package-lock.json"]);
  });

  test("an engine that ran in the rescan but left no record for the finding's pass proves nothing", () => {
    const prior = mkScan({ findings: [A()] });
    const fresh = mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", engine_unchecked: {} });
    expect(diffRescan(prior, fresh).not_rechecked.map((f) => f.fingerprint)).toEqual(["a"]);
    expect(diffRescan(osvScan({ findings: [osvFinding("package-lock.json")] }), osvScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", engine_unchecked: {} })).not_rechecked).toHaveLength(1);
  });
});

// M6 final cleanup: the missing-record default applies only to a scan that should carry records.
describe("diffRescan — which scans must carry rescan-proof records", () => {
  test("a scan from before the records (no engine_unchecked, no dedup marker) keeps the previous behaviour", () => {
    const prior = mkScan({ findings: [A()] });
    const older = mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", engine_unchecked: undefined });
    expect(diffRescan(prior, older).resolved.map((f) => f.fingerprint)).toEqual(["a"]);
  });

  test("a 4.1 scan (the dedup component marker) that lacks the record for the pass proves nothing", () => {
    const prior = mkScan({ findings: [A()] });
    const current = mkScan({
      scan_id: "scan-11111111-1111-4111-8111-111111111111", engine_unchecked: undefined,
      component_signatures: { ...mkScan().component_signatures, [DEDUP_COMPONENT]: "dedup-v1" },
    });
    expect(diffRescan(prior, current).not_rechecked.map((f) => f.fingerprint)).toEqual(["a"]);
  });

  test("an unextracted lockfile names its own reason, not the timeout one", () => {
    const finding = mkFinding({
      fingerprint: "o", engine: "osv-scanner", rule_id: "CVE-1", location: { file: "package-lock.json", start_line: 3, end_line: 3 },
      package: { ecosystem: "npm", name: "lodash", version: "4.17.4" }, producer_components: ["codeinspectus:pipeline", "test:osv-scanner"],
    });
    const scan = (over: Partial<ScanResult>) => mkScan({ engine_details: [engineInfo("osv-scanner", true)],
      component_signatures: { "codeinspectus:pipeline": "pipeline-v1", "test:osv-scanner": "osv-v1" }, ...over });
    const r = diffRescan(scan({ findings: [finding] }), scan({ scan_id: "scan-11111111-1111-4111-8111-111111111111",
      engine_unchecked: { "osv-scanner": { files: ["package-lock.json"] } } }));
    expect(r.not_rechecked.map((f) => f.fingerprint)).toEqual(["o"]);
    expect(r.not_rechecked_note).toContain("osv-scanner listed no packages from this lockfile (unreadable or unsupported layout)");
    expect(r.not_rechecked_note).not.toContain("a timeout");
  });
});

describe("diffRescan — Synvoya per-subject image checks (4.1 M8 Ruling 3)", () => {
  const signatures = { "codeinspectus:pipeline": "p", "synvoya:images": "i", "synvoya:runtime": "r" };
  const synvoya = (producers: string[], fingerprint = "syn-node"): Finding =>
    mkFinding({
      fingerprint,
      engine: "synvoya",
      engines: ["synvoya"],
      rule_id: "SYN-2026-001",
      location: { file: "Dockerfile", start_line: 2, end_line: 2 },
      producer_components: ["codeinspectus:pipeline", ...producers],
    });
  const run = (prior: Partial<ScanResult>, fresh: Partial<ScanResult>) =>
    diffRescan(
      mkScan({ engine_details: [engineInfo("synvoya", true)], component_signatures: signatures, ...prior }),
      mkScan({ scan_id: "scan-11111111-1111-4111-8111-111111111111", engine_details: [engineInfo("synvoya", true)], component_signatures: signatures, ...fresh }),
    );
  const priorWith = (finding: Finding, findings: Record<string, string> = { [finding.fingerprint]: "runtime:node" }) => ({
    findings: [finding],
    synvoya_subjects: { images: { blocked: { Dockerfile: ["runtime:php"] }, findings } },
  });
  const freshBlocked = (keys: string[], checked: Record<string, string[]> = { images: [], runtime: ["Dockerfile"] }) => ({
    synvoya_checked: checked,
    synvoya_subjects: { images: { blocked: { Dockerfile: keys } } },
  });

  test("its subject not blocked in a file read whole: resolved; blocked: not_rechecked", () => {
    const f = synvoya(["synvoya:images"]);
    expect(run(priorWith(f), freshBlocked(["runtime:php"])).resolved.map((x) => x.fingerprint)).toEqual(["syn-node"]);
    expect(run(priorWith(f), freshBlocked(["runtime:node", "runtime:php"])).not_rechecked.map((x) => x.fingerprint)).toEqual(["syn-node"]);
  });

  test("the fresh blocked map must name the file: a file in neither set is not re-checked", () => {
    const f = synvoya(["synvoya:images"]);
    const fresh = { synvoya_checked: { images: [] }, synvoya_subjects: { images: { blocked: { "other/Dockerfile": ["runtime:php"] } } } };
    expect(run(priorWith(f), fresh).not_rechecked.map((x) => x.fingerprint)).toEqual(["syn-node"]);
  });

  test("only the image producer uses subjects: another producer of the same finding still needs its file checked", () => {
    const f = synvoya(["synvoya:images", "synvoya:runtime"]);
    expect(run(priorWith(f), freshBlocked(["runtime:php"], { images: [], runtime: [] })).not_rechecked).toHaveLength(1);
    expect(run(priorWith(f), freshBlocked(["runtime:php"], { images: [], runtime: ["Dockerfile"] })).resolved).toHaveLength(1);
    const runtimeOnly = synvoya(["synvoya:runtime"]);
    expect(run(priorWith(runtimeOnly), freshBlocked(["runtime:php"], { images: [], runtime: [] })).not_rechecked).toHaveLength(1);
  });

  test("a prototype-shaped fingerprint or file name never reads an inherited key", () => {
    const f = synvoya(["synvoya:images"], "constructor");
    expect(run(priorWith(f, {}), freshBlocked(["runtime:php"])).not_rechecked).toHaveLength(1);
    const g = mkFinding({ ...synvoya(["synvoya:images"]), location: { file: "toString", start_line: 1, end_line: 1 } });
    expect(run(priorWith(g), freshBlocked(["runtime:php"])).not_rechecked).toHaveLength(1);
  });
});
