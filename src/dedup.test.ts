/**
 * CG-24 / CG-23 A3-3 — a dedup merge must NEVER lower a finding's severity.
 *
 * Surfaced by the CG-24 redaction fix: with Gitleaks run under --redact, the engine
 * finding can no longer be classified live, so it normalizes to `high` while the AI
 * client-secret check (which reads the file directly) keeps it `critical`. The old
 * precedence preferred Gitleaks by engine rank BEFORE comparing severity, masking the
 * AI critical under a high — a real severity downgrade. Severity must win first; the
 * secret-engine preference is only a tie-break at equal severity.
 */

import { describe, test, expect } from "vitest";
import { dedupFindings } from "./dedup.js";
import type { Finding, Engine, Severity } from "./types.js";

function secretFinding(engine: Engine, severity: Severity): Finding {
  return {
    id: `${engine}-x`,
    fingerprint: `${engine}-x`,
    title: `${engine} secret`,
    severity,
    engine,
    engines: [engine],
    rule_id: `${engine}-rule`,
    cwe: ["CWE-798"],
    location: { file: "src/config.ts", start_line: 5, end_line: 5 },
    message: "secret",
    remediation: { summary: "rotate", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    is_secret: true,
  };
}

describe("dedup secret precedence (CG-24 / CG-23 A3-3)", () => {
  test("AI critical + Gitleaks high at one location merge to CRITICAL", () => {
    const { findings } = dedupFindings([secretFinding("gitleaks", "high"), secretFinding("codeinspectus-ai", "critical")]);
    expect(findings).toHaveLength(1);
    const [f] = findings;
    expect(f!.severity).toBe("critical");
    expect(new Set(f!.engines)).toEqual(new Set(["gitleaks", "codeinspectus-ai"]));
  });

  test("equal severity: Gitleaks still wins the tie (richer secret metadata)", () => {
    const { findings } = dedupFindings([secretFinding("codeinspectus-ai", "high"), secretFinding("gitleaks", "high")]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.engine).toBe("gitleaks");
  });
});

/**
 * CG-75 / Claim 1 (second root cause) — a same-location secret merged from two rules must keep
 * a DETERMINISTIC representative, else its surviving fingerprint (which includes rule_id) flips
 * with engine output order and a like-for-like rescan false-reports it resolved+introduced.
 */
describe("dedup determinism — same-location secret merge is order-independent (CG-75)", () => {
  function gl(fingerprint: string, rule: string): Finding {
    return { ...secretFinding("gitleaks", "high"), fingerprint, rule_id: rule };
  }
  test("two gitleaks rules for one secret keep the SAME fingerprint regardless of input order", () => {
    const a = gl("sha256:aaa", "generic-jwt");
    const b = gl("sha256:bbb", "supabase-service-role");
    const forward = dedupFindings([a, b]).findings;
    const reverse = dedupFindings([b, a]).findings;
    expect(forward).toHaveLength(1);
    expect(reverse).toHaveLength(1);
    expect(forward[0]!.fingerprint).toBe(reverse[0]!.fingerprint);
  });

  test("severity-first still holds: a critical at the same location is never masked by the tiebreak", () => {
    const crit = { ...secretFinding("gitleaks", "critical"), fingerprint: "sha256:zzz", rule_id: "crit" };
    const low = { ...secretFinding("gitleaks", "low"), fingerprint: "sha256:aaa", rule_id: "low" };
    // Even though "sha256:aaa" sorts first, severity must win → critical kept.
    expect(dedupFindings([crit, low]).findings[0]!.severity).toBe("critical");
    expect(dedupFindings([low, crit]).findings[0]!.severity).toBe("critical");
  });
});

describe("dedup provenance attribution", () => {
  test("unions producer component ids even when the representative comes from one engine", () => {
    const gitleaks = {
      ...secretFinding("gitleaks", "high"),
      producer_components: ["codeinspectus:pipeline", "gitleaks:config"],
    };
    const ai = {
      ...secretFinding("codeinspectus-ai", "critical"),
      producer_components: ["codeinspectus:pipeline", "ai:client-secrets"],
    };
    const [merged] = dedupFindings([gitleaks, ai]).findings;
    expect(merged?.engine).toBe("codeinspectus-ai");
    expect(merged?.producer_components).toEqual([
      "ai:client-secrets",
      "codeinspectus:pipeline",
      "gitleaks:config",
    ]);
  });
});
