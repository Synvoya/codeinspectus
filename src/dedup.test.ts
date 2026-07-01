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
