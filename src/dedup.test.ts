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
import { dedupFindings, dedupKey, findingsMatch } from "./dedup.js";
import type { Finding, Engine, Severity } from "./types.js";
import { DEV_SCOPE_NOTE } from "./engines/trivy-dev-scope.js";

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

describe("first-party Pub vulnerability dedup", () => {
  function vulnerability(
    engine: Engine,
    ruleId: string,
    line: number,
    vulnerabilityAliases?: string[],
  ): Finding {
    return {
      id: `${engine}-${ruleId}`,
      fingerprint: `${engine}-${ruleId}`,
      title: ruleId,
      severity: "high",
      engine,
      engines: [engine],
      rule_id: ruleId,
      ...(vulnerabilityAliases ? { vulnerability_aliases: vulnerabilityAliases } : {}),
      cwe: ["CWE-1395"],
      location: { file: "pubspec.lock", start_line: line, end_line: line },
      message: "vulnerable dependency",
      remediation: { summary: "upgrade", steps: [], references: [] },
      frameworks: [],
      confidence: "high",
      finding_kind: "vulnerability",
      producer_components: [`${engine}:component`],
    };
  }

  test("merges the same GHSA from Trivy and the native Pub scanner despite line differences", () => {
    const [merged] = dedupFindings([
      vulnerability("trivy", "CVE-2026-0001", 1),
      vulnerability("codeinspectus-pub", "GHSA-test-0000-0001", 12, ["CVE-2026-0001"]),
    ]).findings;
    expect(merged?.engines).toEqual(["trivy", "codeinspectus-pub"]);
    expect(merged?.producer_components).toEqual([
      "codeinspectus-pub:component",
      "trivy:component",
    ]);
    expect(merged?.vulnerability_aliases).toEqual([
      "CVE-2026-0001",
      "GHSA-test-0000-0001",
    ]);
  });

  test("merges when Trivy reports the GHSA and Pub carries the CVE as an alias", () => {
    const [merged] = dedupFindings([
      vulnerability("trivy", "GHSA-test-0000-0001", 1),
      vulnerability("codeinspectus-pub", "CVE-2026-0001", 12, ["GHSA-test-0000-0001"]),
    ]).findings;
    expect(merged?.engines).toEqual(["trivy", "codeinspectus-pub"]);
    expect(merged?.vulnerability_aliases).toEqual([
      "CVE-2026-0001",
      "GHSA-test-0000-0001",
    ]);
  });

  test("does not collapse distinct advisories that share one lockfile location and CWE", () => {
    const findings = dedupFindings([
      vulnerability("codeinspectus-pub", "GHSA-test-0000-0001", 12),
      vulnerability("codeinspectus-pub", "GHSA-test-0000-0002", 12),
    ]).findings;
    expect(findings).toHaveLength(2);
  });
});

describe("package-aware vulnerability dedup (osv-scanner, Trivy, Pub)", () => {
  function packaged(
    engine: Engine,
    ruleId: string,
    pkg: { ecosystem: string; name: string; version: string },
    options: { file?: string; aliases?: string[]; severity?: Severity } = {},
  ): Finding {
    return {
      id: `${engine}-${pkg.name}-${ruleId}`,
      fingerprint: `${engine}-${pkg.name}-${ruleId}`,
      title: `${ruleId} (${pkg.name}@${pkg.version})`,
      severity: options.severity ?? "high",
      engine,
      engines: [engine],
      rule_id: ruleId,
      ...(options.aliases ? { vulnerability_aliases: options.aliases } : {}),
      cwe: ["CWE-1395"],
      location: { file: options.file ?? "requirements.txt", start_line: 1, end_line: 1 },
      message: `Package: ${pkg.name}\nInstalled Version: ${pkg.version}`,
      remediation: { summary: "upgrade", steps: [], references: [] },
      frameworks: [],
      confidence: "high",
      finding_kind: "vulnerability",
      producer_components: [`${engine}:component`],
      package: pkg,
    };
  }

  test("osv-scanner, Trivy and Pub findings for one package and alias merge into one", () => {
    const pkg = { ecosystem: "Pub", name: "archive", version: "3.3.7" };
    const findings = dedupFindings([
      packaged("codeinspectus-pub", "GHSA-test-0000-0003", pkg, { file: "pubspec.lock", aliases: ["CVE-2026-0003"] }),
      packaged("osv-scanner", "CVE-2026-0003", pkg, { file: "pubspec.lock", aliases: ["GHSA-test-0000-0003"] }),
      packaged("trivy", "CVE-2026-0003", pkg, { file: "pubspec.lock" }),
    ]).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.engines).toEqual(["codeinspectus-pub", "osv-scanner", "trivy"]);
    expect(findings[0]!.vulnerability_aliases).toEqual(["CVE-2026-0003", "GHSA-test-0000-0003"]);
    expect(findings[0]!.package).toEqual(pkg);
  });

  test("same advisory on two packages stays two findings", () => {
    const findings = dedupFindings([
      packaged("osv-scanner", "CVE-2026-111497", { ecosystem: "PyPI", name: "Brotli", version: "1.2.0" }),
      packaged("osv-scanner", "CVE-2026-111497", { ecosystem: "PyPI", name: "brotlicffi", version: "1.2.0.2" }),
      packaged("trivy", "CVE-2026-111497", { ecosystem: "PyPI", name: "Brotli", version: "1.2.0" }),
      packaged("trivy", "CVE-2026-111497", { ecosystem: "PyPI", name: "brotlicffi", version: "1.2.0.2" }),
    ]).findings;
    expect(findings).toHaveLength(2);
    expect(findings.map((finding) => finding.package?.name).sort()).toEqual(["Brotli", "brotlicffi"]);
    for (const finding of findings) expect(finding.engines).toEqual(["osv-scanner", "trivy"]);
  });

  test("Trivy Brotli (case) and osv brotli merge", () => {
    const findings = dedupFindings([
      packaged("trivy", "CVE-2026-111497", { ecosystem: "PyPI", name: "Brotli", version: "1.2.0" }),
      packaged("osv-scanner", "CVE-2026-111497", { ecosystem: "PyPI", name: "brotli", version: "1.2.0" }, { severity: "critical" }),
    ]).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.engines).toEqual(["trivy", "osv-scanner"]);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.package?.name).toBe("brotli");
  });

  test("dedup ignores the package ecosystem, so a best-effort Trivy ecosystem still merges", () => {
    const findings = dedupFindings([
      packaged("trivy", "CVE-2026-0004", { ecosystem: "unknown", name: "left_pad", version: "1.0.0" }),
      packaged("osv-scanner", "CVE-2026-0004", { ecosystem: "PyPI", name: "left-pad", version: "1.0.0" }),
    ]).findings;
    expect(findings).toHaveLength(1);
  });

  test("a `|` in a file name never makes a package-less finding collide with a packaged one", () => {
    const packagedOne = packaged("osv-scanner", "CVE-2026-0007", { ecosystem: "npm", name: "lodash", version: "4.17.4" }, { file: "a" });
    const { package: _omit, ...unpackaged } = packaged("trivy", "CVE-2026-0007", { ecosystem: "npm", name: "x", version: "1" }, { file: "a|lodash" });
    const findings = dedupFindings([packagedOne, unpackaged as Finding]).findings;
    expect(findings).toHaveLength(2);
    expect(dedupKey(packagedOne)).not.toBe(dedupKey(unpackaged as Finding));
  });

  test("cross-scan identity keys are package-aware: one advisory on two packages never matches across scans", () => {
    const brotli = packaged("osv-scanner", "CVE-2026-111497", { ecosystem: "PyPI", name: "Brotli", version: "1.2.0" });
    const cffi = packaged("osv-scanner", "CVE-2026-111497", { ecosystem: "PyPI", name: "brotlicffi", version: "1.2.0.2" });
    expect(findingsMatch(brotli, cffi)).toBe(false);
    expect(findingsMatch(brotli, { ...brotli, fingerprint: "other", package: { ...brotli.package!, name: "brotli" } })).toBe(true);
    expect(dedupKey(brotli)).not.toBe(dedupKey(cffi));
  });

  // Merge of the osv-engine and coverage-honesty branches: eval E78 found an osv-scanner survivor of a
  // merge with a development-only Trivy finding (handlebars in coverage-honesty-corpus/dev-deps)
  // dropping the scope, which only Trivy reports and only as text.
  test("an osv-scanner survivor keeps the development-only scope of the Trivy finding it absorbed", () => {
    const pkg = { ecosystem: "npm", name: "handlebars", version: "4.7.9" };
    const devTrivy = (severity: Severity): Finding => {
      const base = packaged("trivy", "CVE-2026-106445", pkg, { file: "package-lock.json", severity });
      return { ...base, title: `${base.title.slice(0, -1)}, dev dependency)`, message: `${base.message}\n${DEV_SCOPE_NOTE}` };
    };
    const osv = packaged("osv-scanner", "CVE-2026-106445", pkg, { file: "package-lock.json", severity: "critical" });
    for (const order of [[devTrivy("high"), osv], [osv, devTrivy("high")]]) {
      const [merged] = dedupFindings(order).findings;
      expect(merged!.engine).toBe("osv-scanner");
      expect(merged!.fingerprint).toBe(osv.fingerprint);
      expect(merged!.title).toBe("CVE-2026-106445 (handlebars@4.7.9, dev dependency)");
      expect(merged!.message).toBe(`${osv.message}\n${DEV_SCOPE_NOTE}`);
    }
    // A Trivy survivor already carries its own scope text, and a production Trivy finding adds none.
    expect(dedupFindings([devTrivy("critical"), osv]).findings[0]!.title).toBe("CVE-2026-106445 (handlebars@4.7.9, dev dependency)");
    const production = packaged("trivy", "CVE-2026-106445", pkg, { file: "package-lock.json" });
    expect(dedupFindings([production, osv]).findings[0]!.title).toBe(osv.title);
    // Different versions of the package: the scope of one is not claimed for the other.
    const other = packaged("osv-scanner", "CVE-2026-106445", { ...pkg, version: "4.7.0" }, { file: "package-lock.json", severity: "critical" });
    expect(dedupFindings([devTrivy("high"), other]).findings[0]!.title).toBe(other.title);
  });

  test("a stored finding without a package still matches its packaged successor (scans before package support)", () => {
    const fresh = packaged("trivy", "CVE-2026-111497", { ecosystem: "PyPI", name: "Brotli", version: "1.2.0" });
    const { package: _omitted, ...stored } = { ...fresh, fingerprint: "stored-before-package-support" };
    expect(findingsMatch(stored, fresh)).toBe(true);
    expect(findingsMatch(fresh, stored)).toBe(true);
  });
});

describe("Synvoya declaration findings (no package) dedup on advisory and subject", () => {
  function declared(ruleId: string, fingerprint: string, aliases: string[], line: number): Finding {
    return {
      id: fingerprint,
      fingerprint,
      title: `${ruleId} declared in Dockerfile`,
      severity: "critical",
      engine: "synvoya",
      engines: ["synvoya"],
      rule_id: ruleId,
      vulnerability_aliases: aliases,
      cwe: ["CWE-1104"],
      location: { file: "Dockerfile", start_line: line, end_line: line },
      message: "declared",
      remediation: { summary: `fix ${ruleId}`, steps: [], references: [] },
      frameworks: [],
      confidence: "high",
      finding_kind: "vulnerability",
    };
  }

  test("two advisories that share an alias in one file stay two findings", () => {
    const node = declared("SYN-2026-009", "fp-node", ["CVE-2026-0100", "GHSA-test-0000-0100"], 5);
    const dotnet = declared("SYN-2026-011", "fp-dotnet", ["CVE-2026-0100"], 10);
    const { findings } = dedupFindings([node, dotnet]);
    expect(findings.map((finding) => [finding.rule_id, finding.location.start_line, finding.vulnerability_aliases])).toEqual([
      ["SYN-2026-009", 5, ["CVE-2026-0100", "GHSA-test-0000-0100"]],
      ["SYN-2026-011", 10, ["CVE-2026-0100"]],
    ]);
    expect(dedupKey(node)).not.toBe(dedupKey(dotnet));
    expect(findingsMatch(node, dotnet)).toBe(false);
  });

  test("one advisory on two subjects (different fingerprints) in one file stays two findings", () => {
    const left = declared("SYN-EOL-node-20", "fp-a", [], 1);
    const right = declared("SYN-EOL-node-20", "fp-b", [], 2);
    expect(dedupFindings([left, right]).findings).toHaveLength(2);
  });

  test("the same Synvoya finding twice still merges, and matches itself across scans", () => {
    const finding = declared("SYN-2026-009", "fp-node", ["CVE-2026-0100"], 5);
    expect(dedupFindings([finding, { ...finding, location: { ...finding.location, start_line: 7, end_line: 7 } }]).findings).toHaveLength(1);
    expect(findingsMatch(finding, { ...finding, location: { ...finding.location, start_line: 9, end_line: 9 } })).toBe(true);
  });
});
