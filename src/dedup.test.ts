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
import { dedupFindings, dedupKey, findingsMatch, secretContainmentAgainst } from "./dedup.js";
import { DEDUP_COMPONENT, staticComponentSignatures } from "./provenance.js";
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

  // M9 fix round 2 (item 4): per release line, the needed fix is the highest of each engine's minimum there.
  test("merged fixed versions keep, per release line, the highest engine minimum", () => {
    const pkg = { ecosystem: "npm", name: "left-pad", version: "1.2.3" };
    const findings = dedupFindings([
      { ...packaged("trivy", "CVE-2026-0042", pkg, { file: "package-lock.json" }), fixed_versions: ["1.2.5", "2.0.1"] },
      { ...packaged("osv-scanner", "CVE-2026-0042", pkg, { file: "package-lock.json" }), fixed_versions: ["1.2.6", "1.2.9"] },
    ]).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.fixed_versions).toEqual(["1.2.6", "2.0.1"]);
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

/**
 * 4.1 M5 Ruling 7: one finding per secret. Gitleaks and Trivy report the same PEM key with different line
 * ranges (1-30 and 2-29), and a native check can flag a line inside a Gitleaks key block (EmailThing 645 in
 * 645-648); exact-range keys never joined them.
 */
describe("one finding per secret: containment in a private-key block (4.1 M5)", () => {
  function key(engine: Engine, rule: string, start: number, end: number, overrides: Partial<Finding> = {}): Finding {
    return {
      ...secretFinding(engine, "high"),
      fingerprint: `sha256:${engine}-${rule}-${start}-${end}`,
      rule_id: rule,
      location: { file: "keys/server.pem", start_line: start, end_line: end },
      producer_components: [`engine:${engine}`],
      ...overrides,
    };
  }

  test("merges Trivy's private-key inside Gitleaks' block and keeps Gitleaks", () => {
    const gitleaks = key("gitleaks", "private-key", 1, 30, { producer_components: ["engine:gitleaks", "gitleaks:rules"] });
    const trivy = key("trivy", "private-key", 2, 29);
    for (const order of [[gitleaks, trivy], [trivy, gitleaks]]) {
      const { findings, stats } = dedupFindings(order);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.fingerprint).toBe(gitleaks.fingerprint);
      expect(findings[0]!.engines).toEqual(["gitleaks", "trivy"]);
      expect(findings[0]!.producer_components).toEqual(["engine:gitleaks", "engine:trivy", "gitleaks:rules"]);
      expect(findings[0]!.location).toEqual(gitleaks.location);
      expect(stats.merged).toBe(1);
    }
  });

  test("merges a native secret inside a key block and keeps the higher severity", () => {
    const block = key("gitleaks", "private-key", 645, 648, { location: { file: "src/mail.ts", start_line: 645, end_line: 648 } });
    const native = key("codeinspectus-ai", "ci-ai-client-hardcoded-secret", 645, 645, {
      severity: "critical", location: { file: "src/mail.ts", start_line: 645, end_line: 645 }, secret_value_hash: "sha256:abc",
    });
    const { findings } = dedupFindings([block, native]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.fingerprint).toBe(native.fingerprint);
    expect(findings[0]!.severity).toBe("critical");
    expect([...findings[0]!.engines].sort()).toEqual(["codeinspectus-ai", "gitleaks"]);
  });

  test("does not merge a secret below or beside a key block", () => {
    const block = key("gitleaks", "private-key", 1, 30);
    for (const [start, end] of [[31, 31], [30, 31], [0, 1]]) {
      const other = key("gitleaks", "generic-api-key", start!, end!);
      expect(dedupFindings([block, other]).findings).toHaveLength(2);
    }
    expect(dedupFindings([block, { ...key("trivy", "private-key", 2, 29), location: { file: "keys/other.pem", start_line: 2, end_line: 29 } }]).findings).toHaveLength(2);
  });

  test("does not merge inside a non-key multi-line match", () => {
    const curl = key("gitleaks", "curl-auth-header", 10, 12);
    const generic = key("gitleaks", "generic-api-key", 11, 11);
    expect(dedupFindings([curl, generic]).findings).toHaveLength(2);
  });

  test("does not merge when both value hashes are known and differ", () => {
    const block = key("codeinspectus-ai", "ci-ai-private-key", 1, 30, { secret_value_hash: "sha256:one" });
    const inner = key("codeinspectus-ai", "ci-ai-client-hardcoded-secret", 5, 5, { secret_value_hash: "sha256:two" });
    expect(dedupFindings([block, inner]).findings).toHaveLength(2);
    expect(dedupFindings([block, { ...inner, secret_value_hash: "sha256:one" }]).findings).toHaveLength(1);
  });

  test("two different known values inside one hash-less block are never joined through it", () => {
    const block = key("gitleaks", "private-key", 1, 30);
    const first = key("codeinspectus-ai", "ci-ai-a", 3, 3, { secret_value_hash: "sha256:one", severity: "critical" });
    const second = key("codeinspectus-ai", "ci-ai-b", 4, 4, { secret_value_hash: "sha256:two", severity: "critical" });
    const permutations = [[block, first, second], [second, block, first], [first, second, block]];
    const results = permutations.map((order) => dedupFindings(order).findings.map((finding) => finding.fingerprint).sort());
    for (const result of results) {
      expect(result).toHaveLength(2);
      expect(result).toEqual(results[0]);
    }
  });

  test("the result does not depend on input order", () => {
    const gitleaks = key("gitleaks", "private-key", 1, 30);
    const trivy = key("trivy", "private-key", 2, 29);
    const opengrep: Finding = { ...key("opengrep", "hardcoded-credential", 10, 10), is_secret: undefined, finding_kind: "sast", cwe: ["CWE-798"] };
    const all = [gitleaks, trivy, opengrep];
    const permutations = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]].map((order) => order.map((index) => all[index]!));
    const results = permutations.map((order) => dedupFindings(order).findings);
    for (const result of results) {
      expect(result).toHaveLength(1);
      expect(result).toEqual(results[0]);
    }
    expect(results[0]![0]!.fingerprint).toBe(gitleaks.fingerprint);
    expect(results[0]![0]!.engines).toEqual(["gitleaks", "opengrep", "trivy"]);
  });

  // M5 fix round 2: the cross-scan containment match is an explicit, pre-4.1-only option (older side left).
  const pre41 = { secretContainment: true };

  test("findingsMatch: a 4.0 prior that held the absorbed Trivy finding matches the merged survivor", () => {
    const gitleaks = key("gitleaks", "private-key", 1, 30);
    const trivy = key("trivy", "private-key", 2, 29);
    const [survivor] = dedupFindings([gitleaks, trivy]).findings;
    expect(findingsMatch(trivy, survivor!, pre41)).toBe(true);
    expect(findingsMatch(gitleaks, survivor!, pre41)).toBe(true);
    // Off by default, and never for an older 4.1 scan.
    expect(findingsMatch(trivy, survivor!)).toBe(false);
    expect(findingsMatch(trivy, survivor!, { secretContainment: false })).toBe(false);
  });

  test("findingsMatch containment needs a single-engine private-key older finding inside a newer merged survivor", () => {
    const survivor = { ...key("gitleaks", "private-key", 1, 30), engines: ["gitleaks", "trivy"] as Engine[] };
    // The older side must be the absorbed one: never the survivor matching a finding inside it.
    expect(findingsMatch(survivor, key("trivy", "private-key", 2, 29), pre41)).toBe(false);
    // Older single-engine but not a private-key rule (a token inside the key block's lines).
    expect(findingsMatch(key("trivy", "aws-access-token", 15, 15), survivor, pre41)).toBe(false);
    // Older multi-engine (a 4.1-style survivor) never qualifies.
    expect(findingsMatch({ ...key("trivy", "private-key", 2, 29), engines: ["trivy", "codeinspectus-ai"] }, survivor, pre41)).toBe(false);
    // Newer not merged, or merged without the older finding's engine.
    expect(findingsMatch(key("trivy", "private-key", 2, 29), key("gitleaks", "private-key", 1, 30), pre41)).toBe(false);
    expect(findingsMatch(key("trivy", "private-key", 2, 29), { ...survivor, engines: ["gitleaks", "codeinspectus-ai"] }, pre41)).toBe(false);
    // One range must contain the other: a partial overlap never matches.
    expect(findingsMatch(key("trivy", "private-key", 2, 31), survivor, pre41)).toBe(false);
    // Different known values never match.
    expect(findingsMatch(
      key("codeinspectus-ai", "ci-ai-private-key", 2, 29, { secret_value_hash: "sha256:one" }),
      { ...survivor, secret_value_hash: "sha256:two", engines: ["gitleaks", "codeinspectus-ai"] }, pre41,
    )).toBe(false);
    // A key block and a new token inside it, whatever their engines, never match.
    const block = key("gitleaks", "private-key", 10, 40);
    const token = key("gitleaks", "aws-access-token", 15, 15);
    for (const options of [pre41, {}]) {
      expect(findingsMatch(block, token, options)).toBe(false);
      expect(findingsMatch({ ...block, engines: ["gitleaks", "trivy"] }, { ...token, engines: ["gitleaks", "trivy"] }, options)).toBe(false);
    }
  });

  test("EmailThing shape: a 4.0 Gitleaks key block 645-648 matches the 4.1 native survivor at 645 that absorbed it", () => {
    const at = (start: number, end: number) => ({ file: "src/mail.ts", start_line: start, end_line: end });
    const oldBlock = key("gitleaks", "private-key", 645, 648, { location: at(645, 648) });
    const survivor: Finding = {
      ...key("codeinspectus-ai", "ci-ai-client-hardcoded-secret", 645, 645, { location: at(645, 645), severity: "critical", secret_value_hash: "sha256:abc" }),
      engines: ["codeinspectus-ai", "gitleaks"],
    };
    expect(findingsMatch(oldBlock, survivor, pre41)).toBe(true);
    // The same conditions as the other direction: off by default, the survivor must carry the block's engine,
    // and the older block must be single-engine.
    expect(findingsMatch(oldBlock, survivor)).toBe(false);
    expect(findingsMatch(oldBlock, { ...survivor, engines: ["codeinspectus-ai", "trivy"] }, pre41)).toBe(false);
    expect(findingsMatch({ ...oldBlock, engines: ["gitleaks", "trivy"] }, survivor, pre41)).toBe(false);
    // A survivor outside the block's lines never matches.
    expect(findingsMatch(oldBlock, { ...survivor, location: at(649, 649) }, pre41)).toBe(false);
  });

  test("secretContainmentAgainst: an older scan without the 4.1 dedup marker AND a newer scan with it (fix round 3)", () => {
    const v40 = { component_signatures: { "codeinspectus:pipeline": "x" } };
    const v41 = { component_signatures: staticComponentSignatures([DEDUP_COMPONENT]) };
    expect(secretContainmentAgainst(v40, v41)).toEqual({ secretContainment: true });
    expect(secretContainmentAgainst({}, v41)).toEqual({ secretContainment: true });
    // Two 4.0 scans: neither holds a 4.1 merge, so containment stays off.
    expect(secretContainmentAgainst(v40, v40)).toEqual({ secretContainment: false });
    expect(secretContainmentAgainst({}, {})).toEqual({ secretContainment: false });
    // A 4.1 older scan never uses it.
    expect(secretContainmentAgainst(v41, v41)).toEqual({ secretContainment: false });
    expect(secretContainmentAgainst(v41, v40)).toEqual({ secretContainment: false });
  });

  test("reverse containment (older block holds the survivor) needs the survivor's value hash (fix round 3)", () => {
    const block = key("gitleaks", "private-key", 10, 40);
    // A new multi-engine token inside an old single-engine key block: no value hash, so never a match (New).
    const token: Finding = { ...key("gitleaks", "aws-access-token", 15, 15), engines: ["gitleaks", "trivy"] };
    expect(findingsMatch(block, token, pre41)).toBe(false);
    // With a native value hash (the EmailThing survivor) it matches.
    expect(findingsMatch(block, { ...token, engines: ["codeinspectus-ai", "gitleaks"], secret_value_hash: "sha256:abc" }, pre41)).toBe(true);
  });
});

/**
 * 4.1 M5 Ruling 8: Trivy reports a RubyGems advisory as its CVE, osv-scanner as its GHSA (with no CVE alias in
 * the 2.7.0 RubyGems output). The Trivy wrapper now carries the one GHSA the CVE's references name.
 */
describe("RubyGems CVE/GHSA duplicates merge through the Trivy alias (4.1 M5)", () => {
  async function trivyRuby(): Promise<Finding[]> {
    const { readFile } = await import("node:fs/promises");
    const { markAliases, rubyAdvisoryAliases } = await import("./engines/trivy-aliases.js");
    const { normalizeSarif } = await import("./sarif/normalize.js");
    const report = JSON.parse(await readFile("fixtures/output-quality/trivy-ruby.json", "utf8"));
    const results = (report.Results[0].Vulnerabilities as Array<{ VulnerabilityID: string; PkgName: string; InstalledVersion: string }>).map((v) => ({
      ruleId: v.VulnerabilityID, level: "warning",
      message: { text: `Package: ${v.PkgName}\nInstalled Version: ${v.InstalledVersion}\nVulnerability ${v.VulnerabilityID}\nSeverity: MEDIUM\nFixed Version: 9.9.9\nLink: [${v.VulnerabilityID}](https://example.invalid)` },
      locations: [{ physicalLocation: { artifactLocation: { uri: "Gemfile.lock" }, region: { startLine: v.PkgName === "crass" ? 4 : 5, endLine: v.PkgName === "crass" ? 4 : 5 } } }],
    }));
    const log = { version: "2.1.0", runs: [{ tool: { driver: { name: "Trivy", rules: results.map((r) => ({ id: r.ruleId, name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security", "MEDIUM"] } })) } }, results }] };
    markAliases(log as never, rubyAdvisoryAliases(report));
    return normalizeSarif(log as never, "trivy", "/repo");
  }

  /** What osv-scanner 2.7.0 emits for a RubyGems GHSA group (ids [GHSA], no CVE alias). */
  function osvGhsa(name: string, version: string, ghsa: string, line: number): Finding {
    return {
      id: `osv-${name}`, fingerprint: `sha256:osv-${name}-${ghsa}`, title: `Advisory (${name}@${version})`, severity: "medium",
      engine: "osv-scanner", engines: ["osv-scanner"], rule_id: ghsa, cwe: ["CWE-1395"], owasp_web: ["A06:2021"],
      location: { file: "Gemfile.lock", start_line: line, end_line: line }, message: `Gemfile.lock resolves RubyGems package ${name}@${version}.`,
      remediation: { summary: "Upgrade.", steps: [], references: [] }, frameworks: [], confidence: "high",
      producer_components: ["engine:osv-scanner"], finding_kind: "vulnerability", package: { ecosystem: "RubyGems", name, version },
    };
  }

  test("Trivy CVE with a GHSA alias merges with osv-scanner's GHSA finding for the same gem", async () => {
    const trivy = await trivyRuby();
    const osv = [osvGhsa("crass", "1.0.7", "GHSA-pq4g-8rxf-4g29", 4), osvGhsa("shopify_app", "23.0.2", "GHSA-6j52-38f8-qhxr", 5)];
    for (const order of [[...trivy, ...osv], [...osv, ...trivy]]) {
      const { findings } = dedupFindings(order);
      expect(findings).toHaveLength(2);
      const crass = findings.find((finding) => finding.package?.name === "crass")!;
      expect([...crass.engines].sort()).toEqual(["osv-scanner", "trivy"]);
      expect(crass.vulnerability_aliases).toEqual(["CVE-2026-116695", "GHSA-pq4g-8rxf-4g29"]);
    }
    // Package-aware: the same GHSA on another gem stays separate.
    const elsewhere = osvGhsa("nokogiri", "1.16.0", "GHSA-pq4g-8rxf-4g29", 9);
    expect(dedupFindings([...trivy, elsewhere]).findings).toHaveLength(3);
  });

  test("a 4.0 prior GHSA finding matches the merged survivor", async () => {
    const prior = osvGhsa("crass", "1.0.7", "GHSA-pq4g-8rxf-4g29", 4);
    const [survivor] = dedupFindings([...(await trivyRuby()).filter((finding) => finding.package?.name === "crass"), { ...prior }]).findings;
    expect(findingsMatch(prior, survivor!)).toBe(true);
    // A 4.0 prior Trivy CVE finding (no alias then) matches too.
    const [priorTrivy] = (await trivyRuby()).map(({ vulnerability_aliases: _aliases, ...finding }) => finding as Finding);
    expect(findingsMatch(priorTrivy!, survivor!)).toBe(true);
  });
});

/**
 * M5 fix round 1, item 1a: one advisory on two locked versions of one package (semver 5.7.1 nested in a dev
 * tool, 7.5.1 at the top level) is two findings, each with its own location and remediation. Trivy and
 * osv-scanner findings for the same version still merge.
 */
describe("vulnerability dedup keeps different versions of one package apart (M5 fix 1a)", () => {
  function semver(engine: Engine, rule: string, version: string, line: number, overrides: Partial<Finding> = {}): Finding {
    return {
      id: `${engine}-${version}`, fingerprint: `sha256:${engine}-semver-${version}-${rule}`, title: `${rule} (semver@${version})`,
      severity: "high", engine, engines: [engine], rule_id: rule, cwe: ["CWE-1395"],
      location: { file: "package-lock.json", start_line: line, end_line: line },
      message: `Package: semver\nInstalled Version: ${version}`,
      remediation: { summary: `Upgrade semver from ${version}.`, steps: [], references: [] },
      frameworks: [], confidence: "high", finding_kind: "vulnerability", producer_components: [`engine:${engine}`],
      package: { ecosystem: "npm", name: "semver", version },
      ...overrides,
    };
  }

  test("two versions, same advisory: two findings with their own location and remediation, in either order", () => {
    const old = semver("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "5.7.1", 40);
    const current = semver("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "7.5.1", 12);
    for (const order of [[old, current], [current, old]]) {
      const { findings } = dedupFindings(order);
      expect(findings).toHaveLength(2);
      const byVersion = Object.fromEntries(findings.map((finding) => [finding.package!.version, finding]));
      expect(byVersion["5.7.1"]!.location.start_line).toBe(40);
      expect(byVersion["5.7.1"]!.remediation.summary).toBe("Upgrade semver from 5.7.1.");
      expect(byVersion["7.5.1"]!.location.start_line).toBe(12);
      expect(byVersion["7.5.1"]!.fingerprint).toBe(current.fingerprint);
    }
  });

  test("Trivy and osv-scanner findings for the same version still merge, aliases bridging CVE and GHSA", () => {
    const trivy = semver("trivy", "CVE-2022-25883", "7.5.1", 12);
    const osv = semver("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "7.5.1", 12, { vulnerability_aliases: ["CVE-2022-25883"] });
    expect(dedupFindings([trivy, osv]).findings).toHaveLength(1);
    // A leading v (Go) is not a different version.
    expect(dedupFindings([semver("trivy", "CVE-1", "v7.5.1", 1), semver("osv-scanner", "CVE-1", "7.5.1", 1)]).findings).toHaveLength(1);
    // Different versions never merge through the alias graph either.
    const other = semver("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "5.7.1", 40, { vulnerability_aliases: ["CVE-2022-25883"] });
    expect(dedupFindings([trivy, osv, other]).findings).toHaveLength(2);
  });

  test("cross-scan matching stays version-free: a 4.0 merged finding matches both 4.1 findings", () => {
    const merged40 = semver("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "7.5.1", 12);
    expect(findingsMatch(merged40, semver("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "5.7.1", 40))).toBe(true);
    expect(findingsMatch(merged40, semver("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "7.5.1", 12))).toBe(true);
  });

  test("a finding with no version joins the package's one known version, and stays apart when there are several", () => {
    const unknown = semver("trivy", "CVE-1", "", 1);
    expect(dedupFindings([unknown, semver("osv-scanner", "CVE-1", "7.5.1", 12)]).findings).toHaveLength(1);
    expect(dedupFindings([unknown, semver("osv-scanner", "CVE-1", "7.5.1", 12), semver("osv-scanner", "CVE-1", "5.7.1", 40)]).findings).toHaveLength(3);
  });
});
