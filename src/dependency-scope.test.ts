import { describe, expect, test } from "vitest";

import { dedupFindings } from "./dedup.js";
import {
  applyDependencyScope,
  buildScopeIndex,
  lowerOneLevel,
  scopeEvidence,
  scopeKey,
  type DependencyScope,
} from "./dependency-scope.js";
import { DEV_SCOPE_NOTE } from "./engines/trivy-dev-scope.js";
import type { TrivyReportPackage } from "./engines/trivy.js";
import type { OsvScanResult } from "./engines/osv-scanner.js";
import type { Finding, Severity } from "./types.js";

type OsvPackages = NonNullable<OsvScanResult["packages"]>;

function trivyPkg(file: string, name: string, version: string, dev?: boolean): TrivyReportPackage {
  return { ecosystem: "npm", name, version, file, line: 0, ...(dev ? { dev: true } : {}) };
}

function osvPkg(file: string, name: string, version: string, dev?: boolean): OsvPackages[number] {
  return { ecosystem: "npm", name, version, file, ...(dev === undefined ? {} : { dev }) };
}

function vuln(engine: Finding["engine"], rule: string, name: string, version: string, overrides: Partial<Finding> = {}): Finding {
  const file = overrides.location?.file ?? "package-lock.json";
  return {
    id: `fp-${engine}-${rule}`,
    fingerprint: `fp-${engine}-${rule}-${name}`,
    title: `${rule} (${name}@${version})`,
    severity: "high",
    engine,
    engines: [engine],
    rule_id: rule,
    cwe: ["CWE-1395"],
    location: { file, start_line: 3, end_line: 3 },
    message: `Package: ${name}`,
    remediation: { summary: "Upgrade.", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    finding_kind: "vulnerability",
    package: { ecosystem: "npm", name, version },
    ...overrides,
  };
}

const devIndex = (file = "package-lock.json", name = "handlebars", version = "4.7.9") =>
  new Map<string, DependencyScope>([[scopeKey(file, name, version), "dev"]]);

describe("dependency scope", () => {
  test("lowerOneLevel", () => {
    const table: Array<[Severity, Severity]> = [["critical", "high"], ["high", "medium"], ["medium", "low"], ["low", "low"], ["info", "info"]];
    for (const [from, to] of table) expect(lowerOneLevel(from)).toBe(to);
  });

  test("index: dev only when every occurrence is dev", () => {
    const index = buildScopeIndex(scopeEvidence([
      trivyPkg("package-lock.json", "minimist", "1.2.5", true),
      trivyPkg("package-lock.json", "minimist", "1.2.5"),
      trivyPkg("package-lock.json", "handlebars", "4.7.9", true),
      trivyPkg("package-lock.json", "handlebars", "4.7.9", true),
    ]));
    expect(index.get(scopeKey("package-lock.json", "minimist", "1.2.5"))).toBe("prod");
    expect(index.get(scopeKey("package-lock.json", "handlebars", "4.7.9"))).toBe("dev");
  });

  test("index: osv-scanner groups count only for package-lock and composer", () => {
    const evidence = scopeEvidence(undefined, [
      osvPkg("pnpm-lock.yaml", "handlebars", "4.7.9"),
      osvPkg("yarn.lock", "handlebars", "4.7.9", true),
      // osv-scanner.ts reads a package-lock entry without a "dev" group as dev: false.
      osvPkg("package-lock.json", "lodash", "4.17.20", false),
      osvPkg("package-lock.json", "handlebars", "4.7.9", true),
      osvPkg("composer.lock", "phpunit/phpunit", "10.5.26", true),
      osvPkg("requirements.txt", "urllib3", "2.2.2", true),
    ]);
    expect(evidence.map((entry) => `${entry.file}:${entry.name}:${entry.dev}`)).toEqual([
      "package-lock.json:lodash:false",
      "package-lock.json:handlebars:true",
      "composer.lock:phpunit/phpunit:true",
    ]);
    const index = buildScopeIndex(evidence);
    expect(index.get(scopeKey("pnpm-lock.yaml", "handlebars", "4.7.9"))).toBeUndefined();
    expect(index.get(scopeKey("package-lock.json", "lodash", "4.17.20"))).toBe("prod");
    expect(index.get(scopeKey("composer.lock", "phpunit/phpunit", "10.5.26"))).toBe("dev");
  });

  test("index: Trivy and osv-scanner disagree → prod", () => {
    const index = buildScopeIndex(scopeEvidence(
      [trivyPkg("package-lock.json", "handlebars", "4.7.9", true)],
      [osvPkg("package-lock.json", "handlebars", "4.7.9", false)],
    ));
    expect(index.get(scopeKey("package-lock.json", "handlebars", "4.7.9"))).toBe("prod");
  });

  test("index: Trivy evidence counts only for the lockfiles it marks Dev in", () => {
    const evidence = scopeEvidence([
      trivyPkg("Gemfile.lock", "rack", "3.1.8", true),
      trivyPkg("sub/pnpm-lock.yaml", "handlebars", "4.7.9", true),
      trivyPkg("bun.lock", "a", "1.0.0", true),
      trivyPkg("yarn.lock", "b", "1.0.0", true),
      trivyPkg("composer.lock", "c/c", "1.0.0", true),
      trivyPkg("npm-shrinkwrap.json", "d", "1.0.0", true),
    ]);
    expect(evidence.map((entry) => entry.file)).toEqual(["sub/pnpm-lock.yaml", "bun.lock", "yarn.lock", "composer.lock", "npm-shrinkwrap.json"]);
  });

  test("index: names normalize and a leading v is ignored", () => {
    const index = buildScopeIndex(scopeEvidence([{ ...trivyPkg("composer.lock", "Symfony/Http-Foundation", "v5.4.0", true), ecosystem: "Packagist" }]));
    expect(index.get(scopeKey("composer.lock", "symfony/http-foundation", "5.4.0"))).toBe("dev");
    expect(scopeKey("composer.lock", "Symfony/Http_Foundation", "v5.4.0")).toBe(scopeKey("composer.lock", "symfony/http-foundation", "5.4.0"));
    // Only one leading v before a digit is removed.
    expect(scopeKey("x", "a", "vv1")).not.toBe(scopeKey("x", "a", "v1"));
  });

  test("labels and lowers a dev finding", () => {
    const finding = vuln("trivy", "CVE-2026-106445", "handlebars", "4.7.9", { title: "X (handlebars@4.7.9)", severity: "critical", message: "Package: handlebars" });
    const result = applyDependencyScope([finding], { scopes: devIndex(), exploited: new Set() });
    const [scoped] = result.findings;
    expect(scoped!.title).toBe("X (handlebars@4.7.9, dev dependency)");
    expect(scoped!.message).toBe(`Package: handlebars\n${DEV_SCOPE_NOTE}\nSeverity lowered from critical to high: development-only dependency.`);
    expect(scoped!.severity).toBe("high");
    expect(scoped!.dependency_scope).toBe("dev");
    expect(scoped!.fingerprint).toBe(finding.fingerprint);
    expect(result.lowered).toBe(1);
    expect(result.note).toEqual({
      component: "scope:dependencies",
      detail: "1 development-only dependency finding(s) were lowered one severity level (never below low; malware, known-exploited and Synvoya findings keep theirs).",
    });
    // The input is not mutated.
    expect(finding.severity).toBe("critical");
  });

  test("a finding without a package tag in its title gets the generic label", () => {
    const finding = vuln("osv-scanner", "GHSA-xxxx-xxxx-xxxx", "handlebars", "4.7.9", { title: "Prototype pollution" });
    const [scoped] = applyDependencyScope([finding], { scopes: devIndex(), exploited: new Set() }).findings;
    expect(scoped!.title).toBe("Prototype pollution (dev dependency)");
  });

  test("labels a dev-only package that only osv-scanner flags", () => {
    // Trivy listed the package as Dev (its report covers every package) but did not report this advisory.
    const scopes = buildScopeIndex(scopeEvidence([trivyPkg("pnpm-lock.yaml", "handlebars", "4.7.9", true)]));
    const finding = vuln("osv-scanner", "GHSA-p8wg-vrv2-v86f", "handlebars", "4.7.9", { location: { file: "pnpm-lock.yaml", start_line: 21, end_line: 21 } });
    const [scoped] = applyDependencyScope([finding], { scopes, exploited: new Set() }).findings;
    expect(scoped!.dependency_scope).toBe("dev");
    expect(scoped!.title).toBe("GHSA-p8wg-vrv2-v86f (handlebars@4.7.9, dev dependency)");
    expect(scoped!.severity).toBe("medium");
  });

  test("an osv-scanner survivor of a merge with a dev Trivy finding is labelled (the 4.0 carry case)", () => {
    const pkg = { ecosystem: "npm", name: "handlebars", version: "4.7.9" };
    const trivy = vuln("trivy", "CVE-2026-106445", "handlebars", "4.7.9", { severity: "high", package: pkg });
    const osv = vuln("osv-scanner", "CVE-2026-106445", "handlebars", "4.7.9", { severity: "critical", package: pkg });
    const scopes = buildScopeIndex(scopeEvidence([trivyPkg("package-lock.json", "handlebars", "4.7.9", true)]));
    for (const order of [[trivy, osv], [osv, trivy]]) {
      const [merged] = applyDependencyScope(dedupFindings(order).findings, { scopes, exploited: new Set() }).findings;
      expect(merged!.engine).toBe("osv-scanner");
      expect(merged!.fingerprint).toBe(osv.fingerprint);
      expect(merged!.title).toBe("CVE-2026-106445 (handlebars@4.7.9, dev dependency)");
      expect(merged!.severity).toBe("high");
      expect(merged!.dependency_scope).toBe("dev");
    }
    // A different version of the package is not claimed dev.
    const other = vuln("osv-scanner", "CVE-2026-106445", "handlebars", "4.7.0", { package: { ...pkg, version: "4.7.0" } });
    expect(applyDependencyScope([other], { scopes, exploited: new Set() }).findings[0]).toBe(other);
  });

  test("labels from osv-scanner groups alone when Trivy did not run", () => {
    const scopes = buildScopeIndex(scopeEvidence(undefined, [osvPkg("package-lock.json", "handlebars", "4.7.9", true)]));
    const [scoped] = applyDependencyScope([vuln("osv-scanner", "GHSA-1", "handlebars", "4.7.9")], { scopes, exploited: new Set() }).findings;
    expect(scoped!.dependency_scope).toBe("dev");
    expect(scoped!.severity).toBe("medium");
  });

  test("never lowers MAL-, CWE-506, known-exploited or Synvoya findings", () => {
    const cases: Array<[Finding, string, keyof ReturnType<typeof applyDependencyScope>]> = [
      [vuln("osv-scanner", "MAL-2026-1234", "handlebars", "4.7.9", { severity: "critical" }), "Severity not lowered: malicious package.", "keptMalware"],
      [vuln("osv-scanner", "GHSA-a", "handlebars", "4.7.9", { severity: "critical", cwe: ["CWE-506"] }), "Severity not lowered: malicious package.", "keptMalware"],
      [vuln("osv-scanner", "GHSA-b", "handlebars", "4.7.9", { severity: "high", vulnerability_aliases: ["mal-2026-9"] }), "Severity not lowered: malicious package.", "keptMalware"],
      [vuln("trivy", "CVE-2026-0042", "handlebars", "4.7.9", { severity: "high" }), "Severity not lowered: known to be exploited.", "keptExploited"],
      [vuln("osv-scanner", "GHSA-c", "handlebars", "4.7.9", { severity: "high", vulnerability_aliases: ["cve-2026-0042"] }), "Severity not lowered: known to be exploited.", "keptExploited"],
      [vuln("trivy", "CVE-2026-0050", "handlebars", "4.7.9", { severity: "high", engines: ["trivy", "synvoya"] }), "Severity not lowered: Synvoya advisory.", "keptSynvoya"],
      [vuln("trivy", "CVE-2026-0051", "handlebars", "4.7.9", {
        severity: "high",
        remediation: { summary: "Upgrade.", steps: ["Synvoya SYN-2026-001: Upgrade to 4.7.10."], references: [] },
      }), "Severity not lowered: Synvoya advisory.", "keptSynvoya"],
    ];
    for (const [finding, line, counter] of cases) {
      const result = applyDependencyScope([finding], { scopes: devIndex(), exploited: new Set(["CVE-2026-0042", "SYN-2026-001"]) });
      const [scoped] = result.findings;
      expect(scoped!.severity, finding.rule_id).toBe(finding.severity);
      expect(scoped!.dependency_scope).toBe("dev");
      expect(scoped!.message.endsWith(`\n${DEV_SCOPE_NOTE}\n${line}`), finding.rule_id).toBe(true);
      expect(result[counter], finding.rule_id).toBe(1);
      expect(result.lowered).toBe(0);
      expect(result.note).toBeUndefined();
    }
  });

  test("low and info dev findings keep their severity with no lowering line", () => {
    for (const severity of ["low", "info"] as const) {
      const [scoped] = applyDependencyScope([vuln("trivy", "CVE-1", "handlebars", "4.7.9", { severity })], { scopes: devIndex(), exploited: new Set() }).findings;
      expect(scoped!.severity).toBe(severity);
      expect(scoped!.dependency_scope).toBe("dev");
      expect(scoped!.message.endsWith(DEV_SCOPE_NOTE)).toBe(true);
    }
  });

  test("lowers nothing without the known-exploited list", () => {
    const finding = vuln("trivy", "CVE-2026-106445", "handlebars", "4.7.9", { severity: "critical" });
    const result = applyDependencyScope([finding], { scopes: devIndex() });
    expect(result.findings[0]!.severity).toBe("critical");
    expect(result.findings[0]!.dependency_scope).toBe("dev");
    expect(result.findings[0]!.message.endsWith(DEV_SCOPE_NOTE)).toBe(true);
    expect(result.lowered).toBe(0);
    expect(result.note).toEqual({
      component: "scope:dependencies",
      detail: "Development-only dependency findings kept their severity: the Synvoya dataset, which holds the known-exploited list, could not be loaded.",
    });
  });

  test("prod findings are marked prod and unchanged", () => {
    const finding = vuln("trivy", "CVE-1", "lodash", "4.17.20");
    const scopes = new Map<string, DependencyScope>([[scopeKey("package-lock.json", "lodash", "4.17.20"), "prod"]]);
    const result = applyDependencyScope([finding], { scopes, exploited: new Set() });
    expect(result.findings[0]).toEqual({ ...finding, dependency_scope: "prod" });
    expect(result.note).toBeUndefined();
  });

  test("unknown formats get no dependency_scope", () => {
    const finding = vuln("osv-scanner", "PYSEC-1", "urllib3", "2.2.2", { location: { file: "requirements.txt", start_line: 1, end_line: 1 } });
    const licence: Finding = { ...vuln("trivy", "handlebars:MIT", "handlebars", "4.7.9"), finding_kind: "license" };
    const result = applyDependencyScope([finding, licence], { scopes: devIndex(), exploited: new Set() });
    expect(result.findings[0]).toBe(finding);
    expect(result.findings[1]).toBe(licence);
  });

  test("runs after dedup: the survivor's fingerprint equals the 4.0 survivor", () => {
    // Fingerprints chosen so the fingerprint tiebreak prefers osv-scanner once both severities tie.
    const trivy = vuln("trivy", "CVE-2026-106445", "handlebars", "4.7.9", { severity: "medium", fingerprint: "sha256:b-trivy" });
    const osv = vuln("osv-scanner", "GHSA-p8wg-vrv2-v86f", "handlebars", "4.7.9", {
      severity: "low", fingerprint: "sha256:a-osv", vulnerability_aliases: ["CVE-2026-106445"],
    });
    const options = { scopes: devIndex(), exploited: new Set<string>() };
    // Implemented order: dedup (4.0 survivor: Trivy, severity first), then the scope pass.
    const [survivor] = applyDependencyScope(dedupFindings([trivy, osv]).findings, options).findings;
    expect(survivor!.fingerprint).toBe("sha256:b-trivy");
    expect(survivor!.severity).toBe("low");
    expect(survivor!.engines.sort()).toEqual(["osv-scanner", "trivy"]);
    // Lowering first would tie both at low and flip the survivor.
    const [flipped] = dedupFindings(applyDependencyScope([trivy, osv], options).findings).findings;
    expect(flipped!.fingerprint).toBe("sha256:a-osv");
  });

  // M5 fix round 1, item 1: a dev copy of one version must never lower the production copy of another.
  describe("cross-version dev lowering (fix 1)", () => {
    const pkgAt = (version: string) => ({ ecosystem: "npm", name: "semver", version });
    const at = (engine: Finding["engine"], rule: string, version: string, line: number, overrides: Partial<Finding> = {}) =>
      vuln(engine, rule, "semver", version, { package: pkgAt(version), fingerprint: `sha256:${engine}-${version}`, location: { file: "package-lock.json", start_line: line, end_line: line }, ...overrides });
    const scopes = buildScopeIndex(scopeEvidence([
      trivyPkg("package-lock.json", "semver", "5.7.1", true),
      trivyPkg("package-lock.json", "semver", "7.5.1"),
    ]));
    const options = { scopes, exploited: new Set<string>() };

    test("osv findings for 5.7.1 (dev) and 7.5.1 (prod), same GHSA, both orders", () => {
      const dev = at("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "5.7.1", 40);
      const prod = at("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "7.5.1", 12);
      for (const order of [[dev, prod], [prod, dev]]) {
        const findings = applyDependencyScope(dedupFindings(order).findings, options).findings;
        expect(findings).toHaveLength(2);
        const byVersion = Object.fromEntries(findings.map((finding) => [finding.package!.version, finding]));
        expect(byVersion["7.5.1"]).toMatchObject({ dependency_scope: "prod", severity: "high" });
        expect(byVersion["7.5.1"]!.title).not.toContain("dev dependency");
        expect(byVersion["5.7.1"]).toMatchObject({ dependency_scope: "dev", severity: "medium" });
      }
    });

    test("Trivy production copy + osv-scanner dev copy stay two findings with their own scope", () => {
      const prod = at("trivy", "CVE-2022-25883", "7.5.1", 12);
      const dev = at("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "5.7.1", 40, { vulnerability_aliases: ["CVE-2022-25883"] });
      for (const order of [[prod, dev], [dev, prod]]) {
        const findings = applyDependencyScope(dedupFindings(order).findings, options).findings;
        expect(findings.map((finding) => [finding.engine, finding.package!.version, finding.dependency_scope, finding.severity]).sort())
          .toEqual([["osv-scanner", "5.7.1", "dev", "medium"], ["trivy", "7.5.1", "prod", "high"]]);
      }
    });

    test("a merged finding is dev only if every version it absorbed is dev (fix 1b)", () => {
      // A Trivy finding without a version joins the only known version; its unknown scope keeps it production.
      const unknown = at("trivy", "CVE-2022-25883", "", 1, { severity: "critical" });
      const dev = at("osv-scanner", "GHSA-c2qf-rxjj-qqgw", "5.7.1", 40, { vulnerability_aliases: ["CVE-2022-25883"] });
      const devOnly = buildScopeIndex(scopeEvidence([trivyPkg("package-lock.json", "semver", "5.7.1", true)]));
      for (const order of [[unknown, dev], [dev, unknown]]) {
        const [merged] = applyDependencyScope(dedupFindings(order).findings, { scopes: devOnly, exploited: new Set() }).findings;
        expect(merged!.engines.sort()).toEqual(["osv-scanner", "trivy"]);
        expect(merged!.severity).toBe("critical");
        expect(merged!.dependency_scope).not.toBe("dev");
      }
      // The dev finding survives (higher severity) and absorbed the version-less one: still not dev.
      const lowUnknown = { ...unknown, severity: "low" as const };
      for (const order of [[lowUnknown, dev], [dev, lowUnknown]]) {
        const [merged] = applyDependencyScope(dedupFindings(order).findings, { scopes: devOnly, exploited: new Set() }).findings;
        expect(merged!.engine).toBe("osv-scanner");
        expect(merged!.severity).toBe("high");
        expect(merged!.dependency_scope).not.toBe("dev");
      }
      // Two dev findings of one version still read dev, and the internal record never reaches JSON.
      const trivyDev = at("trivy", "CVE-2022-25883", "5.7.1", 40);
      const [both] = applyDependencyScope(dedupFindings([trivyDev, dev]).findings, { scopes: devOnly, exploited: new Set() }).findings;
      expect(both!.dependency_scope).toBe("dev");
      const [mergedUnknown] = dedupFindings([unknown, dev]).findings;
      expect(JSON.stringify(mergedUnknown)).not.toContain("absorbed");
    });
  });
});
