import { describe, expect, test } from "vitest";

import { normalizeSarif } from "../sarif/normalize.js";
import type { SarifLog } from "../sarif/types.js";
import { dedupFindings } from "../dedup.js";
import { DEPENDENCY_SCOPE_PROPERTY, devScopeFromReport, foldDevDuplicates, markDevScope } from "./trivy-dev-scope.js";

// Shapes from the real Trivy 0.76.1 JSON report (--list-all-pkgs --include-dev-deps) and SARIF.
const report = {
  Results: [
    {
      Target: "package-lock.json",
      Packages: [
        { Name: "handlebars", Version: "4.7.9", Dev: true },
        { Name: "lodash", Version: "4.17.20" },
        // The same name and version both dev and production: production wins.
        { Name: "minimist", Version: "1.2.5", Dev: true },
        { Name: "minimist", Version: "1.2.5" },
      ],
    },
    { Target: "composer.lock", Packages: [{ Name: "phpunit/phpunit", Version: "10.5.26", Dev: true }] },
  ],
};

function vulnerability(uri: string, name: string, version: string, rule = "CVE-2026-0001", line = 10) {
  return {
    ruleId: rule, ruleIndex: 0, level: "error",
    message: { text: `Package: ${name}\nInstalled Version: ${version}\nVulnerability ${rule}\nSeverity: HIGH\nFixed Version: 9.9.9\nLink: [${rule}](https://example.invalid)` },
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line, endLine: line + 2 } } }],
  };
}

function sarif(): SarifLog {
  return {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Trivy", rules: [
        { id: "CVE-2026-0001", name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security", "HIGH"] } },
        { id: "handlebars:MIT", name: "License", properties: { tags: ["license"] } },
      ] } },
      results: [
        vulnerability("package-lock.json", "handlebars", "4.7.9"),
        vulnerability("package-lock.json", "lodash", "4.17.20"),
        vulnerability("package-lock.json", "minimist", "1.2.5"),
        vulnerability("composer.lock", "phpunit/phpunit", "10.5.26"),
        {
          ruleId: "handlebars:MIT", ruleIndex: 1, level: "note",
          message: { text: "Artifact: package-lock.json\nLicense MIT\nPkgName: handlebars\n Classification: notice\n Path: package-lock.json" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "package-lock.json" }, region: { startLine: 1, endLine: 1 } } }],
        },
      ],
    }],
  } as SarifLog;
}

describe("Trivy development-dependency scope", () => {
  test("marks only packages that are development-only in the lockfile they cite", () => {
    const log = sarif();
    expect(markDevScope(log, devScopeFromReport(report))).toBe(3);
    const marked = log.runs![0]!.results!.map((result) => result.properties?.[DEPENDENCY_SCOPE_PROPERTY] ?? "-");
    expect(marked).toEqual(["dev", "-", "-", "dev", "dev"]);
  });

  test("an unreadable report marks nothing", () => {
    for (const bad of [undefined, null, "x", {}, { Results: {} }]) {
      const log = sarif();
      expect(markDevScope(log, devScopeFromReport(bad))).toBe(0);
    }
  });

  test("a dev finding names its scope in the text and keeps the fingerprint of an unmarked run", () => {
    const plain = normalizeSarif(sarif(), "trivy", "/repo");
    const log = sarif();
    markDevScope(log, devScopeFromReport(report));
    const scoped = normalizeSarif(log, "trivy", "/repo");

    expect(scoped.map((finding) => finding.fingerprint)).toEqual(plain.map((finding) => finding.fingerprint));
    expect(scoped[0]!.title).toMatch(/\(handlebars@4\.7\.9, dev dependency\)$/);
    expect(scoped[0]!.message).toContain("Dependency scope: development only");
    expect(scoped[1]!.title).toMatch(/\(lodash@4\.17\.20\)$/);
    expect(scoped[1]!.message).not.toContain("Dependency scope");
    expect(scoped[4]!.title).toMatch(/\(dev dependency\)$/);
  });

  // Field validation re-scan: ghostfolio's production undici@7.30.0 (line 241) and development
  // undici@7.29.0 (line 27793) share CVEs in one lockfile; dedup keyed them together and the
  // fingerprint tiebreak kept the dev copy, so the production finding's fingerprint changed.
  test("a dev copy of a CVE that production also has is folded, so the production finding survives dedup", () => {
    const scopeReport = { Results: [{ Target: "package-lock.json", Packages: [
      { Name: "undici", Version: "7.30.0" },
      { Name: "undici", Version: "7.29.0", Dev: true },
    ] }] };
    const build = (withDev: boolean): SarifLog => ({
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: "Trivy", rules: ["CVE-2026-0001", "CVE-2026-0002"].map((id) => ({
          id, name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security", "HIGH"] },
        })) } },
        results: [
          ...(withDev ? [vulnerability("package-lock.json", "undici", "7.29.0", "CVE-2026-0001", 27793)] : []),
          vulnerability("package-lock.json", "undici", "7.30.0", "CVE-2026-0001", 241),
          ...(withDev ? [vulnerability("package-lock.json", "undici", "7.29.0", "CVE-2026-0002", 27793)] : []),
        ],
      }],
    } as SarifLog);
    const plain = dedupFindings(normalizeSarif(build(false), "trivy", "/repo")).findings;
    const log = build(true);
    markDevScope(log, devScopeFromReport(scopeReport));

    expect(foldDevDuplicates(log)).toBe(1);
    const scoped = dedupFindings(normalizeSarif(log, "trivy", "/repo")).findings;
    const production = scoped.find((finding) => finding.rule_id === "CVE-2026-0001");
    expect(production?.fingerprint).toBe(plain[0]!.fingerprint);
    expect(production?.title).not.toMatch(/dev dependency/);
    // A CVE only the development copy has is still reported, and marked.
    expect(scoped.find((finding) => finding.rule_id === "CVE-2026-0002")?.title).toMatch(/\(undici@7\.29\.0, dev dependency\)$/);
    expect(scoped).toHaveLength(2);
  });
});
