import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";

import { normalizeSarif } from "../sarif/normalize.js";
import type { SarifLog } from "../sarif/types.js";
import { markAliases, rubyAdvisoryAliases, TRIVY_ALIASES_PROPERTY } from "./trivy-aliases.js";

// Real Trivy 0.76.1 report for fixtures/output-quality/ruby (crass 1.0.7, shopify_app 23.0.2; the 2026-11-01 C-38 case).
const rubyReport = async () => JSON.parse(await readFile(resolve(process.cwd(), "fixtures/output-quality/trivy-ruby.json"), "utf8"));

function vulnerability(uri: string, name: string, version: string, rule: string) {
  return {
    ruleId: rule, ruleIndex: 0, level: "warning",
    message: { text: `Package: ${name}\nInstalled Version: ${version}\nVulnerability ${rule}\nSeverity: MEDIUM\nFixed Version: 9.9.9\nLink: [${rule}](https://example.invalid)` },
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 4, endLine: 4 } } }],
  };
}

function sarif(results: unknown[]): SarifLog {
  const ids = [...new Set(results.map((result) => (result as { ruleId: string }).ruleId))];
  return {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Trivy", rules: ids.map((id) => ({ id, name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security", "MEDIUM"] } })) } },
      results: results.map((result) => ({ ...(result as object), ruleIndex: ids.indexOf((result as { ruleId: string }).ruleId) })),
    }],
  } as SarifLog;
}

function vuln(target: string, pkg: string, version: string, id: string, source: string, references: string[]) {
  return { VulnerabilityID: id, PkgName: pkg, InstalledVersion: version, DataSource: { ID: source }, References: references };
}

describe("RubyGems CVE findings carry their one GHSA (4.1 M5 Ruling 8)", () => {
  // GHSA ids are kept in the canonical form osv-scanner reports (lower-case body), so a merge lists each once.
  test("crass and shopify_app CVEs gain their one GHSA", async () => {
    const aliases = rubyAdvisoryAliases(await rubyReport());
    expect(Object.fromEntries(aliases)).toEqual({
      "Gemfile.lock\0crass\x001.0.7\0CVE-2026-116695": ["GHSA-pq4g-8rxf-4g29"],
      "Gemfile.lock\0shopify_app\x0023.0.2\0CVE-2026-63414": ["GHSA-6j52-38f8-qhxr"],
    });
    const log = sarif([
      vulnerability("Gemfile.lock", "crass", "1.0.7", "CVE-2026-116695"),
      vulnerability("Gemfile.lock", "shopify_app", "23.0.2", "CVE-2026-63414"),
    ]);
    expect(markAliases(log, aliases)).toBe(2);
    const findings = normalizeSarif(log, "trivy", "/repo");
    expect(findings.map((finding) => finding.vulnerability_aliases)).toEqual([["GHSA-pq4g-8rxf-4g29"], ["GHSA-6j52-38f8-qhxr"]]);
  });

  test("a CVE that references several GHSAs gains none", () => {
    // rexml CVE-2024-41123: three related advisories, not aliases.
    const report = { Results: [{ Target: "Gemfile.lock", Vulnerabilities: [vuln("Gemfile.lock", "rexml", "3.3.1", "CVE-2024-41123", "ruby-advisory-db", [
      "https://github.com/advisories/GHSA-r55c-59qm-vjw6",
      "https://github.com/ruby/rexml/security/advisories/GHSA-4xqq-m2hx-25v8",
      "https://osv.dev/vulnerability/GHSA-vg3r-rm7w-2xgh",
    ])] }] };
    expect(rubyAdvisoryAliases(report).size).toBe(0);
    // The same GHSA in several URL forms is one.
    const one = { Results: [{ Target: "gems.locked", Vulnerabilities: [vuln("gems.locked", "rack", "3.1.8", "CVE-2026-1", "ruby-advisory-db", [
      "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
      "https://github.com/rack/rack/security/advisories/ghsa-aaaa-bbbb-cccc",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
    ])] }] };
    expect(Object.fromEntries(rubyAdvisoryAliases(one))).toEqual({ "gems.locked\0rack\x003.1.8\0CVE-2026-1": ["GHSA-aaaa-bbbb-cccc"] });
  });

  test("a GHSA that two CVEs of one gem version would both claim is given to neither (M5 fix 3)", () => {
    const ref = ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"];
    const report = { Results: [
      { Target: "Gemfile.lock", Vulnerabilities: [
        vuln("Gemfile.lock", "rack", "3.1.8", "CVE-2026-10", "ruby-advisory-db", ref),
        vuln("Gemfile.lock", "rack", "3.1.8", "CVE-2026-11", "ruby-advisory-db", ref),
        // Another version or another lockfile is a different claim and keeps its alias.
        vuln("Gemfile.lock", "rack", "3.1.9", "CVE-2026-12", "ruby-advisory-db", ref),
      ] },
      { Target: "sub/Gemfile.lock", Vulnerabilities: [vuln("sub/Gemfile.lock", "rack", "3.1.8", "CVE-2026-10", "ruby-advisory-db", ref)] },
    ] };
    expect([...rubyAdvisoryAliases(report).keys()]).toEqual([
      "Gemfile.lock\0rack\x003.1.9\0CVE-2026-12",
      "sub/Gemfile.lock\0rack\x003.1.8\0CVE-2026-10",
    ]);
  });

  test("only ruby-advisory-db results on Gemfile.lock / gems.locked", () => {
    const ref = ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"];
    const report = { Results: [
      { Target: "package-lock.json", Vulnerabilities: [vuln("package-lock.json", "lodash", "4.17.20", "CVE-2026-2", "ghsa", ref)] },
      { Target: "Gemfile.lock", Vulnerabilities: [
        vuln("Gemfile.lock", "rack", "3.1.8", "CVE-2026-3", "ghsa", ref),
        vuln("Gemfile.lock", "rack", "3.1.8", "GHSA-aaaa-bbbb-cccc", "ruby-advisory-db", ref),
      ] },
      { Target: "sub/Gemfile.lock", Vulnerabilities: [vuln("sub/Gemfile.lock", "rack", "3.1.8", "CVE-2026-4", "ruby-advisory-db", ref)] },
      { Target: "Gemfile.lock.bak", Vulnerabilities: [vuln("Gemfile.lock.bak", "rack", "3.1.8", "CVE-2026-5", "ruby-advisory-db", ref)] },
    ] };
    expect([...rubyAdvisoryAliases(report).keys()]).toEqual(["sub/Gemfile.lock\0rack\x003.1.8\0CVE-2026-4"]);
    for (const bad of [undefined, null, "x", {}, { Results: {} }, { Results: [{ Target: 1 }] }]) expect(rubyAdvisoryAliases(bad).size).toBe(0);
  });

  test("fingerprint and rule id are unchanged", async () => {
    const results = [vulnerability("Gemfile.lock", "crass", "1.0.7", "CVE-2026-116695")];
    const plain = normalizeSarif(sarif(results), "trivy", "/repo");
    const log = sarif(results);
    markAliases(log, rubyAdvisoryAliases(await rubyReport()));
    expect(log.runs![0]!.results![0]!.properties?.[TRIVY_ALIASES_PROPERTY]).toEqual(["GHSA-pq4g-8rxf-4g29"]);
    const marked = normalizeSarif(log, "trivy", "/repo");
    expect(marked[0]!.fingerprint).toBe(plain[0]!.fingerprint);
    expect(marked[0]!.rule_id).toBe("CVE-2026-116695");
    expect(plain[0]!.vulnerability_aliases).toBeUndefined();
  });

  test("the normalizer reads only GHSA-shaped strings, sorted and unique, never the rule id", () => {
    const log = sarif([vulnerability("Gemfile.lock", "crass", "1.0.7", "GHSA-zzzz-zzzz-zzzz")]);
    log.runs![0]!.results![0]!.properties = { [TRIVY_ALIASES_PROPERTY]: ["GHSA-ZZZZ-ZZZZ-ZZZZ", "GHSA-bbbb-cccc-dddd", "GHSA-BBBB-CCCC-DDDD", "CVE-1", "<script>", 7] };
    expect(normalizeSarif(log, "trivy", "/repo")[0]!.vulnerability_aliases).toEqual(["GHSA-bbbb-cccc-dddd"]);
    log.runs![0]!.results![0]!.properties = { [TRIVY_ALIASES_PROPERTY]: "GHSA-bbbb-cccc-dddd" };
    expect(normalizeSarif(log, "trivy", "/repo")[0]!.vulnerability_aliases).toBeUndefined();
  });
});
