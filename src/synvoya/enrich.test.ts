import { describe, expect, it } from "vitest";

import { osvSbomFindingComponents, osvScannerFindingComponents, synvoyaFindingComponents } from "../provenance.js";
import type { Finding } from "../types.js";
import { enrichUpstream, foldSbomDuplicates } from "./enrich.js";

function upstream(over: Partial<Finding> = {}): Finding {
  return {
    id: "sha256:up",
    fingerprint: "sha256:up",
    title: "lodash prototype pollution (lodash@4.17.4)",
    severity: "high",
    engine: "osv-scanner",
    engines: ["osv-scanner"],
    rule_id: "CVE-2026-1000",
    vulnerability_aliases: ["GHSA-aaaa-bbbb-cccc"],
    cwe: ["CWE-1395"],
    owasp_web: ["A06:2021"],
    location: { file: "package-lock.json", start_line: 7, end_line: 7 },
    message: "package-lock.json resolves npm package lodash@4.17.4.",
    remediation: { summary: "Upgrade lodash to 4.17.21.", steps: ["Upgrade lodash to 4.17.21."], references: ["https://osv.dev/x"] },
    frameworks: [],
    confidence: "high",
    producer_components: osvScannerFindingComponents("npm"),
    finding_kind: "vulnerability",
    package: { ecosystem: "npm", name: "lodash", version: "4.17.4" },
    ...over,
  };
}

function synvoya(over: Partial<Finding> = {}): Finding {
  return {
    id: "sha256:syn",
    fingerprint: "sha256:syn",
    title: "lodash gap (lodash@4.17.4)",
    severity: "critical",
    engine: "synvoya",
    engines: ["synvoya"],
    engine_family: "synvoya",
    rule_id: "SYN-2026-050",
    vulnerability_aliases: ["CVE-2026-1000"],
    cwe: ["CWE-1395"],
    owasp_web: ["A06:2021"],
    location: { file: "package-lock.json", start_line: 7, end_line: 7, snippet: "4.17.4" },
    message: "package-lock.json:7 locks lodash@4.17.4.",
    remediation: {
      summary: "Upgrade lodash to 4.17.21 or later, or remove the package.",
      steps: ["Upgrade lodash to 4.17.21 or later.", "Upgrade lodash to 4.17.21."],
      references: ["https://example.com/advisory"],
    },
    frameworks: [],
    confidence: "high",
    producer_components: synvoyaFindingComponents(),
    finding_kind: "vulnerability",
    package: { ecosystem: "npm", name: "lodash", version: "4.17.4" },
    ...over,
  };
}

/** Everything but the remediation steps, which is the one thing enrichment may change. */
function withoutSteps(finding: Finding): unknown {
  const { remediation, ...rest } = finding;
  return { ...rest, remediation: { ...remediation, steps: undefined } };
}

describe("enrichUpstream", () => {
  it("adds Synvoya's fix to the matching upstream finding, drops the Synvoya finding and changes nothing else", () => {
    const up = upstream();
    const before = structuredClone(up);
    const result = enrichUpstream([up], [synvoya()]);

    expect(result.standalone).toEqual([]);
    expect(result.enriched).toBe(1);
    expect(result.upstream).toHaveLength(1);
    const kept = result.upstream[0]!;
    // Byte-identical apart from the appended steps: id, fingerprint, engine(s), producer components, severity, title.
    expect(withoutSteps(kept)).toEqual(withoutSteps(before));
    expect(kept.fingerprint).toBe(before.fingerprint);
    expect(kept.producer_components).toEqual(before.producer_components);
    expect(kept.engines).toEqual(["osv-scanner"]);
    expect(kept.remediation.steps).toEqual([
      "Upgrade lodash to 4.17.21.",
      "Synvoya SYN-2026-050: Upgrade lodash to 4.17.21 or later, or remove the package.",
      "Upgrade lodash to 4.17.21 or later.",
    ]);
    // The input is never mutated.
    expect(up).toEqual(before);
  });

  it("matches on the upstream rule id too, and on case-insensitive npm names", () => {
    const up = upstream({ rule_id: "GHSA-zzzz-zzzz-zzzz", vulnerability_aliases: ["CVE-2026-1000"], package: { ecosystem: "npm", name: "Lodash", version: "4.17.4" } });
    const result = enrichUpstream([up], [synvoya({ vulnerability_aliases: ["GHSA-zzzz-zzzz-zzzz"] })]);
    expect(result.standalone).toEqual([]);
    expect(result.enriched).toBe(1);
  });

  it("a Synvoya finding with no upstream match stands alone and the upstream finding is the same object", () => {
    const up = upstream();
    const cases: Array<Partial<Finding>> = [
      { vulnerability_aliases: ["CVE-2026-9999"] },
      { vulnerability_aliases: undefined },
      { package: { ecosystem: "npm", name: "lodash", version: "4.17.5" } },
      { package: { ecosystem: "PyPI", name: "lodash", version: "4.17.4" } },
      { package: { ecosystem: "npm", name: "lodash-es", version: "4.17.4" } },
    ];
    for (const over of cases) {
      const syn = synvoya(over);
      const result = enrichUpstream([up], [syn]);
      expect(result.standalone).toEqual([syn]);
      expect(result.upstream[0]).toBe(up);
      expect(result.enriched).toBe(0);
    }
  });

  it("a Synvoya finding without a package never enriches another file's finding, and a package-less upstream finding is never enriched", () => {
    const up = upstream();
    const runtime = synvoya({ package: undefined, location: { file: ".nvmrc", start_line: 1, end_line: 1 } });
    const result = enrichUpstream([up], [runtime]);
    expect(result.standalone).toEqual([runtime]);
    expect(result.upstream[0]).toBe(up);

    const packageless = upstream({ package: undefined });
    expect(enrichUpstream([packageless], [synvoya()]).standalone).toHaveLength(1);
  });

  it("enriches only upstream findings in the same file, every one there", () => {
    const sameA = upstream({ fingerprint: "sha256:a", id: "a", rule_id: "CVE-2026-1000" });
    const sameB = upstream({ fingerprint: "sha256:b", id: "b", rule_id: "GHSA-aaaa-bbbb-cccc", vulnerability_aliases: ["CVE-2026-1000"] });
    const other = upstream({ fingerprint: "sha256:c", id: "c", location: { file: "app/package-lock.json", start_line: 3, end_line: 3 } });
    const result = enrichUpstream([sameA, other, sameB], [synvoya()]);
    // Both copies are steps-enriched, but they are one vulnerability (alias-connected, same file and package).
    expect(result.enriched).toBe(1);
    expect(result.standalone).toEqual([]);
    expect(result.upstream.map((finding) => finding.fingerprint)).toEqual(["sha256:a", "sha256:c", "sha256:b"]);
    expect(result.upstream[1]).toBe(other);
    expect(result.upstream[0]!.remediation.steps.some((step) => step.startsWith("Synvoya SYN-2026-050"))).toBe(true);
    expect(result.upstream[2]!.remediation.steps.some((step) => step.startsWith("Synvoya SYN-2026-050"))).toBe(true);
  });

  it("counts an enriched upstream vulnerability once, as the export shows it: Trivy and osv-scanner copies are one", () => {
    const osv = upstream({ fingerprint: "sha256:osv", id: "osv" });
    const trivy = upstream({ fingerprint: "sha256:trivy", id: "trivy", engine: "trivy", engines: ["trivy"], location: { file: "package-lock.json", start_line: 1, end_line: 1 } });
    const result = enrichUpstream([osv, trivy], [synvoya()]);
    expect(result.enriched).toBe(1);
    expect(result.upstream.every((finding) => finding.remediation.steps.some((step) => step.startsWith("Synvoya SYN-2026-050")))).toBe(true);

    // Two different vulnerabilities each gained a fix: two.
    const second = upstream({ fingerprint: "sha256:second", id: "second", rule_id: "CVE-2026-2000", vulnerability_aliases: [] });
    const two = enrichUpstream([osv, trivy, second], [synvoya(), synvoya({ rule_id: "SYN-2026-051", vulnerability_aliases: ["CVE-2026-2000"] })]);
    expect(two.enriched).toBe(2);
  });

  it("an upstream finding in another file never absorbs the Synvoya finding: it stands alone", () => {
    const other = upstream({ location: { file: "app/package-lock.json", start_line: 3, end_line: 3 } });
    const syn = synvoya();
    const result = enrichUpstream([other], [syn]);
    expect(result.standalone).toEqual([syn]);
    expect(result.upstream[0]).toBe(other);
    expect(result.enriched).toBe(0);
  });

  it("never treats another Synvoya finding as upstream and leaves non-vulnerability upstream findings alone", () => {
    const peer = synvoya({ fingerprint: "sha256:peer", rule_id: "SYN-2026-051" });
    const result = enrichUpstream([peer], [synvoya()]);
    expect(result.standalone).toHaveLength(1);
    const license = upstream({ finding_kind: "license" });
    expect(enrichUpstream([license], [synvoya()]).upstream[0]).toBe(license);
  });
});

describe("foldSbomDuplicates: Magento editions checked under their advisory name", () => {
  const MAGENTO = { ecosystem: "Packagist", name: "magento/product-community-edition", version: "2.3.1" };
  // The main run matched the locked name itself; the SBOM run matched the advisory name and reports the locked one.
  const main = upstream({
    rule_id: "CVE-2019-8121",
    vulnerability_aliases: ["GHSA-89ch-hqf9-rgp3"],
    location: { file: "composer.lock", start_line: 120, end_line: 120 },
    package: MAGENTO,
  });
  const sbom = (over: Partial<Finding> = {}): Finding => upstream({
    id: "sha256:sbom",
    fingerprint: "sha256:sbom",
    rule_id: "CVE-2019-8121",
    vulnerability_aliases: ["GHSA-89ch-hqf9-rgp3"],
    location: { file: "composer.lock", start_line: 120, end_line: 120 },
    producer_components: osvSbomFindingComponents("Packagist"),
    package: MAGENTO,
    ...over,
  });

  it("the same advisory on the locked package in the same file is one finding: the main run's", () => {
    expect(foldSbomDuplicates([main], [sbom()])).toEqual({ kept: [], folded: 1 });
  });

  it("another advisory, or the same one in another lock, stands alone", () => {
    const other = sbom({ rule_id: "CVE-2024-34102", vulnerability_aliases: ["GHSA-m3ww-2c2x-6x2r"] });
    const elsewhere = sbom({ location: { file: "shop/composer.lock", start_line: 9, end_line: 9 } });
    expect(foldSbomDuplicates([main], [other, elsewhere])).toEqual({ kept: [other, elsewhere], folded: 0 });
  });
});

describe("enrichUpstream: Synvoya findings without a package (product, runtime) in the same file", () => {
  // SYN-2026-10801 (CosmicSting) on a Magento 2.4.6-p3 lock, and the SBOM run's finding for the same CVE at the
  // same composer.lock line (the edition checked as magento/community-edition, reported under its locked name).
  const product = synvoya({
    id: "sha256:syn-product",
    fingerprint: "sha256:syn-product",
    title: "Verify APSB24-40 is applied to Magento Open Source 2.4.6-p3 (declared in composer.lock)",
    severity: "medium",
    rule_id: "SYN-2026-10801",
    vulnerability_aliases: ["APSB24-40", "BIT-magento-2024-34102", "CVE-2024-34102", "GHSA-m8cj-3v68-3cxj", "SYN-2026-108"],
    location: { file: "composer.lock", start_line: 12, end_line: 12, snippet: "2.4.6-p3" },
    message: "composer.lock:12 declares Magento Open Source 2.4.6-p3 (composer.lock magento/product-community-edition).",
    remediation: { summary: "Verify APSB24-40 is applied.", steps: ["Verify the VULN-27015 hotfix is applied (vendor/bin/patch-status)."], references: [] },
    producer_components: [...synvoyaFindingComponents(), "synvoya:products"],
    package: undefined,
  });
  const sbom = upstream({
    id: "sha256:sbom-cosmic",
    fingerprint: "sha256:sbom-cosmic",
    title: "Magento Open Source XXE (magento/product-community-edition@2.4.6-p3)",
    severity: "critical",
    rule_id: "CVE-2024-34102",
    vulnerability_aliases: ["GHSA-m8cj-3v68-3cxj"],
    location: { file: "composer.lock", start_line: 12, end_line: 12 },
    remediation: { summary: "Upgrade magento/product-community-edition to 2.4.6-p6.", steps: ["Upgrade magento/product-community-edition to 2.4.6-p6."], references: [] },
    producer_components: osvSbomFindingComponents("Packagist"),
    package: { ecosystem: "Packagist", name: "magento/product-community-edition", version: "2.4.6-p3" },
  });

  it("a Magento product advisory sharing a CVE with the SBOM finding in the same lock is one finding: the SBOM one, gaining the Synvoya steps", () => {
    const before = structuredClone(sbom);
    const result = enrichUpstream([sbom], [product]);
    expect(result.standalone).toEqual([]);
    expect(result.enriched).toBe(1);
    const kept = result.upstream[0]!;
    expect(withoutSteps(kept)).toEqual(withoutSteps(before));
    expect(kept.producer_components).toEqual(osvSbomFindingComponents("Packagist"));
    expect(kept.remediation.steps).toEqual([
      "Upgrade magento/product-community-edition to 2.4.6-p6.",
      "Synvoya SYN-2026-10801: Verify APSB24-40 is applied.",
      "Verify the VULN-27015 hotfix is applied (vendor/bin/patch-status).",
    ]);
  });

  it("a Go runtime advisory sharing a GO id with the stdlib SBOM finding at go.mod is one finding", () => {
    const runtime = synvoya({
      id: "sha256:syn-go", fingerprint: "sha256:syn-go", rule_id: "SYN-2026-019",
      vulnerability_aliases: ["CVE-2026-33818", "GO-2026-5972", "GO-2026-6088"],
      location: { file: "go.mod", start_line: 5, end_line: 5, snippet: "1.26.5" },
      remediation: { summary: "Upgrade the declared Go to 1.26.6 or later.", steps: ["Raise the toolchain line to go1.26.6."], references: [] },
      producer_components: [...synvoyaFindingComponents(), "synvoya:runtime"],
      package: undefined,
    });
    const stdlib = upstream({
      id: "sha256:sbom-go", fingerprint: "sha256:sbom-go", rule_id: "GO-2026-5972", vulnerability_aliases: ["CVE-2026-33818"],
      location: { file: "go.mod", start_line: 5, end_line: 5 },
      producer_components: osvSbomFindingComponents("Go"),
      package: { ecosystem: "Go", name: "stdlib", version: "v1.26.5" },
    });
    const result = enrichUpstream([stdlib], [runtime]);
    expect(result.standalone).toEqual([]);
    expect(result.upstream[0]!.fingerprint).toBe("sha256:sbom-go");
    expect(result.upstream[0]!.remediation.steps).toContain("Synvoya SYN-2026-019: Upgrade the declared Go to 1.26.6 or later.");
  });

  it("no shared advisory id, or another file, keeps the Synvoya finding standalone and the upstream object untouched", () => {
    const unrelated = synvoya({ ...product, vulnerability_aliases: ["CVE-2026-99999"] });
    const elsewhere = synvoya({ ...product, location: { file: "shop/composer.lock", start_line: 12, end_line: 12 } });
    for (const syn of [unrelated, elsewhere]) {
      const result = enrichUpstream([sbom], [syn]);
      expect(result.standalone).toEqual([syn]);
      expect(result.upstream[0]).toBe(sbom);
    }
  });

  it("the Synvoya rule id alone (SYN-…) never matches", () => {
    const upstreamNamingSyn = upstream({ ...sbom, rule_id: "SYN-2026-10801", vulnerability_aliases: [] });
    const onlyId = synvoya({ ...product, vulnerability_aliases: [] });
    expect(enrichUpstream([upstreamNamingSyn], [onlyId]).standalone).toEqual([onlyId]);
  });
});
