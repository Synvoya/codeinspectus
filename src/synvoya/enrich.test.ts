import { describe, expect, it } from "vitest";

import { osvScannerFindingComponents, synvoyaFindingComponents } from "../provenance.js";
import type { Finding } from "../types.js";
import { enrichUpstream } from "./enrich.js";

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

  it("never enriches from or into a finding without a package (runtime, product, image)", () => {
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
