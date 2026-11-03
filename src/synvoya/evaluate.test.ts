import { describe, expect, test } from "vitest";

import { synvoyaFindingComponents } from "../provenance.js";
import { fingerprint } from "../util/hash.js";
import { cycleOf, evaluateSynvoya, spansAffect, type PackageInventory } from "./evaluate.js";
import type { Declaration, EolEntry, SynvoyaAdvisory, SynvoyaDataset } from "./types.js";
import { isAffected, type VersionScheme } from "./versions.js";

const NOW = new Date("2026-11-03T12:00:00Z");
const NO_INVENTORY: PackageInventory = { packages: [] };
const REBUILD = "Rebuild and redeploy every image or host that uses this runtime.";

function adv(overrides: Partial<SynvoyaAdvisory> = {}): SynvoyaAdvisory {
  return {
    id: "SYN-2026-100",
    slug: "node-22-test",
    title: "Node.js 22 before 22.12.0 is affected by a test flaw",
    kind: "runtime",
    aliases: ["CVE-2026-0001"],
    target: { type: "runtime", runtime: "node" },
    affected: [{ line: "22", events: [{ introduced: "22.0.0" }, { fixed: "22.12.0" }] }],
    fixed: ["22.12.0"],
    severity: "high",
    exploited: false,
    remediation_steps: ["Upgrade the declared Node.js runtime to 22.12.0 or later."],
    sources: ["https://nodejs.org/en/blog/vulnerability/test"],
    status: "active",
    provisional: false,
    ...overrides,
  };
}

function eol(product: string, cycle: string, date: string, latest?: string): EolEntry {
  return { product, cycle, eol: date, ...(latest ? { latest } : {}), source: `https://endoflife.date/${product}` };
}

function dataset(advisories: SynvoyaAdvisory[], eolEntries: EolEntry[] = []): SynvoyaDataset {
  return {
    version: "2026.11.03",
    date: "2026-11-03",
    advisories,
    aliases: {},
    imageAliases: {},
    productImages: {},
    eol: eolEntries,
  };
}

function decl(overrides: Partial<Declaration> = {}): Declaration {
  return {
    subject: { type: "runtime", runtime: "node" },
    spec: "22.1.0",
    resolved: "22.1.0",
    precision: "exact",
    file: ".nvmrc",
    line: 1,
    source: ".nvmrc",
    ...overrides,
  };
}

const run = (
  ds: SynvoyaDataset,
  declarations: Declaration[],
  inventory: PackageInventory = NO_INVENTORY,
  now: Date = NOW,
  dbDates: { trivy?: string; osv?: Record<string, string> } = {},
) => evaluateSynvoya(ds, declarations, inventory, now, dbDates);

describe("exact declarations", () => {
  test("an exact affected pin is a high-confidence finding with the advisory's severity", () => {
    const { findings, notes } = run(dataset([adv()]), [decl({ file: "app/.nvmrc", line: 3 })]);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.severity).toBe("high");
    expect(f.confidence).toBe("high");
    expect(f.engine).toBe("synvoya");
    expect(f.engines).toEqual(["synvoya"]);
    expect(f.engine_family).toBe("synvoya");
    expect(f.rule_id).toBe("SYN-2026-100");
    expect(f.vulnerability_aliases).toEqual(["CVE-2026-0001"]);
    expect(f.finding_kind).toBe("vulnerability");
    expect(f.cwe).toEqual(["CWE-1104"]);
    expect(f.producer_components).toEqual(synvoyaFindingComponents());
    expect(f.location).toMatchObject({ file: "app/.nvmrc", start_line: 3, end_line: 3 });
    expect(f.title).toContain("Node.js 22 before 22.12.0 is affected by a test flaw");
    expect(f.title).toContain("22.1.0");
    expect(f.title).toContain("app/.nvmrc");
    expect(f.message).toContain("declares");
    expect(f.message).toContain("declared");
    expect(f.remediation.steps).toContain("Upgrade the declared Node.js runtime to 22.12.0 or later.");
    expect(f.remediation.steps).toContain(REBUILD);
    expect(f.remediation.references).toEqual(["https://nodejs.org/en/blog/vulnerability/test"]);
    expect(f.package).toBeUndefined();
    expect(notes).toEqual([]);
  });

  test("an exact pin outside every range is silent", () => {
    const { findings, notes } = run(dataset([adv()]), [decl({ spec: "22.12.0", resolved: "22.12.0" })]);
    expect(findings).toEqual([]);
    expect(notes).toEqual([]);
  });

  test("an exact pin the scheme cannot compare is a note, never a finding", () => {
    const { findings, notes } = run(dataset([adv()]), [decl({ spec: "22.1.0.0", resolved: "22.1.0.0" })]);
    expect(findings).toEqual([]);
    expect(notes).toHaveLength(1);
    expect(notes[0]).toContain("could not compare 22.1.0.0 for Node.js");
  });

  test("an advisory for another runtime never matches", () => {
    const { findings } = run(dataset([adv({ target: { type: "runtime", runtime: "php" } })]), [decl()]);
    expect(findings).toEqual([]);
  });
});

describe("floating and range declarations", () => {
  test("a floating tag on a supported line with a fix is only an info hygiene note", () => {
    const ds = dataset([adv()], [eol("node", "22", "2027-04-30", "22.21.0")]);
    const { findings, notes } = run(ds, [
      decl({ spec: "22", precision: "floating", resolved: undefined, file: "Dockerfile", source: "Dockerfile FROM" }),
    ]);
    expect(findings).toEqual([]);
    expect(notes).toHaveLength(1);
    expect(notes[0]).toContain("pin Node.js to ≥ 22.12.0");
  });

  describe("advisories on end-of-life lines (.nvmrc 20)", () => {
    const node20 = (events: SynvoyaAdvisory["affected"][number]["events"], fixed: string[]): SynvoyaAdvisory =>
      adv({ id: "SYN-2026-101", title: "Node.js 20 test flaw", affected: [{ line: "20", events }], fixed, severity: "critical" });
    const nvmrc20 = decl({ spec: "20", precision: "floating", resolved: undefined });
    const table = (latest?: string) => [eol("node", "20", "2026-04-30", latest)];

    test("an advisory fixed on the line at or below its latest release leaves only the EOL finding", () => {
      const { findings, notes } = run(dataset([node20([{ introduced: "20.0.0" }, { fixed: "20.18.1" }], ["20.18.1"])], table("20.19.5")), [nvmrc20]);
      expect(findings.map((f) => f.rule_id)).toEqual(["SYN-EOL-node-20"]);
      expect(findings[0]!.title).toBe("Node.js 20 is end-of-life (declared in .nvmrc)");
      expect(notes).toEqual([]);
    });

    test("an advisory unfixed on the line fires next to the EOL finding", () => {
      const { findings } = run(dataset([node20([{ introduced: "20.0.0" }], [])], table("20.19.5")), [nvmrc20]);
      expect(findings.map((f) => f.rule_id).sort()).toEqual(["SYN-2026-101", "SYN-EOL-node-20"]);
      const advisory = findings.find((f) => f.rule_id === "SYN-2026-101")!;
      expect(advisory.severity).toBe("critical");
      expect(advisory.confidence).toBe("high");
    });

    test("an advisory that affects the line's latest release fires next to the EOL finding", () => {
      const { findings } = run(dataset([node20([{ introduced: "20.0.0" }, { fixed: "20.20.0" }], ["20.20.0"])], table("20.19.5")), [nvmrc20]);
      expect(findings.map((f) => f.rule_id).sort()).toEqual(["SYN-2026-101", "SYN-EOL-node-20"]);
    });

    test("without a latest release in the EOL table the advisory does not fire and a note says why", () => {
      const { findings, notes } = run(dataset([node20([{ introduced: "20.0.0" }, { fixed: "20.18.1" }], ["20.18.1"])], table()), [nvmrc20]);
      expect(findings.map((f) => f.rule_id)).toEqual(["SYN-EOL-node-20"]);
      expect(notes).toHaveLength(1);
      expect(notes[0]).toContain("latest release");
      expect(notes[0]).toContain("SYN-2026-101");
    });
  });

  test("a floating pin on a line the advisory leaves unfixed from its first release is a medium-confidence finding", () => {
    const unfixed = adv({ affected: [{ line: "22", events: [{ introduced: "22.0.0" }] }], fixed: [] });
    const ds = dataset([unfixed], [eol("node", "22", "2027-04-30")]);
    const { findings } = run(ds, [decl({ spec: "22", precision: "floating", resolved: undefined })]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe("medium");
    expect(findings[0]!.severity).toBe("high");
  });

  test("an unfixed element introduced after the line's first release is only a note", () => {
    const late = adv({ affected: [{ line: "22", events: [{ introduced: "22.5.0" }] }], fixed: [] });
    const ds = dataset([late], [eol("node", "22", "2027-04-30")]);
    const { findings, notes } = run(ds, [decl({ spec: "22", precision: "floating", resolved: undefined })]);
    expect(findings).toEqual([]);
    expect(notes).toHaveLength(1);
  });

  test("a range is a finding only when every enumerable line is affected or end-of-life", () => {
    const php = adv({
      id: "SYN-2026-102",
      title: "PHP 8.1 unfixed test flaw",
      target: { type: "runtime", runtime: "php" },
      affected: [{ line: "8.1", events: [{ introduced: "8.1.0" }] }],
      fixed: ["8.2.0"],
    });
    const cycles = [
      eol("php", "8.0", "2023-11-26"),
      eol("php", "8.1", "2025-12-31"),
      eol("php", "8.2", "2026-12-31"),
      eol("php", "8.3", "2027-12-31"),
    ];
    const ds = dataset([php], cycles);
    const php81 = (spec: string): Declaration =>
      decl({ subject: { type: "runtime", runtime: "php" }, spec, precision: "range", resolved: undefined, file: "composer.json", source: "composer.json require.php" });

    const supported = run(ds, [php81("^8.1")]);
    expect(supported.findings).toEqual([]);
    expect(supported.notes.some((n) => n.includes("pin PHP to ≥"))).toBe(true);

    // 8.0 resolutions are not affected by the 8.1-only advisory: the EOL finding stands alone.
    const allEol = run(ds, [php81(">=8.0 <8.2")]);
    expect(allEol.findings.map((f) => f.rule_id)).toEqual(["SYN-EOL-php-8.1"]);
    expect(allEol.findings[0]!.title).toBe("PHP 8.0/8.1 is end-of-life (declared in composer.json)");
    expect(allEol.notes).toEqual([]);

    // Every line of the range is unfixed by the advisory (rule b): it fires next to the EOL finding.
    const unfixedOnly = run(ds, [php81(">=8.1 <8.2")]);
    expect(unfixedOnly.findings.map((f) => f.rule_id).sort()).toEqual(["SYN-2026-102", "SYN-EOL-php-8.1"]);
  });

  test("an OR range is EOL only when every alternative's lines are", () => {
    const cycles = [eol("node", "18", "2025-04-30"), eol("node", "20", "2026-04-30"), eol("node", "22", "2027-04-30")];
    const range = (spec: string): Declaration => decl({ spec, precision: "range", resolved: undefined, file: "package.json" });
    expect(run(dataset([], cycles), [range("^20 || ^22")]).findings).toEqual([]);
    expect(run(dataset([], cycles), [range("18.x || 20.x")]).findings.map((f) => f.title)).toEqual([
      "Node.js 18/20 is end-of-life (declared in package.json)",
    ]);
  });

  test("a range with no enumerable lines is a note, never a finding", () => {
    const ds = dataset([adv()], [eol("node", "22", "2027-04-30")]);
    const { findings, notes } = run(ds, [decl({ spec: ">=99", precision: "range", resolved: undefined, file: "package.json" })]);
    expect(findings).toEqual([]);
    expect(notes).toHaveLength(1);
  });

  test("an unresolved declaration is note-only", () => {
    const ds = dataset([adv()], [eol("node", "22", "2027-04-30")]);
    const { findings, notes } = run(ds, [decl({ spec: "lts/*", precision: "unresolved", resolved: undefined })]);
    expect(findings).toEqual([]);
    expect(notes).toHaveLength(1);
    expect(notes[0]).toContain("lts/*");
  });
});

describe("end of life", () => {
  test("an exact runtime pin on an EOL cycle is a high-severity, high-confidence finding", () => {
    const ds = dataset([], [eol("node", "16", "2023-09-11", "16.20.2")]);
    const { findings } = run(ds, [decl({ spec: "16.20.2", resolved: "16.20.2" })]);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.title).toBe("Node.js 16 is end-of-life (declared in .nvmrc)");
    expect(f.severity).toBe("high");
    expect(f.confidence).toBe("high");
    expect(f.cwe).toEqual(["CWE-1104"]);
    expect(f.rule_id).toBe("SYN-EOL-node-16");
    expect(f.message).toContain("declared");
    expect(f.remediation.steps).toContain(REBUILD);
    expect(f.remediation.references).toEqual(["https://endoflife.date/node"]);
  });

  test("a floating EOL pin (.nvmrc 20) is a finding", () => {
    const ds = dataset([], [eol("node", "20", "2026-04-30")]);
    const { findings } = run(ds, [decl({ spec: "20", precision: "floating", resolved: undefined })]);
    expect(findings.map((f) => f.title)).toEqual(["Node.js 20 is end-of-life (declared in .nvmrc)"]);
  });

  test("a service image on an EOL cycle is a medium-severity finding", () => {
    const ds = dataset([], [eol("mysql", "5.7", "2023-10-31")]);
    const { findings } = run(ds, [
      decl({ subject: { type: "image-eol", product: "mysql" }, spec: "5.7", precision: "floating", resolved: undefined, file: "docker-compose.yml", source: "compose image" }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("medium");
    expect(findings[0]!.title).toBe("mysql 5.7 is end-of-life (declared in docker-compose.yml)");
    expect(findings[0]!.remediation.steps).toContain(REBUILD);
  });

  test("EOL is judged against the injected now, not the wall clock", () => {
    const ds = dataset([], [eol("dotnet", "8.0", "2026-11-10")]);
    const declaration = decl({ subject: { type: "runtime", runtime: "dotnet" }, spec: "8.0.11", resolved: "8.0.11", file: "global.json" });
    expect(run(ds, [declaration], NO_INVENTORY, new Date("2026-11-03T00:00:00Z")).findings).toEqual([]);
    expect(run(ds, [declaration], NO_INVENTORY, new Date("2026-11-11T00:00:00Z")).findings).toHaveLength(1);
  });

  test("an eol-kind advisory replaces the table finding and waits for the table's EOL date", () => {
    const eolAdvisory = adv({
      id: "SYN-2026-103",
      kind: "eol",
      title: ".NET 8 reaches end of support",
      target: { type: "runtime", runtime: "dotnet" },
      affected: [{ line: "8.0", events: [{ introduced: "8.0.0" }, { limit: "8.1.0" }] }],
      fixed: [],
      severity: "medium",
    });
    const ds = dataset([eolAdvisory], [eol("dotnet", "8.0", "2026-11-10")]);
    const declaration = decl({ subject: { type: "runtime", runtime: "dotnet" }, spec: "8.0.11", resolved: "8.0.11", file: "global.json" });
    expect(run(ds, [declaration], NO_INVENTORY, new Date("2026-11-03T00:00:00Z")).findings).toEqual([]);
    const after = run(ds, [declaration], NO_INVENTORY, new Date("2026-11-11T00:00:00Z")).findings;
    expect(after.map((f) => [f.rule_id, f.severity])).toEqual([["SYN-2026-103", "medium"]]);
  });
});

describe("product rules", () => {
  const commerce = (overrides: Partial<SynvoyaAdvisory> = {}): SynvoyaAdvisory =>
    adv({
      id: "SYN-2026-002",
      kind: "product",
      title: "Adobe Commerce SessionReaper",
      aliases: ["CVE-2025-54236", "VULN-32437"],
      target: { type: "product", product: "adobe-commerce" },
      affected: [{ line: "2.4.8", events: [{ introduced: "2.4.8" }, { fixed: "2.4.8-p3" }] }],
      fixed: ["2.4.8-p3"],
      severity: "critical",
      product_rule: "verify-hotfix",
      remediation_steps: ["Apply the vendor security hotfix."],
      ...overrides,
    });
  const store = decl({
    subject: { type: "product", product: "adobe-commerce" },
    spec: "2.4.8-p2",
    resolved: "2.4.8-p2",
    file: "composer.lock",
    line: 120,
    source: "composer.lock magento/product-enterprise-edition",
  });

  test("verify-hotfix is a medium 'Verify <hotfix> is applied' finding", () => {
    const { findings } = run(dataset([commerce()]), [store]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("medium");
    expect(findings[0]!.title).toMatch(/^Verify VULN-32437 is applied/);
    expect(findings[0]!.remediation.steps).not.toContain(REBUILD);
  });

  test("version-proves keeps the advisory severity", () => {
    const { findings } = run(dataset([commerce({ product_rule: "version-proves" })]), [store]);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.title).not.toMatch(/^Verify/);
  });

  test("a verify-hotfix line with no patch at all is proven by the version alone", () => {
    const noPatch = commerce({ affected: [{ line: "2.4.8", events: [{ introduced: "2.4.8" }] }] });
    const { findings } = run(dataset([noPatch]), [store]);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.title).not.toMatch(/^Verify/);
  });

  test("a limit-bounded range is a hotfix-only fix, not a line with no patch: verify, never proven", () => {
    // The vendor fix is an isolated patch that never changes the version string: the affected range ends
    // at a limit, not at a fixed release.
    const hotfixOnly = commerce({
      aliases: ["CVE-2026-75650", "VULN-39341"],
      affected: [{ events: [{ introduced: "2.4.4" }, { limit: "2.4.10-alpha1" }] }],
      fixed: [],
    });
    const exact = run(dataset([hotfixOnly]), [store]);
    expect(exact.findings).toHaveLength(1);
    expect(exact.findings[0]!.severity).toBe("medium");
    expect(exact.findings[0]!.title).toMatch(/^Verify VULN-39341 is applied/);
    expect(exact.findings[0]!.remediation.summary).toBe("Verify VULN-39341 is applied.");

    const floating = run(dataset([hotfixOnly]), [decl({ ...store, spec: "2.4.8", resolved: undefined, precision: "floating" })]);
    expect(floating.findings).toHaveLength(1);
    expect(floating.findings[0]!.severity).toBe("medium");
    expect(floating.findings[0]!.title).toMatch(/^Verify VULN-39341 is applied/);
  });
});

describe("point ranges", () => {
  test("a malware version listed as an exact point flags that version only, exact or floating", () => {
    const malware = adv({
      id: "SYN-2026-001",
      kind: "malware",
      title: "LiteLLM 1.107.0 trojanised release",
      target: { type: "package", ecosystem: "PyPI", name: "litellm" },
      affected: [{ events: [{ introduced: "1.107.0" }, { last_affected: "1.107.0" }] }],
      fixed: ["1.106.2"],
    });
    const lock = (version: string): PackageInventory => ({ packages: [{ ecosystem: "PyPI", name: "litellm", version, file: "poetry.lock", line: 3 }] });
    expect(run(dataset([malware]), [], lock("1.107.0")).findings).toHaveLength(1);
    expect(run(dataset([malware]), [], lock("1.106.2")).findings).toEqual([]);
    expect(run(dataset([malware]), [], lock("1.108.0")).findings).toEqual([]);
  });
});

describe("vendor bulletin names", () => {
  test("a WSO2 security advisory id names the hotfix to verify", () => {
    const wso2 = adv({
      id: "SYN-2026-226",
      kind: "product",
      title: "WSO2 API Manager path traversal",
      aliases: ["CVE-2026-5430", "WSO2-2026-5328"],
      target: { type: "product", product: "wso2-api-manager" },
      affected: [{ events: [{ introduced: "4.6.0" }, { limit: "4.6.0.21" }] }],
      fixed: [],
      product_rule: "verify-hotfix",
    });
    const image = decl({ subject: { type: "product", product: "wso2-api-manager" }, spec: "4.6.0", resolved: "4.6.0", file: "Dockerfile", source: "Dockerfile FROM" });
    const { findings } = run(dataset([wso2]), [image]);
    expect(findings[0]!.title).toMatch(/^Verify WSO2-2026-5328 is applied/);
  });
});

describe("no vendor fix", () => {
  test("no_fix_available says to replace or remove the package instead of naming an upgrade", () => {
    const noFix = adv({
      id: "SYN-2026-056",
      kind: "vulnerability",
      title: "extract-zip symlink arbitrary file write",
      target: { type: "package", ecosystem: "npm", name: "extract-zip" },
      affected: [{ events: [{ introduced: "0" }, { last_affected: "2.0.1" }] }],
      fixed: [],
      no_fix_available: true,
      remediation_steps: ["Replace extract-zip with an extractor that rejects symlink entries."],
    });
    const inventory: PackageInventory = {
      packages: [{ ecosystem: "npm", name: "extract-zip", version: "2.0.1", file: "package-lock.json", line: 9 }],
    };
    const { findings } = run(dataset([noFix]), [], inventory);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.remediation.summary).toBe("No fixed release of extract-zip exists; replace or remove the package.");
    expect(findings[0]!.remediation.steps).toContain("Replace extract-zip with an extractor that rejects symlink entries.");
  });
});

describe("status and provisional", () => {
  const covered = (by: "trivy" | "osv-scanner"): SynvoyaAdvisory =>
    adv({
      id: "SYN-2026-104",
      kind: "vulnerability",
      title: "lodash test flaw",
      target: { type: "package", ecosystem: "npm", name: "lodash" },
      affected: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      fixed: ["4.17.21"],
      status: "covered",
      covered_by: by,
      covered_since: "2026-10-01",
    });
  const inventory: PackageInventory = {
    packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.20", file: "package-lock.json", line: 40 }],
  };

  test("a covered entry is silent when the upstream DB is newer than covered_since", () => {
    expect(run(dataset([covered("trivy")]), [], inventory, NOW, { trivy: "2026-10-20T00:00:00Z" }).findings).toEqual([]);
    expect(run(dataset([covered("osv-scanner")]), [], inventory, NOW, { osv: { npm: "2026-10-20" } }).findings).toEqual([]);
  });

  test("a covered entry fires when the upstream DB is older than covered_since, or unknown", () => {
    expect(run(dataset([covered("trivy")]), [], inventory, NOW, { trivy: "2026-09-01" }).findings).toHaveLength(1);
    expect(run(dataset([covered("osv-scanner")]), [], inventory, NOW, { osv: { npm: "2026-09-01" } }).findings).toHaveLength(1);
    expect(run(dataset([covered("trivy")]), [], inventory, NOW, {}).findings).toHaveLength(1);
  });

  test("a provisional entry is low confidence with the provisional title suffix", () => {
    const { findings } = run(dataset([adv({ provisional: true })]), [decl()]);
    expect(findings[0]!.confidence).toBe("low");
    expect(findings[0]!.title).toMatch(/\(provisional — verify with the vendor\)$/);
    expect(findings[0]!.severity).toBe("high");
  });
});

describe("package targets", () => {
  const pkgAdv = (ecosystem: string, name: string, overrides: Partial<SynvoyaAdvisory> = {}): SynvoyaAdvisory =>
    adv({
      id: "SYN-2026-105",
      kind: "vulnerability",
      title: `${name} test flaw`,
      target: { type: "package", ecosystem, name },
      affected: [{ events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
      fixed: ["2.0.0"],
      remediation_steps: [`Upgrade ${name} to 2.0.0.`],
      ...overrides,
    });
  const item = (ecosystem: string, name: string, version = "1.0.0") => ({ ecosystem, name, version, file: "lock", line: 7 });

  test("an inventory package in range is a finding with package set and no rebuild step", () => {
    const { findings } = run(dataset([pkgAdv("npm", "left-pad")]), [], { packages: [item("npm", "left-pad")] });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.package).toEqual({ ecosystem: "npm", name: "left-pad", version: "1.0.0" });
    expect(findings[0]!.location).toMatchObject({ file: "lock", start_line: 7 });
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.cwe).toEqual(["CWE-1395"]);
    expect(findings[0]!.remediation.steps).not.toContain(REBUILD);
  });

  test("npm and PyPI names match case-insensitively (PyPI normalised); others exactly", () => {
    expect(run(dataset([pkgAdv("npm", "left-pad")]), [], { packages: [item("npm", "Left-Pad")] }).findings).toHaveLength(1);
    expect(run(dataset([pkgAdv("PyPI", "foo-bar")]), [], { packages: [item("PyPI", "Foo_Bar.")] }).findings).toHaveLength(0);
    expect(run(dataset([pkgAdv("PyPI", "foo-bar")]), [], { packages: [item("PyPI", "Foo_Bar")] }).findings).toHaveLength(1);
    expect(run(dataset([pkgAdv("Maven", "org.example:Lib")]), [], { packages: [item("Maven", "org.example:lib")] }).findings).toHaveLength(0);
    expect(run(dataset([pkgAdv("Maven", "org.example:Lib")]), [], { packages: [item("Maven", "org.example:Lib")] }).findings).toHaveLength(1);
    expect(run(dataset([pkgAdv("NuGet", "Newtonsoft.Json")]), [], { packages: [item("NuGet", "newtonsoft.json")] }).findings).toHaveLength(1);
    expect(run(dataset([pkgAdv("Packagist", "monolog/monolog")]), [], { packages: [item("Packagist", "Monolog/Monolog")] }).findings).toHaveLength(1);
    expect(run(dataset([pkgAdv("PyPI", "zope.interface")]), [], { packages: [item("PyPI", "Zope_Interface")] }).findings).toHaveLength(1);
  });

  test("a package version outside the range is silent", () => {
    expect(run(dataset([pkgAdv("npm", "left-pad")]), [], { packages: [item("npm", "left-pad", "2.0.0")] }).findings).toEqual([]);
  });

  test("malware is critical whatever the entry says and remediation removes, reinstalls clean and rotates credentials", () => {
    const malware = pkgAdv("npm", "evil-pkg", {
      kind: "malware",
      severity: "high",
      affected: [{ events: [{ introduced: "1.0.0" }, { last_affected: "1.0.0" }] }],
      fixed: [],
      remediation_steps: ["Remove evil-pkg."],
    });
    const { findings } = run(dataset([malware]), [], { packages: [item("npm", "evil-pkg")] });
    expect(findings).toHaveLength(1);
    const steps = findings[0]!.remediation.steps.join("\n");
    expect(findings[0]!.severity).toBe("critical");
    expect(steps).toMatch(/remove/i);
    expect(steps).toMatch(/clean lockfile/i);
    expect(steps).toMatch(/rotate every credential/i);
    const provisional = run(dataset([{ ...malware, provisional: true }]), [], { packages: [item("npm", "evil-pkg")] });
    expect(provisional.findings[0]!.severity).toBe("critical");
  });
});

describe("open-ended and partly listed ranges", () => {
  const LATER = new Date("2028-06-01T00:00:00Z");
  const fullNodeTable = [
    eol("node", "18", "2025-04-30", "18.20.8"),
    eol("node", "19", "2023-06-01", "19.9.0"),
    eol("node", "20", "2026-04-30", "20.19.5"),
    eol("node", "21", "2024-06-01", "21.7.3"),
    eol("node", "22", "2027-04-30", "22.21.0"),
    eol("node", "23", "2025-06-01", "23.11.1"),
    eol("node", "24", "2028-04-30", "24.11.0"),
  ];
  const range = (spec: string): Declaration => decl({ spec, precision: "range", resolved: undefined, file: "package.json", source: "package.json engines.node" });

  test(">=18 can resolve to lines newer than the bundled table, so it is never end-of-life", () => {
    const result = run(dataset([], fullNodeTable), [range(">=18")], NO_INVENTORY, LATER);
    expect(result.findings).toEqual([]);
    expect(run(dataset([], fullNodeTable), [range(">=0.10")], NO_INVENTORY, LATER).findings).toEqual([]);
  });

  test("a closed range whose every listed line is end-of-life still fires", () => {
    const { findings } = run(dataset([], fullNodeTable), [range(">=18 <25")], NO_INVENTORY, LATER);
    expect(findings.map((f) => f.rule_id)).toEqual(["SYN-EOL-node-24"]);
    expect(findings[0]!.title).toBe("Node.js 18/19/20/21/22/23/24 is end-of-life (declared in package.json)");
  });

  test(">=24 with an advisory unfixed on 24 is not a finding: newer lines are unchecked", () => {
    const unfixed24 = adv({ affected: [{ line: "24", events: [{ introduced: "24.0.0" }] }], fixed: [] });
    const { findings, notes } = run(dataset([unfixed24], fullNodeTable), [range(">=24")]);
    expect(findings).toEqual([]);
    expect(notes).toHaveLength(1);
  });

  test("a gap between listed lines is unchecked, never end-of-life", () => {
    const evenOnly = fullNodeTable.filter((entry) => Number(entry.cycle) % 2 === 0);
    expect(run(dataset([], evenOnly), [range(">=20 <22")], NO_INVENTORY, LATER).findings).toEqual([]);
  });

  test("an unbounded advisory span (no fix anywhere) covers the unlisted remainder", () => {
    const everywhere = adv({ affected: [{ events: [{ introduced: "0" }] }], fixed: [] });
    const { findings } = run(dataset([everywhere], fullNodeTable), [range(">=24")]);
    expect(findings.map((f) => [f.rule_id, f.confidence])).toEqual([["SYN-2026-100", "medium"]]);
  });

  test("an eol-kind advisory judges only the lines it reaches", () => {
    const node18 = adv({
      id: "SYN-2026-106",
      kind: "eol",
      title: "Node.js 18 end of life",
      affected: [{ line: "18", events: [{ introduced: "18.0.0" }, { limit: "19.0.0" }] }],
      fixed: [],
    });
    const { findings } = run(dataset([node18], fullNodeTable), [range(">=18 <21")], NO_INVENTORY, LATER);
    expect(findings.map((f) => f.title)).toEqual(["Node.js 18/19/20 is end-of-life (declared in package.json)"]);
  });

  test("x.0-only cycles leave unlisted gaps, so a .NET range across lines is not called end-of-life", () => {
    const cycles = [eol("dotnet", "6.0", "2024-11-12"), eol("dotnet", "7.0", "2024-05-14"), eol("dotnet", "8.0", "2026-11-10")];
    const declaration = decl({ subject: { type: "runtime", runtime: "dotnet" }, spec: ">=6.0 <8.1", precision: "range", resolved: undefined, file: "global.json" });
    expect(run(dataset([], cycles), [declaration], NO_INVENTORY, LATER).findings).toEqual([]);
  });
});

describe("exact versions the scheme cannot parse", () => {
  test("an unparseable exact version never gets an EOL finding", () => {
    const { findings, notes } = run(dataset([], [eol("node", "16", "2023-09-11")]), [decl({ spec: "16foo", resolved: "16foo" })]);
    expect(findings).toEqual([]);
    expect(notes).toHaveLength(1);
    expect(notes[0]).toContain("could not compare 16foo for Node.js");
  });

  test("notes clamp a long repository-controlled spec", () => {
    const long = `>=1 ${"x".repeat(300)}`;
    const { notes } = run(dataset([adv()], [eol("node", "22", "2027-04-30")]), [decl({ spec: long, precision: "range", resolved: undefined })]);
    expect(notes).toHaveLength(1);
    expect(notes[0]!.length).toBeLessThan(300);
  });
});

describe("span walk agrees with isAffected", () => {
  const cases: Array<[VersionScheme, SynvoyaAdvisory["affected"], string[]]> = [
    ["semver", [{ line: "22", events: [{ introduced: "22.0.0" }, { fixed: "22.12.0" }] }], ["21.9.9", "22.0.0", "22.11.9", "22.12.0", "22.12.0-rc.1", "23.0.0"]],
    ["semver", [{ events: [{ introduced: "0" }, { last_affected: "1.4.0" }, { introduced: "2.0.0" }, { fixed: "2.1.0" }] }], ["0.0.1", "1.4.0", "1.4.1", "2.0.0", "2.0.9", "2.1.0"]],
    ["java", [{ line: "1.8", events: [{ introduced: "8.0.0" }, { fixed: "1.8.0_401" }] }], ["1.8.0_400", "8u401", "8u400", "17.0.1", "1.8.0_402"]],
    ["php", [{ line: "8.1", events: [{ introduced: "8.1.0" }, { limit: "8.2.0" }] }], ["8.0.30", "8.1.0", "8.1.34", "8.2.0", "8.1.0RC1"]],
    ["magento", [{ line: "2.4.8", events: [{ introduced: "2.4.8" }, { fixed: "2.4.8-p3" }] }], ["2.4.7-p9", "2.4.8", "2.4.8-p2", "2.4.8-p3", "2.4.8-beta1", "2.4.9"]],
    ["go", [{ line: "1.22", events: [{ introduced: "1.22.0" }, { fixed: "1.22.7" }] }], ["1.22.0", "go1.22.6", "1.22.7", "1.23.0"]],
    // An OSV point range (malware versions): exactly that version.
    ["pep440", [{ events: [{ introduced: "1.82.7" }, { last_affected: "1.82.7" }] }, { events: [{ last_affected: "1.107.0" }, { introduced: "1.107.0" }] }], ["1.82.6", "1.82.7", "1.82.8", "1.106.2", "1.107.0", "1.107.1"]],
    // Contiguous intervals joined at one version: last_affected X then introduced X keeps the next one affected.
    ["semver", [{ events: [{ introduced: "1.0.0" }, { last_affected: "2.0.0" }, { introduced: "2.0.0" }, { fixed: "2.1.0" }] }], ["0.9.0", "1.5.0", "2.0.0", "2.0.5", "2.1.0"]],
  ];
  test.each(cases)("%s", (scheme, affected, versions) => {
    for (const version of versions) expect([version, spansAffect(scheme, version, affected)]).toEqual([version, isAffected(scheme, version, affected)]);
  });
});

describe("identity and output bounds", () => {
  test("the fingerprint is line-independent and equals the id", () => {
    const a = run(dataset([adv()]), [decl({ line: 1 })]).findings[0]!;
    const b = run(dataset([adv()]), [decl({ line: 9 })]).findings[0]!;
    expect(a.fingerprint).toBe(b.fingerprint);
    expect(a.id).toBe(a.fingerprint);
    expect(a.fingerprint).toBe(fingerprint(["synvoya", "SYN-2026-100", ".nvmrc", "runtime:node"]));
    const other = run(dataset([adv()]), [decl({ file: "web/.nvmrc" })]).findings[0]!;
    expect(other.fingerprint).not.toBe(a.fingerprint);
  });

  test("one finding per advisory, file and subject: the first by line wins", () => {
    const { findings } = run(dataset([adv()]), [
      decl({ file: "package.json", line: 30, spec: "22.2.0", resolved: "22.2.0" }),
      decl({ file: "package.json", line: 12, spec: "22.1.0", resolved: "22.1.0" }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.start_line).toBe(12);
  });

  test("notes are capped at 200 with a final '… N more' note", () => {
    const declarations = Array.from({ length: 250 }, (_, i) => decl({ file: `svc${i}/.nvmrc`, spec: "lts/*", precision: "unresolved", resolved: undefined }));
    const { notes } = run(dataset([adv()]), declarations);
    expect(notes).toHaveLength(200);
    expect(notes[199]).toBe("… 51 more");
  });
});

describe("cycleOf", () => {
  test.each([
    ["node", "22.11.0", "22"],
    ["node", "22", "22"],
    ["php", "8.3.12", "8.3"],
    ["php", "8", undefined],
    ["python", "3.12.4", "3.12"],
    ["ruby", "3.3.6", "3.3"],
    ["go", "1.22.5", "1.22"],
    ["go", "go1.23.0", "1.23"],
    ["dotnet", "8.0.11", "8.0"],
    ["dotnet", "8.0.404", "8.0"],
    ["java", "17.0.12", "17"],
    ["java", "1.8.0_401", "8"],
    ["java", "8u402", "8"],
    ["java", "21", "21"],
  ] as const)("%s %s → %s", (runtime, version, cycle) => {
    expect(cycleOf({ type: "runtime", runtime }, version)).toBe(cycle);
  });

  test("a service or product cycle is the longest matching cycle in the EOL table", () => {
    const table = [eol("mysql", "8.0", "2026-04-30"), eol("mysql", "8", "2030-01-01"), eol("postgres", "16", "2028-11-09")];
    expect(cycleOf({ type: "image-eol", product: "mysql" }, "8.0.39", table)).toBe("8.0");
    expect(cycleOf({ type: "image-eol", product: "postgres" }, "16.4", table)).toBe("16");
    expect(cycleOf({ type: "image-eol", product: "postgres" }, "15.4", table)).toBeUndefined();
  });
});

describe("evaluateSynvoya: unjudged declarations (rescan proof)", () => {
  test("reports, per file and producer, every declaration or package it could not judge", () => {
    const data = dataset([adv(), adv({ id: "SYN-2026-200", target: { type: "package", ecosystem: "npm", name: "lodash" }, affected: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }], fixed: ["4.17.21"] })], [eol("node", "16", "2023-09-11", "16.20.2")]);
    const result = evaluateSynvoya(
      data,
      [
        decl({ spec: "22.1.0_custom", resolved: "22.1.0_custom", file: ".nvmrc", producer: "runtime" }),
        decl({ spec: "22.1.0", resolved: "22.1.0", file: ".node-version", source: ".node-version", producer: "runtime" }),
        decl({ spec: "lts/*", precision: "unresolved", resolved: undefined, file: "Dockerfile", source: "Dockerfile FROM", producer: "images" }),
        decl({ spec: "abc || def", precision: "range", resolved: undefined, file: "package.json", source: "package.json engines.node", producer: "runtime" }),
      ],
      { packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4_x", file: "package-lock.json", line: 3, producer: "inventory:osv-scanner" }] },
      NOW,
      {},
    );
    expect(result.unjudged).toEqual([
      { file: ".nvmrc", producer: "runtime" },
      { file: "Dockerfile", producer: "images" },
      { file: "package.json", producer: "runtime" },
      { file: "package-lock.json", producer: "inventory:osv-scanner" },
    ]);
    // A judged declaration is not listed.
    expect(result.unjudged.some((entry) => entry.file === ".node-version")).toBe(false);
  });
});

