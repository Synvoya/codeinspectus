import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, test, vi } from "vitest";

import type { SarifLog } from "./sarif/types.js";

const trivyCalls = vi.hoisted(() => [] as string[][]);

function vulnerability(): unknown {
  return {
    ruleId: "CVE-2026-0001", ruleIndex: 0, level: "error",
    message: { text: "Package: lodash\nInstalled Version: 4.17.20\nVulnerability CVE-2026-0001\nSeverity: HIGH\nFixed Version: 9.9.9\nLink: [CVE-2026-0001](https://example.invalid)" },
    locations: [{ physicalLocation: { artifactLocation: { uri: "package-lock.json" }, region: { startLine: 10, endLine: 12 } } }],
  };
}

function licence(name: string, line: number): unknown {
  return {
    ruleId: `${name}:MIT`, ruleIndex: 1, level: "note",
    message: { text: `Artifact: package-lock.json\nLicense MIT\nPkgName: ${name}\n Classification: notice\n Path: package-lock.json` },
    locations: [{ physicalLocation: { artifactLocation: { uri: "package-lock.json" }, region: { startLine: line, endLine: line } } }],
  };
}

// Trivy is mocked (its invocation signature held constant, so only the licence rule can stop a rescan resolving): the licence results come back only when the `license` scanner was requested.
vi.mock("./engines/trivy.js", () => ({
  readTrivyDbDate: vi.fn(async () => undefined),
  runTrivy: vi.fn(async (_target: string, _tmp: string, scanners: string[]) => {
    trivyCalls.push([...scanners]);
    const results = [
      ...(scanners.includes("vuln") ? [vulnerability()] : []),
      ...(scanners.includes("license") ? [licence("handlebars", 3), licence("lodash", 5)] : []),
    ];
    return {
      engine: "trivy", version: "0.76.1", available: true, ran: true, durationMs: 1,
      componentSignatures: { "trivy:binary": "sha256:binary", "trivy:checks": "sha256:checks", "trivy:invocation": "sha256:invocation" },
      sarif: {
        version: "2.1.0",
        runs: [{
          tool: { driver: { name: "Trivy", rules: [
            { id: "CVE-2026-0001", name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security", "HIGH"] } },
            { id: "handlebars:MIT", name: "License", properties: { tags: ["license"] } },
          ] } },
          results,
        }],
      } as SarifLog,
    };
  }),
}));
const unavailable = (engine: string) => async () => ({ engine, version: "none", available: false, ran: false, durationMs: 0, note: "mocked off" });
vi.mock("./engines/opengrep.js", () => ({ runOpengrep: vi.fn(unavailable("opengrep")) }));
vi.mock("./engines/gitleaks.js", () => ({ runGitleaks: vi.fn(unavailable("gitleaks")) }));
vi.mock("./engines/osv-scanner.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./engines/osv-scanner.js")>()),
  runOsvScanner: vi.fn(async () => ({
    info: { engine: "osv-scanner", version: "none", available: false, ran: false, finding_count: 0, duration_ms: 0 },
    applicable: false, findings: [], coverage: [], lockfiles: [], packages: [], warnings: [], componentSignatures: {},
  })),
  runOsvScannerOnSbom: vi.fn(),
}));
vi.mock("./store.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./store.js")>()),
  saveScan: vi.fn(async () => undefined),
  getScan: vi.fn(async () => undefined),
  getLatestScanForTarget: vi.fn(async () => undefined),
}));

const { executeScan, scanIncludedLicenses } = await import("./scan.js");
const { runRescan } = await import("./rescan.js");
const { getScan } = await import("./store.js");
const { diffRescan } = await import("./rescan.js");
const { createJsonExport } = await import("./export/model.js");
const { buildComplianceReport } = await import("./compliance/report.js");

const NOTE = "Licence findings were not requested (use include_licenses / --licenses).";

async function repo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-licences-"));
  await writeFile(join(dir, "package-lock.json"), "{}\n", "utf8");
  return dir;
}

beforeEach(() => { trivyCalls.length = 0; });

describe("licence findings are opt-in", () => {
  test("default scan: Trivy is not asked for licences, no licence finding, an informational note", async () => {
    const { canonical } = await executeScan({ path: await repo() }, { persist: false });

    expect(trivyCalls[0]).not.toContain("license");
    expect(canonical.findings.filter((finding) => finding.finding_kind === "license")).toEqual([]);
    // The surviving finding keeps its 3.x fingerprint.
    expect(canonical.findings.map((finding) => [finding.rule_id, finding.finding_kind, finding.fingerprint])).toEqual([GOLDEN_3X[0]]);
    expect(canonical.coverage_notes).toContainEqual({ component: "scanner:license", detail: NOTE });
    expect(canonical.scan_config?.include_licenses).toBe(false);
  });

  test("the note never lowers aggregate coverage", async () => {
    const { canonical } = await executeScan({ path: await repo() }, { persist: false });
    const { coverage } = createJsonExport({ ...canonical, storage_schema_version: "2.0.0", canonical_findings: true });

    expect(coverage.evidence).toContainEqual(expect.objectContaining({ component: "scanner:license", state: "informational", detail: NOTE }));
    expect(coverage.evidence.filter((item) => item.component === "scanner:license" && item.state !== "informational")).toEqual([]);
  });

  test("include_licenses: true asks Trivy for licences and matches the 3.x output", async () => {
    const { canonical } = await executeScan({ path: await repo(), include_licenses: true }, { persist: false });

    expect(trivyCalls[0]).toEqual(["vuln", "misconfig", "secret", "license"]);
    // Fingerprints captured from the 3.x default scan (licences always on) of the same mocked Trivy output.
    expect(canonical.findings.map((finding) => [finding.rule_id, finding.finding_kind, finding.fingerprint])).toEqual(GOLDEN_3X);
    expect(canonical.coverage_notes?.some((note) => note.component === "scanner:license") ?? false).toBe(false);
    expect(canonical.scan_config?.include_licenses).toBe(true);
  });

  test("an explicit license scanner is itself the opt-in", async () => {
    const { canonical } = await executeScan({ path: await repo(), scanners: ["license"] }, { persist: false });

    expect(trivyCalls[0]).toEqual(["license"]);
    expect(canonical.findings.every((finding) => finding.finding_kind === "license")).toBe(true);
    expect(canonical.findings.length).toBe(2);
  });

  test("a scanner filter without license adds no licence note", async () => {
    const { canonical } = await executeScan({ path: await repo(), scanners: ["vuln"] }, { persist: false });

    expect(canonical.coverage_notes?.some((note) => note.component === "scanner:license") ?? false).toBe(false);
  });
});

describe("rescan with licences", () => {
  test("licence findings from a prior scan are not_rechecked, never resolved, when the new scan has none", async () => {
    const path = await repo();
    const prior = (await executeScan({ path, include_licenses: true }, { persist: false })).canonical;
    const fresh = (await executeScan({ path }, { persist: false })).canonical;
    const diff = diffRescan(prior, fresh);

    expect(diff.resolved).toEqual([]);
    expect(diff.not_rechecked.map((finding) => finding.finding_kind)).toEqual(["license", "license"]);
    expect(diff.not_rechecked_note).toMatch(/licence findings were not requested/i);
    expect(diff.remaining.map((finding) => finding.rule_id)).toEqual(["CVE-2026-0001"]);
  });

  test("a licence finding that really vanished with licences on is still resolved", async () => {
    const path = await repo();
    const prior = (await executeScan({ path, include_licenses: true }, { persist: false })).canonical;
    const fresh = (await executeScan({ path, include_licenses: true }, { persist: false })).canonical;
    fresh.findings = fresh.findings.filter((finding) => finding.finding_kind !== "license");

    const diff = diffRescan(prior, fresh);
    expect(diff.resolved.map((finding) => finding.finding_kind)).toEqual(["license", "license"]);
  });
});

describe("a rescan follows the prior scan's licence setting", () => {
  test("a prior scan with licences is rescanned with licences, so its licence findings stay remaining", async () => {
    const path = await repo();
    const prior = (await executeScan({ path, include_licenses: true }, { persist: false })).canonical;
    vi.mocked(getScan).mockResolvedValue({ ...prior, storage_schema_version: "2.0.0", canonical_findings: true });
    trivyCalls.length = 0;

    const rescan = await runRescan({ path, prior_scan_id: prior.scan_id });

    expect(trivyCalls[0]).toContain("license");
    expect(rescan.remaining.map((finding) => finding.finding_kind).sort()).toEqual(["license", "license", "vulnerability"]);
    expect(rescan.summary).toMatchObject({ resolved: 0, not_rechecked: 0, introduced: 0 });
  });

  test("a prior scan without licences is rescanned without them", async () => {
    const path = await repo();
    const prior = (await executeScan({ path }, { persist: false })).canonical;
    vi.mocked(getScan).mockResolvedValue({ ...prior, storage_schema_version: "2.0.0", canonical_findings: true });
    trivyCalls.length = 0;

    const rescan = await runRescan({ path, prior_scan_id: prior.scan_id });

    expect(trivyCalls[0]).not.toContain("license");
    expect(rescan.introduced).toEqual([]);
  });

  test("scans stored before 4.0 ran licences unless their scanner filter left them out", () => {
    expect(scanIncludedLicenses({})).toBe(true);
    expect(scanIncludedLicenses({ scan_config: { max_findings: 200 } })).toBe(true);
    expect(scanIncludedLicenses({ scan_config: { scanners: ["vuln", "license"], max_findings: 200 } })).toBe(true);
    expect(scanIncludedLicenses({ scan_config: { scanners: ["vuln"], max_findings: 200 } })).toBe(false);
    expect(scanIncludedLicenses({ scan_config: { scanners: ["vuln", "license"], max_findings: 200, include_licenses: false } })).toBe(false);
  });
});

describe("compliance with licences off", () => {
  test("the compliance report and export carry no licence evidence and keep the note", async () => {
    const path = await repo();
    const off = (await executeScan({ path }, { persist: false })).canonical;
    const on = (await executeScan({ path, include_licenses: true }, { persist: false })).canonical;
    const stored = (scan: typeof off) => ({ ...scan, storage_schema_version: "2.0.0" as const, canonical_findings: true as const });

    vi.mocked(getScan).mockResolvedValue(stored(off));
    const offReport = await buildComplianceReport({ scan_id: off.scan_id });
    vi.mocked(getScan).mockResolvedValue(stored(on));
    const onReport = await buildComplianceReport({ scan_id: on.scan_id });

    expect(offReport.coverage_notes).toEqual([{ component: "scanner:license", detail: NOTE }]);
    expect(onReport.coverage_notes).toBeUndefined();
    // The only difference between the two reports' controls is licence evidence, which the off scan has none of.
    const licenceTags = on.findings.filter((finding) => finding.finding_kind === "license");
    expect(licenceTags.length).toBe(2);
    const exported = createJsonExport(stored(off));
    expect(exported.findings.some((finding) => finding.finding_kind === "license")).toBe(false);
    expect(exported.coverage.evidence).toContainEqual(expect.objectContaining({ component: "scanner:license", state: "informational", detail: NOTE }));
    // (The mocked engines here read partial either way; the choice itself must not change that.)
    expect(exported.coverage.aggregate).toBe(createJsonExport(stored(on)).coverage.aggregate);
  });
});

const GOLDEN_3X: Array<[string, string, string]> = [
  ["CVE-2026-0001", "vulnerability", "sha256:aab218eb1e8b08b6295d32164b2e5ece0e4d82a25e4907d2da3132ae8c374413"],
  ["handlebars:MIT", "license", "sha256:d26d10fef7805cf39cb61cc085e37bc8c8be1780f695149d6ebaa6d181f4940d"],
  ["lodash:MIT", "license", "sha256:c4634dc7609be7d6dc5edcc3d4acf8f909063ed401930cbde00d64a9a7bafce4"],
];
