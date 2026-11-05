/**
 * The Synvoya gap layer in the scan envelope: engine row, findings, enrichment of upstream findings,
 * coverage notes, dataset failure and rescan. Trivy and osv-scanner are mocked (no binary runs, nothing
 * under ~/.codeinspectus is touched); the Synvoya dataset, readers, evaluator, routing and dedup are real.
 */
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OsvScanResult } from "./engines/osv-scanner.js";
import type { Finding, ScanResult } from "./types.js";

const fault = vi.hoisted(() => ({
  reason: undefined as string | undefined,
  dir: undefined as string | undefined,
  deadlineMs: 30_000,
  rejectReader: "" as "" | "images" | "runtime" | "libraries" | "actions",
  trivyPackages: [] as unknown[],
  trivyResults: [] as unknown[],
  /** The OSV GitHub Actions database these tests see: none (never the developer's installed one) unless a test sets it. */
  actionsDb: undefined as { zipPath: string; record: unknown } | undefined,
}));

vi.mock("./engines/trivy.js", () => ({
  runTrivy: vi.fn(async () => ({
    engine: "trivy",
    version: "0.76.1",
    available: true,
    ran: true,
    durationMs: 1,
    sarif: { version: "2.1.0", runs: fault.trivyResults.length ? [{ tool: { driver: { name: "Trivy", rules: [{ id: "CVE-2024-20758", name: "LanguageSpecificPackageVulnerability", shortDescription: { text: "Magento Open Source allows Improper Input Validation" }, properties: { tags: ["vulnerability", "security", "HIGH"], "security-severity": "9.1" } }, { id: "CVE-2025-47110", name: "LanguageSpecificPackageVulnerability", shortDescription: { text: "Magneto contains stored XSS vulnerability" }, properties: { tags: ["vulnerability", "security", "CRITICAL"], "security-severity": "9.1" } }] } }, results: fault.trivyResults }] : [] },
    packages: fault.trivyPackages,
  })),
  readTrivyDbDate: vi.fn(async () => undefined),
}));
vi.mock("./engines/osv-scanner.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./engines/osv-scanner.js")>()),
  runOsvScanner: vi.fn(),
  runOsvScannerOnSbom: vi.fn(),
}));
vi.mock("./synvoya/constants.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./synvoya/constants.js")>()),
  get SYNVOYA_READER_DEADLINE_MS() {
    return fault.deadlineMs;
  },
}));
vi.mock("./synvoya/actions-matcher.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./synvoya/actions-matcher.js")>();
  return {
    ...actual,
    loadActionsDb: () => actual.loadActionsDb({
      zipPath: fault.actionsDb?.zipPath ?? join(tmpdir(), "codeinspectus-no-actions-db", "all.zip"),
      readRecord: async () => fault.actionsDb?.record as never,
    }),
  };
});
vi.mock("./store.js", () => ({ saveScan: vi.fn(async () => undefined), getScan: vi.fn(async () => undefined) }));
vi.mock("./synvoya/readers/images.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./synvoya/readers/images.js")>();
  return {
    ...actual,
    readImageTags: (...args: Parameters<typeof actual.readImageTags>) =>
      fault.rejectReader === "images" ? Promise.reject(new Error("injected")) : actual.readImageTags(...args),
  };
});
vi.mock("./synvoya/readers/runtime.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./synvoya/readers/runtime.js")>();
  return {
    ...actual,
    readRuntimePins: (...args: Parameters<typeof actual.readRuntimePins>) =>
      fault.rejectReader === "runtime" ? Promise.reject(new Error("injected")) : actual.readRuntimePins(...args),
  };
});
vi.mock("./synvoya/readers/libraries.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./synvoya/readers/libraries.js")>();
  return {
    ...actual,
    readLibraries: (...args: Parameters<typeof actual.readLibraries>) =>
      fault.rejectReader === "libraries" ? Promise.reject(new Error("injected")) : actual.readLibraries(...args),
  };
});
vi.mock("./synvoya/readers/actions.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./synvoya/readers/actions.js")>();
  return {
    ...actual,
    readActionReferences: (...args: Parameters<typeof actual.readActionReferences>) =>
      fault.rejectReader === "actions" ? Promise.reject(new Error("injected")) : actual.readActionReferences(...args),
  };
});
vi.mock("./synvoya/dataset.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./synvoya/dataset.js")>();
  return {
    ...actual,
    loadSynvoyaDataset: vi.fn(async (dir?: string) =>
      // The fixture-grade dataset these orchestration tests were written against, unless a test supplies one.
      fault.reason ? { ok: false as const, reason: fault.reason } : actual.loadSynvoyaDataset(fault.dir ?? dir ?? TEST_DATASET),
    ),
  };
});

const { executeScan } = await import("./scan.js");
const { writeActionsFixtureDb } = await import("./synvoya/actions-osv-fixture.js");
const { scanResultSchema } = await import("./schemas.js");
const { runOsvScanner, runOsvScannerOnSbom } = await import("./engines/osv-scanner.js");
const { osvSbomFindingComponents, osvScannerFindingComponents } = await import("./provenance.js");
const { fingerprint: makeFingerprint } = await import("./util/hash.js");
const { assessAggregateCoverage } = await import("./export/model.js");
const { diffRescan } = await import("./rescan.js");
const { summarizeScan } = await import("./summarize.js");
const { sha256Hex } = await import("./util/hash.js");
const { getScan } = await import("./store.js");
const { buildComplianceReport } = await import("./compliance/report.js");

/** Fixture-grade dataset (node 20 < 20.18.1, PHP 8.0 EOL, ...) kept apart from the shipped seed. */
const TEST_DATASET = join(process.cwd(), "fixtures", "synvoya", "dataset");
const roots: string[] = [];
const workflowWith = (job: string) => `on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n${job}    steps:\n      - run: echo\n`;

async function project(files: Record<string, string>): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "ci-synvoya-int-")));
  roots.push(root);
  for (const [name, content] of Object.entries(files)) {
    await mkdir(join(root, ...name.split("/").slice(0, -1)), { recursive: true });
    await writeFile(join(root, ...name.split("/")), content, "utf8");
  }
  return root;
}

/** A copy of the bundled dataset with extra advisories and alias tables, re-digested. */
async function datasetWith(extra: unknown[], aliases?: Record<string, unknown>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-int-dataset-"));
  roots.push(dir);
  await cp(TEST_DATASET, dir, { recursive: true });
  const manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as { files: Record<string, string> };
  const file = JSON.parse(await readFile(join(dir, "advisories.json"), "utf8")) as { advisories: unknown[] };
  file.advisories.push(...extra);
  const text = `${JSON.stringify(file, null, 2)}\n`;
  await writeFile(join(dir, "advisories.json"), text);
  manifest.files["advisories.json"] = `sha256:${sha256Hex(text)}`;
  if (aliases) {
    const table = { ...(JSON.parse(await readFile(join(dir, "aliases.json"), "utf8")) as object), ...aliases };
    const aliasText = `${JSON.stringify(table, null, 2)}\n`;
    await writeFile(join(dir, "aliases.json"), aliasText);
    manifest.files["aliases.json"] = `sha256:${sha256Hex(aliasText)}`;
  }
  await writeFile(join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return dir;
}

async function datasetWithLodash(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-int-dataset-"));
  roots.push(dir);
  await cp(TEST_DATASET, dir, { recursive: true });
  const file = JSON.parse(await readFile(join(dir, "advisories.json"), "utf8")) as { advisories: unknown[] };
  file.advisories.push({
    id: "SYN-2026-900",
    slug: "lodash-test-gap",
    title: "lodash before 4.17.21 is affected by a test gap",
    kind: "vulnerability",
    aliases: ["CVE-2026-1000"],
    target: { type: "package", ecosystem: "npm", name: "lodash" },
    affected: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    fixed: ["4.17.21"],
    severity: "critical",
    exploited: false,
    remediation_steps: ["Upgrade lodash to 4.17.21 or later."],
    sources: ["https://example.com/lodash-advisory"],
    status: "active",
    provisional: false,
  });
  const text = `${JSON.stringify(file, null, 2)}\n`;
  await writeFile(join(dir, "advisories.json"), text);
  const manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as { files: Record<string, string> };
  manifest.files["advisories.json"] = `sha256:${sha256Hex(text)}`;
  await writeFile(join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return dir;
}

function osvResult(over: Partial<OsvScanResult> = {}): OsvScanResult {
  return {
    info: { engine: "osv-scanner", version: "2.7.0", available: true, ran: true, finding_count: 0, duration_ms: 1 },
    applicable: true,
    findings: [],
    coverage: [],
    lockfiles: [],
    componentSignatures: {},
    warnings: [],
    ...over,
  };
}

function lodashFinding(): Finding {
  const fingerprint = "sha256:osv-lodash-4.17.4-CVE-2026-1000";
  return {
    id: fingerprint,
    fingerprint,
    title: "Prototype pollution in lodash (lodash@4.17.4)",
    severity: "high",
    engine: "osv-scanner",
    engines: ["osv-scanner"],
    rule_id: "CVE-2026-1000",
    vulnerability_aliases: ["GHSA-aaaa-bbbb-cccc"],
    cwe: ["CWE-1395"],
    owasp_web: ["A06:2021"],
    location: { file: "package-lock.json", start_line: 5, end_line: 5 },
    message: "package-lock.json resolves npm package lodash@4.17.4.",
    remediation: { summary: "Upgrade lodash to a fixed version.", steps: ["Upgrade lodash to a fixed version."], references: ["https://osv.dev/CVE-2026-1000"] },
    frameworks: [],
    confidence: "high",
    producer_components: osvScannerFindingComponents("npm"),
    finding_kind: "vulnerability",
    package: { ecosystem: "npm", name: "lodash", version: "4.17.4" },
  };
}

const PACKAGE_LOCK = '{\n  "name": "app",\n  "lockfileVersion": 3,\n  "packages": {\n    "node_modules/lodash": {\n      "version": "4.17.4"\n    }\n  }\n}\n';

async function scan(path: string, scanners: Array<"vuln" | "misconfig"> = ["vuln"]): Promise<ScanResult> {
  return (await executeScan({ path, scanners }, { persist: false })).canonical;
}

function aggregate(result: ScanResult): string {
  return assessAggregateCoverage({ ...result, canonical_findings: true, storage_schema_version: "2.0.0" }).aggregate;
}

/** Coverage evidence the Synvoya layer contributes (a vuln-only scan is partial anyway: other scanners are excluded). */
function synvoyaEvidence(result: ScanResult): Array<{ component: string; state: string }> {
  return assessAggregateCoverage({ ...result, canonical_findings: true, storage_schema_version: "2.0.0" }).evidence
    .filter((item) => item.component.includes("synvoya") || /synvoya/i.test(item.detail))
    .map((item) => ({ component: item.component, state: item.state }));
}

const synvoyaRow = (result: ScanResult) => result.engine_details.find((engine) => engine.engine === "synvoya");

beforeEach(() => {
  fault.reason = undefined;
  fault.dir = undefined;
  fault.deadlineMs = 30_000;
  fault.rejectReader = "";
  fault.trivyPackages = [];
  fault.trivyResults = [];
  fault.actionsDb = undefined;
  vi.mocked(runOsvScanner).mockReset();
  vi.mocked(runOsvScanner).mockResolvedValue(osvResult());
});

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("scan orchestrator Synvoya gap layer", () => {
  it("runs in a vulnerability scan: engine row, family finding, dataset signature, schema-valid envelope", async () => {
    const result = await scan(await project({ ".nvmrc": "20.1.0\n" }));

    expect(scanResultSchema.safeParse(result).success).toBe(true);
    const row = synvoyaRow(result);
    expect(row).toMatchObject({ engine: "synvoya", available: true, ran: true, finding_count: 1 });
    expect(row?.version).toMatch(/^\d{4}\.\d{2}\.\d{2}\.\d+$/);
    expect(result.engines_run).toContain(`synvoya@${row?.version}`);
    const finding = result.findings.find((candidate) => candidate.engine === "synvoya");
    expect(finding).toMatchObject({ rule_id: "SYN-2026-001", engine_family: "synvoya", location: { file: ".nvmrc", start_line: 1 } });
    expect(result.component_signatures?.["synvoya:dataset"]).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(synvoyaEvidence(result)).toEqual([{ component: "engine:synvoya", state: "covered" }]);
  });

  it("does not run when vuln is not requested", async () => {
    const result = await scan(await project({ ".nvmrc": "20.1.0\n" }), ["misconfig"]);
    expect(synvoyaRow(result)).toBeUndefined();
    expect(result.findings.some((finding) => finding.engine === "synvoya")).toBe(false);
    expect(result.component_signatures?.["synvoya:dataset"]).toBeUndefined();
  });

  it("a dataset failure is an unavailable engine row, a scan warning and partial coverage", async () => {
    fault.reason = "advisories.json does not match the SHA-256 digest in manifest.json.";
    const result = await scan(await project({ ".nvmrc": "20.1.0\n" }));

    expect(scanResultSchema.safeParse(result).success).toBe(true);
    expect(synvoyaRow(result)).toMatchObject({
      engine: "synvoya",
      available: false,
      ran: false,
      note: `Synvoya gap advisories unavailable: ${fault.reason}`,
    });
    expect(result.warnings).toContain(`Synvoya gap advisories unavailable: ${fault.reason}`);
    expect(result.findings.some((finding) => finding.engine === "synvoya")).toBe(false);
    expect(synvoyaEvidence(result)).toEqual([
      { component: "engine:synvoya", state: "unknown" },
      { component: "scan-pipeline", state: "partial" },
    ]);
    expect(aggregate(result)).toBe("partial");
    // The summary row states the state once, then the reason.
    expect(summarizeScan(result)).toContain(`Synvoya gap advisories: synvoya@unknown unavailable, 0 finding(s) — ${fault.reason}`);
  });

  it("enriches the upstream finding with Synvoya's fix and drops the duplicate; the upstream finding is otherwise untouched", async () => {
    fault.dir = await datasetWithLodash();
    const upstream = lodashFinding();
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({
      findings: [structuredClone(upstream)],
      lockfiles: ["package-lock.json"],
      packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json" }],
    }));
    const result = await scan(await project({ "package-lock.json": PACKAGE_LOCK }));

    expect(result.findings.some((finding) => finding.engine === "synvoya")).toBe(false);
    const kept = result.findings.find((finding) => finding.engine === "osv-scanner");
    expect(kept).toBeDefined();
    expect(kept!.fingerprint).toBe(upstream.fingerprint);
    expect(kept!.producer_components).toEqual(upstream.producer_components);
    expect(kept!.engines).toEqual(["osv-scanner"]);
    expect(kept!.severity).toBe("high");
    expect(kept!.title).toBe(upstream.title);
    expect(kept!.engine_family).toBeUndefined();
    expect(kept!.remediation.summary).toBe(upstream.remediation.summary);
    expect(kept!.remediation.steps).toEqual([
      "Upgrade lodash to a fixed version.",
      "Synvoya SYN-2026-900: Upgrade lodash to 4.17.21 or later, or remove the package.",
      "Upgrade lodash to 4.17.21 or later.",
    ]);
    expect(synvoyaRow(result)).toMatchObject({ ran: true, finding_count: 0 });
    expect(synvoyaRow(result)?.note).toContain("1 matching upstream finding(s) gained its fix");
  });

  it("a Synvoya package finding with no upstream match stands alone", async () => {
    fault.dir = await datasetWithLodash();
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({
      lockfiles: ["package-lock.json"],
      packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json" }],
    }));
    const result = await scan(await project({ "package-lock.json": PACKAGE_LOCK }));
    const finding = result.findings.find((candidate) => candidate.engine === "synvoya");
    expect(finding).toMatchObject({ rule_id: "SYN-2026-900", severity: "critical", location: { file: "package-lock.json", start_line: 5 } });
    expect(synvoyaRow(result)).toMatchObject({ finding_count: 1 });
  });

  it("the engine row counts Synvoya findings as shown, after dedup", async () => {
    const lodash = (id: string) => ({
      id,
      slug: `lodash-gap-${id.slice(-3)}`,
      title: `lodash test gap ${id}`,
      kind: "vulnerability",
      aliases: ["CVE-2026-1000"],
      target: { type: "package", ecosystem: "npm", name: "lodash" },
      affected: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      fixed: ["4.17.21"],
      severity: "high",
      exploited: false,
      remediation_steps: ["Upgrade lodash to 4.17.21 or later."],
      sources: ["https://example.com/lodash-advisory"],
      status: "active",
      provisional: false,
    });
    fault.dir = await datasetWith([lodash("SYN-2026-900"), lodash("SYN-2026-901")]);
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({
      lockfiles: ["package-lock.json"],
      packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json" }],
    }));
    const result = await scan(await project({ "package-lock.json": PACKAGE_LOCK }));
    // Same package, same file, same CVE: package-aware dedup shows one finding, and the row says so.
    const shown = result.findings.filter((finding) => finding.engines.includes("synvoya"));
    expect(shown).toHaveLength(1);
    expect(synvoyaRow(result)).toMatchObject({ finding_count: 1 });
  });

  it("compliance report: runtime and end-of-life Synvoya findings count toward the patch-management controls", async () => {
    const result = await scan(await project({ ".nvmrc": "20.1.0\n", Dockerfile: "FROM php:8.0.30-fpm\n" }));
    const synvoya = result.findings.filter((finding) => finding.engine === "synvoya");
    expect(synvoya.map((finding) => [finding.rule_id, finding.cwe])).toEqual(expect.arrayContaining([
      ["SYN-2026-001", ["CWE-1104"]],
      ["SYN-EOL-php-8.0", ["CWE-1104"]],
    ]));
    for (const finding of synvoya) expect(finding.frameworks.length).toBeGreaterThan(0);
    vi.mocked(getScan).mockResolvedValueOnce({ ...result, scan_id: "synvoya-compliance" } as Awaited<ReturnType<typeof getScan>>);
    const report = await buildComplianceReport({ scan_id: "synvoya-compliance" });
    const control = (framework: string, id: string) =>
      report.frameworks.find((entry) => entry.framework === framework)?.controls.find((entry) => entry.id === id);
    expect(control("EssentialEight", "PatchApplications")).toMatchObject({ findings: synvoya.length, status: "gap" });
    expect(control("ISO27001:2022", "A.8.8")).toMatchObject({ findings: synvoya.length, status: "gap" });
  });

  it("repository text in Synvoya notes and titles passes the credential scrub", async () => {
    const token = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2";
    const result = await scan(await project({
      "docker-compose.yml": `services:\n  db:\n    image: node:${token}\n`,
      ".nvmrc": "20.1.0\n",
    }));
    const notes = (result.coverage_notes ?? []).filter((note) => note.component === "engine:synvoya").map((note) => note.detail);
    expect(notes.some((note) => note.includes("docker-compose.yml:3"))).toBe(true);
    const text = JSON.stringify([notes, result.findings.map((finding) => [finding.title, finding.message]), summarizeScan(result)]);
    expect(text).not.toContain(token);
  });

  it("carries Synvoya notes as engine:synvoya coverage notes and shows the row and notes in the summary", async () => {
    const result = await scan(await project({ ".nvmrc": "lts/*\n" }));
    const notes = (result.coverage_notes ?? []).filter((note) => note.component === "engine:synvoya");
    expect(notes.length).toBeGreaterThan(0);
    expect(notes.some((note) => note.detail.includes(".nvmrc"))).toBe(true);
    // Runtime inputs never lower coverage (design §8.5): the notes are informational only.
    expect(synvoyaEvidence(result).filter((item) => item.state !== "covered" && item.state !== "informational")).toEqual([]);

    const text = summarizeScan(result);
    expect(text).toContain(`Synvoya gap advisories: synvoya@${synvoyaRow(result)?.version} ran`);
    expect(text).toContain(notes[0]!.detail);
  });

  it("rescan of an unchanged repository reports the Synvoya finding unchanged; an unavailable dataset never resolves it", async () => {
    const target = await project({ ".nvmrc": "20.1.0\n" });
    const prior = await scan(target);
    const fresh = await scan(target);
    const unchanged = diffRescan(prior, fresh);
    const synvoya = (findings: Finding[]) => findings.filter((finding) => finding.engine === "synvoya").map((finding) => finding.rule_id);
    expect(synvoya(unchanged.remaining)).toEqual(["SYN-2026-001"]);
    expect(synvoya(unchanged.resolved)).toEqual([]);
    expect(synvoya(unchanged.introduced)).toEqual([]);

    fault.reason = "manifest.json is missing or unreadable.";
    const unavailable = diffRescan(prior, await scan(target));
    expect(synvoya(unavailable.resolved)).toEqual([]);
    expect(synvoya(unavailable.not_rechecked)).toEqual(["SYN-2026-001"]);
    expect(unavailable.not_rechecked_note).toContain("synvoya did not run in the rescan");
  });
  it("rescan after the reader deadline expired never resolves findings in files Synvoya did not read", async () => {
    const target = await project({ ".nvmrc": "20.1.0\n" });
    const prior = await scan(target);
    fault.deadlineMs = 0;
    const fresh = await scan(target);
    expect(synvoyaRow(fresh)).toMatchObject({ ran: true });
    expect(fresh.findings.some((finding) => finding.engine === "synvoya")).toBe(false);
    expect(fresh.synvoya_checked).toEqual({ "inventory:osv-scanner": [], "inventory:trivy": [] });
    // The deadline hit is partial coverage evidence, never only an informational note.
    expect(synvoyaEvidence(fresh)).toContainEqual({ component: "scan-pipeline", state: "partial" });
    expect(synvoyaEvidence(prior)).not.toContainEqual({ component: "scan-pipeline", state: "partial" });

    const diff = diffRescan(prior, fresh);
    const synvoya = (findings: Finding[]) => findings.filter((finding) => finding.engine === "synvoya").map((finding) => finding.rule_id);
    expect(synvoya(diff.resolved)).toEqual([]);
    expect(synvoya(diff.not_rechecked)).toEqual(["SYN-2026-001"]);
    expect(diff.not_rechecked_note).toContain("the Synvoya gap layer did not fully re-check this finding's file in the rescan");
  });

  it("a fixed declaration in a file Synvoya read is resolved", async () => {
    const target = await project({ ".nvmrc": "20.1.0\n" });
    const prior = await scan(target);
    await writeFile(join(target, ".nvmrc"), "20.18.1\n", "utf8");
    const fresh = await scan(target);
    expect(fresh.synvoya_checked).toEqual({ runtime: [".nvmrc"], images: [], products: [], "inventory:osv-scanner": [], "inventory:trivy": [], vendored: [], "sbom:osv-scanner": [], actions: [] });
    const diff = diffRescan(prior, fresh);
    expect(diff.resolved.filter((finding) => finding.engine === "synvoya").map((finding) => finding.rule_id)).toEqual(["SYN-2026-001"]);
  });

  it("keeps the checked-file list in the stored scan only, not in the displayed result", async () => {
    const execution = await executeScan({ path: await project({ ".nvmrc": "20.1.0\n" }), scanners: ["vuln"] }, { persist: false });
    expect(execution.canonical.synvoya_checked).toEqual({ runtime: [".nvmrc"], images: [], products: [], "inventory:osv-scanner": [], "inventory:trivy": [], vendored: [], "sbom:osv-scanner": [], actions: [] });
    expect(execution.display).not.toHaveProperty("synvoya_checked");
  });

  it("a Synvoya finding in lockfile A stays remaining when upstream starts reporting the advisory only in lockfile B", async () => {
    fault.dir = await datasetWithLodash();
    const target = await project({ "package-lock.json": PACKAGE_LOCK });
    await mkdir(join(target, "app"));
    await writeFile(join(target, "app", "package-lock.json"), PACKAGE_LOCK, "utf8");
    const packages = [
      { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json" },
      { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "app/package-lock.json" },
    ];
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({ lockfiles: ["app/package-lock.json", "package-lock.json"], packages }));
    const prior = await scan(target);
    const inA = (findings: Finding[]) =>
      findings.filter((finding) => finding.engine === "synvoya" && finding.location.file === "package-lock.json").map((finding) => finding.rule_id);
    expect(inA(prior.findings)).toEqual(["SYN-2026-900"]);

    const upstreamInB = { ...lodashFinding(), location: { file: "app/package-lock.json", start_line: 5, end_line: 5 } };
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({ findings: [upstreamInB], lockfiles: ["app/package-lock.json", "package-lock.json"], packages }));
    const fresh = await scan(target);
    // B's Synvoya duplicate was folded into the upstream finding; A's still stands.
    expect(inA(fresh.findings)).toEqual(["SYN-2026-900"]);
    expect(fresh.findings.filter((finding) => finding.engine === "synvoya" && finding.location.file === "app/package-lock.json")).toEqual([]);

    const diff = diffRescan(prior, fresh);
    expect(inA(diff.remaining)).toEqual(["SYN-2026-900"]);
    expect(inA(diff.resolved)).toEqual([]);
  });
  it("a declaration finding in a file only the inventory listed this time is not resolved (shared composer.lock)", async () => {
    const composer = `${JSON.stringify({
      packages: [{ name: "magento/framework", version: "103.0.7" }, { name: "monolog/monolog", version: "2.0.0" }],
      platform: { php: "8.0.30" },
    }, null, 1)}\n`;
    const target = await project({ "composer.lock": composer });
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({
      lockfiles: ["composer.lock"],
      packages: [{ ecosystem: "Packagist", name: "monolog/monolog", version: "2.0.0", file: "composer.lock" }],
    }));
    const prior = await scan(target);
    const eol = (findings: Finding[]) => findings.filter((finding) => finding.engine === "synvoya").map((finding) => `${finding.rule_id}@${finding.location.file}`);
    expect(eol(prior.findings)).toEqual(["SYN-EOL-php-8.0@composer.lock"]);

    fault.deadlineMs = 0;
    const fresh = await scan(target);
    expect(fresh.synvoya_checked).toEqual({ "inventory:osv-scanner": ["composer.lock"], "inventory:trivy": [] });
    const diff = diffRescan(prior, fresh);
    expect(eol(diff.resolved)).toEqual([]);
    expect(eol(diff.not_rechecked)).toEqual(["SYN-EOL-php-8.0@composer.lock"]);
  });

  it("a declaration pushed past a per-file cap is not resolved: the capped file was not fully re-checked", async () => {
    const target = await project({ ".tool-versions": "nodejs 20.1.0\n" });
    const prior = await scan(target);
    const tool = (findings: Finding[]) => findings.filter((finding) => finding.engine === "synvoya").map((finding) => `${finding.rule_id}@${finding.location.file}`);
    expect(tool(prior.findings)).toEqual(["SYN-2026-001@.tool-versions"]);

    await writeFile(join(target, ".tool-versions"), `${"python 3.12.4\n".repeat(70)}nodejs 20.1.0\n`, "utf8");
    const fresh = await scan(target);
    expect(fresh.synvoya_checked?.runtime).toEqual([]);
    const diff = diffRescan(prior, fresh);
    expect(tool(diff.resolved)).toEqual([]);
    expect(tool(diff.not_rechecked)).toEqual(["SYN-2026-001@.tool-versions"]);
  });

  it("a package finding is checked against the inventory lockfiles, not the declaration files", async () => {
    fault.dir = await datasetWithLodash();
    const target = await project({ "package-lock.json": PACKAGE_LOCK });
    const packages = [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json" }];
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({ lockfiles: ["package-lock.json"], packages }));
    const prior = await scan(target);
    const pkg = (findings: Finding[]) => findings.filter((finding) => finding.engine === "synvoya").map((finding) => finding.rule_id);
    expect(pkg(prior.findings)).toEqual(["SYN-2026-900"]);

    // osv-scanner did not list the lockfile this time: nothing re-checked it.
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult());
    const missing = diffRescan(prior, await scan(target));
    expect(pkg(missing.resolved)).toEqual([]);
    expect(pkg(missing.not_rechecked)).toEqual(["SYN-2026-900"]);

    // Upgraded and listed again: a real, provable fix.
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({ lockfiles: ["package-lock.json"], packages: [{ ...packages[0]!, version: "4.17.21" }] }));
    const fixed = diffRescan(prior, await scan(target));
    expect(pkg(fixed.resolved)).toEqual(["SYN-2026-900"]);
  });
  describe("per-producer re-check (rescan confirms a fix only from the producer that made the finding)", () => {
    const tagged = (findings: Finding[]) =>
      findings.filter((finding) => finding.engines.includes("synvoya")).map((finding) => `${finding.rule_id}@${finding.location.file}`);

    it("records the producer on each Synvoya finding", async () => {
      const result = await scan(await project({ ".nvmrc": "20.1.0\n", "Dockerfile": "FROM php:8.0.30-fpm\n" }));
      const byRule = Object.fromEntries(result.findings.filter((f) => f.engine === "synvoya").map((f) => [f.rule_id, f.producer_components]));
      expect(byRule["SYN-2026-001"]).toContain("synvoya:runtime");
      expect(byRule["SYN-EOL-php-8.0"]).toContain("synvoya:images");
    });

    it("New-3: a workflow both readers read is not resolved when the image reader failed and the runtime reader parsed it", async () => {
      const workflow = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: php:8.0.30-fpm\n    steps:\n" +
        "      - uses: actions/setup-node@v4\n        with:\n          node-version: 22.11.0\n";
      const target = await project({ ".github/workflows/ci.yml": workflow });
      const prior = await scan(target);
      expect(tagged(prior.findings)).toEqual(["SYN-EOL-php-8.0@.github/workflows/ci.yml"]);
      fault.rejectReader = "images";
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.runtime).toEqual([".github/workflows/ci.yml"]);
      expect(fresh.synvoya_checked?.images).toBeUndefined();
      const diff = diffRescan(prior, fresh);
      expect(tagged(diff.resolved)).toEqual([]);
      expect(tagged(diff.not_rechecked)).toEqual(["SYN-EOL-php-8.0@.github/workflows/ci.yml"]);

      // The other reader failing leaves the image finding provable.
      fault.rejectReader = "runtime";
      const other = diffRescan(prior, await scan(target));
      expect(tagged(other.remaining)).toEqual(["SYN-EOL-php-8.0@.github/workflows/ci.yml"]);
    });

    it("New-4: a pinned image replaced by an unresolvable one is not resolved", async () => {
      const target = await project({ "Dockerfile": "FROM php:8.0.30-fpm\n" });
      const prior = await scan(target);
      await writeFile(join(target, "Dockerfile"), "ARG V\nFROM php:${V}\n", "utf8");
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.images).toEqual([]);
      const diff = diffRescan(prior, fresh);
      expect(tagged(diff.resolved)).toEqual([]);
      expect(tagged(diff.not_rechecked)).toEqual(["SYN-EOL-php-8.0@Dockerfile"]);
    });

    it("a declaration the evaluator could not compare proves nothing: not resolved", async () => {
      const target = await project({ ".nvmrc": "20.1.0\n" });
      const prior = await scan(target);
      expect(tagged(prior.findings)).toEqual(["SYN-2026-001@.nvmrc"]);
      // `20.1.0-custom` is a semver prerelease and still compares; `_` makes it unreadable to the semver scheme.
      await writeFile(join(target, ".nvmrc"), "20.1.0_custom\n", "utf8");
      const fresh = await scan(target);
      expect(fresh.coverage_notes?.some((note) => note.detail.includes("could not compare"))).toBe(true);
      expect(fresh.synvoya_checked?.runtime).toEqual([]);
      const diff = diffRescan(prior, fresh);
      expect(tagged(diff.resolved)).toEqual([]);
      expect(tagged(diff.not_rechecked)).toEqual(["SYN-2026-001@.nvmrc"]);
    });

    it.each([
      ["Dockerfile", "FROM php:8.0.30-fpm\n", "ARG BASE\nFROM ${BASE}\n"],
      ["compose.yaml", "services:\n  app:\n    image: php:8.0.30-fpm\n", "services:\n  app:\n    image: ${APP_IMAGE}\n"],
      [".github/workflows/ci.yml", workflowWith("    container: php:8.0.30-fpm\n"), workflowWith("    container: ${{ vars.IMG }}\n")],
      ["Dockerfile", "FROM php:8.0.30-fpm\n", "FROM registry.internal/php:8.0.30-fpm\n"],
    ])("N5/M6: %s pinned image replaced by one Synvoya cannot confirm is not resolved", async (file, before, after) => {
      const target = await project({ [file]: before });
      const prior = await scan(target);
      expect(tagged(prior.findings)).toEqual([`SYN-EOL-php-8.0@${file}`]);
      await writeFile(join(target, ...file.split("/")), after, "utf8");
      const fresh = await scan(target);
      expect(tagged(fresh.findings)).toEqual([]);
      expect(fresh.synvoya_checked?.images).toEqual([]);
      const diff = diffRescan(prior, fresh);
      expect(tagged(diff.resolved)).toEqual([]);
      expect(tagged(diff.not_rechecked)).toEqual([`SYN-EOL-php-8.0@${file}`]);
    });

    it("a floating tag on a supported line is a real check: the fix resolves", async () => {
      const target = await project({ "Dockerfile": "FROM php:8.0.30-fpm\n" });
      const prior = await scan(target);
      await writeFile(join(target, "Dockerfile"), "FROM php:8.3-fpm\n", "utf8");
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.images).toEqual(["Dockerfile"]);
      expect(tagged(diffRescan(prior, fresh).resolved)).toEqual(["SYN-EOL-php-8.0@Dockerfile"]);
    });

    it("D: a lockfile listed only by Trivy does not re-check a finding the osv-scanner inventory produced", async () => {
      fault.dir = await datasetWithLodash();
      const target = await project({ "package-lock.json": PACKAGE_LOCK });
      vi.mocked(runOsvScanner).mockResolvedValue(osvResult({
        lockfiles: ["package-lock.json"],
        packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json" }],
      }));
      const prior = await scan(target);
      expect(prior.findings.find((f) => f.engine === "synvoya")?.producer_components).toContain("synvoya:inventory:osv-scanner");

      vi.mocked(runOsvScanner).mockResolvedValue(osvResult({
        info: { engine: "osv-scanner", version: "2.7.0", available: false, ran: false, finding_count: 0, duration_ms: 1, note: "not installed" },
        applicable: false,
      }));
      fault.trivyPackages = [{ ecosystem: "npm", name: "left-pad", version: "1.3.0", file: "package-lock.json", line: 7 }];
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.["inventory:trivy"]).toEqual(["package-lock.json"]);
      const diff = diffRescan(prior, fresh);
      expect(tagged(diff.resolved)).toEqual([]);
      expect(tagged(diff.not_rechecked)).toEqual(["SYN-2026-900@package-lock.json"]);
    });

    it("E: an image-alias package finding is re-checked by the image reader, so a real fix resolves", async () => {
      fault.dir = await datasetWith(
        [{
          id: "SYN-2026-901",
          slug: "jenkins-core-test-gap",
          title: "jenkins-core before 2.440.1 is affected by a test gap",
          kind: "vulnerability",
          aliases: [],
          target: { type: "package", ecosystem: "maven", name: "org.jenkins-ci.main:jenkins-core" },
          affected: [{ events: [{ introduced: "0" }, { fixed: "2.440.1" }] }],
          fixed: ["2.440.1"],
          severity: "high",
          exploited: false,
          remediation_steps: ["Upgrade."],
          sources: ["https://example.com/jenkins"],
          status: "active",
          provisional: false,
        }],
        { imageAliases: { "jenkins/jenkins": { ecosystem: "maven", name: "org.jenkins-ci.main:jenkins-core" } } },
      );
      const target = await project({ "Dockerfile": "FROM jenkins/jenkins:2.426.1\n" });
      const prior = await scan(target);
      const finding = prior.findings.find((f) => f.engine === "synvoya");
      expect(finding).toMatchObject({ rule_id: "SYN-2026-901", package: { name: "org.jenkins-ci.main:jenkins-core" } });
      expect(finding?.producer_components).toContain("synvoya:images");

      await writeFile(join(target, "Dockerfile"), "FROM jenkins/jenkins:2.440.1\n", "utf8");
      const diff = diffRescan(prior, await scan(target));
      expect(tagged(diff.resolved)).toEqual(["SYN-2026-901@Dockerfile"]);
    });

    it("a deadline skip anywhere omits every reader set, while the inventory sets stay", async () => {
      fault.dir = await datasetWithLodash();
      vi.mocked(runOsvScanner).mockResolvedValue(osvResult({
        lockfiles: ["package-lock.json"],
        packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json" }],
      }));
      fault.deadlineMs = 0;
      const result = await scan(await project({ ".nvmrc": "20.1.0\n", "package-lock.json": PACKAGE_LOCK }));
      expect(result.synvoya_checked).toEqual({ "inventory:osv-scanner": ["package-lock.json"], "inventory:trivy": [] });
    });
  });
});

describe("vendored libraries through the per-scan SBOM", () => {
  // The main osv-scanner run signs its binary, config and npm database; the SBOM run's findings depend on them.
  const MAIN_SIGNATURES = {
    "osv-scanner:binary": `sha256:${"b".repeat(64)}`,
    "osv-scanner:config": `sha256:${"c".repeat(64)}`,
    "osv-scanner:vulnerability-db:npm": `sha256:${"d".repeat(64)}`,
    "osv-scanner:vulnerability-db:Packagist": `sha256:${"e".repeat(64)}`,
    "osv-scanner:vulnerability-db:Go": `sha256:${"f".repeat(64)}`,
  };
  const sbom = { answer: "ran" as "ran" | "failed" | "unavailable" | "incomplete", vulnerable: ["jquery@1.12.4"], runs: 0 };
  const JQUERY_FILE = "public/js/jquery-1.12.4.min.js";
  const BANNER = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\nvar a;\n";

  beforeEach(() => {
    sbom.answer = "ran";
    sbom.vulnerable = ["jquery@1.12.4"];
    sbom.runs = 0;
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({ componentSignatures: { ...MAIN_SIGNATURES } }));
    vi.mocked(runOsvScannerOnSbom).mockReset();
    // The process boundary only: the SBOM is read back, and each vulnerable package is located through the scanner.
    vi.mocked(runOsvScannerOnSbom).mockImplementation(async (sbomPath, _workDir, options) => {
      sbom.runs += 1;
      const components = (JSON.parse(await readFile(sbomPath, "utf8")) as { components: Array<{ name: string; version: string; purl: string }> }).components;
      const ecosystemOf = new Map(components.map((c) => [`${c.name}@${c.version}`, ({ npm: "npm", composer: "Packagist", golang: "Go" } as Record<string, string>)[c.purl.slice(4, c.purl.indexOf("/"))]!]));
      const base = { version: "2.7.0", missingDatabases: [] as Array<"npm">, findings: [] as Finding[], warnings: [] as string[], complete: false };
      if (sbom.answer === "unavailable") return { ...base, state: "unavailable", missingDatabases: ["npm"], reason: "the OSV npm database is not installed" };
      if (sbom.answer === "failed") return { ...base, state: "failed", reason: "osv-scanner timed out before producing results." };
      const findings = [...new Set(components.map((c) => `${c.name}@${c.version}`))].filter((label) => sbom.vulnerable.includes(label)).flatMap((label) => {
        const at = label.lastIndexOf("@");
        const [name, version] = [label.slice(0, at), label.slice(at + 1)];
        const ecosystem = ecosystemOf.get(label)!;
        return options.locate({ ecosystem, name, version }).map((where): Finding => {
          const shown = where.declaredName ?? name;
          const fingerprint = makeFingerprint(["osv-scanner", where.file, shown, version, "CVE-2020-11022"]);
          return {
            id: fingerprint, fingerprint, title: `XSS in jQuery (${label})`, severity: "medium", engine: "osv-scanner", engines: ["osv-scanner"],
            rule_id: "CVE-2020-11022", vulnerability_aliases: ["GHSA-gxr4-xjj5-5px2"], cwe: ["CWE-1395"], owasp_web: ["A06:2021"],
            location: { file: where.file, start_line: where.line, end_line: where.line }, message: `${where.lead} CVE-2020-11022 is reported against that exact version.`,
            remediation: { summary: "Upgrade jquery to 3.5.0.", steps: ["Upgrade jquery to 3.5.0."], references: [] }, frameworks: [], confidence: "high",
            producer_components: osvSbomFindingComponents(ecosystem), finding_kind: "vulnerability", package: { ecosystem, name: shown, version },
          };
        });
      });
      if (sbom.answer === "incomplete") return { ...base, state: "ran", findings, warnings: ["osv-scanner stopped at an OSV database it could not load"] };
      return { ...base, state: "ran", findings, complete: true };
    });
  });

  const fromSbom = (findings: Finding[]) =>
    findings.filter((f) => f.producer_components?.includes("synvoya:sbom:osv-scanner")).map((f) => `${f.rule_id}@${f.location.file}:${f.location.start_line}`);

  it("reports the vendored library at its file and line in the Synvoya family; the main osv-scanner coverage is untouched", async () => {
    const result = await scan(await project({ [JQUERY_FILE]: BANNER }));
    expect(scanResultSchema.safeParse(result).success).toBe(true);
    expect(fromSbom(result.findings)).toEqual([`CVE-2020-11022@${JQUERY_FILE}:1`]);
    const finding = result.findings.find((f) => f.location.file === JQUERY_FILE)!;
    expect(finding).toMatchObject({ engine: "osv-scanner", engines: ["osv-scanner"], engine_family: "synvoya" });
    expect(result.synvoya_checked).toMatchObject({ vendored: [JQUERY_FILE], "sbom:osv-scanner": [JQUERY_FILE] });
    expect(result.component_signatures?.["osv-scanner:sbom-invocation"]).toMatch(/^sha256:/);
    expect(result.engine_details.find((engine) => engine.engine === "osv-scanner")).toMatchObject({ ran: true });
    expect(result.coverage_gaps ?? []).toEqual([]);
    expect(JSON.stringify(result)).not.toContain("inventory.cdx.json");
    expect(JSON.stringify(result)).not.toContain("synvoya-sbom");
  });

  it("missing npm database: the vendored-js gap makes coverage partial and names the file; installed again, the gap is gone", async () => {
    sbom.answer = "unavailable";
    const target = await project({ [JQUERY_FILE]: BANNER });
    const missing = await scan(target);
    expect(missing.coverage_gaps).toEqual([{ id: "vendored-js", files: 1, examples: [`${JQUERY_FILE} (jquery@1.12.4)`] }]);
    const evidence = assessAggregateCoverage({ ...missing, canonical_findings: true, storage_schema_version: "2.0.0" }).evidence;
    expect(evidence.find((item) => item.component === "gap:vendored-js")).toMatchObject({ state: "partial" });
    expect(evidence.find((item) => item.component === "gap:vendored-js")?.detail).toMatch(/only exact versions are checked.*dist\/.*wp-content/);
    sbom.answer = "ran";
    expect((await scan(target)).coverage_gaps ?? []).toEqual([]);
  });

  it("npm database present but no vendored inputs: no gap and no second run", async () => {
    sbom.answer = "unavailable";
    const result = await scan(await project({ ".nvmrc": "20.1.0\n" }));
    expect(result.coverage_gaps ?? []).toEqual([]);
    expect(sbom.runs).toBe(0);
  });

  it("a failed SBOM run is a scan warning that lowers export coverage; the first run's coverage is not failed", async () => {
    sbom.answer = "failed";
    const result = await scan(await project({ [JQUERY_FILE]: BANNER }));
    expect(result.warnings).toContain("Synvoya SBOM check did not run: osv-scanner timed out before producing results.");
    expect(synvoyaEvidence(result)).toContainEqual({ component: "scan-pipeline", state: "partial" });
    expect(result.engine_details.find((engine) => engine.engine === "osv-scanner")).toMatchObject({ ran: true });
    expect(result.engine_details.find((engine) => engine.engine === "synvoya")).toMatchObject({ ran: true });
  });

  it("a package the main run already reports in the same file is folded into it; another file never absorbs it", async () => {
    const target = await project({ [JQUERY_FILE]: BANNER, "public/old.html": '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>\n' });
    const upstream: Finding = {
      ...lodashFinding(), id: "up", fingerprint: "up", rule_id: "CVE-2020-11022", vulnerability_aliases: [], title: "XSS (jquery@1.12.4)",
      location: { file: JQUERY_FILE, start_line: 1, end_line: 1 }, package: { ecosystem: "npm", name: "jquery", version: "1.12.4" },
      producer_components: osvScannerFindingComponents("npm"),
    };
    vi.mocked(runOsvScanner).mockResolvedValue(osvResult({ findings: [upstream], componentSignatures: { ...MAIN_SIGNATURES } }));
    const result = await scan(target);
    expect(fromSbom(result.findings)).toEqual(["CVE-2020-11022@public/old.html:1"]);
    expect(result.findings.filter((f) => f.location.file === JQUERY_FILE).map((f) => f.fingerprint)).toEqual(["up"]);
  });

  describe("rescan honesty (M1 false-resolved repros on the vendored and SBOM producers)", () => {
    const sbomTagged = (findings: Finding[]) => fromSbom(findings);

    it("unchanged: remaining; a real upgrade in a fully read file: resolved", async () => {
      // A file whose name carries no version, so the banner alone declares it.
      const file = "public/js/jquery.min.js";
      const target = await project({ [file]: BANNER });
      const prior = await scan(target);
      const unchanged = diffRescan(prior, await scan(target));
      expect(sbomTagged(unchanged.remaining)).toEqual([`CVE-2020-11022@${file}:1`]);
      await writeFile(join(target, file), "/*! jQuery v3.7.1 | (c) OpenJS Foundation | jquery.org/license */\nvar a;\n", "utf8");
      const fixed = diffRescan(prior, await scan(target));
      expect(sbomTagged(fixed.resolved)).toEqual([`CVE-2020-11022@${file}:1`]);
      expect(fixed.not_rechecked).toEqual([]);
    });

    it("a vendored file replaced by an upgraded copy under a new name is not resolved (the old file is gone)", async () => {
      const target = await project({ [JQUERY_FILE]: BANNER });
      const prior = await scan(target);
      await rm(join(target, JQUERY_FILE));
      await writeFile(join(target, "public/js/jquery-3.7.1.min.js"), "/*! jQuery v3.7.1 | (c) OpenJS Foundation */\nvar a;\n", "utf8");
      const diff = diffRescan(prior, await scan(target));
      expect(sbomTagged(diff.resolved)).toEqual([]);
      expect(sbomTagged(diff.not_rechecked)).toEqual([`CVE-2020-11022@${JQUERY_FILE}:1`]);
    });

    // Review C1: osv-scanner never sees a floating version, so swapping an exact one for it re-checks nothing.
    // jsDelivr still serves jquery@1.12 as 1.12.4 (the reviewer's real-binary repro resolved all four CVEs).
    it.each([
      ["jquery@1.12 (still 1.12.4)", "https://cdn.jsdelivr.net/npm/jquery@1.12/dist/jquery.min.js"],
      ["jquery@1", "https://cdn.jsdelivr.net/npm/jquery@1/dist/jquery.min.js"],
      ["jquery@3", "https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"],
    ])("an exact version swapped for floating %s is not resolved, and the second run is skipped", async (_label, url) => {
      const target = await project({ "public/b.html": '<html>\n<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>\n' });
      const prior = await scan(target);
      expect(sbomTagged(prior.findings)).toEqual(["CVE-2020-11022@public/b.html:2"]);
      await writeFile(join(target, "public/b.html"), `<html>\n<script src="${url}"></script>\n`, "utf8");
      sbom.runs = 0;
      const fresh = await scan(target);
      expect(sbom.runs).toBe(0);
      expect(fresh.synvoya_checked?.["sbom:osv-scanner"]).toEqual([]);
      const diff = diffRescan(prior, fresh);
      expect(sbomTagged(diff.resolved)).toEqual([]);
      expect(sbomTagged(diff.not_rechecked)).toEqual(["CVE-2020-11022@public/b.html:2"]);
    });

    it("a file holding an exact and a floating library is not SBOM-checked, so its exact finding cannot resolve", async () => {
      const both = '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@3/dist/js/bootstrap.min.js"></script>\n';
      const target = await project({ "public/index.html": both });
      const prior = await scan(target);
      sbom.vulnerable = [];
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.["sbom:osv-scanner"]).toEqual([]);
      expect(sbomTagged(diffRescan(prior, fresh).not_rechecked)).toEqual(["CVE-2020-11022@public/index.html:1"]);
    });

    it.each([
      ["the SBOM run failed", async () => { sbom.answer = "failed"; }],
      ["the SBOM run was incomplete", async () => { sbom.answer = "incomplete"; sbom.vulnerable = []; }],
      ["the npm database is gone", async () => { sbom.answer = "unavailable"; }],
      ["the reader deadline expired", async () => { fault.deadlineMs = 0; }],
      ["the library reader rejected", async () => { fault.rejectReader = "libraries"; sbom.vulnerable = []; }],
      ["the dataset is unavailable", async () => { fault.reason = "manifest.json is missing or unreadable."; }],
    ])("not resolved when %s", async (_label, breakIt) => {
      const target = await project({ [JQUERY_FILE]: BANNER });
      const prior = await scan(target);
      await breakIt();
      const fresh = await scan(target);
      const diff = diffRescan(prior, fresh);
      expect(sbomTagged(diff.resolved)).toEqual([]);
      expect(sbomTagged([...diff.remaining, ...diff.not_rechecked])).toEqual([`CVE-2020-11022@${JQUERY_FILE}:1`]);
    });

    it("not resolved when the version turns unresolvable (pinned to latest), the file is cut by the read cap, or the file is removed", async () => {
      const cdn = '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>\n';
      for (const after of [
        '<script src="https://unpkg.com/jquery@latest/dist/jquery.js"></script>\n',
        `${cdn}${"var a=1;\n".repeat(140_000)}`,
        undefined,
      ]) {
        const target = await project({ "public/index.html": cdn });
        const prior = await scan(target);
        if (after === undefined) await rm(join(target, "public/index.html"));
        else await writeFile(join(target, "public/index.html"), after, "utf8");
        const diff = diffRescan(prior, await scan(target));
        expect(sbomTagged(diff.resolved)).toEqual([]);
        expect(sbomTagged([...diff.remaining, ...diff.not_rechecked])).toEqual(["CVE-2020-11022@public/index.html:1"]);
      }
    });

    it("not resolved when the main osv-scanner run did not run in the rescan", async () => {
      const target = await project({ [JQUERY_FILE]: BANNER });
      const prior = await scan(target);
      sbom.vulnerable = [];
      vi.mocked(runOsvScanner).mockResolvedValue(osvResult({ info: { engine: "osv-scanner", version: "2.7.0", available: true, ran: false, finding_count: 0, duration_ms: 1 } }));
      const diff = diffRescan(prior, await scan(target));
      expect(sbomTagged(diff.resolved)).toEqual([]);
      expect(sbomTagged(diff.not_rechecked)).toEqual([`CVE-2020-11022@${JQUERY_FILE}:1`]);
    });
  });

  describe("rescan honesty for Magento editions and Go toolchains", () => {
    const lock = (name: string, version: string) =>
      `${JSON.stringify({ packages: [{ name: "magento/magento2-base", version }, { name, version }], "packages-dev": [] }, null, 4)}\n`;
    const MAGENTO_LINE = 8;

    it("a Magento edition upgraded in its lock resolves; switched to Adobe Commerce (not checked) it is not resolved", async () => {
      fault.dir = await datasetWith([], { packages: { "Packagist:magento/product-community-edition": "Packagist:magento/community-edition" } });
      sbom.vulnerable = ["magento/community-edition@2.4.7-p2"];
      const target = await project({ "composer.lock": lock("magento/product-community-edition", "2.4.7-p2") });
      const prior = await scan(target);
      expect(fromSbom(prior.findings)).toEqual([`CVE-2020-11022@composer.lock:${MAGENTO_LINE}`]);
      expect(prior.findings.find((f) => f.location.file === "composer.lock")?.package?.name).toBe("magento/product-community-edition");
      expect(prior.synvoya_checked?.["sbom:osv-scanner"]).toEqual(["composer.lock"]);

      await writeFile(join(target, "composer.lock"), lock("magento/product-community-edition", "2.4.7-p3"), "utf8");
      const upgraded = diffRescan(prior, await scan(target));
      expect(fromSbom(upgraded.resolved)).toEqual([`CVE-2020-11022@composer.lock:${MAGENTO_LINE}`]);

      await writeFile(join(target, "composer.lock"), lock("magento/product-enterprise-edition", "2.4.7-p2"), "utf8");
      const enterprise = diffRescan(prior, await scan(target));
      expect(fromSbom(enterprise.resolved)).toEqual([]);
      expect(fromSbom(enterprise.not_rechecked)).toEqual([`CVE-2020-11022@composer.lock:${MAGENTO_LINE}`]);
    });

    it("a golang image upgraded to another exact release resolves; swapped for a floating tag it is not resolved", async () => {
      sbom.vulnerable = ["stdlib@v1.22.5"];
      const target = await project({ "Dockerfile": "FROM golang:1.22.5 AS build\n" });
      const prior = await scan(target);
      expect(fromSbom(prior.findings)).toEqual(["CVE-2020-11022@Dockerfile:1"]);
      await writeFile(join(target, "Dockerfile"), "FROM golang:1.22.12 AS build\n", "utf8");
      expect(fromSbom(diffRescan(prior, await scan(target)).resolved)).toEqual(["CVE-2020-11022@Dockerfile:1"]);
      await writeFile(join(target, "Dockerfile"), "FROM golang:1.22 AS build\n", "utf8");
      const floating = diffRescan(prior, await scan(target));
      expect(fromSbom(floating.resolved)).toEqual([]);
      expect(fromSbom(floating.not_rechecked)).toEqual(["CVE-2020-11022@Dockerfile:1"]);
    });

    /** A Synvoya advisory sharing the SBOM mock's CVE-2020-11022 (as SYN-2026-10801 shares CVE-2024-34102). */
    const sharedAdvisory = (id: string, target: Record<string, unknown>, events: Array<Record<string, string>>) => ({
      id, slug: `${id.toLowerCase()}-test`, title: `${id} shared advisory`, kind: target.type === "runtime" ? "runtime" : "product",
      aliases: ["CVE-2020-11022", "GHSA-gxr4-xjj5-5px2"], target, affected: [{ events }], fixed: ["9.9.9"], severity: "critical",
      exploited: true, remediation_steps: [`Apply the ${id} fix.`], sources: ["https://example.com/advisory"], status: "active", provisional: false,
    });

    it("a Magento product advisory and the SBOM finding for the same CVE at the same lock line are one finding (review I1)", async () => {
      fault.dir = await datasetWith(
        [sharedAdvisory("SYN-2026-990", { type: "product", product: "magento-open-source" }, [{ introduced: "2.4.6" }, { fixed: "2.4.6-p6" }])],
        { packages: { "Packagist:magento/product-community-edition": "Packagist:magento/community-edition" } },
      );
      sbom.vulnerable = ["magento/community-edition@2.4.6-p3"];
      const target = await project({ "composer.lock": lock("magento/product-community-edition", "2.4.6-p3") });
      const prior = await scan(target);
      const shared = prior.findings.filter((f) => [f.rule_id, ...(f.vulnerability_aliases ?? [])].includes("CVE-2020-11022"));
      expect(shared.map((f) => [f.engine, f.location.file, f.location.start_line])).toEqual([["osv-scanner", "composer.lock", MAGENTO_LINE]]);
      expect(shared[0]!.fingerprint).toBe(makeFingerprint(["osv-scanner", "composer.lock", "magento/product-community-edition", "2.4.6-p3", "CVE-2020-11022"]));
      expect(shared[0]!.producer_components).toEqual(osvSbomFindingComponents("Packagist"));
      expect(shared[0]!.remediation.steps.some((step) => step.startsWith("Synvoya SYN-2026-990:"))).toBe(true);
      expect(shared[0]!.remediation.steps).toContain("Apply the SYN-2026-990 fix.");
      expect(prior.findings.some((f) => f.engine === "synvoya")).toBe(false);

      // Rescan honesty: the dropped Synvoya producer re-checked the lock, but the kept finding's producers decide.
      sbom.answer = "failed";
      const failed = diffRescan(prior, await scan(target));
      expect(fromSbom(failed.resolved)).toEqual([]);
      expect(fromSbom(failed.not_rechecked)).toEqual([`CVE-2020-11022@composer.lock:${MAGENTO_LINE}`]);
      sbom.answer = "ran";
      expect(fromSbom(diffRescan(prior, await scan(target)).remaining)).toEqual([`CVE-2020-11022@composer.lock:${MAGENTO_LINE}`]);
    });

    it("a Go runtime advisory and the stdlib SBOM finding for the same id at the toolchain line are one finding", async () => {
      fault.dir = await datasetWith([sharedAdvisory("SYN-2026-991", { type: "runtime", runtime: "go" }, [{ introduced: "0" }, { fixed: "1.22.7" }])]);
      sbom.vulnerable = ["stdlib@v1.22.5"];
      const target = await project({ "go.mod": "module example.com/app\n\ngo 1.22\n\ntoolchain go1.22.5\n" });
      const result = await scan(target);
      const shared = result.findings.filter((f) => [f.rule_id, ...(f.vulnerability_aliases ?? [])].includes("CVE-2020-11022"));
      expect(shared.map((f) => [f.engine, f.location.file, f.location.start_line, f.package?.name])).toEqual([["osv-scanner", "go.mod", 5, "stdlib"]]);
      expect(shared[0]!.remediation.steps.some((step) => step.startsWith("Synvoya SYN-2026-991:"))).toBe(true);
      // The `go 1.22` minimum is a separate declaration (line 3): its own Synvoya finding, if any, stands alone.
      expect(result.findings.filter((f) => f.engine === "synvoya").every((f) => f.location.start_line !== 5)).toBe(true);
    });

    // Ruling: only SBOM-kind declarations decide SBOM checked-ness; the `go` minimum is the runtime producer's.
    it("a go.mod toolchain upgraded to another exact release resolves, despite the `go` minimum", async () => {
      sbom.vulnerable = ["stdlib@v1.22.5"];
      const target = await project({ "go.mod": "module example.com/app\n\ngo 1.22\n\ntoolchain go1.22.5\n" });
      const prior = await scan(target);
      expect(fromSbom(prior.findings)).toEqual(["CVE-2020-11022@go.mod:5"]);
      expect(prior.synvoya_checked?.["sbom:osv-scanner"]).toEqual(["go.mod"]);
      await writeFile(join(target, "go.mod"), "module example.com/app\n\ngo 1.22\n\ntoolchain go1.22.10\n", "utf8");
      const diff = diffRescan(prior, await scan(target));
      expect(fromSbom(diff.resolved)).toEqual(["CVE-2020-11022@go.mod:5"]);
      expect(fromSbom(diff.not_rechecked)).toEqual([]);
    });

    it("a removed toolchain line leaves the effective toolchain unknown: not_rechecked, never resolved", async () => {
      sbom.vulnerable = ["stdlib@v1.22.5"];
      const target = await project({ "go.mod": "module example.com/app\n\ngo 1.22\n\ntoolchain go1.22.5\n" });
      const prior = await scan(target);
      await writeFile(join(target, "go.mod"), "module example.com/app\n\ngo 1.22\n", "utf8");
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.["sbom:osv-scanner"]).toEqual([]);
      const diff = diffRescan(prior, fresh);
      expect(fromSbom(diff.resolved)).toEqual([]);
      expect(fromSbom(diff.not_rechecked)).toEqual(["CVE-2020-11022@go.mod:5"]);
    });
  });
});

describe("Trivy Magento -pN false positives in the scan envelope", () => {
  // Real Trivy 0.76.1 SARIF results (messages verbatim) for magento/community-edition locked at 2.4.7-p3.
  const trivyResult = (id: string, fixed: string) => ({
    ruleId: id,
    level: "error",
    message: { text: `Package: magento/community-edition\nInstalled Version: 2.4.7-p3\nVulnerability ${id}\nSeverity: HIGH\nFixed Version: ${fixed}\nLink: [${id}](https://avd.aquasec.com/nvd/${id.toLowerCase()})` },
    locations: [{ physicalLocation: { artifactLocation: { uri: "composer.lock", uriBaseId: "ROOTPATH" }, region: { startLine: 5, startColumn: 1, endLine: 9, endColumn: 1 } } }],
  });

  it("a provably fixed advisory is not reported and the coverage notes say so; the true positive keeps its fingerprint", async () => {
    const root = await project({ "composer.lock": '{"packages": [{"name": "magento/community-edition", "version": "2.4.7-p3"}]}\n' });
    fault.trivyResults = [trivyResult("CVE-2025-47110", "2.4.8-p1, 2.4.7-p6, 2.4.5-p13, 2.4.6-p11")];
    const baseline = await scan(root);
    const truePositive = baseline.findings.find((finding) => finding.rule_id === "CVE-2025-47110");
    expect(truePositive).toBeDefined();

    fault.trivyResults = [trivyResult("CVE-2024-20758", "2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8"), trivyResult("CVE-2025-47110", "2.4.8-p1, 2.4.7-p6, 2.4.5-p13, 2.4.6-p11")];
    const result = await scan(root);
    expect(scanResultSchema.safeParse(result).success).toBe(true);
    expect(result.findings.filter((finding) => finding.engine === "trivy").map((finding) => [finding.rule_id, finding.fingerprint])).toEqual([
      ["CVE-2025-47110", truePositive!.fingerprint],
    ]);
    expect(result.coverage_notes).toContainEqual({
      component: "engine:trivy",
      detail: "Trivy orders Magento -pN patch releases before their base release, so it matched 1 advisory that Magento ordering shows " +
        "fixed at the installed release; it is not reported: magento/community-edition 2.4.7-p3 in composer.lock (CVE-2024-20758).",
    });
    expect(result.warnings.join(" ")).not.toMatch(/Magento/);
  });
});

describe("scan orchestrator: third-party GitHub Actions", () => {
  const CI = (changedFiles: string) =>
    `on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: tj-actions/changed-files@${changedFiles}\n      - uses: reviewdog/action-setup@main\n`;
  const installDb = async (): Promise<void> => {
    const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-int-actions-"));
    roots.push(dir);
    fault.actionsDb = await writeActionsFixtureDb(dir);
  };
  const gap = (result: ScanResult) => result.coverage_gaps?.find((entry) => entry.id === "actions-unchecked");

  it("without the database every third-party reference stays in actions-unchecked, as before", async () => {
    const result = await scan(await project({ ".github/workflows/ci.yml": CI("v45.0.7") }));
    expect(gap(result)).toEqual({ id: "actions-unchecked", files: 3, examples: [
      "actions/checkout@v4 (.github/workflows/ci.yml)", "tj-actions/changed-files@v45.0.7 (.github/workflows/ci.yml)",
      "reviewdog/action-setup@main (.github/workflows/ci.yml)",
    ] });
    expect(result.findings.filter((finding) => finding.rule_id.startsWith("GHSA-"))).toEqual([]);
  });

  it("with it the tag is a finding and only the reference it could not evaluate (a branch of an action with advisories) stays a gap", async () => {
    await installDb();
    const result = await scan(await project({ ".github/workflows/ci.yml": CI("v45.0.7") }));
    expect(scanResultSchema.safeParse(result).success).toBe(true);
    expect(gap(result)).toEqual({ id: "actions-unchecked", files: 1, examples: ["reviewdog/action-setup@main (.github/workflows/ci.yml)"] });
    const finding = result.findings.find((entry) => entry.rule_id === "GHSA-mrrh-fwg8-r2c3");
    expect(finding).toMatchObject({ engine: "synvoya", engine_family: "synvoya", location: { file: ".github/workflows/ci.yml", start_line: 7 } });
    expect(result.component_signatures?.["osv-scanner:vulnerability-db:GitHub Actions"]).toBe(fault.actionsDb!.record && (fault.actionsDb!.record as { signature: string }).signature);
    // The branch ref leaves the file unconfirmable on rescan.
    expect(result.synvoya_checked?.actions).toEqual([]);
  });

  it("a rescan resolves the finding once the tag is fixed and every reference in the file is definite; a SHA it cannot judge is not_rechecked", async () => {
    await installDb();
    const target = await project({ ".github/workflows/ci.yml": CI("v45.0.7").replace("      - uses: reviewdog/action-setup@main\n", "") });
    const prior = await scan(target);
    expect(prior.findings.some((entry) => entry.rule_id === "GHSA-mrrh-fwg8-r2c3")).toBe(true);
    await writeFile(join(target, ".github", "workflows", "ci.yml"), CI("0e58ed8671d6b60d0890c21b07f8835ace038e67").replace("      - uses: reviewdog/action-setup@main\n", ""), "utf8");
    const pinned = await scan(target);
    expect(diffRescan(prior, pinned).not_rechecked.map((entry) => entry.rule_id)).toContain("GHSA-mrrh-fwg8-r2c3");
    await writeFile(join(target, ".github", "workflows", "ci.yml"), CI("v46.0.1").replace("      - uses: reviewdog/action-setup@main\n", ""), "utf8");
    const fixed = await scan(target);
    expect(fixed.synvoya_checked?.actions).toEqual([".github/workflows/ci.yml"]);
    expect(diffRescan(prior, fixed).resolved.map((entry) => entry.rule_id)).toContain("GHSA-mrrh-fwg8-r2c3");
    // A changed database (no matching install record now) confirms nothing.
    fault.actionsDb = { ...fault.actionsDb!, record: undefined };
    const unsigned = await scan(target);
    expect(diffRescan(prior, unsigned).not_rechecked.map((entry) => entry.rule_id)).toContain("GHSA-mrrh-fwg8-r2c3");
  });
});

describe("rescan honesty for the vendored and Actions producers (M1 repros: deadline, reader rejection, partial file, database missing)", () => {
  const tagged = (findings: Finding[], id: string) => findings.filter((finding) => finding.rule_id === id).map((finding) => `${finding.rule_id}@${finding.location.file}:${finding.location.start_line}`);

  describe("vendored: a Synvoya npm advisory on a vendored library", () => {
    const FILE = "public/js/jquery.min.js";
    const BANNER = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\nvar a;\n";
    const FIXED_BANNER = "/*! jQuery v3.7.1 | (c) OpenJS Foundation | jquery.org/license */\nvar a;\n";
    const ADVISORY = {
      id: "SYN-2026-910", slug: "jquery-test-gap", title: "jQuery before 3.5.0 test gap", kind: "vulnerability", aliases: ["CVE-2026-2000"],
      target: { type: "package", ecosystem: "npm", name: "jquery" }, affected: [{ events: [{ introduced: "0" }, { fixed: "3.5.0" }] }], fixed: ["3.5.0"],
      severity: "high", exploited: false, remediation_steps: ["Upgrade jquery to 3.5.0."], sources: ["https://example.com/jquery"], status: "active", provisional: false,
    };

    beforeEach(async () => {
      fault.dir = await datasetWith([ADVISORY]);
      vi.mocked(runOsvScanner).mockResolvedValue(osvResult());
      vi.mocked(runOsvScannerOnSbom).mockReset();
      vi.mocked(runOsvScannerOnSbom).mockResolvedValue({ state: "ran", version: "2.7.0", missingDatabases: [], findings: [], warnings: [], complete: true });
    });

    it("is reported by the vendored producer, and a real upgrade in a fully read file resolves it", async () => {
      const target = await project({ [FILE]: BANNER });
      const prior = await scan(target);
      expect(tagged(prior.findings, "SYN-2026-910")).toEqual([`SYN-2026-910@${FILE}:1`]);
      expect(prior.findings.find((finding) => finding.rule_id === "SYN-2026-910")?.producer_components).toContain("synvoya:vendored");
      expect(tagged(diffRescan(prior, await scan(target)).remaining, "SYN-2026-910")).toHaveLength(1);
      await writeFile(join(target, FILE), FIXED_BANNER, "utf8");
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.vendored).toEqual([FILE]);
      expect(tagged(diffRescan(prior, fresh).resolved, "SYN-2026-910")).toHaveLength(1);
    });

    it.each([
      ["the reader deadline expired", async () => { fault.deadlineMs = 0; }],
      ["the library reader rejected", async () => { fault.rejectReader = "libraries"; }],
      ["the dataset is unavailable", async () => { fault.reason = "manifest.json is missing or unreadable."; }],
    ])("a fixed copy is not confirmed when %s", async (_label, breakIt) => {
      const target = await project({ [FILE]: BANNER });
      const prior = await scan(target);
      await writeFile(join(target, FILE), FIXED_BANNER, "utf8");
      await breakIt();
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.vendored).toBeUndefined();
      const diff = diffRescan(prior, fresh);
      expect(tagged(diff.resolved, "SYN-2026-910")).toEqual([]);
      expect(tagged(diff.not_rechecked, "SYN-2026-910")).toEqual([`SYN-2026-910@${FILE}:1`]);
    });

    it("a fixed copy read only in part (over the read cap) or removed is not confirmed", async () => {
      for (const after of [`${FIXED_BANNER}${"var a=1;\n".repeat(140_000)}`, undefined]) {
        const target = await project({ [FILE]: BANNER });
        const prior = await scan(target);
        if (after === undefined) await rm(join(target, FILE));
        else await writeFile(join(target, FILE), after, "utf8");
        const fresh = await scan(target);
        expect(fresh.synvoya_checked?.vendored ?? []).not.toContain(FILE);
        const diff = diffRescan(prior, fresh);
        expect(tagged(diff.resolved, "SYN-2026-910")).toEqual([]);
        expect(tagged(diff.not_rechecked, "SYN-2026-910")).toEqual([`SYN-2026-910@${FILE}:1`]);
      }
    });
  });

  describe("actions: the bundled dataset's own advisory and the installed OSV database's", () => {
    const WORKFLOW = ".github/workflows/ci.yml";
    const ci = (conflibot: string, changedFiles = "v46.0.1", extra = "") =>
      `on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: wktk/conflibot@${conflibot}\n      - uses: tj-actions/changed-files@${changedFiles}\n${extra}`;
    const ADVISORY = {
      id: "SYN-2026-911", slug: "conflibot-test", title: "wktk/conflibot test gap", kind: "vulnerability", aliases: ["GHSA-2qvg-qr73-mqxp"],
      target: { type: "package", ecosystem: "GitHub Actions", name: "wktk/conflibot" }, affected: [{ events: [{ introduced: "0" }, { fixed: "1.2.1" }] }], fixed: ["1.2.1"],
      severity: "critical", exploited: false, remediation_steps: ["Bump to conflibot 1.2.1."], sources: ["https://example.com/conflibot"], status: "active", provisional: false,
    };
    const installDb = async (): Promise<void> => {
      const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-int-actions-"));
      roots.push(dir);
      fault.actionsDb = await writeActionsFixtureDb(dir);
    };
    beforeEach(async () => {
      fault.dir = await datasetWith([ADVISORY]);
      await installDb();
    });

    it("an affected tag is found by the dataset and the database; a fixed tag in a fully read file resolves both", async () => {
      const target = await project({ [WORKFLOW]: ci("v1.2.0", "v45.0.7") });
      const prior = await scan(target);
      expect(tagged(prior.findings, "SYN-2026-911")).toEqual([`SYN-2026-911@${WORKFLOW}:6`]);
      expect(tagged(prior.findings, "GHSA-mrrh-fwg8-r2c3")).toEqual([`GHSA-mrrh-fwg8-r2c3@${WORKFLOW}:7`]);
      await writeFile(join(target, WORKFLOW), ci("v1.2.1"), "utf8");
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.actions).toEqual([WORKFLOW]);
      const diff = diffRescan(prior, fresh);
      expect(tagged(diff.resolved, "SYN-2026-911")).toHaveLength(1);
      expect(tagged(diff.resolved, "GHSA-mrrh-fwg8-r2c3")).toHaveLength(1);
    });

    it.each([
      ["the reader deadline expired", async () => { fault.deadlineMs = 0; }],
      ["the Actions reader rejected", async () => { fault.rejectReader = "actions"; }],
      ["the OSV GitHub Actions database is gone", async () => { fault.actionsDb = undefined; }],
      ["the dataset is unavailable", async () => { fault.reason = "manifest.json is missing or unreadable."; }],
    ])("a fixed tag is not confirmed when %s", async (_label, breakIt) => {
      const target = await project({ [WORKFLOW]: ci("v1.2.0", "v45.0.7") });
      const prior = await scan(target);
      await writeFile(join(target, WORKFLOW), ci("v1.2.1"), "utf8");
      await breakIt();
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.actions ?? []).toEqual([]);
      const diff = diffRescan(prior, fresh);
      for (const id of ["SYN-2026-911", "GHSA-mrrh-fwg8-r2c3"]) {
        expect(tagged(diff.resolved, id), id).toEqual([]);
        expect(tagged(diff.not_rechecked, id).length, id).toBe(1);
      }
    });

    it("a database that no longer matches its install record confirms nothing of its own, while the dataset's finding (which never depended on it) still resolves", async () => {
      const target = await project({ [WORKFLOW]: ci("v1.2.0", "v45.0.7") });
      const prior = await scan(target);
      await writeFile(join(target, WORKFLOW), ci("v1.2.1"), "utf8");
      fault.actionsDb = { ...fault.actionsDb!, record: undefined };
      const diff = diffRescan(prior, await scan(target));
      expect(tagged(diff.not_rechecked, "GHSA-mrrh-fwg8-r2c3")).toHaveLength(1);
      expect(tagged(diff.resolved, "GHSA-mrrh-fwg8-r2c3")).toEqual([]);
      expect(tagged(diff.resolved, "SYN-2026-911")).toHaveLength(1);
    });

    it("a workflow cut by the per-file reference cap is read only in part: a fixed tag in it is not confirmed", async () => {
      const target = await project({ [WORKFLOW]: ci("v1.2.0", "v45.0.7") });
      const prior = await scan(target);
      const filler = Array.from({ length: 300 }, (_, index) => `      - uses: example/filler-${index}@v1\n`).join("");
      await writeFile(join(target, WORKFLOW), ci("v1.2.1", "v46.0.1", filler), "utf8");
      const fresh = await scan(target);
      expect(fresh.synvoya_checked?.actions).toEqual([]);
      const diff = diffRescan(prior, fresh);
      expect(tagged(diff.resolved, "SYN-2026-911")).toEqual([]);
      expect(tagged(diff.not_rechecked, "SYN-2026-911")).toHaveLength(1);
    });

    it("without the database the dataset's finding is still reported, but a fixed tag is never confirmed from a file that was not checked", async () => {
      fault.actionsDb = undefined;
      const target = await project({ [WORKFLOW]: ci("v1.2.0") });
      const prior = await scan(target);
      expect(tagged(prior.findings, "SYN-2026-911")).toEqual([`SYN-2026-911@${WORKFLOW}:6`]);
      expect(prior.coverage_gaps?.find((gap) => gap.id === "actions-unchecked")?.files).toBe(2);
      expect(prior.synvoya_checked?.actions).toEqual([]);
      await writeFile(join(target, WORKFLOW), ci("v1.2.1"), "utf8");
      const diff = diffRescan(prior, await scan(target));
      expect(tagged(diff.resolved, "SYN-2026-911")).toEqual([]);
      expect(tagged(diff.not_rechecked, "SYN-2026-911")).toHaveLength(1);
    });
  });
});
