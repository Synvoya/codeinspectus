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
  rejectReader: "" as "" | "images" | "runtime",
  trivyPackages: [] as unknown[],
}));

vi.mock("./engines/trivy.js", () => ({
  runTrivy: vi.fn(async () => ({
    engine: "trivy",
    version: "0.76.1",
    available: true,
    ran: true,
    durationMs: 1,
    sarif: { version: "2.1.0", runs: [] },
    packages: fault.trivyPackages,
  })),
  readTrivyDbDate: vi.fn(async () => undefined),
}));
vi.mock("./engines/osv-scanner.js", () => ({ runOsvScanner: vi.fn() }));
vi.mock("./synvoya/constants.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./synvoya/constants.js")>()),
  get SYNVOYA_READER_DEADLINE_MS() {
    return fault.deadlineMs;
  },
}));
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
const { scanResultSchema } = await import("./schemas.js");
const { runOsvScanner } = await import("./engines/osv-scanner.js");
const { osvScannerFindingComponents } = await import("./provenance.js");
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
    expect(fresh.synvoya_checked).toEqual({ runtime: [".nvmrc"], images: [], products: [], "inventory:osv-scanner": [], "inventory:trivy": [] });
    const diff = diffRescan(prior, fresh);
    expect(diff.resolved.filter((finding) => finding.engine === "synvoya").map((finding) => finding.rule_id)).toEqual(["SYN-2026-001"]);
  });

  it("keeps the checked-file list in the stored scan only, not in the displayed result", async () => {
    const execution = await executeScan({ path: await project({ ".nvmrc": "20.1.0\n" }), scanners: ["vuln"] }, { persist: false });
    expect(execution.canonical.synvoya_checked).toEqual({ runtime: [".nvmrc"], images: [], products: [], "inventory:osv-scanner": [], "inventory:trivy": [] });
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
      "platform-overrides": { php: "8.0.30" },
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
