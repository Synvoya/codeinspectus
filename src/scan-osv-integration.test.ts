/**
 * osv-scanner in the scan envelope: findings, dependency coverage, engine records and warnings.
 * The engine modules are mocked, so no binary runs and nothing under ~/.codeinspectus is touched;
 * the Pub engine, technology detection, OSV lockfile detection, routing and dedup are real.
 */
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OsvScanResult } from "./engines/osv-scanner.js";
import type { DependencyCoverage, Finding, ScanResult } from "./types.js";

vi.mock("./engines/trivy.js", () => ({
  runTrivy: vi.fn(async () => ({
    engine: "trivy",
    version: "0.76.1",
    available: false,
    ran: false,
    durationMs: 1,
    note: "test fixture: Trivy unavailable",
  })),
  readTrivyDbDate: vi.fn(async () => undefined),
}));
vi.mock("./engines/osv-scanner.js", () => ({ runOsvScanner: vi.fn() }));
vi.mock("./store.js", () => ({ saveScan: vi.fn(async () => undefined) }));

const { executeScan } = await import("./scan.js");
const { scanResultSchema } = await import("./schemas.js");
const { runOsvScanner } = await import("./engines/osv-scanner.js");
const { runTrivy } = await import("./engines/trivy.js");
const { osvScannerFindingComponents } = await import("./provenance.js");
const { assessAggregateCoverage } = await import("./export/model.js");

const PUB_TP = resolve(process.cwd(), "fixtures/pub-sca-corpus/tp");
const roots: string[] = [];

async function project(files: Record<string, string>): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "ci-osv-scan-")));
  roots.push(root);
  for (const [name, content] of Object.entries(files)) await writeFile(join(root, name), content, "utf8");
  return root;
}

function info(over: Partial<OsvScanResult["info"]> = {}): OsvScanResult["info"] {
  return { engine: "osv-scanner", version: "2.7.0", available: true, ran: true, finding_count: 0, duration_ms: 1, ...over };
}

function osvFinding(
  file: string,
  ecosystem: string,
  name: string,
  version: string,
  ruleId: string,
  over: Partial<Finding> = {},
): Finding {
  const fingerprint = `sha256:${ecosystem}-${name}-${version}-${ruleId}`;
  return {
    id: fingerprint,
    fingerprint,
    title: `Advisory (${name}@${version})`,
    severity: "high",
    engine: "osv-scanner",
    engines: ["osv-scanner"],
    rule_id: ruleId,
    cwe: ["CWE-1395"],
    owasp_web: ["A06:2021"],
    location: { file, start_line: 1, end_line: 1 },
    message: `${file} resolves ${ecosystem} package ${name}@${version}.`,
    remediation: { summary: "upgrade", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    producer_components: osvScannerFindingComponents(ecosystem),
    finding_kind: "vulnerability",
    package: { ecosystem, name, version },
    ...over,
  };
}

function coverage(ecosystem: string, over: Partial<DependencyCoverage> = {}): DependencyCoverage {
  return {
    ecosystem,
    engine: "osv-scanner",
    state: "ran",
    lockfiles: { discovered: 1, analyzed: 1 },
    packages: { resolved: 3, eligible: 3, skipped: 0 },
    database_version: "2026-10-30T00:00:00.000Z",
    matching: "osv-scanner-offline",
    limitations: [],
    ...over,
  };
}

function osvResult(over: Partial<OsvScanResult> = {}): OsvScanResult {
  // The files osv-scanner listed packages from default to those its findings name.
  const lockfiles = [...new Set((over.findings ?? []).map((finding) => finding.location.file))].sort();
  return { info: info(), applicable: true, findings: [], coverage: [], lockfiles, componentSignatures: {}, warnings: [], ...over };
}

const SIGNATURES = {
  "osv-scanner:binary": "sha256:binary",
  "osv-scanner:invocation": "sha256:invocation",
  "osv-scanner:config": "sha256:config",
  "osv-scanner:vulnerability-db:PyPI": "sha256:pypi-db",
};

const NOT_INSTALLED =
  "Engine 'osv-scanner' is not available. Run `codeinspectus setup` (or the codeinspectus_setup tool) once per machine " +
  "to review, fetch and SHA-pin the engine binaries; downloads happen only after approval. Expected at: /managed/bin/osv-scanner.";

async function scan(path: string): Promise<ScanResult> {
  return (await executeScan({ path, scanners: ["vuln"] }, { persist: false })).canonical;
}

function aggregate(result: ScanResult): string {
  return assessAggregateCoverage({ ...result, canonical_findings: true, storage_schema_version: "2.0.0" }).aggregate;
}

/** Ruling 17: with native Pub coverage, osv-scanner's Pub gap is a note in the export coverage assessment. */
function osvEvidenceStates(result: ScanResult): string[] {
  return assessAggregateCoverage({ ...result, canonical_findings: true, storage_schema_version: "2.0.0" }).evidence
    .filter((item) => item.component.includes("osv-scanner"))
    .map((item) => item.state);
}

function osvCoverage(result: ScanResult): DependencyCoverage[] {
  return (result.dependency_coverage ?? []).filter((entry) => entry.engine === "osv-scanner");
}

beforeEach(() => {
  vi.mocked(runOsvScanner).mockReset();
});

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("scan orchestrator osv-scanner integration", () => {
  it("osv findings and coverage appear in the scan envelope; a run with no package sources is recorded with no findings", async () => {
    const root = await project({ "requirements.txt": "litellm==1.107.0\nBrotli==1.2.0\nbrotlicffi==1.2.0.2\n" });
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      info: info({ finding_count: 3 }),
      findings: [
        osvFinding("requirements.txt", "PyPI", "litellm", "1.107.0", "MAL-2026-2144", { severity: "critical", cwe: ["CWE-506"] }),
        osvFinding("requirements.txt", "PyPI", "Brotli", "1.2.0", "CVE-2026-111497", { location: { file: "requirements.txt", start_line: 2, end_line: 2 } }),
        osvFinding("requirements.txt", "PyPI", "brotlicffi", "1.2.0.2", "CVE-2026-111497", { location: { file: "requirements.txt", start_line: 3, end_line: 3 } }),
      ],
      coverage: [coverage("PyPI")],
      componentSignatures: SIGNATURES,
    }));

    const result = await scan(root);

    expect(scanResultSchema.parse(result)).toEqual(result);
    expect(vi.mocked(runOsvScanner)).toHaveBeenCalledWith(root, expect.any(String));
    const osv = result.findings.filter((finding) => finding.engines.includes("osv-scanner"));
    expect(osv.map((finding) => `${finding.rule_id} ${finding.package?.name}`).sort()).toEqual([
      "CVE-2026-111497 Brotli",
      "CVE-2026-111497 brotlicffi",
      "MAL-2026-2144 litellm",
    ]);
    const malware = osv.find((finding) => finding.rule_id === "MAL-2026-2144")!;
    expect(malware.frameworks.length).toBeGreaterThan(0);
    expect(result.dependency_coverage?.[0]).toMatchObject({ engine: "codeinspectus-pub", ecosystem: "Pub" });
    expect(osvCoverage(result)).toEqual([coverage("PyPI")]);
    expect(result.engine_details).toContainEqual(expect.objectContaining({ engine: "osv-scanner", ran: true, finding_count: 3 }));
    expect(result.engines_run).toContain("osv-scanner@2.7.0");
    expect(result.component_signatures).toMatchObject(SIGNATURES);
    // The Trivy mock reports itself as unavailable; osv-scanner adds nothing to warn about.
    expect(result.warnings.filter((warning) => /osv/i.test(warning))).toEqual([]);

    const empty = await project({ "index.js": "export {};\n" });
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({ componentSignatures: { "osv-scanner:binary": "sha256:binary" } }));
    const noSources = await scan(empty);
    expect(noSources.engine_details).toContainEqual(expect.objectContaining({ engine: "osv-scanner", ran: true, finding_count: 0 }));
    expect(osvCoverage(noSources)).toEqual([]);
    expect(noSources.component_signatures?.["osv-scanner:binary"]).toBe("sha256:binary");
    expect(noSources.warnings.filter((warning) => /osv/i.test(warning))).toEqual([]);
  });

  it("a completed run on a repo without lockfiles leaves aggregate coverage unchanged once another engine covered the scan", async () => {
    const trivyRan = { engine: "trivy" as const, version: "0.76.1", available: true, ran: true, durationMs: 1 };
    const root = await project({ "index.js": "export {};\n" });
    vi.mocked(runTrivy).mockResolvedValueOnce(trivyRan);
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      info: info({ available: false, ran: false, version: "unknown", note: NOT_INSTALLED }),
      applicable: false,
      warnings: [NOT_INSTALLED],
    }));
    const declined = await scan(root);
    vi.mocked(runTrivy).mockResolvedValueOnce(trivyRan);
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({ componentSignatures: SIGNATURES }));
    const installed = await scan(root);

    expect(installed.engine_details).toContainEqual(expect.objectContaining({ engine: "osv-scanner", ran: true, finding_count: 0 }));
    expect(osvCoverage(installed)).toEqual([]);
    expect(aggregate(installed)).toBe(aggregate(declined));
  });

  it("osv-scanner not installed: warning, no engine_details entry, aggregate coverage unchanged", async () => {
    // A detected lockfile must not invent osv coverage when osv-scanner never ran. Trivy runs in both scans,
    // so the comparison is not between two aggregates that are already "unknown" for another reason.
    const trivyRan = { engine: "trivy" as const, version: "0.76.1", available: true, ran: true, durationMs: 1 };
    const root = await project({ "requirements.txt": "requests==2.19.0\n" });
    vi.mocked(runTrivy).mockResolvedValueOnce(trivyRan).mockResolvedValueOnce(trivyRan);
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      info: info({ available: false, ran: false, version: "unknown", note: NOT_INSTALLED }),
      applicable: false,
      warnings: [NOT_INSTALLED],
    }));
    const missing = await scan(root);

    // Reference: osv-scanner not installed and nothing for it to find.
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      info: info({ available: false, ran: false, version: "unknown", note: NOT_INSTALLED }),
      applicable: false,
      warnings: [NOT_INSTALLED],
    }));
    const reference = await scan(await project({ "index.js": "export {};\n" }));

    expect(missing.warnings.filter((warning) => warning === NOT_INSTALLED)).toHaveLength(1);
    expect(missing.warnings.some((warning) => /osv-scanner did not run/.test(warning))).toBe(false);
    expect(missing.engine_details.some((engine) => engine.engine === "osv-scanner")).toBe(false);
    expect(osvCoverage(missing)).toEqual([]);
    // No osv-scanner evidence at all, so it cannot move the aggregate in either direction.
    expect(osvEvidenceStates(missing)).toEqual([]);
    expect(aggregate(reference)).not.toBe("unknown");
    expect(aggregate(missing)).toBe(aggregate(reference));
  });

  it("a failed run is warned once, recorded as not run, and adds no reconciled coverage", async () => {
    const root = await project({ "requirements.txt": "requests==2.19.0\n", "composer.lock": "{}\n" });
    const failure = "osv-scanner timed out before producing results.";
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      info: info({ ran: false, note: failure }),
      warnings: [failure],
    }));

    const result = await scan(root);

    expect(result.warnings.filter((warning) => warning.includes(failure))).toHaveLength(1);
    expect(result.engine_details).toContainEqual(expect.objectContaining({ engine: "osv-scanner", ran: false, note: failure }));
    expect(osvCoverage(result)).toEqual([]);
  });

  it("Ruling 13/31: an allow-listed ecosystem detected by lockfile name but absent from osv-scanner output is a partial note, not a warning", async () => {
    const root = await project({ "requirements.txt": "requests==2.19.0\n", "composer.lock": "{}\n" });
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      coverage: [coverage("PyPI")], lockfiles: ["requirements.txt"], componentSignatures: SIGNATURES,
    }));

    const result = await scan(root);

    expect(osvCoverage(result).map((entry) => `${entry.ecosystem}=${entry.state}`)).toEqual(["PyPI=ran", "Packagist=partial"]);
    expect(osvCoverage(result)[1]).toMatchObject({
      note: "no packages extracted from composer.lock (empty lockfile or unsupported format)",
      lockfiles: { discovered: 0, analyzed: 0 },
      packages: { resolved: 0, eligible: 0, skipped: 0 },
      matching: "osv-scanner-offline",
    });
    expect(result.warnings.filter((warning) => /osv|Packagist|composer/i.test(warning))).toEqual([]);
    // Never silent: the gap still makes aggregate coverage partial.
    expect(aggregate(result)).toBe("partial");
    expect(osvEvidenceStates(result)).toContain("partial");
  });

  it("Ruling 13/31: osv-scanner ran but listed no packages although a lockfile was detected", async () => {
    const root = await project({ "requirements.txt": "requests==2.19.0\n" });
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({ componentSignatures: SIGNATURES }));

    const result = await scan(root);

    expect(osvCoverage(result)).toEqual([expect.objectContaining({
      ecosystem: "PyPI",
      state: "partial",
      note: "no packages extracted from requirements.txt (empty lockfile or unsupported format)",
    })]);
    expect(result.engine_details).toContainEqual(expect.objectContaining({ engine: "osv-scanner", ran: true, finding_count: 0 }));
    expect(result.warnings.filter((warning) => /osv|requirements|PyPI/i.test(warning))).toEqual([]);
  });

  it("Ruling 31: a dependency-less lockfile is a partial coverage note naming it, with no scan warning", async () => {
    // A package-lock.json with only the root entry: real osv-scanner 2.7.0 lists no source for it (exit 0).
    const root = await project({
      "requirements.txt": "requests==2.19.0\n",
      "package-lock.json": '{"name":"x","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","version":"1.0.0"}}}\n',
    });
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      coverage: [coverage("PyPI")], lockfiles: ["requirements.txt"], componentSignatures: SIGNATURES,
    }));

    const result = await scan(root);

    expect(osvCoverage(result).map((entry) => `${entry.ecosystem}=${entry.state}`)).toEqual(["npm=partial", "PyPI=ran"]);
    expect(osvCoverage(result)[0]!.note).toBe("no packages extracted from package-lock.json (empty lockfile or unsupported format)");
    expect(result.warnings.filter((warning) => /osv|lockfile|npm/i.test(warning))).toEqual([]);
    expect(aggregate(result)).toBe("partial");
  });

  it("Ruling 31: an empty second lockfile is noted even when osv-scanner listed its ecosystem from another one", async () => {
    const root = await project({ "requirements.txt": "requests==2.19.0\n" });
    await mkdir(join(root, "services"));
    await writeFile(join(root, "services", "requirements.txt"), "# no pins yet\n", "utf8");
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      coverage: [coverage("PyPI")], lockfiles: ["requirements.txt"], componentSignatures: SIGNATURES,
    }));

    const result = await scan(root);

    expect(osvCoverage(result)).toEqual([expect.objectContaining({
      ecosystem: "PyPI",
      state: "partial",
      packages: { resolved: 3, eligible: 3, skipped: 0 },
      note: "no packages extracted from services/requirements.txt (empty lockfile or unsupported format)",
    })]);
    expect(osvCoverage(result)[0]!.limitations.join(" ")).toContain("listed no packages from it");
    expect(result.warnings.filter((warning) => /osv|requirements|PyPI/i.test(warning))).toEqual([]);
    expect(aggregate(result)).toBe("partial");
  });

  it("Ruling 31: the note names each detected lockfile osv-scanner listed nothing from, without control characters", async () => {
    const root = await project({ "package-lock.json": "{}\n", "yarn.lock": "# yarn lockfile v1\n" });
    // C0, newline, C1 NEL, line separator, a bidirectional override and a zero-width space. Windows
    // forbids C0 characters in names (public CI, win32-x64: EINVAL), so there the folder holds the rest.
    const directory = process.platform === "win32" ? "app\u0085\u2028\u202e\u200bweb" : "app\u0007\n\u0085\u2028\u202e\u200bweb";
    await mkdir(join(root, directory));
    await writeFile(join(root, directory, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n", "utf8");
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({ componentSignatures: SIGNATURES }));

    const result = await scan(root);

    expect(osvCoverage(result)).toEqual([expect.objectContaining({
      ecosystem: "npm",
      state: "partial",
      note: "no packages extracted from appweb/pnpm-lock.yaml, package-lock.json, yarn.lock (empty lockfile or unsupported format)",
    })]);
    expect(result.warnings.filter((warning) => /osv|lockfile|npm/i.test(warning))).toEqual([]);
  });

  it("Ruling 12: with native Pub coverage, a missing OSV Pub database is a coverage note, not a scan warning", async () => {
    const nag = "osv-scanner found 9 Pub packages, but the OSV Pub database is not installed, so they were not checked. Run `codeinspectus setup` to review and download it.";
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      info: info({ ran: false, note: nag }),
      coverage: [coverage("Pub", {
        state: "unavailable",
        lockfiles: { discovered: 1, analyzed: 0 },
        packages: { resolved: 9, eligible: 0, skipped: 9 },
        database_version: undefined,
        limitations: [nag],
        note: nag,
      })],
      warnings: [nag],
    }));

    const result = await scan(PUB_TP);

    expect(result.dependency_coverage?.[0]).toMatchObject({ engine: "codeinspectus-pub", state: "partial" });
    expect(result.warnings.join("\n")).not.toContain("OSV Pub database");
    const pub = osvCoverage(result);
    expect(pub).toHaveLength(1);
    expect(pub[0]).toMatchObject({ ecosystem: "Pub", state: "unavailable" });
    expect(pub[0]!.note).toContain("OSV Pub database is not installed");
    expect(pub[0]!.note).toContain("codeinspectus-pub");
    const engine = result.engine_details.find((detail) => detail.engine === "osv-scanner");
    expect(engine).toMatchObject({ ran: false });
    expect(engine?.note).not.toContain("codeinspectus setup");
    expect(osvEvidenceStates(result).length).toBeGreaterThan(0);
    expect(new Set(osvEvidenceStates(result))).toEqual(new Set(["informational"]));
  });

  it("Ruling 32: a failed run stays a failure warning even when its stderr names the Pub database and native Pub ran", async () => {
    // The note quotes stderr, which a crafted repository path can forge, so it never becomes a coverage note.
    const failure =
      "osv-scanner exited with code 127 and no usable result. Cause: could not load db for Pub ecosystem: unable to fetch OSV database: " +
      "no offline version of the OSV database is available. An OSV database could not be read: run `codeinspectus setup` to reinstall it.";
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({ info: info({ ran: false, note: failure }), warnings: [failure] }));

    const result = await scan(PUB_TP);

    expect(result.dependency_coverage?.[0]).toMatchObject({ engine: "codeinspectus-pub" });
    expect(result.warnings.filter((warning) => warning === failure)).toHaveLength(1);
    expect(osvCoverage(result)).toEqual([]);
    expect(result.engine_details).toContainEqual(expect.objectContaining({ engine: "osv-scanner", ran: false, note: failure }));
  });

  it("Ruling 12 does not hide a missing Pub database that also stopped osv-scanner checking other ecosystems", async () => {
    const root = await project({ "pubspec.lock": "packages: {}\n", "package-lock.json": "{\"lockfileVersion\": 3, \"packages\": {}}\n" });
    const failure = "osv-scanner exited with code 127 and no usable result. Cause: could not load db for Pub ecosystem: unable to fetch OSV database.";
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({ info: info({ ran: false, note: failure }), warnings: [failure] }));

    const result = await scan(root);

    expect(result.warnings.filter((warning) => warning.includes("could not load db for Pub ecosystem"))).toHaveLength(1);
    expect(osvCoverage(result)).toEqual([]);
  });

  it("keeps Finding.package through git-ignored reframing and dedup", async () => {
    const root = await project({ "requirements.txt": "Brotli==1.2.0\n", ".gitignore": "requirements.txt\n" });
    await promisify(execFile)("git", ["init", "-q"], { cwd: root });
    vi.mocked(runOsvScanner).mockResolvedValueOnce(osvResult({
      findings: [
        osvFinding("requirements.txt", "PyPI", "Brotli", "1.2.0", "CVE-2026-111497"),
        osvFinding("requirements.txt", "PyPI", "brotli", "1.2.0", "CVE-2026-111497", { fingerprint: "sha256:second", id: "sha256:second", vulnerability_aliases: ["GHSA-test-0000-0005"] }),
      ],
      coverage: [coverage("PyPI")],
      componentSignatures: SIGNATURES,
    }));

    const result = await scan(root);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.title).toMatch(/^Local hygiene/);
    expect(result.findings[0]!.package).toMatchObject({ ecosystem: "PyPI", version: "1.2.0" });
    expect(result.findings[0]!.vulnerability_aliases).toContain("GHSA-test-0000-0005");
  });
});
