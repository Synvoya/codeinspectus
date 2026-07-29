import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import { Ajv } from "ajv";
import { listNativePacks } from "../packs/registry.js";
import type { StoredScanResult } from "../store.js";
import { runBulkScan, type BulkDependencies } from "./index.js";

const cleanup: string[] = [];

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-bulk-test-"));
  cleanup.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function repository(parent: string, name: string): Promise<string> {
  const path = join(parent, name);
  await mkdir(join(path, ".git"), { recursive: true });
  await writeFile(join(path, "source.ts"), `export const name = ${JSON.stringify(name)};\n`);
  return path;
}

function scan(target: string, sequence: number, finding = false): StoredScanResult {
  return {
    scan_id: `scan-00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
    target, repository_root: target, started_at: "2026-07-30T00:00:00.000Z", duration_ms: 1,
    engines_run: ["opengrep@1", "gitleaks@1", "trivy@1"],
    engine_details: ["opengrep", "gitleaks", "trivy"].map((engine) => ({ engine: engine as "opengrep" | "gitleaks" | "trivy", version: "1", available: true, ran: true, finding_count: engine === "opengrep" && finding ? 1 : 0, duration_ms: 1 })),
    offline: true, detected_technologies: [], pack_coverage: listNativePacks().map((pack) => ({
      pack_id: pack.id, version: pack.version, scanner_kind: pack.scannerKind, state: "not_applicable" as const,
      languages: [], frameworks: [], platforms: [], analyzers: { registered: 0, ran: 0 }, rules: { registered: 0, ran: 0 }, limitations: [],
    })),
    summary: { critical: 0, high: finding ? 1 : 0, medium: 0, low: 0, info: 0, total: finding ? 1 : 0 },
    findings: finding ? [{ id: "CI-0001", fingerprint: `fp-${sequence}`, title: "BULK-LEAK-SENTINEL", severity: "high", engine: "opengrep", engines: ["opengrep"], rule_id: "test", cwe: ["CWE-1"], location: { file: "source.ts", start_line: 1, end_line: 1 }, message: "BULK-LEAK-SENTINEL", remediation: { summary: "fix", steps: [], references: [] }, frameworks: [], confidence: "high", producer_components: ["engine:opengrep"] }] : [],
    truncated: false, total_findings_before_limit: finding ? 1 : 0, disclaimer: "test", warnings: [], secret_coverage: "verified", git_safety: { state: "clean" },
    scan_config: { scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 200 },
    storage_schema_version: "2.0.0", canonical_findings: true,
  };
}

function clock(): () => string {
  let tick = 0;
  return () => new Date(Date.UTC(2026, 6, 30, 0, 0, tick++)).toISOString();
}

describe("bounded bulk scanning", () => {
  test("discovers immediate repositories deterministically, bounds concurrency, and isolates finding detail", async () => {
    const root = await temporaryRoot();
    const parent = join(root, "repositories"); await mkdir(parent);
    const repoB = await repository(parent, "b-repo");
    const repoA = await repository(parent, "a-repo");
    const repoC = await repository(parent, "c-repo");
    await mkdir(join(parent, "not-a-repository"));
    const before = await Promise.all([repoA, repoB, repoC].map((repo) => readFile(join(repo, "source.ts"), "utf8")));
    let active = 0; let peak = 0; let sequence = 0;
    let releaseFirstPair!: () => void;
    const firstPairStarted = new Promise<void>((resolve) => { releaseFirstPair = resolve; });
    const dependencies: BulkDependencies = {
      now: clock(),
      scan: vi.fn(async (repo) => {
        active++; peak = Math.max(peak, active);
        if (active === 2) releaseFirstPair();
        await firstPairStarted;
        active--;
        return scan(repo, ++sequence, repo.endsWith("b-repo"));
      }),
    };
    const manifestPath = join(root, "bulk.json");
    const result = await runBulkScan({ parent, manifestPath, concurrency: 2 }, dependencies);
    expect(peak).toBe(2);
    expect(result.manifest.repositories.map((entry) => entry.relative_path)).toEqual(["a-repo", "b-repo", "c-repo"]);
    expect(result.manifest.aggregate).toMatchObject({ coverage: "complete", complete: 3, finding_count: 1 });
    expect(new Set(result.manifest.repositories.map((entry) => entry.scan_id)).size).toBe(3);
    const persisted = await readFile(manifestPath, "utf8");
    expect(persisted).not.toContain("BULK-LEAK-SENTINEL");
    const staticSchema = JSON.parse(await readFile("schemas/codeinspectus-bulk-manifest-1.0.0.schema.json", "utf8"));
    const validate = new Ajv({ strict: false, validateSchema: false, formats: { "date-time": true } }).compile(staticSchema);
    expect(validate(JSON.parse(persisted)), JSON.stringify(validate.errors)).toBe(true);
    expect(await Promise.all([repoA, repoB, repoC].map((repo) => readFile(join(repo, "source.ts"), "utf8")))).toEqual(before);
  });

  test("resumes only failed work and retains completed repository evidence", async () => {
    const root = await temporaryRoot(); const parent = join(root, "repositories"); await mkdir(parent);
    const repoA = await repository(parent, "a"); const repoB = await repository(parent, "b");
    const manifestPath = join(root, "resume.json");
    const firstCalls: string[] = [];
    const first = await runBulkScan({ parent, manifestPath, concurrency: 1 }, {
      now: clock(), scan: async (repo) => { firstCalls.push(repo); if (repo === repoB) throw new Error("isolated failure"); return scan(repo, 1); },
    });
    expect(firstCalls).toEqual([repoA, repoB]);
    expect(first.manifest.aggregate).toMatchObject({ coverage: "unknown", complete: 1, failed: 1 });
    const completedScan = first.manifest.repositories[0]!.scan_id;

    const resumedCalls: string[] = [];
    const resumed = await runBulkScan({ parent, manifestPath, concurrency: 1 }, {
      now: clock(), scan: async (repo) => { resumedCalls.push(repo); return scan(repo, 2); },
    });
    expect(resumed.resumed).toBe(true);
    expect(resumedCalls).toEqual([repoB]);
    expect(resumed.manifest.repositories[0]!.scan_id).toBe(completedScan);
    expect(resumed.manifest.repositories[1]!.attempts).toBe(2);
    expect(resumed.manifest.aggregate).toMatchObject({ coverage: "complete", complete: 2, failed: 0 });
  });

  test("reports repository and cancellation bounds without scanning omitted or pending work", async () => {
    const root = await temporaryRoot(); const parent = join(root, "repositories"); await mkdir(parent);
    await repository(parent, "a"); await repository(parent, "b"); await repository(parent, "c");
    const bounded = await runBulkScan({ parent, manifestPath: join(root, "bounded.json"), maxRepositories: 2 }, {
      now: clock(), scan: async (repo) => scan(repo, repo.endsWith("a") ? 1 : 2),
    });
    expect(bounded.manifest.discovery).toMatchObject({ repositories_found: 3, repositories_selected: 2, repositories_omitted: 1, partial: true });
    expect(bounded.manifest.aggregate).toMatchObject({ coverage: "partial", complete: 2 });

    const controller = new AbortController(); const calls: string[] = [];
    const cancelled = await runBulkScan({ parent, manifestPath: join(root, "cancelled.json"), concurrency: 1, signal: controller.signal }, {
      now: clock(), scan: async (repo) => { calls.push(repo); controller.abort(); throw new Error("stopped"); },
    });
    expect(calls).toHaveLength(1);
    expect(cancelled.manifest.aggregate).toMatchObject({ coverage: "unknown", cancelled: 1, pending: 2 });
  });

  test("rejects manifests inside the parent, symbolic manifests, and mismatched resume configuration", async () => {
    const root = await temporaryRoot(); const parent = join(root, "repositories"); await mkdir(parent); await repository(parent, "a");
    const dependencies: BulkDependencies = { now: clock(), scan: async (repo) => scan(repo, 1) };
    await expect(runBulkScan({ parent, manifestPath: join(parent, "bulk.json") }, dependencies)).rejects.toThrow(/outside|inside/i);
    const destination = join(root, "actual.json"); await writeFile(destination, "{}");
    const link = join(root, "link.json"); await symlink(destination, link);
    await expect(runBulkScan({ parent, manifestPath: link }, dependencies)).rejects.toThrow(/symbolic/i);
    const manifestPath = join(root, "config.json");
    await runBulkScan({ parent, manifestPath, concurrency: 1 }, dependencies);
    await expect(runBulkScan({ parent, manifestPath, concurrency: 2 }, dependencies)).rejects.toThrow(/configuration/i);
  });
});
