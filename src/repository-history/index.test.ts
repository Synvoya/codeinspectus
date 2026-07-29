import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterEach, describe, expect, test } from "vitest";
import { listNativePacks } from "../packs/registry.js";
import type { StoredScanResult } from "../store.js";
import { runRepositoryHistoryScan, type RepositoryHistoryDependencies } from "./index.js";

const cleanup: string[] = [];
// These cases build and traverse real Git histories. Give only this integration suite enough time
// for slower CI filesystems while leaving Vitest's unit-test timeout unchanged everywhere else.
const GIT_INTEGRATION_TEST_TIMEOUT_MS = 30_000;
afterEach(async () => { await Promise.all(cleanup.splice(0).map((entry) => rm(entry, { recursive: true, force: true }))); });

function git(repository: string, args: string[], date?: string): string {
  return execFileSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...(date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : {}) },
  }).trim();
}

async function repositoryWithHistory(): Promise<{ root: string; repository: string; commits: string[] }> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-repository-history-test-")); cleanup.push(root);
  const repository = join(root, "repository"); await mkdir(repository);
  git(repository, ["init", "-q", "--initial-branch=master"]); git(repository, ["config", "user.name", "Test"]); git(repository, ["config", "user.email", "test@example.com"]);
  await writeFile(join(repository, "historical-secret.txt"), "HISTORY-LEAK-SENTINEL\n");
  git(repository, ["add", "."]); git(repository, ["commit", "-q", "-m", "root"], "2026-07-01T00:00:00Z"); const first = git(repository, ["rev-parse", "HEAD"]);
  git(repository, ["checkout", "-q", "-b", "feature"]);
  await writeFile(join(repository, "feature.txt"), "feature\n"); git(repository, ["add", "."]); git(repository, ["commit", "-q", "-m", "feature"], "2026-07-02T00:00:00Z"); const feature = git(repository, ["rev-parse", "HEAD"]);
  git(repository, ["checkout", "-q", "master"]);
  await rename(join(repository, "historical-secret.txt"), join(repository, "renamed.txt")); git(repository, ["add", "-A"]); git(repository, ["commit", "-q", "-m", "rename"], "2026-07-03T00:00:00Z"); const renamed = git(repository, ["rev-parse", "HEAD"]);
  git(repository, ["merge", "-q", "--no-ff", "feature", "-m", "merge"], "2026-07-04T00:00:00Z"); const merged = git(repository, ["rev-parse", "HEAD"]);
  await rm(join(repository, "renamed.txt")); git(repository, ["add", "-A"]); git(repository, ["commit", "-q", "-m", "delete"], "2026-07-05T00:00:00Z"); const deleted = git(repository, ["rev-parse", "HEAD"]);
  return { root, repository, commits: [first, feature, renamed, merged, deleted] };
}

function fakeScan(target: string, sequence: number): StoredScanResult {
  const finding = sequence === 1;
  return {
    scan_id: `scan-00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
    target, started_at: "2026-07-30T00:00:00.000Z", duration_ms: 1,
    engines_run: ["opengrep@1", "gitleaks@1", "trivy@1"],
    engine_details: ["opengrep", "gitleaks", "trivy"].map((engine) => ({ engine: engine as "opengrep" | "gitleaks" | "trivy", version: "1", available: true, ran: true, finding_count: engine === "opengrep" && finding ? 1 : 0, duration_ms: 1 })),
    offline: true, detected_technologies: [], pack_coverage: listNativePacks().map((pack) => ({
      pack_id: pack.id, version: pack.version, scanner_kind: pack.scannerKind, state: "not_applicable" as const,
      languages: [], frameworks: [], platforms: [], analyzers: { registered: 0, ran: 0 }, rules: { registered: 0, ran: 0 }, limitations: [],
    })),
    summary: { critical: 0, high: finding ? 1 : 0, medium: 0, low: 0, info: 0, total: finding ? 1 : 0 },
    findings: finding ? [{ id: "CI-0001", fingerprint: "history-fp", title: "HISTORY-LEAK-SENTINEL", severity: "high", engine: "opengrep", engines: ["opengrep"], rule_id: "history-test", cwe: ["CWE-1"], location: { file: "historical-secret.txt", start_line: 1, end_line: 1 }, message: "HISTORY-LEAK-SENTINEL", remediation: { summary: "fix", steps: [], references: [] }, frameworks: [], confidence: "high", producer_components: ["engine:opengrep"] }] : [],
    truncated: false, total_findings_before_limit: finding ? 1 : 0, disclaimer: "test", warnings: [], secret_coverage: "verified",
    git_safety: { state: "no_git" }, scan_config: { max_findings: 200 }, storage_schema_version: "2.0.0", canonical_findings: true,
  };
}

function clock(): () => string { let tick = 0; return () => new Date(Date.UTC(2026, 6, 30, 0, 0, tick++)).toISOString(); }
function options(repository: string, from: string, to: string, manifestPath: string, maxCommits = 10) {
  return { repository, from, to, since: "2026-07-01T00:00:00Z", until: "2026-07-31T00:00:00Z", maxCommits, manifestPath };
}

describe("bounded repository-history scanning", () => {
  test("scans exact immutable snapshots, records merges/renames/deletions, and isolates finding detail", async () => {
    const fixture = await repositoryWithHistory(); let sequence = 0; const seen: string[] = [];
    const beforeHead = git(fixture.repository, ["rev-parse", "HEAD"]); const beforeStatus = git(fixture.repository, ["status", "--porcelain"]);
    const result = await runRepositoryHistoryScan(options(fixture.repository, fixture.commits[0]!, fixture.commits[4]!, join(fixture.root, "manifest.json")), {
      now: clock(), scan: async (snapshot) => { seen.push(snapshot); return fakeScan(snapshot, ++sequence); },
    });
    expect(result.manifest.commits).toHaveLength(5);
    expect(result.manifest.commits.at(-1)).toMatchObject({ commit: fixture.commits[4], temporal_scope: "selected_head", state: "complete" });
    expect(result.manifest.commits.filter((entry) => entry.temporal_scope === "historical")).toHaveLength(4);
    expect(result.manifest.commits.some((entry) => entry.parents.length === 2)).toBe(true);
    expect(result.manifest.commits.flatMap((entry) => entry.changes).some((entry) => entry.status === "renamed" && entry.old_path === "historical-secret.txt" && entry.path === "renamed.txt")).toBe(true);
    expect(result.manifest.commits.flatMap((entry) => entry.changes).some((entry) => entry.status === "deleted" && entry.path === "renamed.txt")).toBe(true);
    expect(result.manifest.aggregate).toMatchObject({ coverage: "complete", complete: 5, finding_count: 1 });
    expect(seen).toHaveLength(5);
    const persisted = await readFile(result.manifest_path, "utf8");
    expect(persisted).not.toContain("HISTORY-LEAK-SENTINEL");
    const schema = JSON.parse(await readFile("schemas/codeinspectus-repository-history-manifest-1.0.0.schema.json", "utf8"));
    const validate = new Ajv2020({ strict: false, validateSchema: false, formats: { "date-time": true } }).compile(schema);
    expect(validate(JSON.parse(persisted)), JSON.stringify(validate.errors)).toBe(true);
    expect(git(fixture.repository, ["rev-parse", "HEAD"])).toBe(beforeHead);
    expect(git(fixture.repository, ["status", "--porcelain"])).toBe(beforeStatus);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("retains the selected head but reports partial when the explicit commit limit is reached", async () => {
    const fixture = await repositoryWithHistory(); let sequence = 0;
    const result = await runRepositoryHistoryScan(options(fixture.repository, fixture.commits[0]!, fixture.commits[4]!, join(fixture.root, "bounded.json"), 2), {
      now: clock(), scan: async (snapshot) => fakeScan(snapshot, ++sequence),
    });
    expect(result.manifest.commits).toHaveLength(2);
    expect(result.manifest.commits.at(-1)?.commit).toBe(fixture.commits[4]);
    expect(result.manifest.discovery).toMatchObject({ truncated: true, partial: true, available_at_least: 3 });
    expect(result.manifest.aggregate.coverage).toBe("partial");
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("marks shallow history partial and rejects unsafe or ambiguous scope", async () => {
    const fixture = await repositoryWithHistory(); const shallow = join(fixture.root, "shallow");
    execFileSync("git", ["clone", "-q", "--depth", "1", pathToFileURL(fixture.repository).href, shallow]);
    const head = git(shallow, ["rev-parse", "HEAD"]); let sequence = 0;
    const result = await runRepositoryHistoryScan(options(shallow, head, head, join(fixture.root, "shallow.json")), { now: clock(), scan: async (snapshot) => fakeScan(snapshot, ++sequence) });
    expect(result.manifest.discovery).toMatchObject({ shallow_repository: true, partial: true });
    expect(result.manifest.aggregate.coverage).toBe("partial");
    await expect(runRepositoryHistoryScan(options(fixture.repository, fixture.commits[0]!, fixture.commits[4]!, join(fixture.repository, "inside.json")), { now: clock(), scan: async (snapshot) => fakeScan(snapshot, 1) })).rejects.toThrow(/outside|inside/i);
    await expect(runRepositoryHistoryScan({ ...options(fixture.repository, fixture.commits[0]!, fixture.commits[4]!, join(fixture.root, "bad-date.json")), since: "yesterday" }, { now: clock(), scan: async (snapshot) => fakeScan(snapshot, 1) })).rejects.toThrow(/RFC 3339/i);
    await expect(runRepositoryHistoryScan({ ...options(fixture.repository, fixture.commits[0]!, fixture.commits[4]!, join(fixture.root, "rolled-date.json")), since: "2026-02-30T00:00:00Z" }, { now: clock(), scan: async (snapshot) => fakeScan(snapshot, 1) })).rejects.toThrow(/RFC 3339/i);
    await expect(runRepositoryHistoryScan(options(fixture.repository, fixture.commits[4]!, fixture.commits[0]!, join(fixture.root, "reverse.json")), { now: clock(), scan: async (snapshot) => fakeScan(snapshot, 1) })).rejects.toThrow(/ancestor/i);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("cancellation persists explicit cancelled work without scanning later commits", async () => {
    const fixture = await repositoryWithHistory(); const controller = new AbortController(); let calls = 0;
    const result = await runRepositoryHistoryScan({ ...options(fixture.repository, fixture.commits[0]!, fixture.commits[4]!, join(fixture.root, "cancelled.json")), signal: controller.signal }, {
      now: clock(), scan: async (snapshot) => { calls++; controller.abort(); throw new Error("cancelled"); },
    });
    expect(calls).toBe(1);
    expect(result.manifest.aggregate).toMatchObject({ coverage: "unknown", cancelled: 5 });
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);
});
