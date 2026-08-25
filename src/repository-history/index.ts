import { randomUUID } from "node:crypto";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { MANAGED_REPOSITORY_HISTORY } from "../config.js";
import { createJsonExport } from "../export/model.js";
import { writeExportFile } from "../export/writer.js";
import { detectGitSafety } from "../git-safety.js";
import { findGitRepositoryRoot, materializeGitCommit, resolveGitCommit } from "../git-scope.js";
import { inspectOutputFile, pathIsWithin, requireSafeScanTarget } from "../path-safety.js";
import { redactSnippet } from "../redact.js";
import { executeScan } from "../scan.js";
import { normalizeStoredScanForRuntime, saveScan, type StoredScanResult } from "../store.js";
import type { ScannerKind } from "../types.js";
import { runGitReadBuffer } from "../util/git.js";
import {
  REPOSITORY_HISTORY_SCHEMA_URI,
  REPOSITORY_HISTORY_SCHEMA_VERSION,
  repositoryHistoryManifestSchema,
  type RepositoryHistoryCommitRecord,
  type RepositoryHistoryManifest,
} from "./schemas.js";

export const REPOSITORY_HISTORY_MAX_COMMITS = 50;
export const REPOSITORY_HISTORY_MAX_CHANGES = 10_000;

export interface RepositoryHistoryOptions {
  repository: string;
  from: string;
  to: string;
  since: string;
  until: string;
  maxCommits: number;
  manifestPath?: string;
  scanners?: ScannerKind[];
  maxFindings?: number;
  includeCompliance?: boolean;
  signal?: AbortSignal;
}

export interface RepositoryHistoryResult {
  manifest_path: string;
  manifest: RepositoryHistoryManifest;
}

interface CommitMetadata { commit: string; parents: string[]; committer_at: string }
interface ChangeMetadata { changes: RepositoryHistoryCommitRecord["changes"]; partial: boolean; limitations: string[] }

export interface RepositoryHistoryDependencies {
  scan(snapshot: string, options: RepositoryHistoryOptions): Promise<StoredScanResult>;
  now(): string;
}

const DEFAULT_DEPENDENCIES: RepositoryHistoryDependencies = {
  scan: async (snapshot, options) => {
    const execution = await executeScan({
      path: snapshot,
      ...(options.scanners?.length ? { scanners: options.scanners } : {}),
      max_findings: options.maxFindings,
      include_compliance: options.includeCompliance,
    }, { persist: false });
    return { ...execution.canonical, storage_schema_version: "2.0.0", canonical_findings: true };
  },
  now: () => new Date().toISOString(),
};

function parseBound(value: string, name: string): string {
  const match = value.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/);
  const normalized = Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : "";
  const expected = match ? `${match[1]}.${(match[2] ?? "0").padEnd(3, "0")}Z` : "";
  if (!match || normalized !== expected) {
    throw new Error(`${name} must be an explicit UTC RFC 3339 timestamp (for example 2026-07-01T00:00:00Z).`);
  }
  return normalized;
}

async function commitMetadata(repository: string, commit: string): Promise<CommitMetadata> {
  const result = await runGitReadBuffer(repository, ["show", "-s", "--format=%H%x00%P%x00%cI", commit], { maxBytes: 8 * 1024 });
  const [resolved, parents = "", committed = ""] = result.stdout.toString("utf8").trim().split("\0");
  if (result.code !== 0 || resolved !== commit || !committed || !Number.isFinite(Date.parse(committed))) throw new Error(`Git could not read metadata for commit ${commit}.`);
  return { commit, parents: parents ? parents.split(" ") : [], committer_at: new Date(committed).toISOString() };
}

function safePath(value: string): boolean {
  return Boolean(value) && !value.includes("\\") && !value.startsWith("/") && !value.split("/").some((part) => !part || part === "." || part === "..") && Buffer.byteLength(value) <= 4096;
}

function parseChanges(buffer: Buffer): RepositoryHistoryCommitRecord["changes"] {
  const fields = buffer.toString("utf8").split("\0");
  if (fields.at(-1) === "") fields.pop();
  const changes: RepositoryHistoryCommitRecord["changes"] = [];
  for (let index = 0; index < fields.length;) {
    const code = fields[index++]!;
    const status = code[0];
    const oldPath = status === "R" || status === "C" ? fields[index++] : undefined;
    const path = fields[index++];
    if (!path || !safePath(path) || (oldPath && !safePath(oldPath))) throw new Error("Git returned an unsafe repository-history path.");
    changes.push({
      status: status === "A" || status === "C" ? "added" : status === "D" ? "deleted" : status === "R" ? "renamed" : "modified",
      path,
      ...(oldPath ? { old_path: oldPath } : {}),
    });
  }
  return changes;
}

async function changeMetadata(repository: string, metadata: CommitMetadata): Promise<ChangeMetadata> {
  const args = metadata.parents.length
    ? ["diff", "--name-status", "-z", "--find-renames", "--no-ext-diff", metadata.parents[0]!, metadata.commit]
    : ["diff-tree", "--root", "--no-commit-id", "--name-status", "-r", "-z", "--find-renames", metadata.commit];
  try {
    const result = await runGitReadBuffer(repository, args, { maxBytes: 4 * 1024 * 1024 });
    if (result.code !== 0) throw new Error(result.stderr || "Git change enumeration failed.");
    const changes = parseChanges(result.stdout);
    if (changes.length <= REPOSITORY_HISTORY_MAX_CHANGES) return { changes, partial: false, limitations: [] };
    return {
      changes: changes.slice(0, REPOSITORY_HISTORY_MAX_CHANGES),
      partial: true,
      limitations: [`Change metadata exceeded the ${REPOSITORY_HISTORY_MAX_CHANGES}-entry bound and was truncated.`],
    };
  } catch (error) {
    return { changes: [], partial: true, limitations: [`Change metadata unavailable: ${redactSnippet(error instanceof Error ? error.message : String(error))}`] };
  }
}

function aggregateFor(manifest: Pick<RepositoryHistoryManifest, "discovery" | "commits">): RepositoryHistoryManifest["aggregate"] {
  const count = (state: RepositoryHistoryCommitRecord["state"]): number => manifest.commits.filter((entry) => entry.state === state).length;
  const pending = count("pending"); const complete = count("complete"); const partial = count("partial");
  const unknown = count("unknown"); const failed = count("failed"); const cancelled = count("cancelled");
  const coverage = !manifest.commits.length || pending + unknown + failed + cancelled > 0
    ? "unknown" as const : manifest.discovery.partial || partial > 0 ? "partial" as const : "complete" as const;
  return { coverage, total: manifest.commits.length, pending, complete, partial, unknown, failed, cancelled,
    finding_count: manifest.commits.reduce((sum, entry) => sum + (entry.finding_count ?? 0), 0) };
}

async function enumerateCommits(repository: string, from: string, to: string, since: string, until: string, maxCommits: number): Promise<{ metadata: CommitMetadata[]; truncated: boolean }> {
  const ancestry = await runGitReadBuffer(repository, ["merge-base", "--is-ancestor", from, to], { maxBytes: 1024 });
  if (ancestry.code !== 0) throw new Error("--from must resolve to an ancestor of --to within the local repository history.");
  const fromMeta = await commitMetadata(repository, from);
  const exclusion = fromMeta.parents[0] ? [`^${fromMeta.parents[0]}`] : [];
  const result = await runGitReadBuffer(repository, [
    "rev-list", "--topo-order", `--max-count=${maxCommits + 1}`, `--since=${since}`, `--until=${until}`, to, ...exclusion,
  ], { maxBytes: 128 * 1024 });
  if (result.code !== 0) throw new Error(`Git could not enumerate the bounded history range${result.stderr ? `: ${result.stderr}` : "."}`);
  const newestFirst = result.stdout.toString("utf8").trim().split("\n").filter(Boolean);
  if (!newestFirst.includes(to)) throw new Error("The exact --to revision is outside the requested UTC date window.");
  const truncated = newestFirst.length > maxCommits;
  const selected = newestFirst.slice(0, maxCommits).reverse();
  return { metadata: await Promise.all(selected.map((commit) => commitMetadata(repository, commit))), truncated };
}

export async function runRepositoryHistoryScan(options: RepositoryHistoryOptions, dependencies: RepositoryHistoryDependencies = DEFAULT_DEPENDENCIES): Promise<RepositoryHistoryResult> {
  if (!Number.isInteger(options.maxCommits) || options.maxCommits < 1 || options.maxCommits > REPOSITORY_HISTORY_MAX_COMMITS) throw new Error(`--max-commits must be 1-${REPOSITORY_HISTORY_MAX_COMMITS}.`);
  const maxFindings = options.maxFindings ?? 200;
  if (!Number.isSafeInteger(maxFindings) || maxFindings < 1) throw new Error("--max-findings must be a positive safe integer.");
  const since = parseBound(options.since, "--since"); const until = parseBound(options.until, "--until");
  if (Date.parse(since) > Date.parse(until)) throw new Error("--since must not be later than --until.");
  const inspection = await requireSafeScanTarget(options.repository);
  if (inspection.type !== "directory") throw new Error("Repository-history scanning requires a Git repository directory.");
  const repository = await findGitRepositoryRoot(inspection.canonical_path);
  if (repository !== inspection.canonical_path) throw new Error("Repository-history scanning requires the exact Git repository root, not a subdirectory.");
  const from = await resolveGitCommit(repository, options.from, "--from");
  const to = await resolveGitCommit(repository, options.to, "--to");
  const { metadata, truncated } = await enumerateCommits(repository, from, to, since, until, options.maxCommits);
  const shallowResult = await runGitReadBuffer(repository, ["rev-parse", "--is-shallow-repository"], { maxBytes: 1024 });
  const shallow = shallowResult.code !== 0 || shallowResult.stdout.toString("utf8").trim() !== "false";
  const limitations = [
    ...(truncated ? [`The selected date/revision range exceeded the explicit ${options.maxCommits}-commit limit; only the newest bounded window was scanned.`] : []),
    ...(shallow ? ["The repository is shallow; history outside its local boundary is unavailable."] : []),
  ];
  if (!options.manifestPath) await mkdir(MANAGED_REPOSITORY_HISTORY, { recursive: true });
  const requestedManifest = options.manifestPath ?? join(MANAGED_REPOSITORY_HISTORY, `history-${randomUUID()}.json`);
  const manifestInspection = await inspectOutputFile(requestedManifest, repository, false);
  if (!manifestInspection.safe || !manifestInspection.resolved_path) throw new Error(manifestInspection.error ?? "Unsafe repository-history manifest path.");
  if (manifestInspection.exists) throw new Error("Repository-history manifest already exists; choose a new explicit path.");
  const manifestPath = manifestInspection.resolved_path;
  if (pathIsWithin(repository, manifestPath)) throw new Error("Repository-history manifest must be outside the scanned repository.");
  const created = dependencies.now();
  const manifest: RepositoryHistoryManifest = {
    $schema: REPOSITORY_HISTORY_SCHEMA_URI, schema_version: REPOSITORY_HISTORY_SCHEMA_VERSION,
    run_id: `history-${randomUUID()}`, repository, created_at: created, updated_at: created,
    bounds: { from: { requested: options.from, commit: from }, to: { requested: options.to, commit: to }, since, until,
      max_commits: options.maxCommits, ...(options.scanners?.length ? { scanners: [...new Set(options.scanners)] } : {}), max_findings: maxFindings,
      include_compliance: options.includeCompliance ?? true },
    discovery: { selected_commits: metadata.length, available_at_least: metadata.length + (truncated ? 1 : 0), truncated,
      shallow_repository: shallow, partial: limitations.length > 0, limitations },
    commits: [], aggregate: { coverage: "unknown", total: 0, pending: 0, complete: 0, partial: 0, unknown: 0, failed: 0, cancelled: 0, finding_count: 0 },
  };
  for (const item of metadata) {
    const change = await changeMetadata(repository, item);
    if (change.partial) {
      manifest.discovery.partial = true;
      manifest.discovery.limitations.push(...change.limitations.map((limitation) => `${item.commit}: ${limitation}`));
    }
    manifest.commits.push({ commit: item.commit, parents: item.parents, committer_at: item.committer_at,
      temporal_scope: item.commit === to ? "selected_head" : "historical",
      interpretation: item.commit === to
        ? "Findings are present in the explicitly selected head snapshot; no live-secret verification was performed."
        : "Historical finding presence does not prove that an issue or credential remains active in the selected head or any deployed system.",
      state: "pending", changes: change.changes, change_metadata_partial: change.partial });
  }
  manifest.discovery.limitations = [...new Set(manifest.discovery.limitations)];
  const persist = async (): Promise<void> => {
    manifest.updated_at = dependencies.now(); manifest.aggregate = aggregateFor(manifest);
    const validated = repositoryHistoryManifestSchema.parse(manifest);
    await writeExportFile(manifestPath, `${JSON.stringify(validated, null, 2)}\n`, repository, false);
  };
  await persist();
  for (const [index, record] of manifest.commits.entries()) {
    if (options.signal?.aborted) {
      for (const pending of manifest.commits.slice(index)) { pending.state = "cancelled"; pending.error = "Repository-history scan cancelled before this commit was inspected."; }
      break;
    }
    record.started_at = dependencies.now();
    let snapshot: { directory: string; limitations: string[] } | undefined;
    try {
      snapshot = await materializeGitCommit(repository, record.commit);
      const source = normalizeStoredScanForRuntime(
        await dependencies.scan(snapshot.directory, { ...options, maxFindings, since, until }),
      );
      const snapshotLimitations = [...snapshot.limitations, ...(record.change_metadata_partial ? ["Change metadata was incomplete for this commit."] : [])];
      const temporalScope = record.commit === to ? "selected_head" as const : "historical" as const;
      const canonical: StoredScanResult = {
        ...source, target: repository, repository_root: repository,
        git_safety: await detectGitSafety(repository),
        history_revision: { schema_version: "1.0.0", repository, commit: record.commit, committer_at: record.committer_at,
          temporal_scope: temporalScope, snapshot_completeness: snapshotLimitations.length ? "partial" : "complete", limitations: snapshotLimitations },
        warnings: [...source.warnings,
          temporalScope === "historical"
            ? "Historical snapshot finding presence does not establish current or live exposure."
            : "Selected-head snapshot was scanned offline; potential credentials were not verified against external services.",
          ...snapshotLimitations.map((limitation) => `Repository-history snapshot partial: ${limitation}`)],
        storage_schema_version: "2.0.0", canonical_findings: true,
      };
      await saveScan(normalizeStoredScanForRuntime(canonical), { canonicalFindings: true });
      const coverage = createJsonExport(canonical).coverage.aggregate;
      record.scan_id = canonical.scan_id; record.aggregate_coverage = coverage; record.finding_count = canonical.findings.length; record.state = coverage;
    } catch (error) {
      record.state = options.signal?.aborted ? "cancelled" : "failed";
      record.error = redactSnippet(error instanceof Error ? error.message : String(error));
    } finally {
      if (snapshot) await rm(snapshot.directory, { recursive: true, force: true }).catch(() => undefined);
    }
    record.completed_at = dependencies.now();
    await persist();
  }
  await persist();
  return { manifest_path: manifestPath, manifest: repositoryHistoryManifestSchema.parse(manifest) };
}
