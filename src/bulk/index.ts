import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, opendir, realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { MANAGED_BULK } from "../config.js";
import { createJsonExport } from "../export/model.js";
import { writeExportFile } from "../export/writer.js";
import { inspectOutputFile, pathIsWithin, requireSafeScanTarget } from "../path-safety.js";
import { redactSnippet } from "../redact.js";
import { executeScan } from "../scan.js";
import type { StoredScanResult } from "../store.js";
import { SEVERITY_RANK, type ScannerKind, type Severity } from "../types.js";
import { BULK_SCHEMA_URI, BULK_SCHEMA_VERSION, bulkManifestSchema, type BulkManifest, type BulkRepositoryRecord } from "./schemas.js";

export const BULK_PARENT_ENTRY_LIMIT = 10_000;
export const BULK_DEFAULT_CONCURRENCY = 2;
export const BULK_MAX_CONCURRENCY = 8;
export const BULK_DEFAULT_MAX_REPOSITORIES = 50;
export const BULK_MAX_REPOSITORIES = 500;
export const BULK_DEFAULT_MAX_ATTEMPTS = 2;
export const BULK_MANIFEST_MAX_BYTES = 2 * 1024 * 1024;

export interface BulkScanOptions {
  parent: string;
  manifestPath?: string;
  concurrency?: number;
  maxRepositories?: number;
  maxAttempts?: number;
  scanners?: ScannerKind[];
  maxFindings?: number;
  includeCompliance?: boolean;
  signal?: AbortSignal;
}

export interface BulkRunResult {
  manifest_path: string;
  resumed: boolean;
  manifest: BulkManifest;
}

export interface BulkDependencies {
  scan(repository: string, options: BulkScanOptions): Promise<StoredScanResult>;
  now(): string;
}

const DEFAULT_DEPENDENCIES: BulkDependencies = {
  scan: async (repository, options) => {
    const execution = await executeScan({
      path: repository,
      ...(options.scanners?.length ? { scanners: options.scanners } : {}),
      max_findings: options.maxFindings,
      include_compliance: options.includeCompliance,
    });
    return { ...execution.canonical, storage_schema_version: "2.0.0", canonical_findings: true };
  },
  now: () => new Date().toISOString(),
};

function compareText(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }

function highestSeverity(scan: StoredScanResult): Severity | undefined {
  return scan.findings.reduce<Severity | undefined>((highest, finding) =>
    !highest || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest] ? finding.severity : highest, undefined);
}

function aggregateFor(manifest: Pick<BulkManifest, "discovery" | "repositories">): BulkManifest["aggregate"] {
  const count = (state: BulkRepositoryRecord["state"]): number => manifest.repositories.filter((entry) => entry.state === state).length;
  const pending = count("pending");
  const running = count("running");
  const complete = count("complete");
  const partial = count("partial");
  const unknown = count("unknown");
  const failed = count("failed");
  const cancelled = count("cancelled");
  const unresolved = pending + running + unknown + failed + cancelled;
  const coverage = !manifest.repositories.length || unresolved > 0
    ? "unknown" as const
    : manifest.discovery.partial || partial > 0 ? "partial" as const : "complete" as const;
  return {
    coverage, total: manifest.repositories.length, pending, running, complete, partial, unknown, failed, cancelled,
    finding_count: manifest.repositories.reduce((sum, entry) => sum + (entry.finding_count ?? 0), 0),
  };
}

async function safeReadManifest(path: string): Promise<BulkManifest> {
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > BULK_MANIFEST_MAX_BYTES) throw new Error("Bulk manifest is not a bounded regular file.");
    const buffer = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (offset !== buffer.length || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      throw new Error("Bulk manifest changed during bounded inspection.");
    }
    let parsed: unknown;
    try { parsed = JSON.parse(buffer.toString("utf8")); }
    catch { throw new Error("Bulk manifest is not valid JSON."); }
    return bulkManifestSchema.parse(parsed);
  } finally {
    await handle.close();
  }
}

async function discoverRepositories(parent: string, maxRepositories: number): Promise<{
  repositories: Array<{ repository: string; relative_path: string }>;
  discovery: BulkManifest["discovery"];
}> {
  const limitations: string[] = [];
  const names: string[] = [];
  const directory = await opendir(parent);
  try {
    for await (const entry of directory) {
      names.push(entry.name);
      if (names.length > BULK_PARENT_ENTRY_LIMIT) {
        limitations.push(`Parent contains more than the ${BULK_PARENT_ENTRY_LIMIT}-entry deterministic discovery bound; no repositories were selected.`);
        return { repositories: [], discovery: {
          entry_limit: BULK_PARENT_ENTRY_LIMIT, candidate_entries: names.length, repositories_found: 0,
          repositories_selected: 0, repositories_omitted: 0, partial: true, limitations,
        } };
      }
    }
  } finally {
    await directory.close().catch(() => undefined);
  }
  names.sort(compareText);
  const found: Array<{ repository: string; relative_path: string }> = [];
  for (const name of names) {
    const candidate = join(parent, name);
    try {
      const metadata = await lstat(candidate);
      if (metadata.isSymbolicLink()) {
        limitations.push(`Symbolic child '${redactSnippet(name)}' was not inspected as a repository.`);
        continue;
      }
      if (!metadata.isDirectory()) continue;
      let marker;
      try { marker = await lstat(join(candidate, ".git")); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        limitations.push(`Could not inspect Git marker for '${redactSnippet(name)}'.`);
        continue;
      }
      if (marker.isSymbolicLink()) {
        limitations.push(`Repository candidate '${redactSnippet(name)}' has a symbolic .git marker and was excluded.`);
        continue;
      }
      if (!marker.isDirectory() && !marker.isFile()) {
        limitations.push(`Repository candidate '${redactSnippet(name)}' has an unsupported .git marker and was excluded.`);
        continue;
      }
      const canonical = await realpath(candidate);
      if (!pathIsWithin(parent, canonical) || dirname(canonical) !== parent) {
        limitations.push(`Repository candidate '${redactSnippet(name)}' did not remain an immediate child after canonicalization.`);
        continue;
      }
      found.push({ repository: canonical, relative_path: basename(canonical) });
    } catch (error) {
      limitations.push(`Could not inspect repository candidate '${redactSnippet(name)}': ${redactSnippet(error instanceof Error ? error.message : String(error))}`);
    }
  }
  found.sort((a, b) => compareText(a.repository, b.repository));
  const selected = found.slice(0, maxRepositories);
  const omitted = found.length - selected.length;
  if (omitted) limitations.push(`${omitted} repository candidate(s) exceeded the explicit max-repositories bound.`);
  return { repositories: selected, discovery: {
    entry_limit: BULK_PARENT_ENTRY_LIMIT,
    candidate_entries: names.length,
    repositories_found: found.length,
    repositories_selected: selected.length,
    repositories_omitted: omitted,
    partial: limitations.length > 0,
    limitations,
  } };
}

function sameConfiguration(manifest: BulkManifest, options: Required<Pick<BulkScanOptions, "concurrency" | "maxRepositories" | "maxAttempts" | "maxFindings" | "includeCompliance">> & Pick<BulkScanOptions, "scanners">): boolean {
  return JSON.stringify(manifest.configuration) === JSON.stringify({
    concurrency: options.concurrency,
    max_repositories: options.maxRepositories,
    max_attempts: options.maxAttempts,
    ...(options.scanners?.length ? { scanners: options.scanners } : {}),
    max_findings: options.maxFindings,
    include_compliance: options.includeCompliance,
  });
}

export async function runBulkScan(options: BulkScanOptions, dependencies: BulkDependencies = DEFAULT_DEPENDENCIES): Promise<BulkRunResult> {
  const concurrency = options.concurrency ?? BULK_DEFAULT_CONCURRENCY;
  const maxRepositories = options.maxRepositories ?? BULK_DEFAULT_MAX_REPOSITORIES;
  const maxAttempts = options.maxAttempts ?? BULK_DEFAULT_MAX_ATTEMPTS;
  const maxFindings = options.maxFindings ?? 200;
  const includeCompliance = options.includeCompliance ?? true;
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > BULK_MAX_CONCURRENCY) throw new Error(`Bulk concurrency must be 1-${BULK_MAX_CONCURRENCY}.`);
  if (!Number.isInteger(maxRepositories) || maxRepositories < 1 || maxRepositories > BULK_MAX_REPOSITORIES) throw new Error(`Bulk max repositories must be 1-${BULK_MAX_REPOSITORIES}.`);
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 5) throw new Error("Bulk max attempts must be 1-5.");
  if (!Number.isSafeInteger(maxFindings) || maxFindings < 1) throw new Error("Bulk max findings must be a positive safe integer.");
  const parentInspection = await requireSafeScanTarget(options.parent);
  if (parentInspection.type !== "directory") throw new Error("Bulk parent must be a directory containing repository directories.");
  const parent = parentInspection.canonical_path;
  const normalizedOptions = { concurrency, maxRepositories, maxAttempts, maxFindings, includeCompliance, ...(options.scanners?.length ? { scanners: [...new Set(options.scanners)] } : {}) };
  if (!options.manifestPath) await mkdir(MANAGED_BULK, { recursive: true });
  const requestedManifestPath = options.manifestPath ?? join(MANAGED_BULK, `bulk-${randomUUID()}.json`);
  const manifestInspection = await inspectOutputFile(requestedManifestPath, parent, false);
  if (!manifestInspection.safe || !manifestInspection.resolved_path) throw new Error(manifestInspection.error ?? "Unsafe bulk manifest path.");
  const manifestPath = manifestInspection.resolved_path;
  if (pathIsWithin(parent, manifestPath)) throw new Error("Bulk manifest must be outside the repository parent tree.");
  const existing = manifestInspection.exists;
  let resumed = false;
  let manifest: BulkManifest;
  if (existing) {
    manifest = await safeReadManifest(manifestPath);
    resumed = true;
    if (manifest.parent !== parent) throw new Error("Bulk manifest parent does not match the canonical requested parent.");
    if (!sameConfiguration(manifest, normalizedOptions)) throw new Error("Bulk resume configuration does not exactly match the manifest.");
    for (const entry of manifest.repositories) {
      if (resolve(entry.repository) !== entry.repository || dirname(entry.repository) !== parent || basename(entry.repository) !== entry.relative_path || !pathIsWithin(parent, entry.repository)) {
        throw new Error("Bulk manifest contains a repository outside the exact immediate-child scope.");
      }
      if (["running", "cancelled", "failed"].includes(entry.state) && entry.attempts < maxAttempts) {
        entry.state = "pending";
        delete entry.started_at;
        delete entry.completed_at;
        delete entry.error;
      }
    }
  } else {
    const { repositories, discovery } = await discoverRepositories(parent, maxRepositories);
    const created = dependencies.now();
    manifest = {
      $schema: BULK_SCHEMA_URI,
      schema_version: BULK_SCHEMA_VERSION,
      run_id: `bulk-${randomUUID()}`,
      parent,
      created_at: created,
      updated_at: created,
      configuration: {
        concurrency,
        max_repositories: maxRepositories,
        max_attempts: maxAttempts,
        ...(normalizedOptions.scanners ? { scanners: normalizedOptions.scanners } : {}),
        max_findings: maxFindings,
        include_compliance: includeCompliance,
      },
      discovery,
      repositories: repositories.map((repository) => ({ ...repository, state: "pending", attempts: 0 })),
      aggregate: { coverage: "unknown", total: repositories.length, pending: repositories.length, running: 0, complete: 0, partial: 0, unknown: 0, failed: 0, cancelled: 0, finding_count: 0 },
    };
  }
  const persist = async (): Promise<void> => {
    manifest.updated_at = dependencies.now();
    manifest.aggregate = aggregateFor(manifest);
    const validated = bulkManifestSchema.parse(manifest);
    await writeExportFile(manifestPath, `${JSON.stringify(validated, null, 2)}\n`, parent, false);
  };
  await persist();
  const pending = manifest.repositories.filter((entry) => entry.state === "pending" && entry.attempts < maxAttempts);
  let cursor = 0;
  let writeQueue = Promise.resolve();
  const queuePersist = (): Promise<void> => {
    const snapshotTime = dependencies.now();
    manifest.updated_at = snapshotTime;
    manifest.aggregate = aggregateFor(manifest);
    const content = `${JSON.stringify(bulkManifestSchema.parse(manifest), null, 2)}\n`;
    writeQueue = writeQueue.then(() => writeExportFile(manifestPath, content, parent, false));
    return writeQueue;
  };
  const worker = async (): Promise<void> => {
    while (!options.signal?.aborted) {
      const entry = pending[cursor++];
      if (!entry) return;
      entry.state = "running";
      entry.attempts++;
      entry.started_at = dependencies.now();
      delete entry.completed_at;
      delete entry.error;
      await queuePersist();
      try {
        if (options.signal?.aborted) throw new Error("Bulk scan cancelled before repository start.");
        const scan = await dependencies.scan(entry.repository, { ...options, ...normalizedOptions });
        const coverage = createJsonExport(scan).coverage.aggregate;
        entry.scan_id = scan.scan_id;
        entry.aggregate_coverage = coverage;
        entry.finding_count = scan.findings.length;
        entry.highest_severity = highestSeverity(scan);
        entry.state = coverage;
      } catch (error) {
        entry.state = options.signal?.aborted ? "cancelled" : "failed";
        entry.error = redactSnippet(error instanceof Error ? error.message : String(error));
      }
      entry.completed_at = dependencies.now();
      await queuePersist();
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) }, () => worker()));
  await writeQueue;
  await persist();
  return { manifest_path: manifestPath, resumed, manifest: bulkManifestSchema.parse(manifest) };
}
