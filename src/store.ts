/**
 * Scan-result store. Keeps results in memory for the life of the server process
 * AND persists each to the managed dir so rescan/compliance/explain survive a
 * server restart. Read-only with respect to the USER's files — writes only to
 * ~/.codeinspectus/scans/ (PRD §11: never touch the user's repo).
 */

import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile, readdir, rename, rm, lstat, open } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { MANAGED_SCANS } from "./config.js";
import { scanIdSchema, storedScanResultSchema } from "./schemas.js";
import type { ScanResult } from "./types.js";
import { log } from "./logger.js";
import { sha256Hex } from "./util/hash.js";

export interface StoredScanResult extends ScanResult {
  storage_schema_version?: "2.0.0";
  canonical_findings?: true;
}

/**
 * Older valid records predate fields now required on fresh scan output. Supply runtime-only
 * defaults to consumers that render or diff those records; this never rewrites persisted data.
 */
export function normalizeStoredScanForRuntime(scan: StoredScanResult): ScanResult {
  const legacy = scan as unknown as Partial<ScanResult>;
  return {
    ...scan,
    detected_technologies: legacy.detected_technologies ?? [],
    pack_coverage: legacy.pack_coverage ?? [],
    git_safety: legacy.git_safety ?? { state: "unknown" },
  };
}

export const HISTORY_STORE_READ_LIMIT = 5_000;
export const HISTORY_CORRUPTION_DETAIL_LIMIT = 100;
export const HISTORY_RECORD_READ_LIMIT_BYTES = 8 * 1024 * 1024;
export const HISTORY_TOTAL_READ_LIMIT_BYTES = 64 * 1024 * 1024;
/** Internal verification-only switch. Production persistence remains enabled unless exactly `1`. */
export const INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV = "CODEINSPECTUS_INTERNAL_DISABLE_SCAN_PERSISTENCE";

export function scanPersistenceDisabled(
  environment: Record<string, string | undefined> = process.env,
): boolean {
  return environment[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] === "1";
}

export interface ScanStoreCorruption {
  file: string;
  error: string;
}

export interface ScanStoreSnapshot {
  scans: StoredScanResult[];
  read_limit: number;
  record_byte_limit: number;
  total_byte_limit: number;
  bytes_read: number;
  inspected_files: number;
  candidate_files: number;
  oversized_record_count: number;
  byte_budget_exhausted: boolean;
  omitted_due_to_byte_budget: number;
  corrupt_records: ScanStoreCorruption[];
  corrupt_record_count: number;
  truncated: boolean;
  available: boolean;
  error?: string;
}

const memory = new Map<string, StoredScanResult>();

async function ensureDir(): Promise<void> {
  await mkdir(MANAGED_SCANS, { recursive: true });
}

/**
 * Resolve a scan_id to its on-disk path, or null when the resolved path would escape
 * MANAGED_SCANS (path-traversal guard — CG-75 / Claim 2b). Defense-in-depth behind the
 * schemas.ts scan_id regex: getScan must never read a file outside the managed dir even
 * if a non-conforming id reaches it via an internal caller.
 */
export function resolveScanPath(scanId: string): string | null {
  const base = resolve(MANAGED_SCANS);
  const full = resolve(base, `${scanId}.json`);
  return full.startsWith(base + sep) ? full : null;
}

/**
 * Parse + validate persisted scan JSON before use (CG-75 / Claim 2c). Never returns
 * unvalidated data and never throws on malformed input — the caller decides how to
 * surface the failure. Uses the store-tolerant schema so older on-disk scans still load.
 */
export function safeParseScanJson(
  raw: string,
): { ok: true; value: StoredScanResult } | { ok: false; error: string } {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (e) {
    return { ok: false, error: `invalid JSON: ${(e as Error).message}` };
  }
  const parsed = storedScanResultSchema.safeParse(json);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("; ");
    return { ok: false, error: `does not match the scan schema (${detail})` };
  }
  return { ok: true, value: parsed.data as unknown as StoredScanResult };
}

function safeStoredRecordError(error: string): string {
  return error.startsWith("invalid JSON") ? "invalid JSON" : "does not match the stored scan schema";
}

export async function saveScan(
  result: ScanResult,
  options: { canonicalFindings?: boolean } = {},
): Promise<void> {
  const persisted: StoredScanResult = options.canonicalFindings
    ? { ...result, storage_schema_version: "2.0.0", canonical_findings: true }
    : result;
  memory.set(result.scan_id, persisted);
  // Test/eval scans must remain available for same-process rescan/explain coverage without
  // permanently filling the user's managed history. This is deliberately checked only here:
  // production defaults and all exact load/history semantics stay unchanged.
  if (scanPersistenceDisabled()) return;
  let temporary: string | undefined;
  try {
    await ensureDir();
    const destination = join(MANAGED_SCANS, `${result.scan_id}.json`);
    temporary = `${destination}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, JSON.stringify(persisted), { encoding: "utf8", flag: "wx" });
    await rename(temporary, destination);
    temporary = undefined;
  } catch (err) {
    // Persistence is best-effort; in-memory copy still serves this session.
    log.warn("Failed to persist scan result:", err);
  } finally {
    if (temporary) await rm(temporary, { force: true }).catch(() => undefined);
  }
}

export async function getScan(scanId: string): Promise<StoredScanResult | undefined> {
  const validId = scanIdSchema.safeParse(scanId);
  if (!validId.success) {
    throw new Error(
      `Refusing to load an invalid id from the managed scans directory: ${validId.error.issues[0]?.message ?? `Invalid scan_id '${scanId}'.`}`,
    );
  }
  const cached = memory.get(scanId);
  if (cached) return cached;

  const file = resolveScanPath(scanId);
  if (!file) {
    throw new Error(
      `Refusing to load scan_id '${scanId}': the resolved path escapes the managed scans directory (${MANAGED_SCANS}). Pass a scan_id returned by a prior codeinspectus_scan.`,
    );
  }

  let raw: string;
  try {
    const metadata = await lstat(file);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`Stored scan '${scanId}' is not a regular managed scan file.`);
    }
    raw = await readFile(file, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    return undefined; // not found → callers surface it as "no such scan"
  }

  const parsed = safeParseScanJson(raw);
  if (!parsed.ok) {
    throw new Error(
      `Stored scan '${scanId}' could not be loaded — it ${safeStoredRecordError(parsed.error)}. Re-run codeinspectus_scan to regenerate it.`,
    );
  }
  if (parsed.value.scan_id !== scanId) {
    throw new Error(`Stored scan '${scanId}' is foreign or mismatched: its embedded scan_id does not match the requested ID.`);
  }
  memory.set(scanId, parsed.value);
  return parsed.value;
}

/**
 * Bounded, deterministic history-store inspection. Corrupt/foreign records are isolated and
 * reported; one bad file never hides otherwise valid history.
 */
export async function inspectScanStore(options: {
  directory?: string;
  maxFiles?: number;
  maxRecordBytes?: number;
  maxTotalBytes?: number;
  includeMemory?: boolean;
} = {}): Promise<ScanStoreSnapshot> {
  const directory = options.directory ?? MANAGED_SCANS;
  const maxFiles = Math.max(1, Math.min(options.maxFiles ?? HISTORY_STORE_READ_LIMIT, HISTORY_STORE_READ_LIMIT));
  const maxRecordBytes = Math.max(1, Math.min(
    options.maxRecordBytes ?? HISTORY_RECORD_READ_LIMIT_BYTES,
    HISTORY_RECORD_READ_LIMIT_BYTES,
  ));
  const maxTotalBytes = Math.max(1, Math.min(
    options.maxTotalBytes ?? HISTORY_TOTAL_READ_LIMIT_BYTES,
    HISTORY_TOTAL_READ_LIMIT_BYTES,
  ));
  const includeMemory = options.includeMemory ?? resolve(directory) === resolve(MANAGED_SCANS);
  let names: string[];
  try {
    names = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") names = [];
    else {
      return {
        scans: [], read_limit: maxFiles,
        record_byte_limit: maxRecordBytes, total_byte_limit: maxTotalBytes, bytes_read: 0,
        inspected_files: 0, candidate_files: 0, oversized_record_count: 0,
        byte_budget_exhausted: false, omitted_due_to_byte_budget: 0,
        corrupt_records: [], corrupt_record_count: 0, truncated: false, available: false,
        error: `Could not inspect the managed scan store: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  const selected = names.slice(0, maxFiles);
  const corrupt: ScanStoreCorruption[] = [];
  let corruptCount = 0;
  let oversizedCount = 0;
  let bytesRead = 0;
  let inspectedFiles = 0;
  let byteBudgetExhausted = false;
  let omittedDueToByteBudget = 0;
  const scans = new Map<string, StoredScanResult>();
  const recordCorruption = (file: string, error: string): void => {
    corruptCount++;
    if (corrupt.length < HISTORY_CORRUPTION_DETAIL_LIMIT) corrupt.push({ file, error });
  };
  for (let index = 0; index < selected.length; index++) {
    const name = selected[index]!;
    inspectedFiles++;
    const expectedId = name.slice(0, -".json".length);
    if (!scanIdSchema.safeParse(expectedId).success) {
      // An arbitrary local filename is not trusted output: identify it by a stable digest so a
      // credential-shaped name cannot leak through list JSON or stderr.
      recordCorruption(`unrecognized-json-entry:${sha256Hex(name).slice(0, 12)}`, "Filename is not a CodeInspectus scan_id.");
      continue;
    }
    const file = join(directory, name);
    try {
      const metadata = await lstat(file);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        recordCorruption(name, "Entry is not a regular managed scan file.");
        continue;
      }
      if (metadata.size > maxRecordBytes) {
        oversizedCount++;
        recordCorruption(name, `Record is ${metadata.size} bytes, above the ${maxRecordBytes}-byte history limit.`);
        continue;
      }
      if (bytesRead + metadata.size > maxTotalBytes) {
        byteBudgetExhausted = true;
        omittedDueToByteBudget = selected.length - index;
        break;
      }
      // Reserve the complete statted size before reading so errors cannot allow later records to
      // exceed the total budget. Read through the opened descriptor into a fixed-size buffer;
      // unlike readFile, concurrent file growth cannot turn this into an unbounded allocation.
      bytesRead += metadata.size;
      const handle = await open(file, "r");
      let raw: string;
      try {
        const opened = await handle.stat();
        if (!opened.isFile() || opened.dev !== metadata.dev || opened.ino !== metadata.ino || opened.size !== metadata.size) {
          throw new Error("Managed scan file changed during bounded inspection.");
        }
        const buffer = Buffer.alloc(metadata.size);
        let offset = 0;
        while (offset < buffer.length) {
          const read = await handle.read(buffer, offset, buffer.length - offset, offset);
          if (read.bytesRead === 0) break;
          offset += read.bytesRead;
        }
        const after = await handle.stat();
        if (offset !== metadata.size || after.size !== metadata.size) {
          throw new Error("Managed scan file changed during bounded inspection.");
        }
        raw = buffer.toString("utf8");
      } finally {
        await handle.close();
      }
      const parsed = safeParseScanJson(raw);
      if (!parsed.ok) {
        recordCorruption(name, safeStoredRecordError(parsed.error));
        continue;
      }
      if (parsed.value.scan_id !== expectedId) {
        recordCorruption(name, "Embedded scan_id does not match its filename.");
        continue;
      }
      if (!Number.isFinite(Date.parse(parsed.value.started_at))) {
        recordCorruption(name, "started_at is not a valid timestamp.");
        continue;
      }
      scans.set(parsed.value.scan_id, parsed.value);
    } catch (error) {
      recordCorruption(name, error instanceof Error ? error.message : String(error));
    }
  }
  if (includeMemory) {
    for (const scan of memory.values()) scans.set(scan.scan_id, scan);
  }
  return {
    scans: [...scans.values()].sort((left, right) =>
      right.started_at.localeCompare(left.started_at) || left.scan_id.localeCompare(right.scan_id)),
    read_limit: maxFiles,
    record_byte_limit: maxRecordBytes,
    total_byte_limit: maxTotalBytes,
    bytes_read: bytesRead,
    inspected_files: inspectedFiles,
    candidate_files: names.length,
    oversized_record_count: oversizedCount,
    byte_budget_exhausted: byteBudgetExhausted,
    omitted_due_to_byte_budget: omittedDueToByteBudget,
    corrupt_records: corrupt,
    corrupt_record_count: corruptCount,
    truncated: names.length > selected.length || byteBudgetExhausted,
    available: true,
  };
}

/** Most recent scan for a given target path (for rescan default). */
export async function getLatestScanForTarget(
  target: string,
): Promise<StoredScanResult | undefined> {
  // Prefer in-memory (current session) by started_at desc.
  let best: StoredScanResult | undefined;
  for (const r of memory.values()) {
    if (r.target === target && (!best || r.started_at > best.started_at)) best = r;
  }
  if (best) return best;
  try {
    const files = await readdir(MANAGED_SCANS);
    const candidates: StoredScanResult[] = [];
    for (const f of files) {
      if (!f.endsWith(".json")) continue;
      let raw: string;
      try {
        raw = await readFile(join(MANAGED_SCANS, f), "utf8");
      } catch {
        continue; // unreadable entry — skip
      }
      // Validate before use; never let a corrupt/foreign entry through (CG-75 Claim 2c).
      const parsed = safeParseScanJson(raw);
      if (parsed.ok && parsed.value.target === target) candidates.push(parsed.value);
    }
    candidates.sort((a, b) => (a.started_at < b.started_at ? 1 : -1));
    return candidates[0];
  } catch {
    return undefined;
  }
}
