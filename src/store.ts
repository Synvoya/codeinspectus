/**
 * Scan-result store. Keeps results in memory for the life of the server process
 * AND persists each to the managed dir so rescan/compliance/explain survive a
 * server restart. Read-only with respect to the USER's files — writes only to
 * ~/.codeinspectus/scans/ (PRD §11: never touch the user's repo).
 */

import { mkdir, readFile, writeFile, readdir } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { MANAGED_SCANS } from "./config.js";
import { storedScanResultSchema } from "./schemas.js";
import type { ScanResult } from "./types.js";
import { log } from "./logger.js";

const memory = new Map<string, ScanResult>();

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
): { ok: true; value: ScanResult } | { ok: false; error: string } {
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
  return { ok: true, value: parsed.data as unknown as ScanResult };
}

export async function saveScan(result: ScanResult): Promise<void> {
  memory.set(result.scan_id, result);
  try {
    await ensureDir();
    await writeFile(
      join(MANAGED_SCANS, `${result.scan_id}.json`),
      JSON.stringify(result),
      "utf8",
    );
  } catch (err) {
    // Persistence is best-effort; in-memory copy still serves this session.
    log.warn("Failed to persist scan result:", err);
  }
}

export async function getScan(scanId: string): Promise<ScanResult | undefined> {
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
    raw = await readFile(file, "utf8");
  } catch {
    return undefined; // not found → callers surface it as "no such scan"
  }

  const parsed = safeParseScanJson(raw);
  if (!parsed.ok) {
    throw new Error(
      `Stored scan '${scanId}' could not be loaded — ${parsed.error}. Re-run codeinspectus_scan to regenerate it.`,
    );
  }
  memory.set(scanId, parsed.value);
  return parsed.value;
}

/** Most recent scan for a given target path (for rescan default). */
export async function getLatestScanForTarget(
  target: string,
): Promise<ScanResult | undefined> {
  // Prefer in-memory (current session) by started_at desc.
  let best: ScanResult | undefined;
  for (const r of memory.values()) {
    if (r.target === target && (!best || r.started_at > best.started_at)) best = r;
  }
  if (best) return best;
  try {
    const files = await readdir(MANAGED_SCANS);
    const candidates: ScanResult[] = [];
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
