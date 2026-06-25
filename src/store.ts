/**
 * Scan-result store. Keeps results in memory for the life of the server process
 * AND persists each to the managed dir so rescan/compliance/explain survive a
 * server restart. Read-only with respect to the USER's files — writes only to
 * ~/.codeinspectus/scans/ (PRD §11: never touch the user's repo).
 */

import { mkdir, readFile, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { MANAGED_SCANS } from "./config.js";
import type { ScanResult } from "./types.js";
import { log } from "./logger.js";

const memory = new Map<string, ScanResult>();

async function ensureDir(): Promise<void> {
  await mkdir(MANAGED_SCANS, { recursive: true });
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
  try {
    const raw = await readFile(join(MANAGED_SCANS, `${scanId}.json`), "utf8");
    const parsed = JSON.parse(raw) as ScanResult;
    memory.set(scanId, parsed);
    return parsed;
  } catch {
    return undefined;
  }
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
      try {
        const parsed = JSON.parse(
          await readFile(join(MANAGED_SCANS, f), "utf8"),
        ) as ScanResult;
        if (parsed.target === target) candidates.push(parsed);
      } catch {
        /* skip corrupt entry */
      }
    }
    candidates.sort((a, b) => (a.started_at < b.started_at ? 1 : -1));
    return candidates[0];
  } catch {
    return undefined;
  }
}
