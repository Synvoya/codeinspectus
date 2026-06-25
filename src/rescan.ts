/**
 * Rescan = scan + diff against a prior scan by fingerprint (PRD §11).
 * Resolved = in prior, not in new. Remaining = in both. Introduced = new only.
 */

import { runScan } from "./scan.js";
import { getScan, getLatestScanForTarget } from "./store.js";
import { STANDING_DISCLAIMER } from "./config.js";
import type { RescanResult } from "./types.js";
import type { RescanInput } from "./schemas.js";

export async function runRescan(input: RescanInput): Promise<RescanResult> {
  const prior = input.prior_scan_id
    ? await getScan(input.prior_scan_id)
    : await getLatestScanForTarget(input.path);

  if (!prior) {
    throw new Error(
      input.prior_scan_id
        ? `No scan found with id '${input.prior_scan_id}'. Run codeinspectus_scan first, then rescan with that scan_id.`
        : `No prior scan found for path '${input.path}'. Run codeinspectus_scan on this path first, then rescan.`,
    );
  }

  const fresh = await runScan({
    path: input.path,
    severity_threshold: input.severity_threshold,
    scanners: input.scanners,
    max_findings: input.max_findings,
    include_compliance: false,
  });

  const priorByFp = new Map(prior.findings.map((f) => [f.fingerprint, f]));
  const freshByFp = new Map(fresh.findings.map((f) => [f.fingerprint, f]));

  const resolved = prior.findings.filter((f) => !freshByFp.has(f.fingerprint));
  const remaining = fresh.findings.filter((f) => priorByFp.has(f.fingerprint));
  const introduced = fresh.findings.filter((f) => !priorByFp.has(f.fingerprint));

  return {
    scan_id: fresh.scan_id,
    prior_scan_id: prior.scan_id,
    target: input.path,
    resolved,
    remaining,
    introduced,
    summary: {
      resolved: resolved.length,
      remaining: remaining.length,
      introduced: introduced.length,
    },
    disclaimer: STANDING_DISCLAIMER,
  };
}
