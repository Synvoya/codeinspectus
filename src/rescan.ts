/**
 * Rescan = scan + diff against a prior scan by CONTENT fingerprint (sha256), never display id.
 *
 * CG-75 (Claim 1, Approach C): a prior finding is reported `resolved` ONLY when its resolution
 * is PROVABLE. When the rescan could not have re-detected it — the producing engine did not run,
 * a narrower scanner/threshold scope, a truncated result, or a pre-CG-75 prior without captured
 * config — the finding is `not_rechecked` (indeterminate), never a false "you fixed it".
 */

import { runScan } from "./scan.js";
import { getScan, getLatestScanForTarget } from "./store.js";
import { dedupKey } from "./dedup.js";
import { STANDING_DISCLAIMER } from "./config.js";
import { SEVERITY_RANK } from "./types.js";
import type { Finding, RescanResult, ScanResult, Severity } from "./types.js";
import type { RescanInput } from "./schemas.js";

/**
 * Diff a prior scan against a fresh rescan by fingerprint, gating "resolved" on provability.
 * Pure (no engine calls) so every classification mode is deterministic and unit-testable.
 *
 * A prior finding is matched against the fresh set by fingerprint AND by dedup IDENTITY (location /
 * secret / vuln key), so a same-issue finding whose surviving fingerprint FLIPPED across a
 * git-status transition still counts as present. A prior finding absent by BOTH is `resolved` ONLY
 * when ALL hold:
 *   1. the prior scan captured its config (pre-CG-75 scans can't prove like-for-like scope);
 *   2. EVERY engine that produced it actually RAN in the rescan — a de-scoped or failed engine is
 *      absent / `ran:false` in engine_details, covering a narrower `scanners` request, a
 *      silently-failed engine, AND a merged multi-engine finding whose co-producer did not re-run;
 *   3. neither scan was truncated (absence past a max_findings cut is not proof of a fix).
 * Otherwise the finding is `not_rechecked` — NOT resolved, NOT silently dropped.
 *
 * CG-76: there is NO severity_threshold gate here. runRescan runs the fresh scan WITHOUT a
 * threshold so `fresh.findings` is the complete all-severity set; the threshold is applied
 * display-only in filterRescanForDisplay. That is what lets a still-present finding reframed to
 * `low` (same fingerprint) be matched as `remaining` instead of looking absent (CG-75 MAJOR #2),
 * while a genuinely-removed finding is provably `resolved` under a threshold (precision recovered).
 */
export function diffRescan(prior: ScanResult, fresh: ScanResult): RescanResult {
  const priorByFp = new Map(prior.findings.map((f) => [f.fingerprint, f]));
  const freshByFp = new Map(fresh.findings.map((f) => [f.fingerprint, f]));
  // Dedup-identity keys (location / secret / vuln identity). A finding's surviving fingerprint can
  // FLIP across a git-status transition: reframeLocalHygiene collapses severities, so a co-located
  // Gitleaks(high)⨯AI(critical) secret that merged to the critical representative before can merge
  // to the Gitleaks representative after — a different fingerprint for the SAME live issue. Matching
  // on dedup identity (not just fingerprint) keeps that from being read as resolved/introduced.
  const priorKeys = new Set(prior.findings.map(dedupKey));
  const freshKeys = new Set(fresh.findings.map(dedupKey));
  const stillPresent = (f: Finding): boolean => priorByFp.has(f.fingerprint) || priorKeys.has(dedupKey(f));

  const remaining = fresh.findings.filter(stillPresent);
  const introduced = fresh.findings.filter((f) => !stillPresent(f));

  const priorConfigCaptured = !!prior.scan_config;
  const truncatedEither = prior.truncated || fresh.truncated;

  const resolved: Finding[] = [];
  const not_rechecked: Finding[] = [];
  const reasons = new Set<string>();

  for (const f of prior.findings) {
    if (freshByFp.has(f.fingerprint)) continue; // still present (exact fingerprint) → remaining
    // Same issue still present under a FLIPPED fingerprint (dedup-survivor change across a
    // git-status transition) → still present, NOT resolved. Counted in `remaining` via stillPresent.
    if (freshKeys.has(dedupKey(f))) continue;

    // Absent by both fingerprint AND dedup identity — but was its resolution actually PROVABLE?
    if (!priorConfigCaptured) {
      not_rechecked.push(f);
      reasons.add("the prior scan predates captured config, so like-for-like scope cannot be proven");
      continue;
    }
    // EVERY engine that produced the finding must have run — checking only the representative
    // `f.engine` would let a merged multi-engine finding be marked resolved when a co-producing
    // engine (whose own detection was merged away) never re-ran in the rescan.
    const missing = f.engines.filter((e) => !fresh.engine_details.some((d) => d.engine === e && d.ran));
    if (missing.length) {
      not_rechecked.push(f);
      reasons.add(`${missing.join(", ")} did not run in the rescan`);
      continue;
    }
    // CG-76: NO threshold gate here. diffRescan operates on the COMPLETE fresh finding set
    // (runRescan runs the fresh scan without a severity_threshold), so a still-present finding
    // reframed to `low` is FOUND by fingerprint → remaining, and a genuinely-removed finding is
    // provably resolved. The severity_threshold is applied later, display-only, in
    // filterRescanForDisplay. (This supersedes the CG-75 `>low` band-aid.)
    if (truncatedEither) {
      not_rechecked.push(f);
      reasons.add("results were truncated (max_findings), so absence past the cut is not proof of a fix");
      continue;
    }
    resolved.push(f);
  }

  const partial = not_rechecked.length > 0;
  const not_rechecked_note = partial
    ? `${not_rechecked.length} finding(s) could not be re-checked and are NOT confirmed resolved — ${[
        ...reasons,
      ].join("; ")}.`
    : undefined;

  return {
    scan_id: fresh.scan_id,
    prior_scan_id: prior.scan_id,
    target: fresh.target,
    resolved,
    remaining,
    introduced,
    not_rechecked,
    summary: {
      resolved: resolved.length,
      remaining: remaining.length,
      introduced: introduced.length,
      not_rechecked: not_rechecked.length,
    },
    partial,
    ...(not_rechecked_note ? { not_rechecked_note } : {}),
    disclaimer: STANDING_DISCLAIMER,
  };
}

/**
 * CG-76: apply severity_threshold as a DISPLAY filter. diffRescan classifies on the complete
 * fresh set (so nothing is falsely resolved); this hides sub-threshold findings from the shown
 * resolved/remaining/introduced and recomputes their counts. `not_rechecked` is ALWAYS shown in
 * full — a prior finding we could not confirm resolved matters to the user regardless of its
 * current severity band.
 */
export function filterRescanForDisplay(
  result: RescanResult,
  threshold: Severity | undefined,
): RescanResult {
  if (!threshold) return result;
  const min = SEVERITY_RANK[threshold];
  const keep = (f: Finding): boolean => SEVERITY_RANK[f.severity] >= min;
  const resolved = result.resolved.filter(keep);
  const remaining = result.remaining.filter(keep);
  const introduced = result.introduced.filter(keep);
  return {
    ...result,
    resolved,
    remaining,
    introduced,
    summary: {
      resolved: resolved.length,
      remaining: remaining.length,
      introduced: introduced.length,
      not_rechecked: result.not_rechecked.length,
    },
  };
}

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

  // CG-76: run the fresh scan WITHOUT a severity_threshold so diffRescan sees the COMPLETE
  // all-severity set — a still-present finding reframed to `low` is then matched (remaining)
  // instead of looking absent (CG-75 MAJOR #2). scanners + max_findings are still reused for
  // like-for-like scope; the threshold is applied display-only below. Truncation still applies
  // (max_findings unchanged), so under truncation absent findings remain not_rechecked.
  const effectiveThreshold = input.severity_threshold ?? prior.scan_config?.severity_threshold;
  const fresh = await runScan({
    path: input.path,
    severity_threshold: undefined,
    scanners: input.scanners ?? prior.scan_config?.scanners,
    max_findings: input.max_findings ?? prior.scan_config?.max_findings,
    include_compliance: false,
  });

  return filterRescanForDisplay(diffRescan(prior, fresh), effectiveThreshold);
}
