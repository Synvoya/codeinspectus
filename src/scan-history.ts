import { relative, resolve, sep } from "node:path";
import { assessAggregateCoverage } from "./export/model.js";
import { pathIsWithin } from "./path-safety.js";
import { dedupIdentityKeys } from "./dedup.js";
import { diffRescan } from "./rescan.js";
import { executeScan } from "./scan.js";
import {
  getScan,
  inspectScanStore,
  normalizeStoredScanForRuntime,
  type ScanStoreSnapshot,
  type StoredScanResult,
} from "./store.js";
import { SEVERITY_RANK, type Finding, type Severity } from "./types.js";

export const HISTORY_LIST_DEFAULT_LIMIT = 50;
export const HISTORY_LIST_MAX_LIMIT = 200;

export type HistoryScanStatus = "clean" | "findings" | "partial" | "unknown";
export type HistoryComparisonState = "New" | "Persisting" | "Reopened" | "Resolved" | "Not rechecked / unknown";

export interface HistoryListFilters {
  repository?: string;
  path?: string;
  since?: string;
  until?: string;
  severity?: Severity;
  status?: HistoryScanStatus;
  limit?: number;
}

export interface HistoryListEntry {
  scan_id: string;
  target: string;
  repository: string;
  repository_identity: "recorded" | "legacy_target_fallback";
  started_at: string;
  duration_ms: number;
  status: HistoryScanStatus;
  aggregate_coverage: "complete" | "partial" | "unknown";
  finding_count: number;
  highest_severity?: Severity;
  canonical_findings: boolean;
}

export interface HistoryListResult {
  schema_version: "1.0.0";
  entries: HistoryListEntry[];
  filters: HistoryListFilters;
  bounds: {
    requested_limit: number;
    returned: number;
    matching_records: number;
    inspected_files: number;
    candidate_files: number;
    store_read_limit: number;
    record_byte_limit: number;
    total_byte_limit: number;
    bytes_read: number;
    oversized_record_count: number;
    byte_budget_exhausted: boolean;
    omitted_due_to_byte_budget: number;
    result_truncated: boolean;
    store_truncated: boolean;
  };
  corrupt_record_count: number;
  corrupt_records: ScanStoreSnapshot["corrupt_records"];
  partial: boolean;
  note?: string;
}

export interface HistoryComparisonItem {
  state: HistoryComparisonState;
  finding: Finding;
  prior_finding_id?: string;
  evidence: string;
}

export interface HistoryComparisonResult {
  schema_version: "1.0.0";
  old_scan_id: string;
  new_scan_id: string;
  target: string;
  items: HistoryComparisonItem[];
  summary: Record<HistoryComparisonState, number>;
  partial: boolean;
  history_provenance: {
    same_canonical_target: true;
    available: boolean;
    inspected_records: number;
    inspected_files: number;
    candidate_files: number;
    corrupt_record_count: number;
    oversized_record_count: number;
    bytes_read: number;
    total_byte_limit: number;
    byte_budget_exhausted: boolean;
    store_truncated: boolean;
    reopened_proof: "complete" | "unavailable";
    notes: string[];
  };
}

function scanStatus(scan: StoredScanResult): HistoryScanStatus {
  const coverage = assessAggregateCoverage(scan).aggregate;
  if (coverage === "unknown") return "unknown";
  if (coverage === "partial") return "partial";
  return scan.findings.length ? "findings" : "clean";
}

function highestSeverity(findings: readonly Finding[]): Severity | undefined {
  return findings.reduce<Severity | undefined>((highest, finding) =>
    !highest || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest] ? finding.severity : highest, undefined);
}

function repositoryIdentity(scan: StoredScanResult): string {
  return scan.repository_root ?? scan.target;
}

function normalized(value: string): string {
  return resolve(value);
}

function scanMatchesPath(scan: StoredScanResult, requested: string): boolean {
  const absolute = normalized(requested);
  if (scan.target === absolute || pathIsWithin(absolute, scan.target) || pathIsWithin(scan.target, absolute)) return true;
  if (!scan.repository_root || !pathIsWithin(scan.repository_root, absolute)) return false;
  const projectRelative = relative(scan.repository_root, absolute).split(sep).join("/");
  return scan.findings.some((finding) =>
    finding.location.file === projectRelative || finding.location.file.startsWith(`${projectRelative}/`));
}

function toEntry(scan: StoredScanResult): HistoryListEntry {
  const coverage = assessAggregateCoverage(scan).aggregate;
  const highest = highestSeverity(scan.findings);
  return {
    scan_id: scan.scan_id,
    target: scan.target,
    repository: repositoryIdentity(scan),
    repository_identity: scan.repository_root ? "recorded" : "legacy_target_fallback",
    started_at: scan.started_at,
    duration_ms: scan.duration_ms,
    status: coverage === "unknown" ? "unknown" : coverage === "partial" ? "partial" : scan.findings.length ? "findings" : "clean",
    aggregate_coverage: coverage,
    finding_count: scan.findings.length,
    ...(highest ? { highest_severity: highest } : {}),
    canonical_findings: scan.canonical_findings === true,
  };
}

export function listScanHistory(snapshot: ScanStoreSnapshot, filters: HistoryListFilters = {}): HistoryListResult {
  const limit = Math.max(1, Math.min(filters.limit ?? HISTORY_LIST_DEFAULT_LIMIT, HISTORY_LIST_MAX_LIMIT));
  const since = filters.since ? Date.parse(filters.since) : undefined;
  const until = filters.until ? Date.parse(filters.until) : undefined;
  const repository = filters.repository ? normalized(filters.repository) : undefined;
  const entries = snapshot.scans
    .slice()
    .sort((left, right) =>
      right.started_at.localeCompare(left.started_at) || left.scan_id.localeCompare(right.scan_id))
    .filter((scan) => !repository || repositoryIdentity(scan) === repository)
    .filter((scan) => !filters.path || scanMatchesPath(scan, filters.path))
    .filter((scan) => since === undefined || Date.parse(scan.started_at) >= since)
    .filter((scan) => until === undefined || Date.parse(scan.started_at) <= until)
    .filter((scan) => !filters.severity || scan.findings.some((finding) =>
      SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[filters.severity!]))
    .filter((scan) => !filters.status || scanStatus(scan) === filters.status)
    .map(toEntry);
  const partial = !snapshot.available || snapshot.truncated || snapshot.corrupt_record_count > 0;
  const notes = [
    ...(!snapshot.available ? [snapshot.error ?? "The managed scan store was unavailable."] : []),
    ...(snapshot.candidate_files > snapshot.read_limit
      ? ["The managed store exceeded the bounded file-count limit; omitted records were not inspected."]
      : []),
    ...(snapshot.byte_budget_exhausted
      ? [`The ${snapshot.total_byte_limit}-byte history budget was exhausted; ${snapshot.omitted_due_to_byte_budget} selected record(s) were not read.`]
      : []),
    ...(snapshot.oversized_record_count
      ? [`${snapshot.oversized_record_count} record(s) exceeded the ${snapshot.record_byte_limit}-byte per-record limit.`]
      : []),
    ...(snapshot.corrupt_record_count ? [`${snapshot.corrupt_record_count} corrupt or foreign record(s) were isolated.`] : []),
  ];
  return {
    schema_version: "1.0.0",
    entries: entries.slice(0, limit),
    filters: { ...filters, limit },
    bounds: {
      requested_limit: limit,
      returned: Math.min(entries.length, limit),
      matching_records: entries.length,
      inspected_files: snapshot.inspected_files,
      candidate_files: snapshot.candidate_files,
      store_read_limit: snapshot.read_limit,
      record_byte_limit: snapshot.record_byte_limit,
      total_byte_limit: snapshot.total_byte_limit,
      bytes_read: snapshot.bytes_read,
      oversized_record_count: snapshot.oversized_record_count,
      byte_budget_exhausted: snapshot.byte_budget_exhausted,
      omitted_due_to_byte_budget: snapshot.omitted_due_to_byte_budget,
      result_truncated: entries.length > limit,
      store_truncated: snapshot.truncated,
    },
    corrupt_record_count: snapshot.corrupt_record_count,
    corrupt_records: snapshot.corrupt_records,
    partial,
    ...(notes.length ? { note: notes.join(" ") } : {}),
  };
}

export function findingsMatch(left: Finding, right: Finding): boolean {
  if (left.fingerprint === right.fingerprint) return true;
  const keys = new Set(dedupIdentityKeys(left));
  return dedupIdentityKeys(right).some((key) => keys.has(key));
}

function comparisonCoverageSufficient(oldScan: StoredScanResult, newScan: StoredScanResult): boolean {
  return oldScan.canonical_findings === true && newScan.canonical_findings === true &&
    assessAggregateCoverage(oldScan).aggregate === "complete" &&
    assessAggregateCoverage(newScan).aggregate === "complete";
}

export function findingAbsenceProvableAgainst(
  oldScan: StoredScanResult,
  newScan: StoredScanResult,
  finding: Finding,
): boolean {
  if (!comparisonCoverageSufficient(oldScan, newScan)) return false;
  if (!finding.producer_components?.length || !oldScan.component_signatures || !newScan.component_signatures) return false;
  if (finding.engines.some((engine) => !oldScan.engine_details.some((detail) => detail.engine === engine && detail.ran))) return false;
  return finding.producer_components.every((component) => {
    const oldSignature = oldScan.component_signatures?.[component];
    const newSignature = newScan.component_signatures?.[component];
    return Boolean(oldSignature && newSignature && oldSignature === newSignature);
  });
}

function earlierOccurrenceWasProvablyResolved(
  earlier: StoredScanResult,
  oldScan: StoredScanResult,
  occurrence: Finding,
): boolean {
  if (!comparisonCoverageSufficient(earlier, oldScan)) return false;
  return diffRescan(
    normalizeStoredScanForRuntime(earlier),
    normalizeStoredScanForRuntime(oldScan),
  ).resolved.includes(occurrence);
}

export function compareScanHistory(
  oldScan: StoredScanResult,
  newScan: StoredScanResult,
  history: ScanStoreSnapshot,
): HistoryComparisonResult {
  if (oldScan.scan_id === newScan.scan_id) throw new Error("History comparison requires two distinct scan IDs.");
  if (oldScan.target !== newScan.target) {
    throw new Error(`History comparison requires the same canonical target; got '${oldScan.target}' and '${newScan.target}'.`);
  }
  if (Date.parse(oldScan.started_at) > Date.parse(newScan.started_at)) {
    throw new Error("OLD_SCAN_ID is newer than NEW_SCAN_ID; swap the comparison order.");
  }

  const notes: string[] = [];
  const historyReliable = history.available && !history.truncated && history.corrupt_record_count === 0;
  if (!history.available) notes.push(history.error ?? "Managed history was unavailable.");
  if (history.candidate_files > history.read_limit) notes.push("History exceeded the bounded file-count limit, so reopened proof is unavailable.");
  if (history.byte_budget_exhausted) notes.push(
    `History exhausted its ${history.total_byte_limit}-byte budget; ${history.omitted_due_to_byte_budget} selected record(s) were not read.`,
  );
  if (history.oversized_record_count) notes.push(
    `${history.oversized_record_count} oversized history record(s) were isolated.`,
  );
  if (history.corrupt_record_count) notes.push(`${history.corrupt_record_count} corrupt or foreign history record(s) prevent reopened proof.`);
  const sufficient = comparisonCoverageSufficient(oldScan, newScan);
  if (!sufficient) notes.push("One or both compared scans lack complete canonical, whole-product coverage; absence cannot prove resolution.");

  const diff = diffRescan(
    normalizeStoredScanForRuntime(oldScan),
    normalizeStoredScanForRuntime(newScan),
  );
  const matchedOld = new Set<Finding>();
  const items: HistoryComparisonItem[] = [];
  for (const finding of newScan.findings) {
    const prior = oldScan.findings.find((candidate) => findingsMatch(candidate, finding));
    if (prior) {
      matchedOld.add(prior);
      items.push({ state: "Persisting", finding, prior_finding_id: prior.id, evidence: "The finding is present in both compared scans by fingerprint or dedup identity." });
      continue;
    }
    if (!findingAbsenceProvableAgainst(oldScan, newScan, finding)) {
      items.push({ state: "Not rechecked / unknown", finding, evidence: "The finding is present now, but OLD did not run the same producer engines/components with compatible signatures, so absence cannot be proven." });
      continue;
    }
    const earlierCandidates = history.scans
      .filter((scan) => scan.target === oldScan.target && scan.scan_id !== oldScan.scan_id && scan.scan_id !== newScan.scan_id)
      .filter((scan) => Date.parse(scan.started_at) < Date.parse(oldScan.started_at))
      .sort((left, right) => right.started_at.localeCompare(left.started_at) || left.scan_id.localeCompare(right.scan_id));
    const priorOccurrences = earlierCandidates.flatMap((scan) =>
      scan.findings.filter((candidate) => findingsMatch(candidate, finding)).map((occurrence) => ({ scan, occurrence })));
    if (!historyReliable) {
      items.push({ state: "Not rechecked / unknown", finding, evidence: "The finding is absent from OLD, but bounded history is incomplete so recurrence cannot be proven." });
    } else if (priorOccurrences.some(({ scan, occurrence }) => earlierOccurrenceWasProvablyResolved(scan, oldScan, occurrence))) {
      items.push({ state: "Reopened", finding, evidence: "An earlier same-target occurrence was provably resolved in OLD and is present again in NEW." });
    } else if (priorOccurrences.length) {
      items.push({ state: "Not rechecked / unknown", finding, evidence: "An earlier occurrence exists, but its absence in OLD was not provably resolved." });
    } else {
      items.push({ state: "New", finding, evidence: "The finding is absent from OLD and no earlier occurrence exists in the complete bounded history inspected." });
    }
  }

  const resolvedSet = new Set(diff.resolved);
  for (const finding of oldScan.findings) {
    if (matchedOld.has(finding)) continue;
    if (sufficient && resolvedSet.has(finding)) {
      items.push({ state: "Resolved", finding, evidence: "The finding is absent from NEW with compatible producer signatures and complete like-for-like coverage." });
    } else {
      items.push({ state: "Not rechecked / unknown", finding, evidence: "Absence from NEW is not resolution because coverage or producer compatibility was insufficient." });
    }
  }

  const stateOrder: HistoryComparisonState[] = ["New", "Reopened", "Persisting", "Resolved", "Not rechecked / unknown"];
  items.sort((left, right) =>
    stateOrder.indexOf(left.state) - stateOrder.indexOf(right.state) ||
    SEVERITY_RANK[right.finding.severity] - SEVERITY_RANK[left.finding.severity] ||
    left.finding.location.file.localeCompare(right.finding.location.file) ||
    left.finding.fingerprint.localeCompare(right.finding.fingerprint));
  const summary = Object.fromEntries(stateOrder.map((state) => [state, items.filter((item) => item.state === state).length])) as Record<HistoryComparisonState, number>;
  const partial = items.some((item) => item.state === "Not rechecked / unknown") || !historyReliable || !sufficient;
  return {
    schema_version: "1.0.0", old_scan_id: oldScan.scan_id, new_scan_id: newScan.scan_id,
    target: newScan.target, items, summary, partial,
    history_provenance: {
      same_canonical_target: true,
      available: history.available,
      inspected_records: history.scans.length,
      inspected_files: history.inspected_files,
      candidate_files: history.candidate_files,
      corrupt_record_count: history.corrupt_record_count,
      oversized_record_count: history.oversized_record_count,
      bytes_read: history.bytes_read,
      total_byte_limit: history.total_byte_limit,
      byte_budget_exhausted: history.byte_budget_exhausted,
      store_truncated: history.truncated,
      reopened_proof: historyReliable ? "complete" : "unavailable",
      notes,
    },
  };
}

export async function rerunStoredScan(prior: StoredScanResult): Promise<StoredScanResult> {
  const execution = await executeScan({
    path: prior.target,
    scanners: prior.scan_config?.scanners,
    severity_threshold: undefined,
    max_findings: prior.scan_config?.max_findings,
    include_compliance: false,
  });
  const stored = await getScan(execution.canonical.scan_id);
  if (!stored) throw new Error(`Fresh rerun '${execution.canonical.scan_id}' was not available from the managed store.`);
  return stored;
}

export async function loadHistorySnapshot(): Promise<ScanStoreSnapshot> {
  return inspectScanStore();
}
