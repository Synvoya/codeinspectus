import { assessAggregateCoverage } from "./export/model.js";
import { findingAbsenceProvableAgainst, findingsMatch } from "./scan-history.js";
import { SEVERITY_RANK, type Finding, type Severity } from "./types.js";
import type { StoredScanResult } from "./store.js";

export type BaselineFindingState = "New" | "Existing" | "Not rechecked / unknown";

export interface BaselineItem {
  state: BaselineFindingState;
  finding: Finding;
  baseline_finding_id?: string;
  evidence: string;
}

export interface BaselineComparison {
  schema_version: "1.0.0";
  baseline_scan_id: string;
  scan_id: string;
  target: string;
  repository: string;
  items: BaselineItem[];
  summary: { New: number; Existing: number; "Not rechecked / unknown": number };
  coverage: "complete" | "partial" | "unknown";
  partial: boolean;
  notes: string[];
}

function repositoryIdentity(scan: StoredScanResult): string {
  return scan.repository_root ?? scan.target;
}

export function compareAgainstBaseline(baseline: StoredScanResult, fresh: StoredScanResult): BaselineComparison {
  const notes: string[] = [];
  const sameTarget = baseline.target === fresh.target;
  const sameRepository = repositoryIdentity(baseline) === repositoryIdentity(fresh);
  const ordered = Date.parse(baseline.started_at) <= Date.parse(fresh.started_at);
  const baselineCoverage = assessAggregateCoverage(baseline).aggregate;
  const freshCoverage = assessAggregateCoverage(fresh).aggregate;
  const foundationComplete = sameTarget && sameRepository && ordered &&
    baseline.canonical_findings === true && fresh.canonical_findings === true &&
    baselineCoverage === "complete" && freshCoverage === "complete";
  if (!sameTarget) notes.push("Baseline and current scan do not have the same canonical target.");
  if (!sameRepository) notes.push("Baseline and current scan do not have the same repository identity.");
  if (!ordered) notes.push("The baseline scan is newer than the current scan.");
  if (baseline.canonical_findings !== true || fresh.canonical_findings !== true) notes.push("One or both scans lack the canonical-finding marker.");
  if (baselineCoverage !== "complete" || freshCoverage !== "complete") notes.push("One or both scans lack complete aggregate coverage.");

  const items: BaselineItem[] = fresh.findings.map((finding) => {
    const existing = baseline.findings.find((candidate) => findingsMatch(candidate, finding));
    if (existing) return {
      state: "Existing", finding, baseline_finding_id: existing.id,
      evidence: "The finding exists in the baseline by fingerprint or stable dedup identity.",
    };
    if (foundationComplete && findingAbsenceProvableAgainst(baseline, fresh, finding)) return {
      state: "New", finding,
      evidence: "The complete baseline ran compatible producer engines/components and did not contain this finding.",
    };
    return {
      state: "Not rechecked / unknown", finding,
      evidence: "Baseline absence is not proof because target, coverage, producer execution, or component signatures were incompatible.",
    };
  });
  const unknown = items.some((item) => item.state === "Not rechecked / unknown");
  const coverage = !foundationComplete
    ? (baselineCoverage === "unknown" || freshCoverage === "unknown" ? "unknown" : "partial")
    : unknown ? "partial" : "complete";
  return {
    schema_version: "1.0.0", baseline_scan_id: baseline.scan_id, scan_id: fresh.scan_id,
    target: fresh.target, repository: repositoryIdentity(fresh), items,
    summary: {
      New: items.filter((item) => item.state === "New").length,
      Existing: items.filter((item) => item.state === "Existing").length,
      "Not rechecked / unknown": items.filter((item) => item.state === "Not rechecked / unknown").length,
    },
    coverage, partial: coverage !== "complete", notes,
  };
}

export function evaluateNewFindingPolicy(comparison: BaselineComparison, threshold?: Severity): {
  exit_code: 0 | 1 | 2;
  findings_at_or_above_threshold: number;
  reason: string;
} {
  const count = threshold ? comparison.items.filter((item) =>
    item.state === "New" && SEVERITY_RANK[item.finding.severity] >= SEVERITY_RANK[threshold]).length : 0;
  if (comparison.coverage !== "complete") return {
    exit_code: 2, findings_at_or_above_threshold: count,
    reason: `Baseline coverage is ${comparison.coverage}; unknown compatibility cannot pass CI.`,
  };
  if (threshold && count) return {
    exit_code: 1, findings_at_or_above_threshold: count,
    reason: `${count} new finding(s) met or exceeded the configured ${threshold} severity threshold.`,
  };
  return {
    exit_code: 0, findings_at_or_above_threshold: count,
    reason: threshold ? `No proven new findings met or exceeded ${threshold}.` : "Baseline comparison completed with compatible coverage.",
  };
}
