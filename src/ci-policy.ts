import { SEVERITY_RANK, type Severity } from "./types.js";
import type { AggregateCoverage, JsonExport } from "./export/schemas.js";

export type CiPolicyExitCode = 0 | 1 | 2;

export interface CiPolicyEvaluation {
  mode: "report_only" | "enforcement";
  coverage: AggregateCoverage;
  threshold?: Severity;
  /** Declared coverage gaps the caller accepted; coverage still reads partial. */
  accepted_gaps?: string[];
  findings_at_or_above_threshold: number;
  exit_code: CiPolicyExitCode;
  reason: string;
}

/**
 * True when coverage is partial only through declared gaps (`gap:<id>`) the caller accepted. Fail
 * closed: some accepted gap must be the cause, and nothing else may be partial, excluded or unknown.
 */
export function partialOnlyThroughAcceptedGaps(
  coverage: Pick<JsonExport["coverage"], "aggregate" | "evidence">,
  acceptedGaps: readonly string[],
): boolean {
  const accepted = new Set(acceptedGaps.map((id) => `gap:${id}`));
  return coverage.aggregate === "partial" &&
    coverage.evidence.some((item) => accepted.has(item.component)) &&
    coverage.evidence.every((item) =>
      !["partial", "unknown", "excluded"].includes(item.state) || accepted.has(item.component));
}

/**
 * Coverage is evaluated before severity. A finding cannot turn an incomplete scan into the
 * more reassuring exit 1: missing/partial proof always fails closed with exit 2. The one exception
 * is opt-in: when every non-complete evidence item is a declared gap (`gap:<id>`) the caller named
 * in `accept_gaps`, coverage stays reported as partial but does not fail CI.
 */
export function evaluateCiPolicy(
  document: Pick<JsonExport, "coverage" | "findings">,
  threshold?: Severity,
  acceptedGaps: readonly string[] = [],
): CiPolicyEvaluation {
  const count = threshold
    ? document.findings.filter((finding) =>
      (finding.scope_role === undefined || finding.scope_role === "primary") &&
      SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[threshold]
    ).length
    : 0;
  const mode = threshold ? "enforcement" as const : "report_only" as const;
  const onlyAcceptedGaps = partialOnlyThroughAcceptedGaps(document.coverage, acceptedGaps);
  const coverage = document.coverage.aggregate;
  const acceptedNote = onlyAcceptedGaps ? { accepted_gaps: [...new Set(acceptedGaps)] } : {};
  if (coverage !== "complete" && !onlyAcceptedGaps) {
    return {
      mode,
      coverage: document.coverage.aggregate,
      ...(threshold ? { threshold } : {}),
      findings_at_or_above_threshold: count,
      exit_code: 2,
      reason: `Aggregate coverage is ${document.coverage.aggregate}; incomplete or unknown coverage cannot pass CI.`,
    };
  }
  const gapReason = onlyAcceptedGaps ? " Coverage is partial only through accepted gaps." : "";
  if (threshold && count > 0) {
    return {
      mode,
      coverage,
      ...acceptedNote,
      threshold,
      findings_at_or_above_threshold: count,
      exit_code: 1,
      reason: `${count} finding(s) met or exceeded the configured ${threshold} severity threshold.${gapReason}`,
    };
  }
  return {
    mode,
    coverage,
    ...acceptedNote,
    ...(threshold ? { threshold } : {}),
    findings_at_or_above_threshold: count,
    exit_code: 0,
    reason: (threshold
      ? `No findings met or exceeded the configured ${threshold} severity threshold.`
      : "Report-only scan completed with sufficient coverage; findings do not change the exit code.") + gapReason,
  };
}
