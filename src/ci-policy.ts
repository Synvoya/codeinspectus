import { SEVERITY_RANK, type Severity } from "./types.js";
import type { AggregateCoverage, JsonExport } from "./export/schemas.js";

export type CiPolicyExitCode = 0 | 1 | 2;

export interface CiPolicyEvaluation {
  mode: "report_only" | "enforcement";
  coverage: AggregateCoverage;
  threshold?: Severity;
  findings_at_or_above_threshold: number;
  exit_code: CiPolicyExitCode;
  reason: string;
}

/**
 * Coverage is evaluated before severity. A finding cannot turn an incomplete scan into the
 * more reassuring exit 1: missing/partial proof always fails closed with exit 2.
 */
export function evaluateCiPolicy(
  document: Pick<JsonExport, "coverage" | "findings">,
  threshold?: Severity,
): CiPolicyEvaluation {
  const count = threshold
    ? document.findings.filter((finding) =>
      (finding.scope_role === undefined || finding.scope_role === "primary") &&
      SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[threshold]
    ).length
    : 0;
  const mode = threshold ? "enforcement" as const : "report_only" as const;
  if (document.coverage.aggregate !== "complete") {
    return {
      mode,
      coverage: document.coverage.aggregate,
      ...(threshold ? { threshold } : {}),
      findings_at_or_above_threshold: count,
      exit_code: 2,
      reason: `Aggregate coverage is ${document.coverage.aggregate}; incomplete or unknown coverage cannot pass CI.`,
    };
  }
  if (threshold && count > 0) {
    return {
      mode,
      coverage: "complete",
      threshold,
      findings_at_or_above_threshold: count,
      exit_code: 1,
      reason: `${count} finding(s) met or exceeded the configured ${threshold} severity threshold.`,
    };
  }
  return {
    mode,
    coverage: "complete",
    ...(threshold ? { threshold } : {}),
    findings_at_or_above_threshold: count,
    exit_code: 0,
    reason: threshold
      ? `No findings met or exceeded the configured ${threshold} severity threshold.`
      : "Report-only scan completed with sufficient coverage; findings do not change the exit code.",
  };
}
