import { compareShadowFindings } from "./shadow/opengrep-parity.js";
import type { Finding } from "./types.js";

export const PROMOTED_OPENGREP_RULE_IDS = new Set([
  "ci-baseline-weak-hash",
  "ci-baseline-weak-cipher",
]);

export interface NativeSastReconciliation {
  findings: Finding[];
  nativeFindings: Finding[];
  referenceFindings: Finding[];
  suppressedCandidateCount: number;
  metadataMismatchCount: number;
  referenceOnlyCount: number;
  usedFallback: boolean;
  note?: string;
}

function identity(finding: Finding): string {
  return JSON.stringify([
    finding.rule_id,
    finding.location.file.replace(/\\/g, "/"),
    finding.location.start_line,
    finding.location.end_line,
  ]);
}

/**
 * Replace selected Opengrep results only when a native result is semantically exact.
 * This runs before routing and global dedup so producer provenance can never be unioned.
 */
export function reconcileNativeSast(
  opengrepRan: boolean,
  referenceFindings: readonly Finding[],
  candidateFindings: readonly Finding[],
): NativeSastReconciliation {
  const selectedReference = referenceFindings.filter((finding) => PROMOTED_OPENGREP_RULE_IDS.has(finding.rule_id));
  const unrelatedReference = referenceFindings.filter((finding) => !PROMOTED_OPENGREP_RULE_IDS.has(finding.rule_id));
  if (!opengrepRan) {
    return {
      findings: [...unrelatedReference, ...candidateFindings],
      nativeFindings: [...candidateFindings],
      referenceFindings: [...unrelatedReference],
      suppressedCandidateCount: 0,
      metadataMismatchCount: 0,
      referenceOnlyCount: 0,
      usedFallback: true,
      note: "Opengrep did not run; promoted rules used the native fallback.",
    };
  }

  const unmatchedReference = [...selectedReference];
  const nativeFindings: Finding[] = [];
  let metadataMismatchCount = 0;
  let suppressedCandidateCount = 0;

  for (const candidate of candidateFindings) {
    const exactIndex = unmatchedReference.findIndex(
      (reference) => identity(reference) === identity(candidate) &&
        compareShadowFindings([reference], [candidate]).exact,
    );
    if (exactIndex >= 0) {
      unmatchedReference.splice(exactIndex, 1);
      nativeFindings.push(candidate);
      continue;
    }
    if (unmatchedReference.some((reference) => identity(reference) === identity(candidate))) {
      metadataMismatchCount++;
    }
    suppressedCandidateCount++;
  }

  const noteParts: string[] = [];
  if (suppressedCandidateCount) noteParts.push(`${suppressedCandidateCount} native-only or mismatched candidate(s) suppressed`);
  if (metadataMismatchCount) noteParts.push(`${metadataMismatchCount} metadata mismatch(es) retained from Opengrep`);
  if (unmatchedReference.length) noteParts.push(`${unmatchedReference.length} Opengrep-only finding(s) retained`);
  return {
    findings: [...unrelatedReference, ...unmatchedReference, ...nativeFindings],
    nativeFindings,
    referenceFindings: [...unrelatedReference, ...unmatchedReference],
    suppressedCandidateCount,
    metadataMismatchCount,
    referenceOnlyCount: unmatchedReference.length,
    usedFallback: false,
    ...(noteParts.length ? { note: `${noteParts.join("; ")}.` } : {}),
  };
}
