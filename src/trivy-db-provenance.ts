import type { TrivyDbProvenance } from "./types.js";

export const TRIVY_DB_PROVENANCE_INSTRUCTION =
  "Run `codeinspectus install-engines` once to enable CVE rescan tracking.";

export const TRIVY_DB_PROVENANCE_MESSAGE =
  "CVE rescan tracking is not yet enabled on this machine. Run `codeinspectus install-engines` once to turn it on. (Your current scan results are complete and unaffected.)";

/**
 * Advisory metadata only. A Trivy vulnerability scan that completed without the
 * install-time DB content signature is useful for current findings, but cannot
 * later prove that a vanished CVE was checked by the same DB.
 */
export function trivyDbProvenanceSignal(
  trivyVulnerabilityScanRan: boolean,
  componentSignatures: Record<string, string>,
): TrivyDbProvenance | undefined {
  if (!trivyVulnerabilityScanRan || componentSignatures["trivy:vulnerability-db"]) {
    return undefined;
  }

  return {
    state: "unrecorded",
    instruction: TRIVY_DB_PROVENANCE_INSTRUCTION,
  };
}
