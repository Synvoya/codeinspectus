import { describe, expect, test } from "vitest";

import { summarizeScan } from "./summarize.js";
import {
  TRIVY_DB_PROVENANCE_INSTRUCTION,
  TRIVY_DB_PROVENANCE_MESSAGE,
  trivyDbProvenanceSignal,
} from "./trivy-db-provenance.js";
import type { ScanResult } from "./types.js";

function resultWithSignal(): ScanResult {
  const trivy_db_provenance = trivyDbProvenanceSignal(true, {
    "trivy:binary": "sha256:binary",
  });

  return {
    scan_id: "scan-test",
    target: "/tmp/repo",
    started_at: "2026-07-19T00:00:00.000Z",
    duration_ms: 1,
    engines_run: ["trivy@0.71.2"],
    engine_details: [],
    offline: true,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findings: [],
    truncated: false,
    total_findings_before_limit: 0,
    disclaimer: "This is not an audit or certification.",
    warnings: [],
    ...(trivy_db_provenance ? { trivy_db_provenance } : {}),
    git_safety: { state: "clean" },
  };
}

describe("Trivy DB provenance advisory", () => {
  test("digest absent + completed Trivy vuln scan surfaces both output halves without changing counts", () => {
    const result = resultWithSignal();

    expect(result.trivy_db_provenance).toEqual({
      state: "unrecorded",
      instruction: TRIVY_DB_PROVENANCE_INSTRUCTION,
    });
    expect(summarizeScan(result)).toContain(TRIVY_DB_PROVENANCE_MESSAGE);
    expect(result.summary.total).toBe(result.findings.length);
  });

  test("digest present produces no advisory", () => {
    expect(
      trivyDbProvenanceSignal(true, {
        "trivy:binary": "sha256:binary",
        "trivy:vulnerability-db": "sha256:database",
      }),
    ).toBeUndefined();
  });

  test("AI-only scan with absent digest produces no advisory", () => {
    expect(trivyDbProvenanceSignal(false, {})).toBeUndefined();
  });
});
