/**
 * CG-42 — the git-safety advisory renders under its OWN "Before you fix:" line in the
 * human-readable scan summary, NOT under "Warnings:" (a non-expert reads "Warnings" as
 * "problems in my code"; the checkpoint nudge is a pre-fix safety note, not a finding).
 * CG-30 routing warnings still render under "Warnings:".
 */

import { describe, test, expect } from "vitest";
import { summarizeScan } from "./summarize.js";
import { NO_GIT_RECOMMENDATION, DIRTY_RECOMMENDATION } from "./git-safety.js";
import type { ScanResult, GitSafety } from "./types.js";

function mkResult(over: Partial<ScanResult> = {}): ScanResult {
  return {
    scan_id: "scan-test",
    target: "/tmp/x",
    started_at: "2026-07-01T00:00:00.000Z",
    duration_ms: 1,
    engines_run: ["codeinspectus-ai@1"],
    engine_details: [],
    offline: true,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findings: [],
    truncated: false,
    total_findings_before_limit: 0,
    disclaimer: "This is not an audit or certification.",
    warnings: [],
    git_safety: { state: "clean" } as GitSafety,
    ...over,
  };
}

describe("summarizeScan — git-safety advisory placement (CG-42)", () => {
  test("no_git → recommendation under 'Before you fix:', and NO 'Warnings:' section", () => {
    const out = summarizeScan(
      mkResult({ git_safety: { state: "no_git", recommendation: NO_GIT_RECOMMENDATION }, warnings: [] }),
    );
    expect(out).toContain(`Before you fix:\n  ${NO_GIT_RECOMMENDATION}`);
    expect(out).not.toContain("Warnings:");
  });

  test("dirty + CG-30 routing warning → advice under 'Before you fix:', routing under 'Warnings:'", () => {
    const routing =
      "File routing: reframed 2 git-ignored finding(s) as local-hygiene (lower urgency).";
    const out = summarizeScan(
      mkResult({
        git_safety: { state: "dirty", recommendation: DIRTY_RECOMMENDATION },
        warnings: [routing],
      }),
    );
    expect(out).toContain(`Before you fix:\n  ${DIRTY_RECOMMENDATION}`);
    expect(out).toContain(`Warnings:\n  - ${routing}`);
    // the git recommendation must NOT leak into the Warnings section
    const warningsSection = out.slice(out.indexOf("Warnings:"));
    expect(warningsSection).not.toContain(DIRTY_RECOMMENDATION);
  });

  test("clean → no 'Before you fix:' line", () => {
    const out = summarizeScan(mkResult({ git_safety: { state: "clean" }, warnings: [] }));
    expect(out).not.toContain("Before you fix:");
  });

  test("unknown → no 'Before you fix:' line (degrade silently)", () => {
    const out = summarizeScan(mkResult({ git_safety: { state: "unknown" }, warnings: [] }));
    expect(out).not.toContain("Before you fix:");
  });
});
