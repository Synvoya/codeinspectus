import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";

const RULE_FILES = [
  "agent-rules/codeinspectus-fix-one/SKILL.md",
  "agent-rules/codex-AGENTS.md",
  "agent-rules/claude-code.md",
  "agent-rules/cursor.mdc",
  "agent-rules/windsurf.md",
  "agent-rules/cline.md",
] as const;

type WorkflowCase = {
  id: string;
  disposition: "actionable" | "disproven";
  reproduction: "approved_safe" | "not_needed" | "unsafe";
  regression_before: "failing_as_expected" | "not_practical" | "failed_to_run" | "not_run";
  patch_approval: "approved" | "rejected" | "not_requested";
  focused_tests: "passed" | "failed" | "not_run";
  rescan: "resolved" | "not_rechecked" | "not_run";
  unrelated_findings: number;
  expected: { may_reproduce: boolean; may_patch: boolean; target_report: string };
};

function evaluate(testCase: WorkflowCase): WorkflowCase["expected"] {
  const mayReproduce = testCase.disposition === "actionable" && testCase.reproduction === "approved_safe";
  const mayPatch = testCase.disposition === "actionable" && testCase.patch_approval === "approved" &&
    testCase.regression_before !== "failed_to_run";
  let targetReport: string;
  if (testCase.disposition === "disproven") targetReport = "disproven_not_resolved";
  else if (testCase.regression_before === "failed_to_run") targetReport = "blocked_regression";
  else if (testCase.patch_approval === "rejected") targetReport = "stopped_no_edit";
  else if (testCase.focused_tests === "failed") targetReport = "tests_failed_unverified";
  else if (testCase.rescan === "not_rechecked") targetReport = "proof_gap_not_rechecked";
  else if (testCase.rescan === "resolved" && testCase.unrelated_findings > 0) targetReport = "scanner_resolved_unrelated_untouched";
  else if (testCase.rescan === "resolved" && (testCase.reproduction === "unsafe" || testCase.regression_before === "not_practical")) {
    targetReport = "scanner_resolved_with_proof_gap";
  } else if (testCase.rescan === "resolved") targetReport = "scanner_resolved";
  else targetReport = "unverified";
  return { may_reproduce: mayReproduce, may_patch: mayPatch, target_report: targetReport };
}

describe("shipped one-finding agent workflow", () => {
  test.each(RULE_FILES)("%s carries every mutation and proof gate", async (file) => {
    const content = await readFile(file, "utf8");
    const compact = content.replace(/\s+/g, " ");
    for (const required of [
      /exactly one/i,
      /source, sink, controls, and reachability/i,
      /do not reproduce by default|reproduce only/i,
      /explicit(?:ly)? approved|explicit (?:user |patch )?approval/i,
      /failing-before-fix/i,
      /smallest (?:source-and-test )?patch|smallest test/i,
      /patch approval separately/i,
      /no source or test edit before explicit patch approval/i,
      /add the focused regression first/i,
      /focused[^.]{0,80}(?:tests|regression)/i,
      /exact (?:original|prior)[^\n.]{0,40}scan ID|exact original `scan_id`/i,
      /only when[^.]{0,120}`resolved`/i,
      /`not_rechecked`[^.]{0,80}proof gap/i,
      /unrelated findings[^.]{0,80}(?:untouched|separately|out of the patch)|do not fix unrelated findings/i,
      /investigation[^.]{0,80}regression[^.]{0,80}test[^.]{0,80}rescan\/proof/i,
    ]) expect(compact).toMatch(required);
    const triageSentence = compact.split(/(?<=[.!?])\s+/).find((sentence) =>
      /triage/i.test(sentence) && /`Accepted`/.test(sentence));
    expect(triageSentence).toBeDefined();
    expect(triageSentence).toMatch(/context|do not interpret/i);
    expect(triageSentence).toMatch(/not|never/i);
    expect(triageSentence).toMatch(/approval|permission/i);
  });

  test("synthetic cases deterministically preserve approvals and proof gaps", async () => {
    const fixtureText = await readFile("fixtures/agent-remediation-workflow/cases.json", "utf8");
    expect(fixtureText).not.toMatch(/sk_live_|ghp_|AKIA[0-9A-Z]|BEGIN (?:RSA )?PRIVATE KEY/i);
    const fixture = JSON.parse(fixtureText) as {
      schema_version: string; synthetic: boolean; cases: WorkflowCase[];
    };
    expect(fixture).toMatchObject({ schema_version: "1.0.0", synthetic: true });
    expect(fixture.cases.map((entry) => entry.id)).toEqual([
      "accepted-selection", "disproven-by-control", "unsafe-to-reproduce", "rescan-not-rechecked",
      "rejected-patch", "failing-regression-command", "focused-test-fails-after-patch",
      "target-resolved-unrelated-remain",
    ]);
    for (const testCase of fixture.cases) expect(evaluate(testCase), testCase.id).toEqual(testCase.expected);
  });

  test("skill metadata and fail-closed public projection include the workflow artifacts", async () => {
    const metadata = await readFile("agent-rules/codeinspectus-fix-one/agents/openai.yaml", "utf8");
    expect(metadata).toMatch(/display_name: "CodeInspectus Fix One"/);
    expect(metadata).toMatch(/short_description: "Fix one selected security finding safely"/);
    expect(metadata).toMatch(/default_prompt: "Use \$codeinspectus-fix-one /);
    if (existsSync("scripts/seed-public.mjs")) {
      const seed = await readFile("scripts/seed-public.mjs", "utf8");
      expect(seed).toContain('"docs/ONE-FINDING-REMEDIATION.md"');
      expect(seed).toContain('"fixtures/agent-remediation-workflow/"');
    } else {
      await expect(readFile("docs/ONE-FINDING-REMEDIATION.md", "utf8")).resolves.toContain("Required sequence");
      await expect(readFile("fixtures/agent-remediation-workflow/cases.json", "utf8")).resolves.toContain("accepted-selection");
    }
  });
});
