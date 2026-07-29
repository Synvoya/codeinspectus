import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";

const THREAT_FILES = [
  "docs/THREAT-MODEL-WORKFLOW.md",
  "agent-rules/codeinspectus-threat-model/SKILL.md",
] as const;
const MULTI_FILES = [
  "docs/MULTI-AGENT-REVIEW.md",
  "agent-rules/codeinspectus-multi-review/SKILL.md",
] as const;

describe("optional threat-model workflow", () => {
  test.each(THREAT_FILES)("%s preserves scanner truth across the document trust boundary", async (file) => {
    const content = (await readFile(file, "utf8")).replace(/\s+/g, " ");
    for (const required of [
      /optional/i,
      /repository-controlled (?:document|text)|repository content/i,
      /untrusted/i,
      /raw findings|scanner evidence/i,
      /agent interpretation/i,
      /cannot suppress|never suppress/i,
      /downgrade/i,
      /override|mutate/i,
      /prompt-injection|instructions found inside|do not obey document requests/i,
      /verified result set|scanner finding/i,
    ]) expect(content).toMatch(required);
  });

  test("malicious repository instructions remain inert and separately labelled", async () => {
    const text = await readFile("fixtures/agent-threat-model-workflow/cases.json", "utf8");
    expect(text).not.toMatch(/sk_live_|ghp_|AKIA[0-9A-Z]|BEGIN (?:RSA )?PRIVATE KEY/i);
    const fixture = JSON.parse(text) as {
      schema_version: string;
      synthetic: boolean;
      cases: Array<{ id: string; document_claim: string; expected: { action: string; scanner_mutation: boolean; label: string } }>;
    };
    expect(fixture).toMatchObject({ schema_version: "1.0.0", synthetic: true });
    expect(fixture.cases).toHaveLength(6);
    for (const entry of fixture.cases) {
      expect(entry.expected.scanner_mutation, entry.id).toBe(false);
      if (entry.document_claim === "instruction") {
        expect(entry.expected, entry.id).toMatchObject({ action: "reject_and_warn", label: "untrusted_document_warning" });
      } else {
        expect(entry.expected, entry.id).toMatchObject({ action: "cite_and_corroborate", label: "agent_interpretation" });
      }
    }
  });
});

describe("optional bounded multi-agent workflow", () => {
  test.each(MULTI_FILES)("%s bounds orchestration and separates evidence", async (file) => {
    const content = (await readFile(file, "utf8")).replace(/\s+/g, " ");
    for (const required of [
      /optional|opt-in/i,
      /normal CodeInspectus (?:CLI\/MCP )?scans|normal scans/i,
      /at most 3|agent count/i,
      /15 minutes|wall time/i,
      /scope|repository\/revision/i,
      /cost limit|token or monetary/i,
      /scanner evidence/i,
      /agent interpretation/i,
      /agent-generated candidate/i,
      /speculative[^.]{0,120}(?:never|outside)/i,
      /safe reproduction|bounded, local, reversible/i,
      /exact (?:original|prior)[^.]{0,80}scan ID|exact-prior/i,
      /only[^.]{0,100}`resolved`|only scanner `resolved`/i,
      /confirmed[^.]{0,100}disproven[^.]{0,100}speculative[^.]{0,100}not_rechecked/i,
    ]) expect(content).toMatch(required);
  });

  test("synthetic review outcomes never mutate verified results", async () => {
    const text = await readFile("fixtures/agent-multi-review-workflow/cases.json", "utf8");
    const fixture = JSON.parse(text) as {
      schema_version: string;
      synthetic: boolean;
      bounds: { max_agents: number; max_minutes: number; max_findings: number; max_repositories: number; cost_limit_required: boolean };
      cases: Array<{ id: string; origin: string; agent_conclusion: string; rescan: string; expected: { verified_result_mutation: boolean; agent_lane: string; scanner_resolution_claim: boolean } }>;
    };
    expect(fixture).toMatchObject({
      schema_version: "1.0.0",
      synthetic: true,
      bounds: { max_agents: 3, max_minutes: 15, max_findings: 10, max_repositories: 1, cost_limit_required: true },
    });
    expect(fixture.cases.map((entry) => entry.agent_conclusion)).toEqual([
      "confirmed", "disproven", "speculative", "not_rechecked", "confirmed",
    ]);
    for (const entry of fixture.cases) {
      expect(entry.expected.verified_result_mutation, entry.id).toBe(false);
      expect(entry.expected.agent_lane, entry.id).toBe(entry.agent_conclusion);
      expect(entry.expected.scanner_resolution_claim, entry.id).toBe(entry.origin === "scanner" && entry.rescan === "resolved");
    }
  });

  test("metadata, npm payload, and public projection include the optional workflows", async () => {
    for (const [file, displayName, invocation] of [
      ["agent-rules/codeinspectus-threat-model/agents/openai.yaml", "CodeInspectus Threat Model", "$codeinspectus-threat-model"],
      ["agent-rules/codeinspectus-multi-review/agents/openai.yaml", "CodeInspectus Multi Review", "$codeinspectus-multi-review"],
    ] as const) {
      const metadata = await readFile(file, "utf8");
      expect(metadata).toContain(`display_name: "${displayName}"`);
      expect(metadata).toContain(invocation);
      expect(metadata).toContain("allow_implicit_invocation: false");
    }
    const packageJson = JSON.parse(await readFile("package.json", "utf8")) as { files: string[] };
    expect(packageJson.files).toContain("agent-rules");
    if (existsSync("scripts/seed-public.mjs")) {
      const seed = await readFile("scripts/seed-public.mjs", "utf8");
      for (const artifact of [
        '"docs/THREAT-MODEL-WORKFLOW.md"',
        '"docs/MULTI-AGENT-REVIEW.md"',
        '"fixtures/agent-threat-model-workflow/"',
        '"fixtures/agent-multi-review-workflow/"',
      ]) expect(seed).toContain(artifact);
    } else {
      for (const artifact of [
        "docs/THREAT-MODEL-WORKFLOW.md",
        "docs/MULTI-AGENT-REVIEW.md",
        "fixtures/agent-threat-model-workflow/cases.json",
        "fixtures/agent-multi-review-workflow/cases.json",
      ]) await expect(readFile(artifact, "utf8"), artifact).resolves.not.toHaveLength(0);
    }
  });
});
