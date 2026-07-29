import { describe, expect, test } from "vitest";
import type { JsonExport } from "./schemas.js";
import { createSarifExport } from "./sarif.js";

describe("SARIF export", () => {
  test("maps rule, severity, remediation, fingerprint, producers, and coverage", () => {
    const source = {
      $schema: "https://codeinspectus.com/schemas/v2.0.0/export.schema.json",
      schema_version: "2.0.0", generated_by: { name: "codeinspectus", version: "2" },
      scan: { id: "scan-00000000-0000-4000-8000-000000000000", target: "/repo", started_at: "now", duration_ms: 1, offline: true, canonical_findings: true, configuration: { policy_mode: "report_only" }, summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 } },
      coverage: { aggregate: "partial", evidence: [{ category: "bounded_input", component: "files", state: "partial", detail: "one skipped" }] },
      findings: [{
        id: "f1", fingerprint: "fp", title: "Rule", severity: "high", engine: "opengrep", engines: ["opengrep"], rule_id: "r1", cwe: ["CWE-79"],
        location: { file: "src\\app.ts", start_line: 2, end_line: 3 }, message: "problem",
        remediation: { summary: "fix it", steps: ["fix"], references: [] }, frameworks: [], confidence: "high",
        producer_components: ["opengrep@1"], coverage_context: { aggregate: "partial", producer_components: ["opengrep@1"] },
      }],
    } satisfies JsonExport;
    const sarif = createSarifExport(source);
    expect(sarif.runs[0]).toMatchObject({
      tool: { driver: { rules: [{ id: "r1", help: { text: "fix it" } }] } },
      results: [{ ruleId: "r1", level: "error", fingerprints: { "codeinspectus/v2": "fp" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.ts" } } }], properties: { aggregate_coverage: "partial", producer_components: ["opengrep@1"] } }],
      properties: { aggregate_coverage: "partial" },
    });
  });
});
