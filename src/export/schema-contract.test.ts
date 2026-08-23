import { readFile } from "node:fs/promises";
import { Ajv } from "ajv";
import { describe, expect, test } from "vitest";
import type { StoredScanResult } from "../store.js";
import { compareAgainstBaseline } from "../baseline.js";
import { createTriageEvent } from "../triage.js";
import { createJsonExport } from "./model.js";
import { createSarifExport } from "./sarif.js";

const scan: StoredScanResult = {
  scan_id: "scan-00000000-0000-4000-8000-000000000000", target: "/repo",
  started_at: "2026-07-29T00:00:00.000Z", duration_ms: 1, engines_run: [], engine_details: [], offline: true,
  detected_technologies: [], pack_coverage: [], summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
  findings: [{
    id: "f1", fingerprint: "fp", title: "rule", severity: "high", engine: "opengrep", engines: ["opengrep"], rule_id: "r1",
    cwe: ["CWE-79"], location: { file: "src/app.ts", start_line: 1, end_line: 1 }, message: "problem",
    remediation: { summary: "fix", steps: ["fix"], references: [] }, frameworks: [], confidence: "high", producer_components: ["opengrep@1"],
  }], truncated: false, total_findings_before_limit: 1, disclaimer: "test", warnings: [], git_safety: { state: "clean" },
  scan_config: { scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 200 },
  secret_coverage: "verified", storage_schema_version: "2.0.0", canonical_findings: true,
};

async function compilePackagedSchema(path: string) {
  const [schema, repositoryTrust] = await Promise.all([
    readFile(path, "utf8").then((value) => JSON.parse(value) as object),
    readFile("schemas/codeinspectus-repository-trust-1.0.0.schema.json", "utf8").then(
      (value) => JSON.parse(value) as object,
    ),
  ]);
  const ajv = new Ajv({ strict: false, validateSchema: false });
  ajv.addSchema(repositoryTrust);
  return ajv.compile(schema);
}

describe("packaged V3 schemas", () => {
  test.each([
    ["schemas/codeinspectus-export-3.0.0.schema.json", () => createJsonExport(scan)],
    ["schemas/codeinspectus-sarif-3.0.0.schema.json", () => createSarifExport(createJsonExport(scan))],
  ] as const)("validates a runtime document against %s", async (path, document) => {
    const validate = await compilePackagedSchema(path);
    expect(validate(document()), JSON.stringify(validate.errors)).toBe(true);
  });

  test("packaged JSON and SARIF schemas accept typed Git scope and reject malformed commits", async () => {
    const scoped: StoredScanResult = { ...scan, git_scope: {
      schema_version: "1.0.0", mode: "working_tree", repository: "/repo",
      base: { requested: "HEAD", commit: "a".repeat(40) },
      entries: [{ status: "modified", path: "src/app.ts", binary: false, generated: false, submodule: false, inspected: true }],
      primary_paths: ["src/app.ts"], primary_finding_count: 1, supporting_context_finding_count: 0, supporting_context_scanned: true, completeness: "complete", limitations: [],
    }, history_revision: {
      schema_version: "1.0.0", repository: "/repo", commit: "b".repeat(40),
      committer_at: "2026-07-29T00:00:00.000Z", temporal_scope: "historical",
      snapshot_completeness: "complete", limitations: [],
    }, findings: [{ ...scan.findings[0]!, scope_role: "primary" }] };
    for (const [path, document] of [
      ["schemas/codeinspectus-export-3.0.0.schema.json", createJsonExport(scoped)],
      ["schemas/codeinspectus-sarif-3.0.0.schema.json", createSarifExport(createJsonExport(scoped))],
    ] as const) {
      const validate = await compilePackagedSchema(path);
      expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
      const invalid = structuredClone(document) as Record<string, any>;
      if ("scan" in invalid) invalid.scan.git_scope.base.commit = "HEAD";
      else invalid.runs[0].properties.git_scope.base.commit = "HEAD";
      expect(validate(invalid)).toBe(false);
    }
  });

  test("validates standalone baseline and triage contracts and rejects malformed identities", async () => {
    const baselineSchema = JSON.parse(await readFile("schemas/codeinspectus-baseline-1.0.0.schema.json", "utf8")) as object;
    const triageSchema = JSON.parse(await readFile("schemas/codeinspectus-triage-1.0.0.schema.json", "utf8")) as object;
    const ajv = new Ajv({ strict: false, validateSchema: false });
    const validateBaseline = ajv.compile(baselineSchema);
    const comparison = createJsonExport(scan, { baseline: compareAgainstBaseline(scan, scan) }).baseline!;
    expect(validateBaseline(comparison), JSON.stringify(validateBaseline.errors)).toBe(true);
    const invalidComparison = structuredClone(comparison);
    invalidComparison.baseline_scan_id = "../../outside";
    expect(validateBaseline(invalidComparison)).toBe(false);

    const validateTriage = ajv.compile(triageSchema);
    const event = createTriageEvent({ scan, finding: scan.findings[0]!, state: "Needs review", reason: "inspect" });
    expect(validateTriage(event), JSON.stringify(validateTriage.errors)).toBe(true);
    const invalidEvent = structuredClone(event) as Record<string, unknown>;
    invalidEvent.previous_event_id = "event-00000000-0000-4000-8000-000000000009";
    expect(validateTriage(invalidEvent)).toBe(false);
  });

  test("JSON schema rejects missing required fields and invalid coverage enum", async () => {
    const validate = await compilePackagedSchema("schemas/codeinspectus-export-3.0.0.schema.json");
    const missing = JSON.parse(JSON.stringify(createJsonExport(scan)));
    delete missing.findings[0].producer_components;
    expect(validate(missing)).toBe(false);
    const invalid = JSON.parse(JSON.stringify(createJsonExport(scan)));
    invalid.coverage.aggregate = "mostly";
    expect(validate(invalid)).toBe(false);
    const missingRepositoryTrust = JSON.parse(JSON.stringify(createJsonExport(scan)));
    delete missingRepositoryTrust.repository_trust;
    expect(validate(missingRepositoryTrust)).toBe(false);
    const contradictory = JSON.parse(JSON.stringify(createJsonExport(scan)));
    contradictory.scan.configuration.fail_on_severity = "high";
    expect(validate(contradictory)).toBe(false);

    const missingBaseline = JSON.parse(JSON.stringify(createJsonExport(scan)));
    missingBaseline.scan.configuration = {
      policy_mode: "new_findings_enforcement",
      baseline_scan_id: "scan-00000000-0000-4000-8000-000000000009",
      fail_on_new_severity: "high",
    };
    expect(validate(missingBaseline)).toBe(false);

    const malformedBaselineId = JSON.parse(JSON.stringify(createJsonExport(scan)));
    malformedBaselineId.scan.configuration.baseline_scan_id = "../../outside";
    expect(validate(malformedBaselineId)).toBe(false);
  });

  test("SARIF schema rejects missing fingerprint, remediation, and coverage", async () => {
    const validate = await compilePackagedSchema("schemas/codeinspectus-sarif-3.0.0.schema.json");
    const source = createSarifExport(createJsonExport(scan));
    for (const mutate of [
      (value: ReturnType<typeof createSarifExport>) => { delete (value.runs[0]!.results[0] as Partial<typeof value.runs[0]["results"][number]>).fingerprints; },
      (value: ReturnType<typeof createSarifExport>) => { delete (value.runs[0]!.results[0]!.properties as Partial<typeof value.runs[0]["results"][number]["properties"]>).remediation; },
      (value: ReturnType<typeof createSarifExport>) => { delete (value.runs[0]!.properties as Partial<typeof value.runs[0]["properties"]>).aggregate_coverage; },
    ]) {
      const invalid = structuredClone(source);
      mutate(invalid);
      expect(validate(invalid)).toBe(false);
    }

    const missingBaseline = structuredClone(source) as Record<string, any>;
    missingBaseline.runs[0].properties.policy_mode = "new_findings_enforcement";
    missingBaseline.runs[0].properties.baseline_scan_id = "scan-00000000-0000-4000-8000-000000000009";
    missingBaseline.runs[0].properties.fail_on_new_severity = "high";
    expect(validate(missingBaseline)).toBe(false);

    const malformedScanId = structuredClone(source) as Record<string, any>;
    malformedScanId.runs[0].properties.scan_id = "scan-../../outside";
    expect(validate(malformedScanId)).toBe(false);
  });
});
