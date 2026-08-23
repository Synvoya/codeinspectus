import { SERVER_VERSION } from "../config.js";
import type { Severity } from "../types.js";
import type { JsonExport } from "./schemas.js";
import { SARIF_SCHEMA_URI, sarifExportSchema, type SarifExport } from "./schemas.js";

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  return severity === "critical" || severity === "high" ? "error" : severity === "medium" ? "warning" : "note";
}

export function createSarifExport(source: JsonExport): SarifExport {
  const rules = [...new Map(source.findings.map((finding) => [finding.rule_id, finding])).values()]
    .sort((left, right) => left.rule_id.localeCompare(right.rule_id))
    .map((finding) => ({
      id: finding.rule_id,
      name: finding.title,
      shortDescription: { text: finding.title },
      help: { text: finding.remediation.summary },
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        cwe: finding.cwe,
        producer: finding.engine,
        producer_components: finding.producer_components,
      },
    }));
  const document: SarifExport = {
    $schema: SARIF_SCHEMA_URI,
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "CodeInspectus",
        version: SERVER_VERSION,
        informationUri: "https://codeinspectus.com",
        rules,
      } },
      invocations: [{
        executionSuccessful: source.coverage.aggregate !== "unknown",
        properties: {
          offline: true,
          scan_id: source.scan.id,
          aggregate_coverage: source.coverage.aggregate,
          coverage_evidence: source.coverage.evidence,
          repository_trust: source.repository_trust,
          ...(source.scan.git_scope ? { git_scope: source.scan.git_scope } : {}),
          ...(source.scan.history_revision ? { history_revision: source.scan.history_revision } : {}),
        },
      }],
      results: source.findings.map((finding) => ({
        ruleId: finding.rule_id,
        ...(source.baseline?.items.find((item) => item.finding_id === finding.id)?.state === "New"
          ? { baselineState: "new" as const }
          : source.baseline?.items.find((item) => item.finding_id === finding.id)?.state === "Existing"
            ? { baselineState: "unchanged" as const }
            : {}),
        level: sarifLevel(finding.severity),
        message: { text: finding.message },
        locations: [{ physicalLocation: {
          artifactLocation: { uri: finding.location.file.replace(/\\/g, "/") },
          region: {
            startLine: Math.max(1, finding.location.start_line),
            endLine: Math.max(1, finding.location.end_line),
            ...(finding.location.snippet ? { snippet: { text: finding.location.snippet } } : {}),
          },
        } }],
        fingerprints: { "codeinspectus/v3": finding.fingerprint },
        properties: {
          finding_id: finding.id,
          severity: finding.severity,
          confidence: finding.confidence,
          cwe: finding.cwe,
          remediation: finding.remediation,
          producer: finding.engine,
          producers: finding.engines,
          producer_components: finding.producer_components,
          aggregate_coverage: source.coverage.aggregate,
          coverage_context: finding.coverage_context,
          ...(finding.scope_role ? { scope_role: finding.scope_role } : {}),
          ...(finding.triage_context ? { triage_context: finding.triage_context } : {}),
        },
      })),
      properties: {
        codeinspectus_schema_version: source.schema_version,
        scan_id: source.scan.id,
        target: source.scan.target,
        policy_mode: source.scan.configuration.policy_mode,
        ...(source.scan.configuration.fail_on_severity
          ? { fail_on_severity: source.scan.configuration.fail_on_severity }
          : {}),
        ...(source.scan.configuration.fail_on_new_severity
          ? { fail_on_new_severity: source.scan.configuration.fail_on_new_severity, baseline_scan_id: source.scan.configuration.baseline_scan_id }
          : {}),
        ...(source.baseline ? { baseline: source.baseline } : {}),
        ...(source.triage_store ? { triage_store: source.triage_store } : {}),
        aggregate_coverage: source.coverage.aggregate,
        coverage_evidence: source.coverage.evidence,
        repository_trust: source.repository_trust,
        ...(source.scan.git_scope ? { git_scope: source.scan.git_scope } : {}),
        ...(source.scan.history_revision ? { history_revision: source.scan.history_revision } : {}),
      },
    }],
  };
  return sarifExportSchema.parse(document);
}
