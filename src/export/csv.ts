import { jsonExportSchema, type JsonExport } from "./schemas.js";

export const CSV_SCHEMA_VERSION = "1.0.0" as const;

export const CSV_COLUMNS = [
  "record_type",
  "csv_schema_version",
  "scan_id",
  "target",
  "started_at",
  "duration_ms",
  "aggregate_coverage",
  "coverage_evidence_json",
  "policy_mode",
  "finding_id",
  "fingerprint",
  "title",
  "severity",
  "confidence",
  "engine",
  "engines_json",
  "producer_components_json",
  "rule_id",
  "vulnerability_aliases_json",
  "cwes_json",
  "owasp_web_json",
  "owasp_api_json",
  "owasp_llm_json",
  "attack_techniques_json",
  "file",
  "start_line",
  "end_line",
  "snippet",
  "message",
  "remediation_summary",
  "remediation_steps_json",
  "remediation_code_suggestion",
  "remediation_references_json",
  "frameworks_json",
  "is_secret",
  "secret_value_hash",
  "finding_kind",
  "scope_role",
  "baseline_state",
  "triage_context_json",
] as const;

type CsvColumn = (typeof CSV_COLUMNS)[number];
type CsvRow = Record<CsvColumn, string | number | undefined>;

function stableJson(value: unknown): string {
  return JSON.stringify(value);
}

/**
 * RFC 4180 quoting is not sufficient to stop spreadsheet formula execution. Prefix any cell
 * whose first non-whitespace character is a formula trigger, and any leading control character,
 * with a literal apostrophe before quoting it.
 */
export function spreadsheetSafeValue(value: string): string {
  return /^[\t\r\n]/.test(value) || /^\s*[=+@-]/.test(value) ? `'${value}` : value;
}

function encodeCell(value: string | number | undefined): string {
  const raw = value === undefined ? "" : String(value);
  return `"${spreadsheetSafeValue(raw).replaceAll('"', '""')}"`;
}

function encodeRow(row: CsvRow): string {
  return CSV_COLUMNS.map((column) => encodeCell(row[column])).join(",");
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function findingOrder(a: JsonExport["findings"][number], b: JsonExport["findings"][number]): number {
  return compareText(
    [a.id, a.fingerprint, a.location.file, String(a.location.start_line)].join("\0"),
    [b.id, b.fingerprint, b.location.file, String(b.location.start_line)].join("\0"),
  );
}

/** A deterministic, spreadsheet-safe projection of the validated canonical V2 JSON export. */
export function createCsvExport(input: JsonExport): string {
  const document = jsonExportSchema.parse(input);
  const coverageEvidence = [...document.coverage.evidence].sort((a, b) => compareText(
    [a.category, a.component, a.state, a.detail].join("\0"),
    [b.category, b.component, b.state, b.detail].join("\0"),
  ));
  const common = {
    csv_schema_version: CSV_SCHEMA_VERSION,
    scan_id: document.scan.id,
    target: document.scan.target,
    started_at: document.scan.started_at,
    duration_ms: document.scan.duration_ms,
    aggregate_coverage: document.coverage.aggregate,
    coverage_evidence_json: stableJson(coverageEvidence),
    policy_mode: document.scan.configuration.policy_mode,
  };
  const rows: CsvRow[] = [{
    ...Object.fromEntries(CSV_COLUMNS.map((column) => [column, undefined])) as CsvRow,
    ...common,
    record_type: "scan",
  }];
  const baseline = new Map(
    (document.baseline?.items ?? []).map((item) => [`${item.finding_id}\0${item.fingerprint}`, item.state]),
  );
  for (const finding of [...document.findings].sort(findingOrder)) {
    rows.push({
      ...Object.fromEntries(CSV_COLUMNS.map((column) => [column, undefined])) as CsvRow,
      ...common,
      record_type: "finding",
      finding_id: finding.id,
      fingerprint: finding.fingerprint,
      title: finding.title,
      severity: finding.severity,
      confidence: finding.confidence,
      engine: finding.engine,
      engines_json: stableJson([...finding.engines].sort()),
      producer_components_json: stableJson([...finding.producer_components].sort()),
      rule_id: finding.rule_id,
      vulnerability_aliases_json: stableJson([...(finding.vulnerability_aliases ?? [])].sort()),
      cwes_json: stableJson([...finding.cwe].sort()),
      owasp_web_json: stableJson([...(finding.owasp_web ?? [])].sort()),
      owasp_api_json: stableJson([...(finding.owasp_api ?? [])].sort()),
      owasp_llm_json: stableJson([...(finding.owasp_llm ?? [])].sort()),
      attack_techniques_json: stableJson([...(finding.attack_techniques ?? [])].sort()),
      file: finding.location.file,
      start_line: finding.location.start_line,
      end_line: finding.location.end_line,
      snippet: finding.location.snippet,
      message: finding.message,
      remediation_summary: finding.remediation.summary,
      remediation_steps_json: stableJson(finding.remediation.steps),
      remediation_code_suggestion: finding.remediation.code_suggestion,
      remediation_references_json: stableJson(finding.remediation.references),
      frameworks_json: stableJson(finding.frameworks
        .map((framework) => ({ ...framework, controls: [...framework.controls].sort() }))
        .sort((a, b) => compareText([a.framework, ...a.controls].join("\0"), [b.framework, ...b.controls].join("\0")))),
      is_secret: finding.is_secret === undefined ? undefined : String(finding.is_secret),
      secret_value_hash: finding.secret_value_hash,
      finding_kind: finding.finding_kind,
      scope_role: finding.scope_role,
      baseline_state: baseline.get(`${finding.id}\0${finding.fingerprint}`),
      triage_context_json: stableJson([...(finding.triage_context ?? [])].sort((a, b) => compareText(a.annotation_id, b.annotation_id))),
    });
  }
  return `${CSV_COLUMNS.map(encodeCell).join(",")}\r\n${rows.map(encodeRow).join("\r\n")}\r\n`;
}
