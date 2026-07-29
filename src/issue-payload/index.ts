import { SERVER_VERSION } from "../config.js";
import { createJsonExport } from "../export/model.js";
import { redactSnippet } from "../redact.js";
import type { StoredScanResult } from "../store.js";
import { ISSUE_PAYLOAD_SCHEMA_URI, ISSUE_PAYLOAD_SCHEMA_VERSION, issuePayloadSchema, type DestinationVisibility, type IssueAdapter, type IssuePayload } from "./schemas.js";

const MAX_BODY = 20_000;

function compareText(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
function cleanText(value: string): string { return redactSnippet(value).replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim(); }
function truncate(value: string, maximum: number): string { return value.length <= maximum ? value : `${value.slice(0, maximum - 15)}… [truncated]`; }
function markdown(value: string): string {
  return cleanText(value).replace(/@/g, "@\u200b").replace(/([\\`*_{}\[\]()#+.!|>~-])/g, "\\$1");
}

function labels(severity: string, cwe: string[]): string[] {
  return [...new Set(["codeinspectus", `severity-${severity}`, ...cwe.slice(0, 10).map((entry) => cleanText(entry).toLowerCase().replace(/[^a-z0-9-]/g, "-"))])]
    .filter(Boolean).sort(compareText).slice(0, 20);
}

function warnings(visibility: DestinationVisibility): string[] {
  return [
    "The payload is redacted but repository paths, vulnerability metadata and remediation context can still be sensitive. Review every field before sharing.",
    visibility === "public"
      ? "PUBLIC DESTINATION: confirm authorization and coordinated-disclosure requirements before posting this payload."
      : "PRIVATE DESTINATION: verify project membership, integrations, retention and access controls before posting this payload.",
    "CodeInspectus generated JSON only. No issue was submitted and no network request was made.",
  ];
}

function bodyFor(scan: StoredScanResult, finding: ReturnType<typeof createJsonExport>["findings"][number], visibility: DestinationVisibility, aggregate: string): string {
  const notice = warnings(visibility)[1]!;
  const lines = [
    `> ${notice}`,
    "",
    "Generated from a local CodeInspectus scan. Review before disclosure; no issue was submitted automatically.",
    "",
    `- Scan: ${markdown(scan.scan_id)}`,
    `- Finding: ${markdown(finding.id)} (${markdown(finding.fingerprint)})`,
    `- Rule: ${markdown(finding.rule_id)}`,
    `- Severity / confidence: ${markdown(finding.severity)} / ${markdown(finding.confidence)}`,
    `- Location: ${markdown(finding.location.file)}:${finding.location.start_line}-${finding.location.end_line}`,
    `- CWE: ${finding.cwe.slice(0, 50).map(markdown).sort(compareText).join(", ")}`,
    `- Producer components: ${finding.producer_components.slice(0, 50).map(markdown).sort(compareText).join(", ")}`,
    `- Aggregate scan coverage: ${markdown(aggregate)}`,
    "",
    "## Evidence",
    markdown(finding.message),
    "",
    "## Remediation",
    markdown(finding.remediation.summary),
    ...finding.remediation.steps.slice(0, 20).map((step, index) => `${index + 1}. ${markdown(step)}`),
    "",
    "No source snippet or matched secret value is included in this payload.",
  ];
  return truncate(lines.join("\n"), MAX_BODY);
}

export function createIssuePayload(scan: StoredScanResult, findingId: string, adapter: IssueAdapter, visibility: DestinationVisibility): IssuePayload {
  const exported = createJsonExport(scan);
  const finding = exported.findings.find((entry) => entry.id === findingId);
  if (!finding) throw new Error(`Finding '${cleanText(findingId)}' does not exist in stored scan '${scan.scan_id}'.`);
  const title = truncate(`[${finding.severity.toUpperCase()}] ${cleanText(finding.title).replace(/@/g, "@\u200b")} (${cleanText(finding.rule_id)})`, 240);
  const body = bodyFor(scan, finding, visibility, exported.coverage.aggregate);
  const common = {
    $schema: ISSUE_PAYLOAD_SCHEMA_URI, schema_version: ISSUE_PAYLOAD_SCHEMA_VERSION,
    generated_by: { name: "codeinspectus" as const, version: SERVER_VERSION },
    source: { scan_id: scan.scan_id, finding_id: finding.id, fingerprint: finding.fingerprint, aggregate_coverage: exported.coverage.aggregate },
    destination: {
      visibility, warnings: warnings(visibility), review_required: true as const, submission: "not_performed" as const,
      required_destination_fields: adapter === "github" ? ["repository_owner", "repository_name"] : adapter === "jira" ? ["fields.project", "fields.issuetype"] : ["teamId"],
    },
  };
  const document = adapter === "github"
    ? { ...common, adapter, payload: { title, body, labels: labels(finding.severity, finding.cwe) } }
    : adapter === "jira"
      ? { ...common, adapter, payload: { fields: { summary: title, description: { type: "doc" as const, version: 1 as const, content: [{ type: "paragraph" as const, content: [{ type: "text" as const, text: body }] }] }, labels: labels(finding.severity, finding.cwe) } } }
      : { ...common, adapter, payload: { title, description: body } };
  return issuePayloadSchema.parse(document);
}
