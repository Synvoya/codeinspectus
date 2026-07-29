import { z } from "zod";
import { findingSchema, gitScanScopeSchema, repositoryHistoryRevisionSchema, scanIdSchema, scannerEnum, severityEnum, summarySchema } from "../schemas.js";

export const EXPORT_SCHEMA_VERSION = "2.0.0" as const;
export const EXPORT_SCHEMA_URI = "https://codeinspectus.com/schemas/v2.0.0/export.schema.json" as const;
export const SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json" as const;

export const aggregateCoverageSchema = z.enum(["complete", "partial", "unknown"]);
export const coverageEvidenceSchema = z.object({
  category: z.enum([
    "component_execution",
    "declared_scope",
    "excluded_input",
    "bounded_input",
    "truncation",
    "dependency_limitation",
    "secret_uncertainty",
    "incompatible_surface",
    "deferred_surface",
    "not_rechecked",
    "legacy_store",
  ]),
  component: z.string(),
  state: z.enum(["covered", "not_applicable", "informational", "excluded", "partial", "unknown"]),
  detail: z.string(),
});

export const aggregateCoverageEnvelopeSchema = z.object({
  aggregate: aggregateCoverageSchema,
  evidence: z.array(coverageEvidenceSchema),
});

export const exportFindingSchema = findingSchema.extend({
  producer_components: z.array(z.string()).min(1),
  coverage_context: z.object({
    aggregate: aggregateCoverageSchema,
    producer_components: z.array(z.string()).min(1),
  }),
  triage_context: z.array(z.object({
    annotation_id: z.string().regex(/^triage-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
    state: z.enum(["Accepted", "False positive", "Risk accepted", "Needs review", "Fixed pending verification"]),
    reason: z.string(), recorded_at: z.string().datetime(), actor: z.string().optional(),
  })).optional(),
});

const exportConfigurationSchema = z.object({
  policy_mode: z.enum(["report_only", "enforcement", "new_findings_enforcement"]),
  fail_on_severity: severityEnum.optional(),
  baseline_scan_id: scanIdSchema.optional(),
  fail_on_new_severity: severityEnum.optional(),
  scanners: z.array(scannerEnum).optional(),
  severity_threshold: severityEnum.optional(),
  max_findings: z.number().int().positive().optional(),
}).superRefine((configuration, context) => {
  if (configuration.policy_mode === "enforcement" && !configuration.fail_on_severity) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["fail_on_severity"], message: "enforcement policy requires fail_on_severity" });
  }
  if (configuration.policy_mode === "enforcement" && configuration.fail_on_new_severity) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["fail_on_new_severity"], message: "enforcement must not declare fail_on_new_severity" });
  }
  if (configuration.policy_mode === "report_only" && (configuration.fail_on_severity || configuration.fail_on_new_severity)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["policy_mode"], message: "report_only must not declare a failure threshold" });
  }
  if (configuration.policy_mode === "new_findings_enforcement" && (!configuration.baseline_scan_id || !configuration.fail_on_new_severity)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["fail_on_new_severity"], message: "new-findings enforcement requires a baseline and threshold" });
  }
  if (configuration.policy_mode === "new_findings_enforcement" && configuration.fail_on_severity) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["fail_on_severity"], message: "new-findings enforcement must not declare fail_on_severity" });
  }
});

export const jsonExportSchema = z.object({
  $schema: z.literal(EXPORT_SCHEMA_URI),
  schema_version: z.literal(EXPORT_SCHEMA_VERSION),
  generated_by: z.object({ name: z.literal("codeinspectus"), version: z.string() }),
  scan: z.object({
    id: z.string(),
    target: z.string(),
    started_at: z.string(),
    duration_ms: z.number().int().nonnegative(),
    offline: z.literal(true),
    canonical_findings: z.boolean(),
    configuration: exportConfigurationSchema,
    summary: summarySchema,
    git_scope: gitScanScopeSchema.optional(),
    history_revision: repositoryHistoryRevisionSchema.optional(),
  }),
  coverage: aggregateCoverageEnvelopeSchema,
  baseline: z.object({
    schema_version: z.literal("1.0.0"), baseline_scan_id: scanIdSchema, scan_id: scanIdSchema, target: z.string(), repository: z.string(),
    summary: z.object({ New: z.number().int(), Existing: z.number().int(), "Not rechecked / unknown": z.number().int() }),
    coverage: aggregateCoverageSchema, partial: z.boolean(), notes: z.array(z.string()),
    items: z.array(z.object({ state: z.enum(["New", "Existing", "Not rechecked / unknown"]), finding_id: z.string(), fingerprint: z.string(), evidence: z.string() })),
  }).optional(),
  triage_store: z.object({ partial: z.boolean(), matched_annotations: z.number().int().nonnegative() }).optional(),
  findings: z.array(exportFindingSchema),
}).superRefine((document, context) => {
  if (document.baseline && !document.scan.configuration.baseline_scan_id) context.addIssue({ code: z.ZodIssueCode.custom, path: ["scan", "configuration", "baseline_scan_id"], message: "baseline projection requires baseline_scan_id" });
  if (document.scan.configuration.baseline_scan_id && document.baseline?.baseline_scan_id !== document.scan.configuration.baseline_scan_id) context.addIssue({ code: z.ZodIssueCode.custom, path: ["baseline", "baseline_scan_id"], message: "baseline ID must match scan configuration" });
  if (document.baseline && document.baseline.scan_id !== document.scan.id) context.addIssue({ code: z.ZodIssueCode.custom, path: ["baseline", "scan_id"], message: "baseline current scan ID must match export scan" });
  if (document.scan.configuration.policy_mode === "new_findings_enforcement" && !document.baseline) context.addIssue({ code: z.ZodIssueCode.custom, path: ["baseline"], message: "new-findings enforcement requires a baseline projection" });
});

const sarifMessageSchema = z.object({ text: z.string() });
const sarifRegionSchema = z.object({
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  snippet: sarifMessageSchema.optional(),
});
export const sarifExportSchema = z.object({
  $schema: z.literal(SARIF_SCHEMA_URI),
  version: z.literal("2.1.0"),
  runs: z.array(z.object({
    tool: z.object({ driver: z.object({
      name: z.literal("CodeInspectus"),
      version: z.string(),
      informationUri: z.string(),
      rules: z.array(z.object({
        id: z.string(),
        name: z.string(),
        shortDescription: sarifMessageSchema,
        help: sarifMessageSchema,
        properties: z.record(z.unknown()),
      })),
    }) }),
    invocations: z.array(z.object({ executionSuccessful: z.boolean(), properties: z.record(z.unknown()) })),
    results: z.array(z.object({
      ruleId: z.string(),
      baselineState: z.enum(["new", "unchanged"]).optional(),
      level: z.enum(["error", "warning", "note"]),
      message: sarifMessageSchema,
      locations: z.array(z.object({ physicalLocation: z.object({
        artifactLocation: z.object({ uri: z.string() }),
        region: sarifRegionSchema,
      }) })),
      fingerprints: z.record(z.string()),
      properties: z.record(z.unknown()),
    })),
    properties: z.record(z.unknown()),
  })).length(1),
});

export type AggregateCoverage = z.infer<typeof aggregateCoverageSchema>;
export type CoverageEvidence = z.infer<typeof coverageEvidenceSchema>;
export type JsonExport = z.infer<typeof jsonExportSchema>;
export type SarifExport = z.infer<typeof sarifExportSchema>;
