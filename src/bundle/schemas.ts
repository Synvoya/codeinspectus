import { z } from "zod";
import { gitScanScopeSchema, scanIdSchema, scannerEnum, severityEnum } from "../schemas.js";
import { aggregateCoverageEnvelopeSchema, exportFindingSchema } from "../export/schemas.js";

export const BUNDLE_SCHEMA_VERSION = "1.0.0" as const;
export const BUNDLE_SCHEMA_URI = "https://codeinspectus.com/schemas/bundle/1.0.0/manifest.schema.json" as const;

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const timestampSchema = z.string().datetime();

export const bundleArtifactPathSchema = z.enum([
  "findings.json",
  "coverage.json",
  "report.md",
  "results.sarif",
  "artifacts/scan-record.json",
  "artifacts/export.json",
]);

export const bundleManifestSchema = z.object({
  $schema: z.literal(BUNDLE_SCHEMA_URI),
  schema_version: z.literal(BUNDLE_SCHEMA_VERSION),
  bundle_id: z.string().regex(/^bundle-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
  created_by: z.object({ name: z.literal("codeinspectus"), version: z.string() }),
  schemas: z.object({
    bundle: z.literal(BUNDLE_SCHEMA_VERSION),
    export: z.enum(["2.0.0", "3.0.0"]),
    sarif: z.literal("2.1.0"),
    stored_scan: z.literal("2.0.0"),
  }),
  detection_database: z.object({ version: z.string(), date: z.string() }),
  native_engine: z.object({ name: z.literal("codeinspectus-ai"), version: z.string() }),
  engine_platform: z.string(),
  commodity_engines: z.array(z.object({
    engine: z.enum(["opengrep", "gitleaks", "trivy"]),
    version: z.string(),
    ran: z.boolean(),
    integrity_state: z.enum(["verified", "unavailable", "not_recorded"]),
    verified_sha256: sha256Schema.optional(),
  })).length(3),
  component_signatures: z.record(z.string()),
  target: z.object({
    path: z.string(),
    repository_root: z.string().optional(),
    git_revision: z.object({ commit: z.string().regex(/^[0-9a-f]{40,64}$/), source: z.enum(["commit_diff_head"]) }).optional(),
  }),
  scan_id: scanIdSchema,
  scan_configuration: z.object({ scanners: z.array(scannerEnum).optional(), severity_threshold: severityEnum.optional(), max_findings: z.number().int().positive() }).optional(),
  scan_scope: z.union([
    z.object({ mode: z.literal("whole_target"), target: z.string() }),
    gitScanScopeSchema,
  ]),
  timestamps: z.object({ started_at: timestampSchema, completed_at: timestampSchema, sealed_at: timestampSchema }),
  artifacts: z.array(z.object({ path: bundleArtifactPathSchema, media_type: z.string(), bytes: z.number().int().nonnegative(), sha256: sha256Schema })).length(6),
  seal: z.object({ algorithm: z.literal("sha256"), manifest_payload_sha256: sha256Schema }),
}).superRefine((manifest, context) => {
  const paths = manifest.artifacts.map((artifact) => artifact.path);
  if (new Set(paths).size !== paths.length) context.addIssue({ code: z.ZodIssueCode.custom, path: ["artifacts"], message: "artifact paths must be unique" });
  for (const expected of bundleArtifactPathSchema.options) {
    if (!paths.includes(expected)) context.addIssue({ code: z.ZodIssueCode.custom, path: ["artifacts"], message: `missing required artifact ${expected}` });
  }
  if (new Set(manifest.commodity_engines.map((engine) => engine.engine)).size !== 3) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["commodity_engines"], message: "commodity engines must contain opengrep, gitleaks, and trivy exactly once" });
  }
  for (const engine of manifest.commodity_engines) {
    if ((engine.integrity_state === "verified") !== Boolean(engine.verified_sha256)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["commodity_engines"], message: "verified integrity requires exactly one verified_sha256" });
    }
  }
});

export const bundleFindingsSchema = z.object({
  schema_version: z.literal(BUNDLE_SCHEMA_VERSION),
  scan_id: scanIdSchema,
  findings: z.array(exportFindingSchema),
});

export const bundleCoverageSchema = z.object({
  schema_version: z.literal(BUNDLE_SCHEMA_VERSION),
  scan_id: scanIdSchema,
  coverage: aggregateCoverageEnvelopeSchema,
});

export type BundleManifest = z.infer<typeof bundleManifestSchema>;
