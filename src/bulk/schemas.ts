import { z } from "zod";
import { scanIdSchema, scannerEnum } from "../schemas.js";

export const BULK_SCHEMA_VERSION = "1.0.0" as const;
export const BULK_SCHEMA_URI = "https://codeinspectus.com/schemas/bulk/1.0.0/manifest.schema.json" as const;

const repositoryStateSchema = z.enum(["pending", "running", "complete", "partial", "unknown", "failed", "cancelled"]);

export const bulkManifestSchema = z.object({
  $schema: z.literal(BULK_SCHEMA_URI),
  schema_version: z.literal(BULK_SCHEMA_VERSION),
  run_id: z.string().regex(/^bulk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
  parent: z.string(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  configuration: z.object({
    concurrency: z.number().int().min(1).max(8),
    max_repositories: z.number().int().min(1).max(500),
    max_attempts: z.number().int().min(1).max(5),
    scanners: z.array(scannerEnum).optional(),
    max_findings: z.number().int().positive(),
    include_compliance: z.boolean(),
  }),
  discovery: z.object({
    entry_limit: z.number().int().positive(),
    candidate_entries: z.number().int().nonnegative(),
    repositories_found: z.number().int().nonnegative(),
    repositories_selected: z.number().int().nonnegative(),
    repositories_omitted: z.number().int().nonnegative(),
    partial: z.boolean(),
    limitations: z.array(z.string()),
  }),
  repositories: z.array(z.object({
    repository: z.string(),
    relative_path: z.string().min(1).refine((value) => value !== "." && value !== ".." && !/[\\/]/.test(value), "relative path must be one child name"),
    state: repositoryStateSchema,
    attempts: z.number().int().nonnegative().max(5),
    started_at: z.string().datetime().optional(),
    completed_at: z.string().datetime().optional(),
    scan_id: scanIdSchema.optional(),
    aggregate_coverage: z.enum(["complete", "partial", "unknown"]).optional(),
    finding_count: z.number().int().nonnegative().optional(),
    highest_severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
    error: z.string().optional(),
  })).max(500),
  aggregate: z.object({
    coverage: z.enum(["complete", "partial", "unknown"]),
    total: z.number().int().nonnegative(),
    pending: z.number().int().nonnegative(),
    running: z.number().int().nonnegative(),
    complete: z.number().int().nonnegative(),
    partial: z.number().int().nonnegative(),
    unknown: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative(),
    cancelled: z.number().int().nonnegative(),
    finding_count: z.number().int().nonnegative(),
  }),
}).superRefine((manifest, context) => {
  const repositories = manifest.repositories.map((entry) => entry.repository);
  const relative = manifest.repositories.map((entry) => entry.relative_path);
  if (new Set(repositories).size !== repositories.length || new Set(relative).size !== relative.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["repositories"], message: "bulk repositories must be unique" });
  }
  if (manifest.configuration.scanners && new Set(manifest.configuration.scanners).size !== manifest.configuration.scanners.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["configuration", "scanners"], message: "scanner classes must be unique" });
  }
  const sorted = [...repositories].sort();
  if (repositories.some((repository, index) => repository !== sorted[index])) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["repositories"], message: "bulk repositories must be deterministically sorted" });
  }
  if (manifest.discovery.repositories_selected !== manifest.repositories.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["discovery", "repositories_selected"], message: "selected count must match repository records" });
  }
  if (manifest.discovery.repositories_found !== manifest.discovery.repositories_selected + manifest.discovery.repositories_omitted) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["discovery", "repositories_found"], message: "found count must equal selected plus omitted" });
  }
  if (manifest.discovery.partial !== (manifest.discovery.repositories_omitted > 0 || manifest.discovery.limitations.length > 0)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["discovery", "partial"], message: "partial discovery must match omissions or limitations" });
  }
  const states = Object.fromEntries(repositoryStateSchema.options.map((state) => [state, manifest.repositories.filter((entry) => entry.state === state).length]));
  for (const state of repositoryStateSchema.options) {
    if (manifest.aggregate[state] !== states[state]) context.addIssue({ code: z.ZodIssueCode.custom, path: ["aggregate", state], message: `${state} count does not match repository records` });
  }
  if (manifest.aggregate.total !== manifest.repositories.length) context.addIssue({ code: z.ZodIssueCode.custom, path: ["aggregate", "total"], message: "aggregate total does not match repository records" });
  const findings = manifest.repositories.reduce((sum, entry) => sum + (entry.finding_count ?? 0), 0);
  if (manifest.aggregate.finding_count !== findings) context.addIssue({ code: z.ZodIssueCode.custom, path: ["aggregate", "finding_count"], message: "aggregate finding count does not match repository records" });
  for (const [index, entry] of manifest.repositories.entries()) {
    if (entry.attempts > manifest.configuration.max_attempts) context.addIssue({ code: z.ZodIssueCode.custom, path: ["repositories", index, "attempts"], message: "attempts exceed configured bound" });
    if (["complete", "partial", "unknown"].includes(entry.state) && (
      !entry.scan_id || entry.aggregate_coverage !== entry.state || entry.finding_count === undefined || !entry.started_at || !entry.completed_at
    )) context.addIssue({ code: z.ZodIssueCode.custom, path: ["repositories", index], message: "completed repository state requires exact scan evidence" });
  }
  const unresolved = manifest.aggregate.pending + manifest.aggregate.running + manifest.aggregate.unknown + manifest.aggregate.failed + manifest.aggregate.cancelled;
  const expectedCoverage = !manifest.repositories.length || unresolved > 0
    ? "unknown"
    : manifest.discovery.partial || manifest.aggregate.partial > 0 ? "partial" : "complete";
  if (manifest.aggregate.coverage !== expectedCoverage) context.addIssue({ code: z.ZodIssueCode.custom, path: ["aggregate", "coverage"], message: "aggregate coverage contradicts repository/discovery state" });
});

export type BulkManifest = z.infer<typeof bulkManifestSchema>;
export type BulkRepositoryRecord = BulkManifest["repositories"][number];
