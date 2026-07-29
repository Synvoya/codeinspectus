import { z } from "zod";
import { scanIdSchema, scannerEnum } from "../schemas.js";

export const REPOSITORY_HISTORY_SCHEMA_VERSION = "1.0.0" as const;
export const REPOSITORY_HISTORY_SCHEMA_URI = "https://codeinspectus.com/schemas/repository-history/1.0.0/manifest.schema.json" as const;

const revisionSchema = z.object({
  requested: z.string().min(1),
  commit: z.string().regex(/^[0-9a-f]{40,64}$/),
});

const changeSchema = z.object({
  status: z.enum(["added", "modified", "deleted", "renamed"]),
  path: z.string().min(1),
  old_path: z.string().min(1).optional(),
});

const commitStateSchema = z.enum(["pending", "complete", "partial", "unknown", "failed", "cancelled"]);

export const repositoryHistoryManifestSchema = z.object({
  $schema: z.literal(REPOSITORY_HISTORY_SCHEMA_URI),
  schema_version: z.literal(REPOSITORY_HISTORY_SCHEMA_VERSION),
  run_id: z.string().regex(/^history-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
  repository: z.string(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  bounds: z.object({
    from: revisionSchema,
    to: revisionSchema,
    since: z.string().datetime(),
    until: z.string().datetime(),
    max_commits: z.number().int().min(1).max(50),
    scanners: z.array(scannerEnum).optional(),
    max_findings: z.number().int().positive(),
    include_compliance: z.boolean(),
  }),
  discovery: z.object({
    selected_commits: z.number().int().nonnegative(),
    available_at_least: z.number().int().nonnegative(),
    truncated: z.boolean(),
    shallow_repository: z.boolean(),
    partial: z.boolean(),
    limitations: z.array(z.string()),
  }),
  commits: z.array(z.object({
    commit: z.string().regex(/^[0-9a-f]{40,64}$/),
    parents: z.array(z.string().regex(/^[0-9a-f]{40,64}$/)),
    committer_at: z.string().datetime(),
    temporal_scope: z.enum(["historical", "selected_head"]),
    interpretation: z.string(),
    state: commitStateSchema,
    changes: z.array(changeSchema).max(10_000),
    change_metadata_partial: z.boolean(),
    scan_id: scanIdSchema.optional(),
    aggregate_coverage: z.enum(["complete", "partial", "unknown"]).optional(),
    finding_count: z.number().int().nonnegative().optional(),
    started_at: z.string().datetime().optional(),
    completed_at: z.string().datetime().optional(),
    error: z.string().optional(),
  })).max(50),
  aggregate: z.object({
    coverage: z.enum(["complete", "partial", "unknown"]),
    total: z.number().int().nonnegative(),
    pending: z.number().int().nonnegative(),
    complete: z.number().int().nonnegative(),
    partial: z.number().int().nonnegative(),
    unknown: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative(),
    cancelled: z.number().int().nonnegative(),
    finding_count: z.number().int().nonnegative(),
  }),
}).superRefine((manifest, context) => {
  if (manifest.bounds.from.commit === manifest.bounds.to.commit && manifest.commits.length > 1) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["commits"], message: "a single-revision range cannot contain multiple commits" });
  }
  if (manifest.discovery.selected_commits !== manifest.commits.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["discovery", "selected_commits"], message: "selected count must match commit records" });
  }
  if (manifest.discovery.partial !== (manifest.discovery.truncated || manifest.discovery.shallow_repository || manifest.discovery.limitations.length > 0)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["discovery", "partial"], message: "partial discovery must match its evidence" });
  }
  const commits = manifest.commits.map((entry) => entry.commit);
  if (new Set(commits).size !== commits.length) context.addIssue({ code: z.ZodIssueCode.custom, path: ["commits"], message: "commit records must be unique" });
  const heads = manifest.commits.filter((entry) => entry.temporal_scope === "selected_head");
  if (heads.length !== 1 || heads[0]?.commit !== manifest.bounds.to.commit) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["commits"], message: "exactly one selected-head record must match the requested to revision" });
  }
  for (const [index, entry] of manifest.commits.entries()) {
    if (["complete", "partial", "unknown"].includes(entry.state) && (
      !entry.scan_id || entry.aggregate_coverage !== entry.state || entry.finding_count === undefined || !entry.started_at || !entry.completed_at
    )) context.addIssue({ code: z.ZodIssueCode.custom, path: ["commits", index], message: "scanned commit state requires exact scan evidence" });
  }
  const states = Object.fromEntries(commitStateSchema.options.map((state) => [state, manifest.commits.filter((entry) => entry.state === state).length]));
  for (const state of commitStateSchema.options) {
    if (manifest.aggregate[state] !== states[state]) context.addIssue({ code: z.ZodIssueCode.custom, path: ["aggregate", state], message: `${state} count does not match commit records` });
  }
  if (manifest.aggregate.total !== manifest.commits.length) context.addIssue({ code: z.ZodIssueCode.custom, path: ["aggregate", "total"], message: "aggregate total does not match commit records" });
  const findings = manifest.commits.reduce((sum, entry) => sum + (entry.finding_count ?? 0), 0);
  if (manifest.aggregate.finding_count !== findings) context.addIssue({ code: z.ZodIssueCode.custom, path: ["aggregate", "finding_count"], message: "aggregate finding count does not match commit records" });
  const unresolved = manifest.aggregate.pending + manifest.aggregate.unknown + manifest.aggregate.failed + manifest.aggregate.cancelled;
  const expected = !manifest.commits.length || unresolved > 0 ? "unknown" : manifest.discovery.partial || manifest.aggregate.partial > 0 ? "partial" : "complete";
  if (manifest.aggregate.coverage !== expected) context.addIssue({ code: z.ZodIssueCode.custom, path: ["aggregate", "coverage"], message: "aggregate coverage contradicts discovery or commit state" });
});

export type RepositoryHistoryManifest = z.infer<typeof repositoryHistoryManifestSchema>;
export type RepositoryHistoryCommitRecord = RepositoryHistoryManifest["commits"][number];
