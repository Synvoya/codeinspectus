import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { z } from "zod";
import { MANAGED_CLEANUPS } from "../config.js";
import { pathIsWithin, requireSafeScanTarget } from "../path-safety.js";
import { sha256Hex } from "../util/hash.js";
import { diffRepositoryTrust } from "./diff.js";
import { scanRepositoryTrust } from "./index.js";
import {
  repositoryTrustChangesSchema,
  repositoryTrustDocumentSchema,
  type RepositoryArtifact,
  type RepositoryTrustDocument,
} from "./schemas.js";

export const CLEANUP_SCHEMA_VERSION = "1.0.0" as const;
const PLAN_ID_RE = /^cleanup-plan-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLEANUP_ID_RE = /^cleanup-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ARTIFACT_ID_RE = /^artifact-[a-z0-9][a-z0-9._:-]{0,127}$/;
const MAX_SELECTED_ARTIFACTS = 100;
const MAX_MUTATION_FILE_BYTES = 256 * 1024 * 1024;

const textEditSchema = z.object({
  artifact_id: z.string().regex(ARTIFACT_ID_RE),
  kind: z.enum(["remove_utf8_range", "remove_attribution_line"]),
  byte_start: z.number().int().nonnegative(),
  byte_end: z.number().int().positive(),
}).strict().refine((edit) => edit.byte_end > edit.byte_start, "cleanup edit must have a positive byte range");

const cleanupOperationSchema = z.object({
  operation_id: z.string().regex(/^operation-[a-z0-9]{16}$/),
  artifact_ids: z.array(z.string().regex(ARTIFACT_ID_RE)).min(1),
  file: z.string().min(1),
  destination_file: z.string().min(1).optional(),
  action: z.enum(["edit_text", "create_sanitized_asset_copy"]),
  mode: z.enum(["in_place", "copy"]),
  transformation: z.string().min(1),
  preimage_sha256: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  preimage_bytes: z.number().int().nonnegative(),
  validators: z.array(z.string().min(1)).min(1),
  edits: z.array(textEditSchema).optional(),
}).strict().superRefine((operation, context) => {
  if (operation.action === "edit_text" && (operation.mode !== "in_place" || !operation.edits?.length || operation.destination_file)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "text cleanup requires in-place edits and no destination", path: ["action"] });
  }
  if (operation.action === "create_sanitized_asset_copy" && (operation.mode !== "copy" || !operation.destination_file || operation.edits)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "asset cleanup requires copy mode and a destination", path: ["action"] });
  }
});

const cleanupBlockerSchema = z.object({
  artifact_id: z.string().regex(ARTIFACT_ID_RE),
  file: z.string().min(1),
  reason: z.string().min(1),
}).strict();

export const cleanupPlanObjectSchema = z.object({
  schema_version: z.literal(CLEANUP_SCHEMA_VERSION),
  plan_id: z.string().regex(PLAN_ID_RE),
  plan_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  created_at: z.string().datetime(),
  target: z.string().min(1),
  outcome: z.enum(["ready", "blocked"]),
  artifact_ids: z.array(z.string().regex(ARTIFACT_ID_RE)).min(1),
  operations: z.array(cleanupOperationSchema),
  blockers: z.array(cleanupBlockerSchema),
  checkpoint: z.object({
    required: z.literal(true),
    strategy: z.literal("managed_content_backup"),
    original_assets_preserved_for_copy_operations: z.literal(true),
  }).strict(),
  approval: z.object({
    required: z.literal(true),
    exact_artifact_ids: z.array(z.string().regex(ARTIFACT_ID_RE)).min(1),
    rights_confirmation_required: z.boolean(),
    metadata_container_acknowledged: z.boolean(),
    provenance_copy_acknowledged: z.boolean(),
  }).strict(),
  verification: z.object({
    same_validator_rescan_required: z.literal(true),
    repository_checks_required: z.literal(true),
    repository_checks_state: z.literal("not_run"),
  }).strict(),
  limitations: z.array(z.string().min(1)),
}).strict();

export const cleanupPlanSchema = cleanupPlanObjectSchema.superRefine((plan, context) => {
  if (plan.outcome === "ready" && (plan.operations.length === 0 || plan.blockers.length > 0)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "ready plans require operations and no blockers", path: ["outcome"] });
  }
  if (plan.outcome === "blocked" && plan.blockers.length === 0) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "blocked plans require an explicit blocker", path: ["blockers"] });
  }
});

const operationResultSchema = z.object({
  operation_id: z.string().regex(/^operation-[a-z0-9]{16}$/),
  file: z.string(),
  destination_file: z.string().optional(),
  status: z.enum(["applied", "rolled_back", "unchanged", "failed"]),
  before_sha256: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  after_sha256: z.string().regex(/^sha256:[0-9a-f]{64}$/).optional(),
  targeted_artifacts_resolved: z.boolean(),
  limitation: z.string().optional(),
}).strict();

export const cleanupResultSchema = z.object({
  schema_version: z.literal(CLEANUP_SCHEMA_VERSION),
  cleanup_id: z.string().regex(CLEANUP_ID_RE),
  plan_id: z.string().regex(PLAN_ID_RE),
  outcome: z.enum(["applied", "incomplete", "rolled_back", "rollback_refused"]),
  target: z.string().min(1),
  started_at: z.string().datetime(),
  completed_at: z.string().datetime(),
  checkpoint: z.object({
    state: z.enum(["created", "restored", "preserved"]),
    managed: z.literal(true),
    content_retained: z.literal(true),
  }).strict(),
  operations: z.array(operationResultSchema),
  repository_trust_before: repositoryTrustDocumentSchema,
  repository_trust_after: repositoryTrustDocumentSchema,
  repository_trust_changes: repositoryTrustChangesSchema,
  verification: z.object({
    same_validators_ran: z.boolean(),
    targeted_artifacts_resolved: z.boolean(),
    repository_checks: z.object({
      state: z.literal("not_run"),
      required: z.literal(true),
      reason: z.string().min(1),
    }).strict(),
  }).strict(),
  audit_log_path: z.string().min(1),
  limitations: z.array(z.string().min(1)),
}).strict();

export type CleanupPlan = z.infer<typeof cleanupPlanSchema>;
export type CleanupResult = z.infer<typeof cleanupResultSchema>;
type CleanupOperation = z.infer<typeof cleanupOperationSchema>;

export interface CleanupPlanInput {
  path: string;
  artifact_ids: string[];
  acknowledge_metadata_container_removal?: boolean;
  acknowledge_provenance_copy?: boolean;
}

export interface CleanupApplyInput {
  plan_id: string;
  approved_artifact_ids: string[];
  confirm_cleanup: boolean;
  confirm_rights_to_modify?: boolean;
}

export interface CleanupRollbackInput {
  cleanup_id: string;
  confirm_rollback: boolean;
}

type TrustScanner = (target: string) => Promise<RepositoryTrustDocument>;

interface InternalOperation extends CleanupOperation {
  absolute: string;
  destination_absolute?: string;
}

interface InternalPlan {
  output: CleanupPlan;
  before: RepositoryTrustDocument;
  operations: InternalOperation[];
  created: number;
}

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

// The journal is written (with every backup) before the first mutation, so an apply interrupted at
// any point can be recovered from disk alone. It records hashes and paths, never file content.
const journalOperationSchema = z.object({
  operation_id: z.string().regex(/^operation-[a-z0-9]{16}$/),
  artifact_ids: z.array(z.string().regex(ARTIFACT_ID_RE)).min(1),
  file: z.string().min(1),
  destination_file: z.string().min(1).optional(),
  mode: z.enum(["in_place", "copy"]),
  validators: z.array(z.string().min(1)).min(1),
  preimage_sha256: z.string().regex(SHA256_RE),
  output_sha256: z.string().regex(SHA256_RE),
}).strict();

const journalSchema = z.object({
  schema_version: z.literal(CLEANUP_SCHEMA_VERSION),
  cleanup_id: z.string().regex(CLEANUP_ID_RE),
  plan_id: z.string().regex(PLAN_ID_RE),
  target: z.string().min(1),
  artifact_ids: z.array(z.string().regex(ARTIFACT_ID_RE)).min(1),
  started_at: z.string().datetime(),
  operations: z.array(journalOperationSchema).min(1),
}).strict();

type Journal = z.infer<typeof journalSchema>;
type JournalOperation = z.infer<typeof journalOperationSchema>;

export interface CleanupRuntime {
  storeRoot?: string;
  scan?: TrustScanner;
  now?: () => Date;
  randomId?: () => string;
  beforeOperation?: (operation: CleanupOperation, index: number) => Promise<void> | void;
}

const MAX_PLANS = 32;
const PLAN_TTL_MS = 30 * 60 * 1000;
const plans = new Map<string, InternalPlan>();

/** Internal test seam for proving managed-checkpoint recovery across a server restart. */
export function resetCleanupRuntimeStateForTests(): void {
  plans.clear();
  heldLocks.clear();
}

function rememberPlan(plan: InternalPlan): void {
  for (const [id, item] of plans) if (plan.created - item.created > PLAN_TTL_MS) plans.delete(id);
  while (plans.size >= MAX_PLANS) plans.delete(plans.keys().next().value!);
  plans.set(plan.output.plan_id, plan);
}

function assertUnique(ids: readonly string[], label: string): void {
  if (new Set(ids).size !== ids.length) throw new Error(`${label} must be unique.`);
}

function attribute(artifact: RepositoryArtifact, name: string): string | number | boolean | undefined {
  return artifact.evidence.attributes.find((item) => item.name === name)?.value;
}

function digest(value: string | Buffer): string {
  return `sha256:${sha256Hex(value)}`;
}

function exactSet(left: readonly string[], right: readonly string[]): boolean {
  const a = [...new Set(left)].sort();
  const b = [...new Set(right)].sort();
  return a.length === b.length && a.every((item, index) => item === b[index]);
}

function withinTarget(target: string, relativeFile: string): string {
  if (!relativeFile || relativeFile.includes("\0") || relativeFile.split(/[\\/]+/).includes("..")) {
    throw new Error(`Unsafe cleanup file path '${relativeFile}'.`);
  }
  const absolute = resolve(target, relativeFile);
  if (!pathIsWithin(target, absolute)) throw new Error(`Cleanup file escapes the target: ${relativeFile}`);
  return absolute;
}

async function safeRead(path: string): Promise<{ buffer: Buffer; mode: number; identity: string }> {
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(MAX_MUTATION_FILE_BYTES)) {
      throw new Error(`Cleanup supports regular files up to ${MAX_MUTATION_FILE_BYTES / (1024 * 1024)} MiB.`);
    }
    const buffer = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) {
      throw new Error("Cleanup target changed while it was being read.");
    }
    return {
      buffer,
      mode: Number(before.mode & BigInt(0o777)),
      identity: `${before.dev}:${before.ino}:${before.size}:${before.mtimeNs}`,
    };
  } finally {
    await handle.close();
  }
}

async function assertIdentity(path: string, expected: string): Promise<void> {
  const current = await lstat(path, { bigint: true });
  const identity = `${current.dev}:${current.ino}:${current.size}:${current.mtimeNs}`;
  if (!current.isFile() || current.isSymbolicLink() || identity !== expected) {
    throw new Error("Cleanup target identity changed before atomic replacement.");
  }
}

function lineRange(buffer: Buffer, line: number): { start: number; end: number } | undefined {
  if (!Number.isSafeInteger(line) || line < 1) return undefined;
  let current = 1;
  let start = 0;
  for (let index = 0; index <= buffer.length; index++) {
    if (index === buffer.length || buffer[index] === 0x0a) {
      if (current === line) return { start, end: index < buffer.length ? index + 1 : index };
      current++;
      start = index + 1;
    }
  }
  return undefined;
}

function codePointRange(buffer: Buffer, artifact: RepositoryArtifact): { start: number; end: number } | undefined {
  const byteStart = attribute(artifact, "utf8_byte_offset");
  const sequenceLength = attribute(artifact, "sequence_length");
  if (typeof byteStart !== "number" || typeof sequenceLength !== "number" || byteStart < 0 || sequenceLength < 1) return undefined;
  let suffix: string;
  try {
    suffix = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buffer.subarray(byteStart));
  } catch {
    return undefined;
  }
  const marker = [...suffix].slice(0, sequenceLength);
  if (marker.length !== sequenceLength) return undefined;
  // The offset must land on exactly the recorded code points; anything else is a different byte range.
  const recorded = String(attribute(artifact, "code_points") ?? "").match(/U\+[0-9A-F]{4,6}/g) ?? [];
  const actual = marker.map((character) => {
    const codePoint = character.codePointAt(0)!;
    return `U+${codePoint.toString(16).toUpperCase().padStart(codePoint <= 0xffff ? 4 : 6, "0")}`;
  });
  if (recorded.length === 0 || recorded.some((label, index) => label !== actual[index])) return undefined;
  return { start: byteStart, end: byteStart + Buffer.byteLength(marker.join("")) };
}

function safeAttributionComment(buffer: Buffer, range: { start: number; end: number }): boolean {
  const raw = buffer.subarray(range.start, range.end).toString("utf8");
  // A lone CR ends a line for editors and compilers but not for the scanner's /\r?\n/ split, so
  // such a "line" can span real code and is never a standalone comment.
  if (/\r(?!\n)/.test(raw)) return false;
  const line = raw.trim();
  if (/^(?:\/\/|#)/.test(line)) return true;
  // A block comment is standalone only when its first terminator is the end of the line.
  if (line.startsWith("/*") && line.indexOf("*/", 2) === line.length - 2) return true;
  if (line.startsWith("<!--") && line.indexOf("-->", 4) === line.length - 3) return true;
  // An interior JSDoc/block-comment line is safe only when it cannot also close the block.
  return /^\*(?!\/).*[^/]$/.test(line) && !line.includes("*/");
}

const MEDIA_EXTENSIONS = new Set(["png", "jpg", "jpeg", "mp3", "wav", "mp4", "mov", "m4a", "m4v"]);

function cleanedFilename(file: string): string {
  const extension = extname(file);
  return `${file.slice(0, -extension.length)}.codeinspectus-clean${extension}`;
}

function operationId(file: string, artifacts: RepositoryArtifact[]): string {
  return `operation-${sha256Hex([file, ...artifacts.map((item) => item.fingerprint).sort()].join("\0")).slice(0, 16)}`;
}

function planDigest(plan: Omit<CleanupPlan, "plan_digest">): string {
  return digest(JSON.stringify(plan));
}

export async function planRepositoryCleanup(input: CleanupPlanInput, runtime: CleanupRuntime = {}): Promise<CleanupPlan> {
  if (!Array.isArray(input.artifact_ids) || input.artifact_ids.length < 1 || input.artifact_ids.length > MAX_SELECTED_ARTIFACTS) {
    throw new Error(`Select between 1 and ${MAX_SELECTED_ARTIFACTS} exact artifact IDs.`);
  }
  assertUnique(input.artifact_ids, "Artifact IDs");
  for (const id of input.artifact_ids) if (!ARTIFACT_ID_RE.test(id)) throw new Error(`Invalid artifact ID '${id}'.`);
  const target = await requireSafeScanTarget(input.path);
  if (target.type !== "directory" || !target.canonical_path) throw new Error("V3.3 cleanup requires a repository directory target.");
  const scan = runtime.scan ?? scanRepositoryTrust;
  const before = await scan(target.canonical_path);
  const indexed = new Map(before.artifacts.map((artifact) => [artifact.artifact_id, artifact]));
  const selected = input.artifact_ids.map((id) => indexed.get(id)).filter((item): item is RepositoryArtifact => Boolean(item));
  const blockers: Array<z.infer<typeof cleanupBlockerSchema>> = [];
  const interrupted = await interruptedCleanup(runtime.storeRoot ?? MANAGED_CLEANUPS, target.canonical_path);
  if (interrupted) {
    for (const id of input.artifact_ids) blockers.push({ artifact_id: id, file: "(repository)", reason: `Cleanup ${interrupted} was interrupted or its automatic rollback did not complete. Review it and run codeinspectus_rollback_cleanup before planning new cleanup.` });
  }
  for (const id of input.artifact_ids) {
    if (!indexed.has(id)) blockers.push({ artifact_id: id, file: "(not found)", reason: "The artifact was not present in the fresh V3.3 pre-clean scan." });
  }
  const groups = new Map<string, RepositoryArtifact[]>();
  for (const artifact of selected) {
    const current = groups.get(artifact.location.file) ?? [];
    current.push(artifact);
    groups.set(artifact.location.file, current);
  }
  const operations: InternalOperation[] = [];
  for (const [file, artifacts] of groups) {
    const absolute = withinTarget(target.canonical_path, file);
    if (artifacts.some((artifact) => artifact.remediation.protected_record || artifact.location.file === ".git")) {
      for (const artifact of artifacts) blockers.push({ artifact_id: artifact.artifact_id, file, reason: artifact.remediation.reason });
      continue;
    }
    if (artifacts.some((artifact) => artifact.state !== "verified" || !artifact.remediation.eligible)) {
      for (const artifact of artifacts.filter((item) => item.state !== "verified" || !item.remediation.eligible)) {
        blockers.push({ artifact_id: artifact.artifact_id, file, reason: artifact.remediation.reason });
      }
      continue;
    }
    const inspected = await safeRead(absolute);
    const extension = extname(file).slice(1).toLowerCase();
    const media = MEDIA_EXTENSIONS.has(extension) && artifacts.some((artifact) =>
      artifact.location.field !== undefined || artifact.kind === "content_provenance"
    );
    if (media) {
      if (!input.acknowledge_metadata_container_removal) {
        for (const artifact of artifacts) blockers.push({ artifact_id: artifact.artifact_id, file, reason: "The supported media adapter removes complete metadata containers. Re-plan with acknowledge_metadata_container_removal=true after reviewing that transformation." });
        continue;
      }
      if (artifacts.some((artifact) => artifact.kind === "content_provenance") && !input.acknowledge_provenance_copy) {
        for (const artifact of artifacts.filter((item) => item.kind === "content_provenance")) blockers.push({ artifact_id: artifact.artifact_id, file, reason: "C2PA/content-provenance cleanup requires acknowledge_provenance_copy=true and always creates a copy." });
        continue;
      }
      const allFileMetadata = before.artifacts.filter((artifact) => artifact.location.file === file &&
        artifact.remediation.eligible && (artifact.location.field !== undefined || artifact.kind === "content_provenance"));
      if (!exactSet(artifacts.map((item) => item.artifact_id), allFileMetadata.map((item) => item.artifact_id))) {
        for (const artifact of artifacts) blockers.push({ artifact_id: artifact.artifact_id, file, reason: "Select every cleanup-eligible metadata/provenance artifact in this file because the adapter removes complete metadata containers." });
        continue;
      }
      const destinationFile = cleanedFilename(file);
      const destinationAbsolute = withinTarget(target.canonical_path, destinationFile);
      try {
        await lstat(destinationAbsolute);
        for (const artifact of artifacts) blockers.push({ artifact_id: artifact.artifact_id, file, reason: `Clean-copy destination already exists: ${destinationFile}` });
        continue;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      operations.push({
        operation_id: operationId(file, artifacts), artifact_ids: artifacts.map((item) => item.artifact_id).sort(),
        file, destination_file: destinationFile, action: "create_sanitized_asset_copy", mode: "copy",
        transformation: `Create a new ${extension.toUpperCase()} asset with supported metadata containers removed; preserve encoded media payloads and the original file.`,
        preimage_sha256: digest(inspected.buffer), preimage_bytes: inspected.buffer.length,
        validators: [...new Set(artifacts.map((item) => `${item.validator.id}${item.validator.version ? `@${item.validator.version}` : ""}`))],
        absolute, destination_absolute: destinationAbsolute,
      });
      continue;
    }
    const edits: z.infer<typeof textEditSchema>[] = [];
    for (const artifact of artifacts) {
      if (artifact.kind === "source_integrity") {
        const range = codePointRange(inspected.buffer, artifact);
        if (!range) blockers.push({ artifact_id: artifact.artifact_id, file, reason: "The exact UTF-8 byte range could not be reproduced from the fresh artifact evidence." });
        else edits.push({ artifact_id: artifact.artifact_id, kind: "remove_utf8_range", byte_start: range.start, byte_end: range.end });
      } else if (artifact.kind === "explicit_ai_attribution" && artifact.location.start_line !== undefined) {
        const range = lineRange(inspected.buffer, artifact.location.start_line);
        if (!range || !safeAttributionComment(inspected.buffer, range)) {
          blockers.push({ artifact_id: artifact.artifact_id, file, reason: "Automatic text cleanup is limited to standalone attribution comments; structured declarations require bounded agent guidance." });
        } else edits.push({ artifact_id: artifact.artifact_id, kind: "remove_attribution_line", byte_start: range.start, byte_end: range.end });
      } else {
        blockers.push({ artifact_id: artifact.artifact_id, file, reason: "No bounded V3.3 adapter supports this artifact location." });
      }
    }
    if (edits.length === artifacts.length) {
      const ordered = [...edits].sort((a, b) => a.byte_start - b.byte_start || a.byte_end - b.byte_end);
      if (ordered.some((item, index) => index > 0 && item.byte_start < ordered[index - 1]!.byte_end)) {
        for (const artifact of artifacts) blockers.push({ artifact_id: artifact.artifact_id, file, reason: "Selected cleanup ranges overlap and cannot be applied independently." });
        continue;
      }
      operations.push({
        operation_id: operationId(file, artifacts), artifact_ids: artifacts.map((item) => item.artifact_id).sort(),
        file, action: "edit_text", mode: "in_place",
        transformation: "Remove only the exact verified UTF-8 ranges and standalone attribution-comment lines, using an atomic replacement.",
        preimage_sha256: digest(inspected.buffer), preimage_bytes: inspected.buffer.length,
        validators: [...new Set(artifacts.map((item) => `${item.validator.id}${item.validator.version ? `@${item.validator.version}` : ""}`))],
        edits: ordered, absolute,
      });
    }
  }
  const now = runtime.now ?? (() => new Date());
  const id = runtime.randomId ?? randomUUID;
  const planWithoutDigest: Omit<CleanupPlan, "plan_digest"> = {
    schema_version: CLEANUP_SCHEMA_VERSION,
    plan_id: `cleanup-plan-${id()}`,
    created_at: now().toISOString(),
    target: target.canonical_path,
    outcome: blockers.length || operations.length === 0 ? "blocked" : "ready",
    artifact_ids: [...input.artifact_ids].sort(),
    operations: operations.map(({ absolute: _absolute, destination_absolute: _destination, ...operation }) => operation),
    blockers,
    checkpoint: { required: true, strategy: "managed_content_backup", original_assets_preserved_for_copy_operations: true },
    approval: {
      required: true,
      exact_artifact_ids: [...input.artifact_ids].sort(),
      rights_confirmation_required: selected.some((artifact) => artifact.kind === "explicit_ai_attribution" || artifact.kind === "content_provenance"),
      metadata_container_acknowledged: input.acknowledge_metadata_container_removal === true,
      provenance_copy_acknowledged: input.acknowledge_provenance_copy === true,
    },
    verification: { same_validator_rescan_required: true, repository_checks_required: true, repository_checks_state: "not_run" },
    limitations: [
      "V3.3 does not rewrite Git history, remove statistical watermarks, alter pixels/audio/video frames, or claim human authorship.",
      "Repository tests, formatters, and builds are not executed by this mutation tool; the calling agent must run relevant checks and report cleanup incomplete until they pass.",
    ],
  };
  const output = cleanupPlanSchema.parse({ ...planWithoutDigest, plan_digest: planDigest(planWithoutDigest) });
  rememberPlan({ output, before, operations, created: now().getTime() });
  return output;
}

function applyRanges(buffer: Buffer, edits: NonNullable<CleanupOperation["edits"]>): Buffer {
  const descending = [...edits].sort((a, b) => b.byte_start - a.byte_start);
  let output = buffer;
  for (const edit of descending) output = Buffer.concat([output.subarray(0, edit.byte_start), output.subarray(edit.byte_end)]);
  return output;
}

function sanitizePng(input: Buffer): Buffer {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (input.length < 20 || !input.subarray(0, 8).equals(signature)) throw new Error("Invalid PNG signature.");
  const remove = new Set(["tEXt", "zTXt", "iTXt", "eXIf", "caBX"]);
  const parts = [input.subarray(0, 8)];
  let offset = 8;
  let ended = false;
  while (offset < input.length) {
    if (offset + 12 > input.length) throw new Error("Truncated PNG chunk.");
    const length = input.readUInt32BE(offset);
    const end = offset + 12 + length;
    if (end > input.length) throw new Error("PNG chunk exceeds the file bound.");
    const type = input.toString("ascii", offset + 4, offset + 8);
    if (!remove.has(type)) parts.push(input.subarray(offset, end));
    offset = end;
    if (type === "IEND") { ended = true; break; }
  }
  if (!ended || offset !== input.length) throw new Error("PNG did not end at a valid IEND chunk.");
  return Buffer.concat(parts);
}

function sanitizeJpeg(input: Buffer): Buffer {
  if (input.length < 4 || input[0] !== 0xff || input[1] !== 0xd8) throw new Error("Invalid JPEG signature.");
  const parts = [input.subarray(0, 2)];
  const remove = new Set([0xe1, 0xeb, 0xed, 0xfe]);
  let offset = 2;
  while (offset < input.length) {
    const start = offset;
    if (input[offset] !== 0xff) throw new Error("Invalid JPEG marker boundary.");
    while (offset < input.length && input[offset] === 0xff) offset++;
    if (offset >= input.length) throw new Error("Truncated JPEG marker.");
    const marker = input[offset++]!;
    if (marker === 0xda) { parts.push(input.subarray(start)); return Buffer.concat(parts); }
    if (marker === 0xd9) { parts.push(input.subarray(start, offset)); return Buffer.concat(parts); }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { parts.push(input.subarray(start, offset)); continue; }
    if (offset + 2 > input.length) throw new Error("Truncated JPEG segment length.");
    const length = input.readUInt16BE(offset);
    if (length < 2 || offset + length > input.length) throw new Error("JPEG segment exceeds the file bound.");
    const end = offset + length;
    if (!remove.has(marker)) parts.push(input.subarray(start, end));
    offset = end;
  }
  throw new Error("JPEG scan data marker was not found.");
}

function sanitizeMp3(input: Buffer): Buffer {
  let start = 0;
  let end = input.length;
  if (input.length >= 10 && input.toString("ascii", 0, 3) === "ID3") {
    const bytes = [input[6]!, input[7]!, input[8]!, input[9]!];
    if (bytes.some((value) => value > 0x7f)) throw new Error("Invalid ID3 synchsafe size.");
    const size = (bytes[0]! << 21) | (bytes[1]! << 14) | (bytes[2]! << 7) | bytes[3]!;
    start = 10 + size + ((input[5]! & 0x10) ? 10 : 0);
    if (start > input.length) throw new Error("ID3 tag exceeds the file bound.");
  }
  if (end - start >= 128 && input.toString("ascii", end - 128, end - 125) === "TAG") end -= 128;
  return input.subarray(start, end);
}

function sanitizeWav(input: Buffer): Buffer {
  if (input.length < 12 || input.toString("ascii", 0, 4) !== "RIFF" || input.toString("ascii", 8, 12) !== "WAVE") throw new Error("Invalid RIFF/WAVE signature.");
  // C2PA stores its manifest in a "C2PA" chunk (c2pa-rs riff_io); WAV XMP uses "_PMX", WebP-style "XMP ".
  const remove = new Set(["LIST", "ID3 ", "id3 ", "bext", "iXML", "XMP ", "_PMX", "axml", "C2PA"]);
  const chunks: Buffer[] = [];
  let offset = 12;
  while (offset < input.length) {
    if (offset + 8 > input.length) throw new Error("Truncated WAVE chunk.");
    const id = input.toString("ascii", offset, offset + 4);
    const size = input.readUInt32LE(offset + 4);
    const end = offset + 8 + size + (size % 2);
    if (end > input.length) throw new Error("WAVE chunk exceeds the file bound.");
    if (!remove.has(id)) chunks.push(input.subarray(offset, end));
    offset = end;
  }
  const body = Buffer.concat(chunks);
  const header = Buffer.from(input.subarray(0, 12));
  header.writeUInt32LE(body.length + 4, 4);
  return Buffer.concat([header, body]);
}

function c2paUuidPayload(payload: Buffer): boolean {
  const preview = payload.subarray(0, Math.min(payload.length, 4096)).toString("latin1").toLowerCase();
  return preview.includes("c2pa") || preview.includes("jumb") || preview.includes("contentauth");
}

const ISO_CONTAINERS = new Set(["moov", "trak", "mdia", "minf", "stbl", "edts", "dinf"]);
// Boxes that carry absolute or moof-relative data offsets this adapter does not rewrite.
const ISO_UNSUPPORTED = new Set(["moof", "mfra", "sidx", "ssix", "saio", "iloc"]);

function isoBoxes(input: Buffer, start: number, end: number): Array<{ type: string; offset: number; header: number; size: number }> {
  const boxes = [];
  let offset = start;
  while (offset < end) {
    if (offset + 8 > end) throw new Error("Truncated ISO BMFF box.");
    const size32 = input.readUInt32BE(offset);
    const type = input.toString("ascii", offset + 4, offset + 8);
    let header = 8;
    let size: number;
    if (size32 === 1) {
      if (offset + 16 > end) throw new Error("Truncated ISO BMFF large box.");
      const large = input.readBigUInt64BE(offset + 8);
      if (large > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("ISO BMFF box exceeds safe integer bounds.");
      size = Number(large); header = 16;
    } else size = size32 === 0 ? end - offset : size32;
    if (size < header || offset + size > end) throw new Error("ISO BMFF box exceeds the file bound.");
    if (ISO_UNSUPPORTED.has(type)) throw new Error(`Fragmented or externally indexed ISO BMFF files ('${type}') are not supported by the V3.3 adapter.`);
    boxes.push({ type, offset, header, size });
    offset += size;
  }
  return boxes;
}

function removedIsoRanges(input: Buffer, start: number, end: number, depth: number, ranges: Array<[number, number]>): Array<[number, number]> {
  if (depth > 8) throw new Error("ISO BMFF box nesting exceeded the cleanup bound.");
  for (const box of isoBoxes(input, start, end)) {
    const payload = input.subarray(box.offset + box.header, box.offset + box.size);
    if (box.type === "udta" || (box.type === "uuid" && c2paUuidPayload(payload))) ranges.push([box.offset, box.offset + box.size]);
    else if (ISO_CONTAINERS.has(box.type)) removedIsoRanges(input, box.offset + box.header, box.offset + box.size, depth + 1, ranges);
  }
  return ranges;
}

/** Rewrite stco/co64 chunk offsets so they still address media data after metadata boxes are removed. */
function shiftedChunkOffsets(box: Buffer, header: number, type: string, removed: Array<[number, number]>): Buffer {
  const output = Buffer.from(box);
  const width = type === "co64" ? 8 : 4;
  if (header + 8 > output.length) throw new Error(`Truncated ${type} box.`);
  const count = output.readUInt32BE(header + 4);
  if (header + 8 + count * width > output.length) throw new Error(`${type} entries exceed the box bound.`);
  for (let index = 0; index < count; index++) {
    const position = header + 8 + index * width;
    const original = width === 8 ? Number(output.readBigUInt64BE(position)) : output.readUInt32BE(position);
    let shift = 0;
    for (const [start, end] of removed) {
      if (original >= end) shift += end - start;
      else if (original >= start) throw new Error("A media chunk offset points into removed metadata.");
    }
    if (width === 8) output.writeBigUInt64BE(BigInt(original - shift), position);
    else output.writeUInt32BE(original - shift, position);
  }
  return output;
}

function sanitizeIsoBoxes(input: Buffer): Buffer {
  return rebuildIsoBoxes(input, 0, input.length, removedIsoRanges(input, 0, input.length, 0, []));
}

function rebuildIsoBoxes(input: Buffer, start: number, end: number, removed: Array<[number, number]>): Buffer {
  const parts: Buffer[] = [];
  for (const { type, offset, header, size } of isoBoxes(input, start, end)) {
    const payloadStart = offset + header;
    const remove = removed.some(([removedStart]) => removedStart === offset);
    if (!remove && (type === "stco" || type === "co64")) {
      parts.push(shiftedChunkOffsets(input.subarray(offset, offset + size), header, type, removed));
    } else if (!remove && ISO_CONTAINERS.has(type)) {
      const cleaned = rebuildIsoBoxes(input, payloadStart, offset + size, removed);
      const rebuiltHeader = Buffer.from(input.subarray(offset, offset + header));
      const rebuiltSize = header + cleaned.length;
      if (header === 8) rebuiltHeader.writeUInt32BE(rebuiltSize, 0);
      else rebuiltHeader.writeBigUInt64BE(BigInt(rebuiltSize), 8);
      parts.push(rebuiltHeader, cleaned);
    } else if (!remove) parts.push(input.subarray(offset, offset + size));
  }
  return Buffer.concat(parts);
}

export function sanitizeAsset(extension: string, input: Buffer): Buffer {
  switch (extension.toLowerCase()) {
    case "png": return sanitizePng(input);
    case "jpg": case "jpeg": return sanitizeJpeg(input);
    case "mp3": return sanitizeMp3(input);
    case "wav": return sanitizeWav(input);
    case "mp4": case "mov": case "m4a": case "m4v": return sanitizeIsoBoxes(input);
    default: throw new Error(`No V3.3 asset adapter supports .${extension}.`);
  }
}

async function atomicReplace(path: string, content: Buffer, mode: number, expectedIdentity: string): Promise<void> {
  const temporary = `${path}.codeinspectus-${process.pid}-${randomUUID()}.tmp`;
  try {
    const handle = await open(temporary, "wx", mode);
    try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
    await chmod(temporary, mode);
    await assertIdentity(path, expectedIdentity);
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

async function atomicCreate(path: string, content: Buffer, mode: number): Promise<void> {
  const temporary = `${path}.codeinspectus-${process.pid}-${randomUUID()}.tmp`;
  try {
    const handle = await open(temporary, "wx", mode);
    try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
    await chmod(temporary, mode);
    await link(temporary, path);
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
}

async function writeRecord(storeRoot: string, cleanupId: string, filename: string, value: unknown): Promise<string> {
  const directory = join(storeRoot, cleanupId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, filename);
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  return path;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

const heldLocks = new Set<string>();
const LOCK_MAX_AGE_MS = 60 * 60 * 1000;

/**
 * Exclusive per-repository lock for apply/rollback, keyed on the repository root so nested
 * targets share it. The lock file is written completely and then hard-linked into place, so it is
 * never observed empty. It is reclaimed when its owner process is dead, when it names this PID but
 * is not held by this process instance (a previous incarnation), or when it is older than an hour
 * (a reused PID). Automatic rollback is independently limited to operations the run itself wrote.
 */
async function acquireRepositoryLock(storeRoot: string, target: string): Promise<() => Promise<void>> {
  const inspected = await requireSafeScanTarget(target).catch(() => undefined);
  const key = inspected?.repository_root ?? target;
  const directory = join(storeRoot, "locks");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, `${sha256Hex(key).slice(0, 32)}.lock`);
  for (let attempt = 0; attempt < 3; attempt++) {
    const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
    const ownership = `${process.pid} ${randomUUID()}\n`;
    await writeFile(temporary, ownership, { flag: "wx", mode: 0o600 });
    try {
      await link(temporary, path);
      heldLocks.add(path);
      return async () => {
        heldLocks.delete(path);
        // Remove the lock only while it is still ours; a reclaimer may have replaced it.
        if (await readFile(path, "utf8").catch(() => undefined) === ownership) await rm(path, { force: true });
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    } finally {
      await unlink(temporary).catch(() => undefined);
    }
    const [content, entry] = await Promise.all([
      readFile(path, "utf8").catch(() => undefined),
      lstat(path).catch(() => undefined),
    ]);
    if (content === undefined || !entry) continue; // released meanwhile; retry
    const owner = Number.parseInt(content, 10);
    const expired = Date.now() - entry.mtimeMs > LOCK_MAX_AGE_MS;
    const busy = !expired && (owner === process.pid ? heldLocks.has(path) : Number.isSafeInteger(owner) && owner > 0 && processAlive(owner));
    if (busy) throw new Error("Another cleanup apply or rollback is running for this repository; wait for it to finish, then create a fresh plan.");
    await rm(path, { force: true });
  }
  throw new Error("Could not acquire the repository cleanup lock.");
}

function backupPath(storeRoot: string, cleanupId: string, operationId: string): string {
  return join(storeRoot, cleanupId, "backups", `${operationId}.bin`);
}

async function readIfPresent(path: string): Promise<Awaited<ReturnType<typeof safeRead>> | undefined> {
  try {
    return await safeRead(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function readJournal(storeRoot: string, cleanupId: string): Promise<Journal> {
  const file = await readIfPresent(join(storeRoot, cleanupId, "journal.json"));
  if (!file) throw new Error(`No managed cleanup journal exists for ${cleanupId}.`);
  const journal = journalSchema.parse(JSON.parse(file.buffer.toString("utf8")));
  if (journal.cleanup_id !== cleanupId) throw new Error("Managed cleanup journal identity does not match the requested cleanup.");
  return journal;
}

async function hasRollbackRecord(storeRoot: string, cleanupId: string): Promise<boolean> {
  const entries = await readdir(join(storeRoot, cleanupId)).catch(() => [] as string[]);
  return entries.some((name) => name.startsWith("rollback"));
}

/**
 * An apply is unresolved until reviewed: its journal has no rollback record and either no audit
 * (interrupted) or an audit saying automatic rollback did not complete.
 */
async function interruptedCleanup(storeRoot: string, target: string): Promise<string | undefined> {
  let entries: string[];
  try {
    entries = await readdir(storeRoot);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  for (const entry of entries.filter((name) => CLEANUP_ID_RE.test(name)).sort()) {
    const journal = await readJournal(storeRoot, entry).catch(() => undefined);
    if (!journal || journal.target !== target) continue;
    if (await hasRollbackRecord(storeRoot, entry)) continue;
    const audit = await readIfPresent(join(storeRoot, entry, "audit.json"));
    let outcome: string | undefined;
    try {
      outcome = audit ? (JSON.parse(audit.buffer.toString("utf8")) as { outcome?: string }).outcome : undefined;
    } catch {
      return entry; // An unreadable audit cannot prove the cleanup finished; keep it for review.
    }
    if (audit && outcome !== "failed_rollback_incomplete") continue;
    return entry;
  }
  return undefined;
}

async function assertParentWithinTarget(target: string, absolute: string): Promise<void> {
  const parent = dirname(absolute);
  if ((await realpath(parent)) !== parent || !pathIsWithin(target, parent)) {
    throw new Error("A cleanup path's parent directory no longer resolves inside the approved repository.");
  }
}

interface OperationState {
  state: "untouched" | "applied" | "changed";
  current?: Awaited<ReturnType<typeof safeRead>>;
}

async function fileIdentity(path: string): Promise<string> {
  const entry = await lstat(path, { bigint: true });
  // Birth time (or ctime where unavailable) guards against a reused inode number.
  return `${entry.dev}:${entry.ino}:${entry.birthtimeNs > 0n ? entry.birthtimeNs : entry.ctimeNs}`;
}

async function operationState(storeRoot: string, journal: Journal, operation: JournalOperation): Promise<OperationState> {
  if (operation.mode === "copy") {
    const destination = withinTarget(journal.target, operation.destination_file!);
    const current = await readIfPresent(destination);
    // Only a copy this cleanup recorded creating is ours to remove; an identical copy made by
    // another cleanup (or the user) is left alone.
    const marker = await readIfPresent(join(storeRoot, journal.cleanup_id, `created-${operation.operation_id}.json`));
    const created = marker ? (JSON.parse(marker.buffer.toString("utf8")) as { identity?: string }).identity : undefined;
    if (!current || !created || created !== await fileIdentity(destination)) return { state: "untouched" };
    return { state: digest(current.buffer) === operation.output_sha256 ? "applied" : "changed", current };
  }
  const current = await readIfPresent(withinTarget(journal.target, operation.file));
  const hash = current ? digest(current.buffer) : undefined;
  if (hash === operation.preimage_sha256) return { state: "untouched", current };
  return { state: hash === operation.output_sha256 ? "applied" : "changed", current };
}

async function restoreOperation(storeRoot: string, journal: Journal, operation: JournalOperation): Promise<"restored" | "untouched"> {
  const observed = await operationState(storeRoot, journal, operation);
  if (observed.state === "untouched") return "untouched";
  if (observed.state === "changed") throw new Error("changed after cleanup; refusing to overwrite it");
  if (operation.mode === "copy") {
    const destination = withinTarget(journal.target, operation.destination_file!);
    await assertParentWithinTarget(journal.target, destination);
    await unlink(destination);
    return "restored";
  }
  const absolute = withinTarget(journal.target, operation.file);
  const backup = await safeRead(backupPath(storeRoot, journal.cleanup_id, operation.operation_id));
  if (digest(backup.buffer) !== operation.preimage_sha256) throw new Error("managed backup hash mismatch");
  await assertParentWithinTarget(journal.target, absolute);
  await atomicReplace(absolute, backup.buffer, observed.current!.mode, observed.current!.identity);
  return "restored";
}

/** Best-effort restore of every journaled operation; one failure never stops the others. */
async function restoreJournal(storeRoot: string, journal: Journal, onlyOperations?: ReadonlySet<string>): Promise<string[]> {
  const errors: string[] = [];
  for (const operation of [...journal.operations].reverse()) {
    if (onlyOperations && !onlyOperations.has(operation.operation_id)) continue;
    try {
      await restoreOperation(storeRoot, journal, operation);
    } catch (error) {
      errors.push(`${operation.destination_file ?? operation.file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return errors;
}

function sameValidators(before: RepositoryTrustDocument, after: RepositoryTrustDocument, artifacts: RepositoryArtifact[]): boolean {
  return artifacts.every((artifact) => {
    const beforeCoverage = before.coverage.capabilities.find((item) => item.capability === artifact.kind);
    const afterCoverage = after.coverage.capabilities.find((item) => item.capability === artifact.kind);
    return Boolean(beforeCoverage && afterCoverage && ["ran", "partial"].includes(afterCoverage.state) &&
      artifact.validator.id && afterCoverage.validators.some((validator) => validator.startsWith(artifact.validator.id)));
  });
}

export async function applyRepositoryCleanup(input: CleanupApplyInput, runtime: CleanupRuntime = {}): Promise<CleanupResult> {
  if (!PLAN_ID_RE.test(input.plan_id)) throw new Error("Invalid cleanup plan ID.");
  if (input.confirm_cleanup !== true) throw new Error("Cleanup confirmation is required. Review the plan, then retry with confirm_cleanup=true.");
  const now = runtime.now ?? (() => new Date());
  const plan = plans.get(input.plan_id);
  if (!plan || now().getTime() - plan.created > PLAN_TTL_MS) throw new Error("Cleanup plan is unavailable or expired; create a fresh plan and approve that exact result.");
  if (plan.output.outcome !== "ready") throw new Error("Blocked cleanup plans cannot be applied.");
  assertUnique(input.approved_artifact_ids, "Approved artifact IDs");
  if (!exactSet(input.approved_artifact_ids, plan.output.approval.exact_artifact_ids)) throw new Error("Approved artifact IDs must exactly match the plan scope.");
  if (plan.output.approval.rights_confirmation_required && input.confirm_rights_to_modify !== true) {
    throw new Error("Attribution/provenance cleanup requires confirm_rights_to_modify=true.");
  }
  // Claim the plan before the first await: a plan drives at most one apply attempt, so a retry or a
  // concurrent apply of the same plan must re-plan.
  plans.delete(input.plan_id);
  const lockRoot = runtime.storeRoot ?? MANAGED_CLEANUPS;
  // One apply or rollback per repository at a time: two plans for the same bytes must never interleave.
  const release = await acquireRepositoryLock(lockRoot, plan.output.target);
  try {    const currentTarget = await requireSafeScanTarget(plan.output.target);
    if (currentTarget.canonical_path !== plan.output.target || currentTarget.type !== "directory") throw new Error("Cleanup target identity no longer matches the approved plan.");
    const scan = runtime.scan ?? scanRepositoryTrust;
    const freshBefore = await scan(plan.output.target);
    const approved = plan.output.approval.exact_artifact_ids.map((id) => freshBefore.artifacts.find((item) => item.artifact_id === id));
    if (approved.some((item) => !item)) throw new Error("One or more approved artifacts changed or disappeared; create a fresh cleanup plan.");
    const storeRoot = runtime.storeRoot ?? MANAGED_CLEANUPS;
    const cleanupId = `cleanup-${(runtime.randomId ?? randomUUID)()}`;
    const startedAt = now().toISOString();

    // Phase 1: verify every preimage and compute every output before anything is written.
    const prepared: Array<{ operation: InternalOperation; inspected: Awaited<ReturnType<typeof safeRead>>; output: Buffer }> = [];
    for (const operation of plan.operations) {
      const inspected = await safeRead(operation.absolute);
      if (digest(inspected.buffer) !== operation.preimage_sha256) throw new Error("File content no longer matches the approved preimage hash.");
      if (operation.destination_absolute && await lstat(operation.destination_absolute).then(() => true, () => false)) {
        throw new Error(`Clean-copy destination already exists: ${operation.destination_file}`);
      }
      const output = operation.action === "edit_text"
        ? applyRanges(inspected.buffer, operation.edits ?? [])
        : sanitizeAsset(extname(operation.file).slice(1), inspected.buffer);
      if (output.equals(inspected.buffer)) throw new Error("The approved transformation produced no byte change.");
      prepared.push({ operation, inspected, output });
    }

    // Phase 2: persist every backup, then the journal, before the first mutation.
    const journal = journalSchema.parse({
      schema_version: CLEANUP_SCHEMA_VERSION,
      cleanup_id: cleanupId,
      plan_id: plan.output.plan_id,
      target: plan.output.target,
      artifact_ids: plan.output.artifact_ids,
      started_at: startedAt,
      operations: prepared.map(({ operation, output }) => ({
        operation_id: operation.operation_id,
        artifact_ids: operation.artifact_ids,
        file: operation.file,
        ...(operation.destination_file ? { destination_file: operation.destination_file } : {}),
        mode: operation.mode,
        validators: operation.validators,
        preimage_sha256: operation.preimage_sha256,
        output_sha256: digest(output),
      })),
    });
    await mkdir(join(storeRoot, cleanupId, "backups"), { recursive: true, mode: 0o700 });
    for (const { operation, inspected } of prepared) {
      await writeFile(backupPath(storeRoot, cleanupId, operation.operation_id), inspected.buffer, { flag: "wx", mode: 0o600 });
    }
    await writeRecord(storeRoot, cleanupId, "journal.json", journal);

    // Phase 3: mutate, verify, and audit. Any failure restores every journaled operation it safely can.
    const operationResults: z.infer<typeof operationResultSchema>[] = [];
    // Automatic rollback restores only what this run wrote: identical bytes written by another
    // cleanup (or the user) are never treated as ours.
    const appliedThisRun = new Set<string>();
    try {
      for (const [index, { operation, inspected, output }] of prepared.entries()) {
        await runtime.beforeOperation?.(operation, index);
        if (operation.mode === "copy" && operation.destination_absolute) {
          await assertParentWithinTarget(plan.output.target, operation.destination_absolute);
          await atomicCreate(operation.destination_absolute, output, inspected.mode);
          const identity = await fileIdentity(operation.destination_absolute);
          try {
            await writeRecord(storeRoot, cleanupId, `created-${operation.operation_id}.json`, { identity });
          } catch (error) {
            // Without the marker no later rollback could prove the copy is ours, so remove it now.
            if (await fileIdentity(operation.destination_absolute).catch(() => undefined) === identity) await unlink(operation.destination_absolute);
            throw error;
          }
        } else {
          await assertParentWithinTarget(plan.output.target, operation.absolute);
          await atomicReplace(operation.absolute, output, inspected.mode, inspected.identity);
        }
        appliedThisRun.add(operation.operation_id);
        operationResults.push({
          operation_id: operation.operation_id, file: operation.file,
          ...(operation.destination_file ? { destination_file: operation.destination_file } : {}),
          status: "applied", before_sha256: operation.preimage_sha256, after_sha256: digest(output),
          targeted_artifacts_resolved: false,
        });
      }
      const selectedArtifacts = approved.filter((item): item is RepositoryArtifact => Boolean(item));
      const after = await scan(plan.output.target);
      const changes = diffRepositoryTrust(freshBefore, after);
      let targetedResolved = true;
      let copyValidatorsRan = true;
      for (const operation of plan.operations) {
        const result = operationResults.find((item) => item.operation_id === operation.operation_id)!;
        if (operation.mode === "copy" && operation.destination_absolute) {
          const destinationScan = await scan(operation.destination_absolute);
          const operationArtifacts = selectedArtifacts.filter((artifact) => operation.artifact_ids.includes(artifact.artifact_id));
          copyValidatorsRan &&= sameValidators(freshBefore, destinationScan, operationArtifacts);
          result.targeted_artifacts_resolved = !destinationScan.artifacts.some((artifact) =>
            operation.artifact_ids.some((id) => {
              const original = freshBefore.artifacts.find((item) => item.artifact_id === id);
              return original?.kind === artifact.kind && original.marker_class === artifact.marker_class;
            })
          );
        } else {
          result.targeted_artifacts_resolved = operation.artifact_ids.every((id) =>
            !after.artifacts.some((artifact) => artifact.artifact_id === id)
          );
        }
        targetedResolved &&= result.targeted_artifacts_resolved;
      }
      const validatorsRan = sameValidators(freshBefore, after, selectedArtifacts) && copyValidatorsRan;
      const completedAt = now().toISOString();
      const limitations = [
        "Repository tests, formatters, and build checks have not been run by CodeInspectus; cleanup remains incomplete until the calling agent runs the relevant checks.",
        ...(plan.operations.some((operation) => operation.mode === "copy")
          ? ["Media cleanup created sanitized copies and intentionally preserved the original provenance-bearing assets."] : []),
      ];
      const verification = {
        same_validators_ran: validatorsRan,
        targeted_artifacts_resolved: targetedResolved,
        repository_checks: {
          state: "not_run" as const,
          required: true as const,
          reason: "Run the repository's relevant tests, formatter, and build after reviewing the bounded cleanup diff.",
        },
      };
      const auditLog = await writeRecord(storeRoot, cleanupId, "audit.json", {
        schema_version: CLEANUP_SCHEMA_VERSION,
        cleanup_id: cleanupId,
        plan_id: plan.output.plan_id,
        target: plan.output.target,
        artifact_ids: plan.output.artifact_ids,
        // Same-validator proof covers the selected markers only. Repository-specific tests/builds are
        // deliberately not executed, so the end-to-end cleanup result must remain incomplete.
        outcome: "incomplete",
        operations: operationResults.map((result) => {
          const operation = plan.operations.find((item) => item.operation_id === result.operation_id)!;
          return { ...result, artifact_ids: operation.artifact_ids, validators: operation.validators };
        }),
        started_at: startedAt,
        completed_at: completedAt,
        verification,
        limitations,
      });
      return cleanupResultSchema.parse({
        schema_version: CLEANUP_SCHEMA_VERSION,
        cleanup_id: cleanupId,
        plan_id: plan.output.plan_id,
        outcome: "incomplete",
        target: plan.output.target,
        started_at: startedAt,
        completed_at: completedAt,
        checkpoint: { state: "created", managed: true, content_retained: true },
        operations: operationResults,
        repository_trust_before: freshBefore,
        repository_trust_after: after,
        repository_trust_changes: changes,
        verification,
        audit_log_path: auditLog,
        limitations,
      });
    } catch (error) {
      const cause = error instanceof Error ? error : new Error(String(error));
      const rollbackErrors = await restoreJournal(storeRoot, journal, appliedThisRun);
      const auditValue = {
        schema_version: CLEANUP_SCHEMA_VERSION,
        cleanup_id: cleanupId,
        plan_id: plan.output.plan_id,
        target: plan.output.target,
        artifact_ids: plan.output.artifact_ids,
        outcome: rollbackErrors.length ? "failed_rollback_incomplete" : "failed_rolled_back",
        applied_operations: operationResults,
        failure: cause.message,
        rollback_errors: rollbackErrors,
        started_at: startedAt,
        completed_at: now().toISOString(),
      };
      const failureAudit = await writeRecord(storeRoot, cleanupId, "audit.json", auditValue)
        .catch(() => writeRecord(storeRoot, cleanupId, "failure.json", auditValue).catch(() => undefined));
      throw new Error(`Cleanup ${cleanupId} failed; automatic rollback ${rollbackErrors.length ? `requires review (${rollbackErrors.join("; ")})` : "completed"}. Audit: ${failureAudit ?? "unavailable"}. Cause: ${cause.message}`);
    }
  } finally {
    await release();
  }
}

function operationResult(operation: JournalOperation, status: z.infer<typeof operationResultSchema>["status"], limitation?: string): z.infer<typeof operationResultSchema> {
  return {
    operation_id: operation.operation_id, file: operation.file,
    ...(operation.destination_file ? { destination_file: operation.destination_file } : {}),
    status, before_sha256: operation.preimage_sha256,
    ...(status === "applied" ? { after_sha256: operation.output_sha256 } : {}),
    targeted_artifacts_resolved: false,
    ...(limitation ? { limitation } : {}),
  };
}

export async function rollbackRepositoryCleanup(input: CleanupRollbackInput, runtime: CleanupRuntime = {}): Promise<CleanupResult> {
  if (!CLEANUP_ID_RE.test(input.cleanup_id)) throw new Error("Invalid cleanup ID.");
  if (input.confirm_rollback !== true) throw new Error("Rollback confirmation is required.");
  const storeRoot = runtime.storeRoot ?? MANAGED_CLEANUPS;
  const scan = runtime.scan ?? scanRepositoryTrust;
  const now = runtime.now ?? (() => new Date());
  const release = await acquireRepositoryLock(storeRoot, (await readJournal(storeRoot, input.cleanup_id)).target);
  try {    const journal = await readJournal(storeRoot, input.cleanup_id);
    if (await readIfPresent(join(storeRoot, input.cleanup_id, "rollback.json"))) throw new Error(`Cleanup ${input.cleanup_id} was already rolled back.`);
    const priorAudit = await readIfPresent(join(storeRoot, input.cleanup_id, "audit.json"));
    const priorOutcome = (() => {
      try { return priorAudit ? (JSON.parse(priorAudit.buffer.toString("utf8")) as { outcome?: string }).outcome : undefined; } catch { return undefined; }
    })();
    if (priorOutcome === "failed_rolled_back") {
      throw new Error(`Cleanup ${input.cleanup_id} failed and was already rolled back automatically; nothing it applied remains to restore.`);
    }
    const target = await requireSafeScanTarget(journal.target);
    if (target.type !== "directory" || target.canonical_path !== journal.target) throw new Error("Persisted cleanup target identity no longer matches.");
    const beforeRollback = await scan(journal.target);
    const states = await Promise.all(journal.operations.map((operation) =>
      operationState(storeRoot, journal, operation).catch((): OperationState => ({ state: "changed" }))
    ));
    const base = {
      schema_version: CLEANUP_SCHEMA_VERSION,
      cleanup_id: journal.cleanup_id,
      plan_id: journal.plan_id,
      target: journal.target,
      started_at: journal.started_at,
      repository_trust_before: beforeRollback,
    };
    const changed = journal.operations.filter((_operation, index) => states[index]!.state === "changed");
    if (changed.length) {
      // All-or-nothing: a single post-clean change means no file is touched.
      const completedAt = now().toISOString();
      const limitations = [`Rollback refused because ${changed.map((item) => item.destination_file ?? item.file).join(", ")} changed after cleanup; no file was modified.`];
      const record = await writeRecord(storeRoot, journal.cleanup_id, `rollback-refused-${now().getTime()}.json`, {
        schema_version: CLEANUP_SCHEMA_VERSION,
        cleanup_id: journal.cleanup_id,
        plan_id: journal.plan_id,
        target: journal.target,
        outcome: "rollback_refused",
        completed_at: completedAt,
        limitations,
      });
      return cleanupResultSchema.parse({
        ...base,
        outcome: "rollback_refused",
        completed_at: completedAt,
        checkpoint: { state: "preserved", managed: true, content_retained: true },
        operations: journal.operations.map((operation, index) => {
          const state = states[index]!.state;
          return state === "changed"
            ? operationResult(operation, "failed", "Changed after cleanup; refusing to overwrite it.")
            : operationResult(operation, state === "applied" ? "applied" : "unchanged");
        }),
        repository_trust_after: beforeRollback,
        repository_trust_changes: diffRepositoryTrust(beforeRollback, beforeRollback),
        verification: {
          same_validators_ran: false,
          targeted_artifacts_resolved: false,
          repository_checks: { state: "not_run", required: true, reason: "No file was restored; review the changed paths before retrying." },
        },
        audit_log_path: record,
        limitations,
      });
    }
    const errors = await restoreJournal(storeRoot, journal);
    if (errors.length) {
      // Record the reviewed failure so the repository is not locked against new plans forever.
      await writeRecord(storeRoot, journal.cleanup_id, `rollback-failed-${now().getTime()}.json`, {
        schema_version: CLEANUP_SCHEMA_VERSION, cleanup_id: journal.cleanup_id, plan_id: journal.plan_id,
        target: journal.target, outcome: "rollback_failed", completed_at: now().toISOString(), errors,
      }).catch(() => undefined);
      throw new Error(`Rollback of ${journal.cleanup_id} did not complete (${errors.join("; ")}). Restored operations are safe to retry.`);
    }
    const after = await scan(journal.target);
    const restoredArtifactIds = new Set(journal.operations.flatMap((operation) => operation.artifact_ids));
    const restoredArtifacts = after.artifacts.filter((artifact) => restoredArtifactIds.has(artifact.artifact_id));
    const verification = {
      same_validators_ran: restoredArtifacts.length === 0 || sameValidators(beforeRollback, after, restoredArtifacts),
      targeted_artifacts_resolved: false,
      repository_checks: { state: "not_run" as const, required: true as const, reason: "Review the restored files and rerun relevant repository checks." },
    };
    const operations = journal.operations.map((operation, index) =>
      operationResult(operation, states[index]!.state === "applied" ? "rolled_back" : "unchanged")
    );
    const completedAt = now().toISOString();
    const limitations = ["Rollback restored the managed checkpoint; repository checks remain required."];
    const rollbackAuditPath = await writeRecord(storeRoot, journal.cleanup_id, "rollback.json", {
      schema_version: CLEANUP_SCHEMA_VERSION,
      cleanup_id: journal.cleanup_id,
      plan_id: journal.plan_id,
      target: journal.target,
      outcome: "rolled_back",
      operations,
      completed_at: completedAt,
      verification,
      limitations,
    });
    return cleanupResultSchema.parse({
      ...base,
      outcome: "rolled_back",
      completed_at: completedAt,
      checkpoint: { state: "restored", managed: true, content_retained: true },
      operations,
      repository_trust_after: after,
      repository_trust_changes: diffRepositoryTrust(beforeRollback, after),
      verification,
      audit_log_path: rollbackAuditPath,
      limitations,
    });
  } finally {
    await release();
  }
}
