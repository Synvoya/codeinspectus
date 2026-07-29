import { randomUUID } from "node:crypto";
import { lstat, link, mkdir, open, readdir, rm, writeFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { z } from "zod";
import { MANAGED_TRIAGE, SERVER_VERSION } from "./config.js";
import { redactSnippet } from "./redact.js";
import { sha256Hex } from "./util/hash.js";
import type { Finding } from "./types.js";
import type { StoredScanResult } from "./store.js";
import { scanIdSchema } from "./schemas.js";

export const TRIAGE_SCHEMA_VERSION = "1.0.0" as const;
export const TRIAGE_EVENT_MAX_BYTES = 64 * 1024;
export const TRIAGE_STORE_MAX_BYTES = 16 * 1024 * 1024;
export const TRIAGE_STORE_MAX_EVENTS = 5_000;
export const INTERNAL_DISABLE_TRIAGE_PERSISTENCE_ENV = "CODEINSPECTUS_INTERNAL_DISABLE_TRIAGE_PERSISTENCE";

export const triageStateSchema = z.enum([
  "Accepted", "False positive", "Risk accepted", "Needs review", "Fixed pending verification",
]);
export type TriageState = z.infer<typeof triageStateSchema>;

const UUID_RE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
export const annotationIdSchema = z.string().regex(new RegExp(`^triage-${UUID_RE}$`), "annotation_id must be a generated triage UUID.");
export const triageEventIdSchema = z.string().regex(new RegExp(`^event-${UUID_RE}$`), "event_id must be a generated event UUID.");
const safeSingleLine = z.string().min(1).max(2_000).refine((value) => !/[\u0000-\u001f\u007f-\u009f]/.test(value), "must not contain control characters");
const actorSchema = z.string().min(1).max(128).refine((value) => !/[\u0000-\u001f\u007f-\u009f]/.test(value), "must not contain control characters");

export const triageEventSchema = z.object({
  schema_version: z.literal(TRIAGE_SCHEMA_VERSION),
  event_id: triageEventIdSchema,
  annotation_id: annotationIdSchema,
  operation: z.enum(["create", "update", "delete"]),
  previous_event_id: triageEventIdSchema.optional(),
  recorded_at: z.string().datetime(),
  tool_version: z.string(),
  source_scan_id: scanIdSchema,
  scope: z.object({ repository: z.string(), target: z.string(), scope_id: z.string().regex(/^[0-9a-f]{64}$/) }),
  finding_identity: z.object({
    fingerprint: z.string(), rule_id: z.string(), file: z.string(),
    producer_components: z.array(z.string()),
  }),
  state: triageStateSchema,
  reason: safeSingleLine,
  actor: actorSchema.optional(),
}).superRefine((event, context) => {
  if (event.operation === "create" && event.previous_event_id) context.addIssue({ code: z.ZodIssueCode.custom, path: ["previous_event_id"], message: "create must not reference a prior event" });
  if (event.operation !== "create" && !event.previous_event_id) context.addIssue({ code: z.ZodIssueCode.custom, path: ["previous_event_id"], message: "update/delete requires the prior event ID" });
});
export type TriageEvent = z.infer<typeof triageEventSchema>;

export interface TriageAnnotation extends Omit<TriageEvent, "event_id" | "operation"> {
  latest_event_id: string;
  deleted: boolean;
}

export interface TriageSnapshot {
  events: TriageEvent[];
  annotations: TriageAnnotation[];
  corrupt_record_count: number;
  corrupt_records: Array<{ file: string; error: string }>;
  inspected_files: number;
  candidate_files: number;
  bytes_read: number;
  truncated: boolean;
  available: boolean;
  error?: string;
}

function repositoryIdentity(scan: StoredScanResult): string {
  return scan.repository_root ?? scan.target;
}

export function triageScopeForScan(scan: StoredScanResult): TriageEvent["scope"] {
  const repository = repositoryIdentity(scan);
  return { repository, target: scan.target, scope_id: sha256Hex(JSON.stringify({ repository, target: scan.target })) };
}

export function triageFindingIdentity(finding: Finding): TriageEvent["finding_identity"] {
  return {
    fingerprint: finding.fingerprint,
    rule_id: finding.rule_id,
    file: finding.location.file,
    producer_components: [...(finding.producer_components ?? [])].sort(),
  };
}

export function triagePersistenceDisabled(environment: Record<string, string | undefined> = process.env): boolean {
  return environment[INTERNAL_DISABLE_TRIAGE_PERSISTENCE_ENV] === "1";
}

function sanitize(value: string): string {
  return redactSnippet(value);
}

export function createTriageEvent(input: {
  scan: StoredScanResult;
  finding: Finding;
  state: TriageState;
  reason: string;
  actor?: string;
  operation?: "create" | "update" | "delete";
  annotationId?: string;
  eventId?: string;
  recordedAt?: string;
  previousEventId?: string;
}): TriageEvent {
  return triageEventSchema.parse({
    schema_version: TRIAGE_SCHEMA_VERSION,
    event_id: input.eventId ?? `event-${randomUUID()}`,
    annotation_id: input.annotationId ?? `triage-${randomUUID()}`,
    operation: input.operation ?? "create",
    ...(input.previousEventId ? { previous_event_id: input.previousEventId } : {}),
    recorded_at: input.recordedAt ?? new Date().toISOString(),
    tool_version: SERVER_VERSION,
    source_scan_id: input.scan.scan_id,
    scope: triageScopeForScan(input.scan),
    finding_identity: triageFindingIdentity(input.finding),
    state: input.state,
    reason: sanitize(input.reason),
    ...(input.actor ? { actor: sanitize(input.actor) } : {}),
  });
}

function scopeDirectory(root: string, scopeId: string): string {
  const base = resolve(root);
  const destination = resolve(base, scopeId, "events");
  if (!destination.startsWith(`${base}${sep}`)) throw new Error("Triage scope escaped the managed root.");
  return destination;
}

async function ensureSafeDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error(`Unsafe triage directory: ${path}`);
}

const memoryEvents = new Map<string, TriageEvent[]>();

export async function writeTriageEvent(event: TriageEvent, options: {
  root?: string;
  linkFile?: typeof link;
} = {}): Promise<void> {
  const parsed = triageEventSchema.parse(event);
  const validated: TriageEvent = {
    ...parsed, reason: sanitize(parsed.reason), ...(parsed.actor ? { actor: sanitize(parsed.actor) } : {}),
  };
  const root = options.root ?? MANAGED_TRIAGE;
  const key = validated.scope.scope_id;
  const serialized = JSON.stringify(validated);
  if (Buffer.byteLength(serialized) > TRIAGE_EVENT_MAX_BYTES) throw new Error("Triage event exceeds the 64 KiB storage limit.");
  if (triagePersistenceDisabled() && root === MANAGED_TRIAGE) {
    memoryEvents.set(key, [...(memoryEvents.get(key) ?? []), validated]);
    return;
  }
  await ensureSafeDirectory(root);
  const scope = resolve(root, key);
  await ensureSafeDirectory(scope);
  const directory = scopeDirectory(root, key);
  await ensureSafeDirectory(directory);
  const destination = join(directory, `${validated.event_id}.json`);
  const temporary = `${destination}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, serialized, { encoding: "utf8", flag: "wx" });
    // link(2) is atomic and fails with EEXIST; unlike POSIX rename it cannot overwrite an
    // immutable audit event when an ID collides.
    await (options.linkFile ?? link)(temporary, destination);
    memoryEvents.set(key, [...(memoryEvents.get(key) ?? []), validated]);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

function sameImmutableIdentity(left: TriageEvent, right: TriageEvent): boolean {
  return JSON.stringify(left.scope) === JSON.stringify(right.scope) &&
    JSON.stringify(left.finding_identity) === JSON.stringify(right.finding_identity);
}

function projectAnnotations(events: TriageEvent[]): { annotations: TriageAnnotation[]; invalid: Array<{ file: string; error: string }> } {
  const current = new Map<string, TriageAnnotation>();
  const priorEvents = new Map<string, TriageEvent>();
  const invalid: Array<{ file: string; error: string }> = [];
  for (const event of events.slice().sort((a, b) => a.recorded_at.localeCompare(b.recorded_at) || a.event_id.localeCompare(b.event_id))) {
    const prior = priorEvents.get(event.annotation_id);
    if ((event.operation === "create" && prior) || (event.operation !== "create" && (!prior || event.previous_event_id !== prior.event_id || current.get(event.annotation_id)?.deleted)) ||
        (prior && !sameImmutableIdentity(prior, event))) {
      invalid.push({ file: `${event.event_id}.json`, error: "Invalid annotation event chain or immutable identity change." });
      continue;
    }
    priorEvents.set(event.annotation_id, event);
    current.set(event.annotation_id, {
      schema_version: event.schema_version, annotation_id: event.annotation_id,
      recorded_at: event.recorded_at, tool_version: event.tool_version, source_scan_id: event.source_scan_id,
      scope: event.scope, finding_identity: event.finding_identity, state: event.state,
      reason: event.reason, ...(event.actor ? { actor: event.actor } : {}),
      latest_event_id: event.event_id, deleted: event.operation === "delete",
    });
  }
  return {
    annotations: [...current.values()].sort((a, b) => b.recorded_at.localeCompare(a.recorded_at) || a.annotation_id.localeCompare(b.annotation_id)),
    invalid,
  };
}

export async function inspectTriageStore(scan: StoredScanResult, options: { root?: string; includeMemory?: boolean } = {}): Promise<TriageSnapshot> {
  const root = options.root ?? MANAGED_TRIAGE;
  const scope = triageScopeForScan(scan);
  const directory = scopeDirectory(root, scope.scope_id);
  const includeMemory = options.includeMemory ?? root === MANAGED_TRIAGE;
  let names: string[] = [];
  try {
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("Triage event directory is not a regular managed directory.");
    names = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") return {
      events: [], annotations: [], corrupt_record_count: 0, corrupt_records: [], inspected_files: 0,
      candidate_files: 0, bytes_read: 0, truncated: false, available: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
  const selected = names.slice(0, TRIAGE_STORE_MAX_EVENTS);
  const events: TriageEvent[] = [];
  const corrupt: Array<{ file: string; error: string }> = [];
  let bytesRead = 0;
  let inspected = 0;
  let truncated = names.length > selected.length;
  for (const name of selected) {
    inspected++;
    const eventId = name.slice(0, -5);
    if (!triageEventIdSchema.safeParse(eventId).success) {
      corrupt.push({ file: `unrecognized:${sha256Hex(name).slice(0, 12)}`, error: "Invalid event filename." });
      continue;
    }
    const path = join(directory, name);
    try {
      const metadata = await lstat(path);
      if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("Not a regular event file.");
      if (metadata.size > TRIAGE_EVENT_MAX_BYTES) throw new Error("Event exceeds the per-record size limit.");
      if (bytesRead + metadata.size > TRIAGE_STORE_MAX_BYTES) { truncated = true; break; }
      bytesRead += metadata.size;
      const handle = await open(path, "r");
      let raw: string;
      try {
        const opened = await handle.stat();
        if (!opened.isFile() || opened.dev !== metadata.dev || opened.ino !== metadata.ino || opened.size !== metadata.size) throw new Error("Event changed during bounded open.");
        const buffer = Buffer.alloc(metadata.size);
        let offset = 0;
        while (offset < buffer.length) {
          const read = await handle.read(buffer, offset, buffer.length - offset, offset);
          if (!read.bytesRead) break;
          offset += read.bytesRead;
        }
        const after = await handle.stat();
        if (offset !== metadata.size || after.size !== metadata.size || after.dev !== metadata.dev || after.ino !== metadata.ino) throw new Error("Event changed during bounded read.");
        raw = buffer.toString("utf8");
      } finally { await handle.close(); }
      let json: unknown;
      try { json = JSON.parse(raw); } catch { throw new Error("Invalid JSON event."); }
      const parsed = triageEventSchema.safeParse(json);
      if (!parsed.success) throw new Error("Event does not match the triage schema.");
      if (parsed.data.event_id !== eventId || parsed.data.scope.scope_id !== scope.scope_id ||
          parsed.data.scope.repository !== scope.repository || parsed.data.scope.target !== scope.target) {
        throw new Error("Foreign or mismatched triage event.");
      }
      events.push({
        ...parsed.data,
        reason: sanitize(parsed.data.reason),
        ...(parsed.data.actor ? { actor: sanitize(parsed.data.actor) } : {}),
      });
    } catch (error) {
      corrupt.push({ file: name, error: error instanceof Error ? error.message : String(error) });
    }
  }
  if (includeMemory) {
    for (const event of memoryEvents.get(scope.scope_id) ?? []) {
      if (!events.some((candidate) => candidate.event_id === event.event_id)) events.push(event);
    }
  }
  const projection = projectAnnotations(events);
  corrupt.push(...projection.invalid);
  const validEventIds = new Set(events.filter((event) => !projection.invalid.some((item) => item.file === `${event.event_id}.json`)).map((event) => event.event_id));
  return {
    events: events.filter((event) => validEventIds.has(event.event_id)), annotations: projection.annotations, corrupt_record_count: corrupt.length,
    corrupt_records: corrupt.slice(0, 100), inspected_files: inspected, candidate_files: names.length,
    bytes_read: bytesRead, truncated, available: true,
  };
}

export function matchingTriageAnnotations(scan: StoredScanResult, snapshot: TriageSnapshot): Array<{
  finding_id: string;
  annotation: TriageAnnotation;
}> {
  const scope = triageScopeForScan(scan);
  const output: Array<{ finding_id: string; annotation: TriageAnnotation }> = [];
  for (const annotation of snapshot.annotations) {
    if (annotation.deleted || annotation.scope.scope_id !== scope.scope_id || annotation.scope.repository !== scope.repository || annotation.scope.target !== scope.target) continue;
    const finding = scan.findings.find((candidate) => {
      const identity = triageFindingIdentity(candidate);
      return identity.fingerprint === annotation.finding_identity.fingerprint &&
        identity.rule_id === annotation.finding_identity.rule_id && identity.file === annotation.finding_identity.file &&
        JSON.stringify(identity.producer_components) === JSON.stringify(annotation.finding_identity.producer_components);
    });
    if (finding) output.push({ finding_id: finding.id, annotation });
  }
  return output.sort((a, b) => a.finding_id.localeCompare(b.finding_id) || a.annotation.annotation_id.localeCompare(b.annotation.annotation_id));
}
