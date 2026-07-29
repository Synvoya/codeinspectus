import { loadStoredScanForExport } from "./export/index.js";
import { scanIdSchema } from "./schemas.js";
import {
  annotationIdSchema,
  createTriageEvent,
  inspectTriageStore,
  triageFindingIdentity,
  triageScopeForScan,
  triageStateSchema,
  writeTriageEvent,
  TRIAGE_EVENT_MAX_BYTES,
  TRIAGE_SCHEMA_VERSION,
  TRIAGE_STORE_MAX_BYTES,
  TRIAGE_STORE_MAX_EVENTS,
  type TriageAnnotation,
  type TriageSnapshot,
  type TriageState,
} from "./triage.js";
import type { StoredScanResult } from "./store.js";

export interface TriageCliIo { stdout(text: string): void; stderr(text: string): void }
export interface TriageCliDependencies {
  loadScan(scanId: string): Promise<StoredScanResult>;
  inspect(scan: StoredScanResult): Promise<TriageSnapshot>;
  write(event: ReturnType<typeof createTriageEvent>): Promise<void>;
}

class TriageUsageError extends Error {}
const STATE_BY_SLUG: Record<string, TriageState> = {
  accepted: "Accepted", "false-positive": "False positive", "risk-accepted": "Risk accepted",
  "needs-review": "Needs review", "fixed-pending-verification": "Fixed pending verification",
};

export function triageCliHelp(): string {
  return [
    "Usage:",
    "  codeinspectus triage add SCAN_ID FINDING_ID --state STATE --reason TEXT [--actor LABEL]",
    "  codeinspectus triage list SCAN_ID [--limit 1..200] [--format text|json]",
    "  codeinspectus triage show SCAN_ID ANNOTATION_ID [--format text|json]",
    "  codeinspectus triage update SCAN_ID ANNOTATION_ID --state STATE --reason TEXT [--actor LABEL]",
    "  codeinspectus triage delete SCAN_ID ANNOTATION_ID --reason TEXT [--actor LABEL]",
    "",
    `States: ${Object.keys(STATE_BY_SLUG).join(", ")}`,
    "Delete creates an auditable tombstone; it never deletes or suppresses raw findings.",
    "",
  ].join("\n");
}

function valueAfter(argv: readonly string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new TriageUsageError(`${option} requires a value.`);
  return value;
}

function parseOptions(argv: readonly string[]): { positional: string[]; state?: TriageState; reason?: string; actor?: string; limit: number; limitSpecified: boolean; format: "text" | "json" } {
  const positional: string[] = [];
  let state: TriageState | undefined;
  let reason: string | undefined;
  let actor: string | undefined;
  let limit = 50;
  let limitSpecified = false;
  let format: "text" | "json" = "text";
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    if (!arg.startsWith("--")) { positional.push(arg); continue; }
    const value = valueAfter(argv, index, arg); index++;
    if (arg === "--state") {
      state = STATE_BY_SLUG[value] ?? (triageStateSchema.safeParse(value).success ? value as TriageState : undefined);
      if (!state) throw new TriageUsageError(`Invalid triage state '${value}'.`);
    } else if (arg === "--reason") reason = value;
    else if (arg === "--actor") actor = value;
    else if (arg === "--limit") {
      if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 200) throw new TriageUsageError("--limit must be an integer from 1 to 200.");
      limit = Number(value); limitSpecified = true;
    } else if (arg === "--format") {
      if (value !== "text" && value !== "json") throw new TriageUsageError("--format must be text or json.");
      format = value;
    } else throw new TriageUsageError(`Unknown triage option '${arg}'.`);
  }
  return { positional, ...(state ? { state } : {}), ...(reason ? { reason } : {}), ...(actor ? { actor } : {}), limit, limitSpecified, format };
}

function requireScanId(value: string | undefined): string {
  const parsed = scanIdSchema.safeParse(value);
  if (!parsed.success) throw new TriageUsageError(parsed.error.issues[0]?.message ?? "Invalid scan ID.");
  return parsed.data;
}

function requireAnnotationId(value: string | undefined): string {
  const parsed = annotationIdSchema.safeParse(value);
  if (!parsed.success) throw new TriageUsageError(parsed.error.issues[0]?.message ?? "Invalid annotation ID.");
  return parsed.data;
}

async function loadExact(deps: TriageCliDependencies, id: string): Promise<StoredScanResult> {
  const scan = await deps.loadScan(id);
  if (!scan || scan.scan_id !== id) throw new TriageUsageError(`No stored CodeInspectus scan found with id '${id}'.`);
  return scan;
}

function findAnnotation(snapshot: TriageSnapshot, id: string): TriageAnnotation {
  const annotation = snapshot.annotations.find((candidate) => candidate.annotation_id === id);
  if (!annotation) throw new TriageUsageError(`No triage annotation found with id '${id}' in this scan scope.`);
  return annotation;
}

function findingForAnnotation(scan: StoredScanResult, annotation: TriageAnnotation) {
  const finding = scan.findings.find((candidate) =>
    JSON.stringify(triageFindingIdentity(candidate)) === JSON.stringify(annotation.finding_identity));
  if (!finding) throw new TriageUsageError("The annotation finding identity is not present in the supplied scan scope.");
  return finding;
}

function requireCompleteSnapshot(snapshot: TriageSnapshot): void {
  if (!snapshot.available || snapshot.truncated || snapshot.corrupt_record_count) {
    throw new TriageUsageError("Triage mutation refused because the exact scope store is unavailable, bounded, or corrupt.");
  }
}

function render(value: unknown, format: "text" | "json"): string {
  if (format === "json") return `${JSON.stringify(value, null, 2)}\n`;
  if (Array.isArray(value)) return `${value.map((item) => {
    const annotation = item as TriageAnnotation;
    return `${annotation.annotation_id}  ${annotation.deleted ? "Deleted" : annotation.state}  ${annotation.finding_identity.file}  ${annotation.reason}`;
  }).join("\n")}\n`;
  const annotation = value as TriageAnnotation;
  return `${annotation.annotation_id}\nState: ${annotation.deleted ? "Deleted" : annotation.state}\nFinding: ${annotation.finding_identity.rule_id} ${annotation.finding_identity.file}\nReason: ${annotation.reason}${annotation.actor ? `\nActor: ${annotation.actor}` : ""}\n`;
}

function inspectionEnvelope(snapshot: TriageSnapshot) {
  return {
    available: snapshot.available,
    partial: !snapshot.available || snapshot.truncated || snapshot.corrupt_record_count > 0,
    truncated: snapshot.truncated,
    candidate_files: snapshot.candidate_files,
    inspected_files: snapshot.inspected_files,
    bytes_read: snapshot.bytes_read,
    corrupt_record_count: snapshot.corrupt_record_count,
    limits: { max_events: TRIAGE_STORE_MAX_EVENTS, max_store_bytes: TRIAGE_STORE_MAX_BYTES, max_event_bytes: TRIAGE_EVENT_MAX_BYTES },
  };
}

export async function runTriageCli(
  argv: readonly string[], io: TriageCliIo,
  deps: TriageCliDependencies = { loadScan: loadStoredScanForExport, inspect: inspectTriageStore, write: writeTriageEvent },
): Promise<number> {
  try {
    const action = argv[0];
    if (!action || action === "--help" || action === "-h") { io.stdout(triageCliHelp()); return action ? 0 : 2; }
    if (!["add", "list", "show", "update", "delete"].includes(action)) throw new TriageUsageError(`Unknown triage subcommand '${action}'.`);
    const parsed = parseOptions(argv.slice(1));
    const expected = action === "add" ? 2 : action === "list" ? 1 : 2;
    if (parsed.positional.length !== expected) throw new TriageUsageError(`triage ${action} expects exactly ${expected} positional argument(s).`);
    if (action === "add" && (!parsed.state || !parsed.reason)) throw new TriageUsageError("triage add requires --state and --reason.");
    if (action === "update" && (!parsed.state || !parsed.reason)) throw new TriageUsageError("triage update requires --state and --reason.");
    if (action === "delete" && (!parsed.reason || parsed.state)) throw new TriageUsageError("triage delete requires --reason and does not accept --state.");
    if ((action === "list" || action === "show") && (parsed.state || parsed.reason || parsed.actor)) throw new TriageUsageError(`triage ${action} does not accept mutation options.`);
    if (action !== "list" && parsed.limitSpecified) throw new TriageUsageError(`triage ${action} does not accept --limit.`);
    const scan = await loadExact(deps, requireScanId(parsed.positional[0]));
    if (action === "add") {
      const finding = scan.findings.find((candidate) => candidate.id === parsed.positional[1]);
      if (!finding) throw new TriageUsageError(`Finding '${parsed.positional[1]}' does not exist in the raw scan.`);
      const snapshot = await deps.inspect(scan);
      requireCompleteSnapshot(snapshot);
      const identity = triageFindingIdentity(finding);
      if (snapshot.annotations.some((annotation) => !annotation.deleted && JSON.stringify(annotation.finding_identity) === JSON.stringify(identity))) {
        throw new TriageUsageError("This finding already has an active annotation in the exact scan scope; update it instead.");
      }
      const event = createTriageEvent({ scan, finding, state: parsed.state!, reason: parsed.reason!, ...(parsed.actor ? { actor: parsed.actor } : {}) });
      await deps.write(event); io.stdout(render({ ...event, latest_event_id: event.event_id, deleted: false }, parsed.format)); return 0;
    }
    const snapshot = await deps.inspect(scan);
    if (action === "list") {
      const output = snapshot.annotations.slice(0, parsed.limit);
      io.stdout(parsed.format === "json" ? `${JSON.stringify({
        schema_version: TRIAGE_SCHEMA_VERSION,
        source_scan_id: scan.scan_id,
        scope: triageScopeForScan(scan),
        inspection: { ...inspectionEnvelope(snapshot), annotation_count: snapshot.annotations.length, returned_annotation_count: output.length },
        annotations: output,
      }, null, 2)}\n` : render(output, "text"));
      if (!snapshot.available || snapshot.truncated || snapshot.corrupt_record_count) io.stderr("CodeInspectus triage: annotation inspection was partial.\n");
      return !snapshot.available || snapshot.truncated || snapshot.corrupt_record_count ? 2 : 0;
    }
    const annotation = findAnnotation(snapshot, requireAnnotationId(parsed.positional[1]));
    if (action === "show") {
      const output = {
        schema_version: TRIAGE_SCHEMA_VERSION,
        source_scan_id: scan.scan_id,
        scope: triageScopeForScan(scan),
        inspection: inspectionEnvelope(snapshot),
        annotation,
        audit_events: snapshot.events.filter((event) => event.annotation_id === annotation.annotation_id),
      };
      io.stdout(parsed.format === "json" ? `${JSON.stringify(output, null, 2)}\n` : render(annotation, "text"));
      const partial = !snapshot.available || snapshot.truncated || snapshot.corrupt_record_count > 0;
      if (partial) io.stderr("CodeInspectus triage: annotation inspection was partial.\n");
      return partial ? 2 : 0;
    }
    requireCompleteSnapshot(snapshot);
    if (annotation.deleted) throw new TriageUsageError("Deleted annotations cannot be updated or deleted again.");
    const finding = findingForAnnotation(scan, annotation);
    if (action === "update") {
      const event = createTriageEvent({ scan, finding, annotationId: annotation.annotation_id, previousEventId: annotation.latest_event_id, operation: "update", state: parsed.state!, reason: parsed.reason!, ...(parsed.actor ? { actor: parsed.actor } : {}) });
      await deps.write(event); io.stdout(render({ ...event, latest_event_id: event.event_id, deleted: false }, parsed.format)); return 0;
    }
    if (action === "delete") {
      const event = createTriageEvent({ scan, finding, annotationId: annotation.annotation_id, previousEventId: annotation.latest_event_id, operation: "delete", state: annotation.state, reason: parsed.reason!, ...(parsed.actor ? { actor: parsed.actor } : {}) });
      await deps.write(event); io.stdout(render({ ...event, latest_event_id: event.event_id, deleted: true }, parsed.format)); return 0;
    }
    throw new TriageUsageError(`Unknown triage subcommand '${action}'.`);
  } catch (error) {
    io.stderr(`CodeInspectus triage: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}
