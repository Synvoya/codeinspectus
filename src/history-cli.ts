import { createJsonExport, redactFindingForOutput } from "./export/model.js";
import { loadStoredScanForExport } from "./export/index.js";
import { scanIdSchema } from "./schemas.js";
import {
  HISTORY_LIST_MAX_LIMIT,
  compareScanHistory,
  listScanHistory,
  loadHistorySnapshot,
  rerunStoredScan,
  type HistoryListFilters,
  type HistoryScanStatus,
} from "./scan-history.js";
import { normalizeStoredScanForRuntime, type ScanStoreSnapshot, type StoredScanResult } from "./store.js";
import { summarizeScan } from "./summarize.js";
import { redactSnippet } from "./redact.js";
import type { Severity } from "./types.js";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: readonly HistoryScanStatus[] = ["clean", "findings", "partial", "unknown"];

export interface HistoryCliIo {
  stdout(text: string): void;
  stderr(text: string): void;
}

export interface HistoryCliDependencies {
  loadScan(scanId: string): Promise<StoredScanResult>;
  loadHistory(): Promise<ScanStoreSnapshot>;
  rerun(scan: StoredScanResult): Promise<StoredScanResult>;
}

class HistoryUsageError extends Error {}

export function historyCliHelp(): string {
  return [
    "Usage:",
    "  codeinspectus scans list [filters]",
    "  codeinspectus scans show SCAN_ID [--format text|json]",
    "  codeinspectus scans rerun SCAN_ID [--format text|json]",
    "  codeinspectus scans compare OLD_SCAN_ID NEW_SCAN_ID [--format text|json]",
    "",
    "List filters:",
    "  --repository <canonical-root> Exact recorded Git root (legacy fallback: exact target).",
    "  --path <path>                 Target containment or finding-location path.",
    "  --since <date|ISO-8601>       Inclusive UTC date or timestamp with timezone.",
    "  --until <date|ISO-8601>       Inclusive UTC date or timestamp with timezone.",
    "  --severity <level>            Scans containing a finding at or above the level.",
    "  --status <status>             clean, findings, partial, or unknown.",
    `  --limit <n>                   Return 1-${HISTORY_LIST_MAX_LIMIT} records (default 50).`,
    "  --format <text|json>          Output format (default text).",
    "",
  ].join("\n");
}

function valueAfter(argv: readonly string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new HistoryUsageError(`${option} requires a value.`);
  return value;
}

function parseFormat(value: string): "text" | "json" {
  if (value !== "text" && value !== "json") throw new HistoryUsageError("History --format must be text or json.");
  return value;
}

function parseTimestamp(value: string, option: string): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const boundary = option === "--until" ? "T23:59:59.999Z" : "T00:00:00.000Z";
    const parsed = new Date(`${value}${boundary}`);
    if (Number.isFinite(parsed.valueOf()) && parsed.toISOString().startsWith(value)) return parsed.toISOString();
  }
  if (!/^\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})$/.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new HistoryUsageError(`${option} must be a YYYY-MM-DD date or ISO-8601 timestamp with an explicit timezone.`);
  }
  return new Date(value).toISOString();
}

function requireScanId(value: string | undefined, label: string): string {
  if (!value) throw new HistoryUsageError(`${label} is required.`);
  const parsed = scanIdSchema.safeParse(value);
  if (!parsed.success) throw new HistoryUsageError(parsed.error.issues[0]?.message ?? `Invalid ${label}.`);
  return parsed.data;
}

async function loadExact(dependencies: HistoryCliDependencies, scanId: string): Promise<StoredScanResult> {
  const scan = await dependencies.loadScan(scanId);
  if (!scan || scan.scan_id !== scanId) throw new HistoryUsageError(`No stored CodeInspectus scan found with id '${scanId}'.`);
  return scan;
}

function parseList(argv: readonly string[]): { filters: HistoryListFilters; format: "text" | "json" } {
  const filters: HistoryListFilters = {};
  let format: "text" | "json" = "text";
  for (let index = 0; index < argv.length; index++) {
    const option = argv[index]!;
    const value = valueAfter(argv, index, option);
    index++;
    if (option === "--repository") filters.repository = value;
    else if (option === "--path") filters.path = value;
    else if (option === "--since") filters.since = parseTimestamp(value, option);
    else if (option === "--until") filters.until = parseTimestamp(value, option);
    else if (option === "--severity") {
      if (!SEVERITIES.includes(value as Severity)) throw new HistoryUsageError(`Invalid severity '${value}'.`);
      filters.severity = value as Severity;
    } else if (option === "--status") {
      if (!STATUSES.includes(value as HistoryScanStatus)) throw new HistoryUsageError(`Invalid scan status '${value}'.`);
      filters.status = value as HistoryScanStatus;
    } else if (option === "--limit") {
      if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > HISTORY_LIST_MAX_LIMIT) {
        throw new HistoryUsageError(`--limit must be an integer from 1 to ${HISTORY_LIST_MAX_LIMIT}.`);
      }
      filters.limit = Number(value);
    } else if (option === "--format") format = parseFormat(value);
    else throw new HistoryUsageError(`Unknown scans list option '${option}'.`);
  }
  if (filters.since && filters.until && Date.parse(filters.since) > Date.parse(filters.until)) {
    throw new HistoryUsageError("--since must not be later than --until.");
  }
  return { filters, format };
}

function parseIdCommand(argv: readonly string[], count: 1 | 2): { ids: string[]; format: "text" | "json" } {
  const positional: string[] = [];
  let format: "text" | "json" = "text";
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index]!;
    if (value === "--format") {
      format = parseFormat(valueAfter(argv, index, value));
      index++;
    } else if (value.startsWith("--")) throw new HistoryUsageError(`Unknown history option '${value}'.`);
    else positional.push(value);
  }
  if (positional.length !== count) throw new HistoryUsageError(`Expected exactly ${count} scan ID${count === 1 ? "" : "s"}.`);
  return { ids: positional.map((value, index) => requireScanId(value, count === 1 ? "SCAN_ID" : index ? "NEW_SCAN_ID" : "OLD_SCAN_ID")), format };
}

function listText(result: ReturnType<typeof listScanHistory>): string {
  const lines = result.entries.map((entry) =>
    `${entry.started_at}  ${entry.scan_id}  ${entry.status.padEnd(8)}  ${String(entry.finding_count).padStart(4)} finding(s)  ${redactSnippet(entry.target)}`);
  return [
    `CodeInspectus scan history: ${result.bounds.returned}/${result.bounds.matching_records} matching record(s).`,
    ...lines,
    ...(result.note ? [`History warning: ${result.note}`] : []),
    ...(result.bounds.result_truncated ? [`Output limited to ${result.bounds.requested_limit} record(s).`] : []),
    "",
  ].join("\n");
}

function comparisonText(result: ReturnType<typeof compareScanHistory>): string {
  const safeResult = comparisonJson(result);
  const lines = safeResult.items.map((item) =>
    `${item.state}: ${item.finding.severity} ${item.finding.rule_id} ${item.finding.location.file}:${item.finding.location.start_line}`);
  return [
    `CodeInspectus comparison ${safeResult.old_scan_id} -> ${safeResult.new_scan_id}`,
    ...Object.entries(safeResult.summary).map(([state, count]) => `  ${state}: ${count}`),
    ...lines,
    ...safeResult.history_provenance.notes.map((note) => `History warning: ${note}`),
    "",
  ].join("\n");
}

function scanForText(scan: StoredScanResult): ReturnType<typeof normalizeStoredScanForRuntime> {
  const normalized = normalizeStoredScanForRuntime(scan);
  const aggregate = createJsonExport(scan).coverage.aggregate;
  return {
    ...normalized,
    target: redactSnippet(normalized.target),
    findings: normalized.findings.map((finding) => redactFindingForOutput(finding, aggregate)),
  };
}

function comparisonJson(result: ReturnType<typeof compareScanHistory>): ReturnType<typeof compareScanHistory> {
  const aggregate = result.partial ? "partial" : "complete";
  return {
    ...result,
    items: result.items.map((item) => ({
      ...item,
      finding: redactFindingForOutput(item.finding, aggregate),
    })),
  };
}

export async function runHistoryCli(
  argv: readonly string[],
  io: HistoryCliIo,
  dependencies: HistoryCliDependencies = {
    loadScan: loadStoredScanForExport,
    loadHistory: loadHistorySnapshot,
    rerun: rerunStoredScan,
  },
): Promise<number> {
  try {
    const action = argv[0];
    if (!action || action === "--help" || action === "-h") {
      io.stdout(historyCliHelp());
      return action ? 0 : 2;
    }
    if (action === "list") {
      const parsed = parseList(argv.slice(1));
      const result = listScanHistory(await dependencies.loadHistory(), parsed.filters);
      io.stdout(parsed.format === "json" ? `${JSON.stringify(result, null, 2)}\n` : listText(result));
      if (result.partial) io.stderr(`CodeInspectus history: ${result.note ?? "History inspection was partial."}\n`);
      return result.partial ? 2 : 0;
    }
    if (action === "show") {
      const parsed = parseIdCommand(argv.slice(1), 1);
      const scan = await loadExact(dependencies, parsed.ids[0]!);
      const document = createJsonExport(scan);
      io.stdout(parsed.format === "json" ? `${JSON.stringify(document, null, 2)}\n` : `${summarizeScan(scanForText(scan))}\n`);
      return 0;
    }
    if (action === "compare") {
      const parsed = parseIdCommand(argv.slice(1), 2);
      const [oldScan, newScan, history] = await Promise.all([
        loadExact(dependencies, parsed.ids[0]!), loadExact(dependencies, parsed.ids[1]!), dependencies.loadHistory(),
      ]);
      const result = compareScanHistory(oldScan, newScan, history);
      io.stdout(parsed.format === "json" ? `${JSON.stringify(comparisonJson(result), null, 2)}\n` : comparisonText(result));
      if (result.partial) io.stderr("CodeInspectus history: comparison contains unknown or incomplete history evidence.\n");
      return result.partial ? 2 : 0;
    }
    if (action === "rerun") {
      const parsed = parseIdCommand(argv.slice(1), 1);
      const prior = await loadExact(dependencies, parsed.ids[0]!);
      const fresh = await dependencies.rerun(prior);
      const history = await dependencies.loadHistory();
      const comparison = compareScanHistory(prior, fresh, history);
      const result = { schema_version: "1.0.0", rerun_of: prior.scan_id, scan: createJsonExport(fresh), comparison: comparisonJson(comparison) };
      io.stdout(parsed.format === "json" ? `${JSON.stringify(result, null, 2)}\n` : comparisonText(comparison));
      if (comparison.partial) io.stderr("CodeInspectus history: rerun comparison contains unknown or incomplete evidence.\n");
      return comparison.partial ? 2 : 0;
    }
    throw new HistoryUsageError(`Unknown scans subcommand '${action}'.`);
  } catch (error) {
    io.stderr(`CodeInspectus history: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}
