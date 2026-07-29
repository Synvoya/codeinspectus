import { DEFAULT_MAX_FINDINGS } from "../config.js";
import { terminateActiveEngineProcesses } from "../engines/exec.js";
import { ALL_SCANNERS } from "../preflight.js";
import type { ScannerKind } from "../types.js";
import { REPOSITORY_HISTORY_MAX_COMMITS, runRepositoryHistoryScan, type RepositoryHistoryOptions, type RepositoryHistoryResult } from "./index.js";

export interface RepositoryHistoryCliIo { stdout(text: string): void; stderr(text: string): void }
export interface RepositoryHistoryCliDependencies { run(options: RepositoryHistoryOptions): Promise<RepositoryHistoryResult> }
class RepositoryHistoryUsageError extends Error {}

export function repositoryHistoryCliHelp(): string {
  return [
    "Usage: codeinspectus history scan REPOSITORY --from REV --to REV --since UTC --until UTC --max-commits N [options]",
    "",
    "Repository history requires explicit revision, date, and commit-count bounds and is otherwise disabled.",
    "Snapshots are materialized read-only and historical findings never imply a secret remains active.",
    "",
    "  --from <revision>          Exact inclusive ancestor revision.",
    "  --to <revision>            Exact inclusive selected-head revision.",
    "  --since <UTC timestamp>    Inclusive RFC 3339 UTC lower date bound.",
    "  --until <UTC timestamp>    Inclusive RFC 3339 UTC upper date bound.",
    `  --max-commits <1-${REPOSITORY_HISTORY_MAX_COMMITS}> Explicit newest-window commit cap.`,
    "  --manifest <file>          New manifest outside the repository.",
    "  --scanner <name[,name]>    Scanner classes (repeatable; default all).",
    `  --max-findings <n>         Per-commit finding cap (default ${DEFAULT_MAX_FINDINGS}).`,
    "  --no-compliance            Omit per-commit compliance rendering work.",
    "  --format <text|json>       Summary output (default text).",
    "",
  ].join("\n");
}

function takeValue(argv: readonly string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new RepositoryHistoryUsageError(`${option} requires a value.`);
  return value;
}

function boundedInteger(value: string, option: string, maximum: number): number {
  if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > maximum || !Number.isSafeInteger(Number(value))) {
    throw new RepositoryHistoryUsageError(`${option} must be an integer from 1 to ${maximum}.`);
  }
  return Number(value);
}

function parseScanners(value: string): ScannerKind[] {
  const scanners = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (!scanners.length || scanners.some((scanner) => !ALL_SCANNERS.includes(scanner as ScannerKind))) {
    throw new RepositoryHistoryUsageError(`--scanner must contain: ${ALL_SCANNERS.join(", ")}.`);
  }
  return scanners as ScannerKind[];
}

export async function runRepositoryHistoryCli(
  argv: readonly string[],
  io: RepositoryHistoryCliIo,
  dependencies: RepositoryHistoryCliDependencies = { run: runRepositoryHistoryScan },
): Promise<number> {
  try {
    if (!argv[0] || argv[0] === "--help" || argv[0] === "-h") { io.stdout(repositoryHistoryCliHelp()); return argv[0] ? 0 : 2; }
    if (argv[0] !== "scan") throw new RepositoryHistoryUsageError(`Unknown history subcommand '${argv[0]}'.`);
    let repository: string | undefined; let from: string | undefined; let to: string | undefined;
    let since: string | undefined; let until: string | undefined; let maxCommits: number | undefined;
    let manifestPath: string | undefined; let maxFindings = DEFAULT_MAX_FINDINGS; let includeCompliance = true;
    let format: "text" | "json" = "text"; const scanners: ScannerKind[] = [];
    for (let index = 1; index < argv.length; index++) {
      const arg = argv[index]!;
      if (arg === "--from") { from = takeValue(argv, index, arg); index++; }
      else if (arg === "--to") { to = takeValue(argv, index, arg); index++; }
      else if (arg === "--since") { since = takeValue(argv, index, arg); index++; }
      else if (arg === "--until") { until = takeValue(argv, index, arg); index++; }
      else if (arg === "--max-commits") { maxCommits = boundedInteger(takeValue(argv, index, arg), arg, REPOSITORY_HISTORY_MAX_COMMITS); index++; }
      else if (arg === "--manifest") { manifestPath = takeValue(argv, index, arg); index++; }
      else if (arg === "--scanner" || arg === "--scanners") { scanners.push(...parseScanners(takeValue(argv, index, arg))); index++; }
      else if (arg === "--max-findings") { maxFindings = boundedInteger(takeValue(argv, index, arg), arg, Number.MAX_SAFE_INTEGER); index++; }
      else if (arg === "--no-compliance") includeCompliance = false;
      else if (arg === "--format") { const value = takeValue(argv, index, arg); if (value !== "text" && value !== "json") throw new RepositoryHistoryUsageError("History --format must be text or json."); format = value; index++; }
      else if (arg.startsWith("-")) throw new RepositoryHistoryUsageError(`Unknown history option '${arg}'.`);
      else if (repository) throw new RepositoryHistoryUsageError("history scan accepts exactly one repository.");
      else repository = arg;
    }
    const missing = [["REPOSITORY", repository], ["--from", from], ["--to", to], ["--since", since], ["--until", until], ["--max-commits", maxCommits]]
      .filter(([, value]) => value === undefined).map(([name]) => name);
    if (missing.length) throw new RepositoryHistoryUsageError(`history scan requires explicit ${missing.join(", ")}.`);
    const controller = new AbortController(); let interrupted: 130 | 143 | undefined;
    const onInterrupt = (): void => { interrupted ??= 130; controller.abort(); terminateActiveEngineProcesses("SIGTERM"); };
    const onTerminate = (): void => { interrupted ??= 143; controller.abort(); terminateActiveEngineProcesses("SIGTERM"); };
    process.once("SIGINT", onInterrupt); process.once("SIGTERM", onTerminate);
    try {
      const result = await dependencies.run({ repository: repository!, from: from!, to: to!, since: since!, until: until!, maxCommits: maxCommits!,
        ...(manifestPath ? { manifestPath } : {}), ...(scanners.length ? { scanners: [...new Set(scanners)] } : {}), maxFindings, includeCompliance, signal: controller.signal });
      if (format === "json") io.stdout(`${JSON.stringify({ ...result.manifest, manifest_path: result.manifest_path }, null, 2)}\n`);
      else io.stdout([
        `CodeInspectus repository history ${result.manifest.run_id}: coverage=${result.manifest.aggregate.coverage}`,
        `Commits: ${result.manifest.aggregate.complete} complete, ${result.manifest.aggregate.partial} partial, ${result.manifest.aggregate.unknown} unknown, ${result.manifest.aggregate.failed} failed, ${result.manifest.aggregate.cancelled} cancelled`,
        `Findings across snapshots: ${result.manifest.aggregate.finding_count}`,
        `Manifest: ${result.manifest_path}`,
        "Historical findings are snapshot evidence only; they do not prove current or live exposure.", "",
      ].join("\n"));
      if (interrupted) return interrupted;
      if (result.manifest.aggregate.coverage !== "complete") io.stderr(`CodeInspectus history: aggregate coverage is ${result.manifest.aggregate.coverage}; bounded or incomplete history cannot pass.\n`);
      return result.manifest.aggregate.coverage === "complete" ? 0 : 2;
    } finally {
      process.removeListener("SIGINT", onInterrupt); process.removeListener("SIGTERM", onTerminate);
    }
  } catch (error) {
    io.stderr(`CodeInspectus history: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}
