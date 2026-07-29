import { DEFAULT_MAX_FINDINGS } from "../config.js";
import { terminateActiveEngineProcesses } from "../engines/exec.js";
import { ALL_SCANNERS } from "../preflight.js";
import type { ScannerKind } from "../types.js";
import {
  BULK_DEFAULT_CONCURRENCY,
  BULK_DEFAULT_MAX_ATTEMPTS,
  BULK_DEFAULT_MAX_REPOSITORIES,
  BULK_MAX_CONCURRENCY,
  BULK_MAX_REPOSITORIES,
  runBulkScan,
  type BulkRunResult,
  type BulkScanOptions,
} from "./index.js";

export interface BulkCliIo { stdout(text: string): void; stderr(text: string): void }
export interface BulkCliDependencies { run(options: BulkScanOptions): Promise<BulkRunResult> }
class BulkUsageError extends Error {}

export function bulkCliHelp(): string {
  return [
    "Usage: codeinspectus bulk scan PARENT [options]",
    "",
    "PARENT must contain already-existing Git repositories as immediate child directories.",
    "No repository is cloned and no GitHub account or network discovery is used.",
    "",
    `  --concurrency <1-${BULK_MAX_CONCURRENCY}>       Concurrent repositories (default ${BULK_DEFAULT_CONCURRENCY}).`,
    `  --max-repositories <1-${BULK_MAX_REPOSITORIES}> Discovery bound (default ${BULK_DEFAULT_MAX_REPOSITORIES}).`,
    "  --max-attempts <1-5>       Resume attempts per repository (default 2).",
    "  --manifest <file>          Explicit manifest outside PARENT; reuse the same file to resume.",
    "  --scanner <name[,name]>    Scanner classes (repeatable; default all).",
    `  --max-findings <n>         Per-repository display cap retained in scan config (default ${DEFAULT_MAX_FINDINGS}).`,
    "  --no-compliance            Omit per-scan compliance rendering work.",
    "  --format <text|json>       Summary output (default text).",
    "",
  ].join("\n");
}

function takeValue(argv: readonly string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new BulkUsageError(`${option} requires a value.`);
  return value;
}

function boundedInteger(value: string, option: string, minimum: number, maximum: number): number {
  if (!/^\d+$/.test(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new BulkUsageError(`${option} must be an integer from ${minimum} to ${maximum}.`);
  }
  return Number(value);
}

function parseScanners(value: string): ScannerKind[] {
  const scanners = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (!scanners.length || scanners.some((scanner) => !ALL_SCANNERS.includes(scanner as ScannerKind))) {
    throw new BulkUsageError(`--scanner must contain: ${ALL_SCANNERS.join(", ")}.`);
  }
  return scanners as ScannerKind[];
}

export async function runBulkCli(
  argv: readonly string[],
  io: BulkCliIo,
  dependencies: BulkCliDependencies = { run: runBulkScan },
): Promise<number> {
  try {
    if (!argv[0] || argv[0] === "--help" || argv[0] === "-h") {
      io.stdout(bulkCliHelp());
      return argv[0] ? 0 : 2;
    }
    if (argv[0] !== "scan") throw new BulkUsageError(`Unknown bulk subcommand '${argv[0]}'.`);
    let parent: string | undefined;
    let manifestPath: string | undefined;
    let concurrency = BULK_DEFAULT_CONCURRENCY;
    let maxRepositories = BULK_DEFAULT_MAX_REPOSITORIES;
    let maxAttempts = BULK_DEFAULT_MAX_ATTEMPTS;
    let maxFindings = DEFAULT_MAX_FINDINGS;
    let includeCompliance = true;
    let format: "text" | "json" = "text";
    const scanners: ScannerKind[] = [];
    for (let index = 1; index < argv.length; index++) {
      const arg = argv[index]!;
      if (arg === "--concurrency") { concurrency = boundedInteger(takeValue(argv, index, arg), arg, 1, BULK_MAX_CONCURRENCY); index++; }
      else if (arg === "--max-repositories") { maxRepositories = boundedInteger(takeValue(argv, index, arg), arg, 1, BULK_MAX_REPOSITORIES); index++; }
      else if (arg === "--max-attempts") { maxAttempts = boundedInteger(takeValue(argv, index, arg), arg, 1, 5); index++; }
      else if (arg === "--max-findings") { maxFindings = boundedInteger(takeValue(argv, index, arg), arg, 1, Number.MAX_SAFE_INTEGER); index++; }
      else if (arg === "--manifest") { manifestPath = takeValue(argv, index, arg); index++; }
      else if (arg === "--scanner" || arg === "--scanners") { scanners.push(...parseScanners(takeValue(argv, index, arg))); index++; }
      else if (arg === "--format") {
        const value = takeValue(argv, index, arg);
        if (value !== "text" && value !== "json") throw new BulkUsageError("Bulk --format must be text or json.");
        format = value; index++;
      } else if (arg === "--no-compliance") includeCompliance = false;
      else if (arg.startsWith("-")) throw new BulkUsageError(`Unknown bulk option '${arg}'.`);
      else if (parent) throw new BulkUsageError("bulk scan accepts exactly one parent directory.");
      else parent = arg;
    }
    if (!parent) throw new BulkUsageError("bulk scan requires a parent directory.");
    const controller = new AbortController();
    let interrupted: 130 | 143 | undefined;
    const onInterrupt = (): void => { interrupted ??= 130; controller.abort(); terminateActiveEngineProcesses("SIGTERM"); };
    const onTerminate = (): void => { interrupted ??= 143; controller.abort(); terminateActiveEngineProcesses("SIGTERM"); };
    process.once("SIGINT", onInterrupt);
    process.once("SIGTERM", onTerminate);
    try {
      const result = await dependencies.run({
        parent,
        ...(manifestPath ? { manifestPath } : {}),
        concurrency,
        maxRepositories,
        maxAttempts,
        ...(scanners.length ? { scanners: [...new Set(scanners)] } : {}),
        maxFindings,
        includeCompliance,
        signal: controller.signal,
      });
      if (format === "json") io.stdout(`${JSON.stringify({ ...result.manifest, manifest_path: result.manifest_path, resumed: result.resumed }, null, 2)}\n`);
      else io.stdout([
        `CodeInspectus bulk ${result.manifest.run_id}: coverage=${result.manifest.aggregate.coverage}`,
        `Repositories: ${result.manifest.aggregate.complete} complete, ${result.manifest.aggregate.partial} partial, ${result.manifest.aggregate.unknown} unknown, ${result.manifest.aggregate.failed} failed, ${result.manifest.aggregate.cancelled} cancelled, ${result.manifest.aggregate.pending} pending`,
        `Findings: ${result.manifest.aggregate.finding_count}`,
        `Manifest: ${result.manifest_path}${result.resumed ? " (resumed)" : ""}`,
        "",
      ].join("\n"));
      if (interrupted) return interrupted;
      if (result.manifest.aggregate.coverage !== "complete") io.stderr(`CodeInspectus bulk: aggregate coverage is ${result.manifest.aggregate.coverage}; every repository must complete before the bulk result can pass.\n`);
      return result.manifest.aggregate.coverage === "complete" ? 0 : 2;
    } finally {
      process.removeListener("SIGINT", onInterrupt);
      process.removeListener("SIGTERM", onTerminate);
    }
  } catch (error) {
    io.stderr(`CodeInspectus bulk: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}
