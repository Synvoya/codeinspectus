import { randomUUID } from "node:crypto";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { DEFAULT_MAX_FINDINGS, SERVER_VERSION } from "./config.js";
import { terminateActiveEngineProcesses } from "./engines/exec.js";
import { inspectOutputDirectory, inspectTargetPath, outputContainmentRoot, requireSafeScanTarget } from "./path-safety.js";
import {
  ALL_SCANNERS,
  runPreflight,
  summarizePreflight,
  type CliOutputFormat,
  type CliScanConfiguration,
  type PreflightResult,
} from "./preflight.js";
import { runScan } from "./scan.js";
import { runGitScopedScan, type GitScopeRequest } from "./git-scope.js";
import { createExport, loadStoredScanForExport, type ExportFormat } from "./export/index.js";
import { writeExportFile } from "./export/writer.js";
import { summarizeScan } from "./summarize.js";
import type { ScanResult, ScannerKind, Severity } from "./types.js";
import type { StoredScanResult } from "./store.js";
import { scanIdSchema } from "./schemas.js";
import { evaluateCiPolicy } from "./ci-policy.js";
import { createJsonExport } from "./export/model.js";
import { createSarifExport } from "./export/sarif.js";
import { runHistoryCli } from "./history-cli.js";
import { runTriageCli } from "./triage-cli.js";
import { compareAgainstBaseline, evaluateNewFindingPolicy, type BaselineComparison } from "./baseline.js";
import { inspectTriageStore, matchingTriageAnnotations, type TriageSnapshot } from "./triage.js";
import { runBundleCli } from "./bundle/cli.js";
import { createCsvExport } from "./export/csv.js";
import { runBulkCli } from "./bulk/cli.js";
import { runRepositoryHistoryCli } from "./repository-history/cli.js";
import { runIssuePayloadCli } from "./issue-payload/cli.js";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const FORMATS: readonly CliOutputFormat[] = ["text", "json", "sarif", "csv"];

export class CliUsageError extends Error {
  readonly exitCode = 2;
}

export interface ParsedCliCommand {
  command: "scan" | "preflight" | "export";
  target: string;
  configuration: CliScanConfiguration;
}

export interface CliIo {
  stdout(text: string): void;
  stderr(text: string): void;
}

export interface CliDependencies {
  preflight(target: string, config: CliScanConfiguration): Promise<PreflightResult>;
  scan(input: {
    path: string;
    severity_threshold?: Severity;
    scanners?: ScannerKind[];
    max_findings?: number;
    include_compliance?: boolean;
    git_scope?: GitScopeRequest;
  }): Promise<ScanResult>;
  loadScan(scanId: string): Promise<StoredScanResult>;
  inspectTriage?(scan: StoredScanResult): Promise<TriageSnapshot>;
}

const DEFAULT_IO: CliIo = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
};

const DEFAULT_DEPS: CliDependencies = {
  preflight: runPreflight,
  scan: async (input) => input.git_scope
    ? runGitScopedScan(input, input.git_scope)
    : runScan(input),
  loadScan: loadStoredScanForExport,
  inspectTriage: inspectTriageStore,
};

function takeValue(argv: readonly string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new CliUsageError(`${option} requires a value.`);
  return value;
}

function parseScanners(value: string): ScannerKind[] {
  const scanners = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (!scanners.length) throw new CliUsageError("--scanner requires at least one scanner name.");
  for (const scanner of scanners) {
    if (!ALL_SCANNERS.includes(scanner as ScannerKind)) {
      throw new CliUsageError(`Unknown scanner '${scanner}'. Expected one of: ${ALL_SCANNERS.join(", ")}.`);
    }
  }
  return scanners as ScannerKind[];
}

export function parseCliCommand(argv: readonly string[]): ParsedCliCommand {
  const command = argv[0];
  if (command !== "scan" && command !== "preflight" && command !== "export") {
    throw new CliUsageError(`Unknown subcommand '${command ?? ""}'. See 'codeinspectus --help'.`);
  }

  let target: string | undefined;
  const scanners: ScannerKind[] = [];
  let severity: Severity | undefined;
  let maxFindings: number | undefined;
  let outputDirectory: string | undefined;
  let outputFile: string | undefined;
  let outputFormat: CliOutputFormat | undefined;
  let allowOutputInTarget = false;
  let includeCompliance = true;
  let failOnSeverity: Severity | undefined;
  let baselineScanId: string | undefined;
  let failOnNewSeverity: Severity | undefined;
  let diffBase: string | undefined;
  let headRevision: string | undefined;
  let workingTree = false;
  let workingTreeBase: string | undefined;

  for (let index = 1; index < argv.length; index++) {
    const arg = argv[index]!;
    if (arg === "--scanner" || arg === "--scanners") {
      scanners.push(...parseScanners(takeValue(argv, index, arg)));
      index++;
    } else if (arg === "--severity" || arg === "--severity-threshold") {
      const value = takeValue(argv, index, arg);
      if (!SEVERITIES.includes(value as Severity)) {
        throw new CliUsageError(`Invalid severity '${value}'. Expected one of: ${SEVERITIES.join(", ")}.`);
      }
      severity = value as Severity;
      index++;
    } else if (arg === "--max-findings") {
      const value = takeValue(argv, index, arg);
      if (!/^\d+$/.test(value) || Number(value) < 1 || !Number.isSafeInteger(Number(value))) {
        throw new CliUsageError("--max-findings must be a positive safe integer.");
      }
      maxFindings = Number(value);
      index++;
    } else if (arg === "--fail-on-severity") {
      const value = takeValue(argv, index, arg);
      if (!SEVERITIES.includes(value as Severity)) {
        throw new CliUsageError(`Invalid fail-on severity '${value}'. Expected one of: ${SEVERITIES.join(", ")}.`);
      }
      failOnSeverity = value as Severity;
      index++;
    } else if (arg === "--baseline") {
      const value = takeValue(argv, index, arg);
      const parsed = scanIdSchema.safeParse(value);
      if (!parsed.success) throw new CliUsageError(parsed.error.issues[0]?.message ?? "Invalid baseline scan ID.");
      baselineScanId = parsed.data; index++;
    } else if (arg === "--fail-on-new-severity") {
      const value = takeValue(argv, index, arg);
      if (!SEVERITIES.includes(value as Severity)) throw new CliUsageError(`Invalid fail-on-new severity '${value}'.`);
      failOnNewSeverity = value as Severity; index++;
    } else if (arg === "--diff") {
      diffBase = takeValue(argv, index, arg); index++;
    } else if (arg === "--head") {
      headRevision = takeValue(argv, index, arg); index++;
    } else if (arg === "--working-tree") {
      workingTree = true;
    } else if (arg === "--base") {
      workingTreeBase = takeValue(argv, index, arg); index++;
    } else if (arg === "--output-dir") {
      outputDirectory = takeValue(argv, index, arg);
      index++;
    } else if (arg === "--output") {
      outputFile = takeValue(argv, index, arg);
      index++;
    } else if (arg === "--format" || arg === "--output-format") {
      const value = takeValue(argv, index, arg);
      if (!FORMATS.includes(value as CliOutputFormat)) {
        throw new CliUsageError(`Invalid output format '${value}'. Expected one of: ${FORMATS.join(", ")}.`);
      }
      outputFormat = value as CliOutputFormat;
      index++;
    } else if (arg === "--allow-output-in-target") {
      allowOutputInTarget = true;
    } else if (arg === "--no-compliance") {
      includeCompliance = false;
    } else if (arg.startsWith("-")) {
      throw new CliUsageError(`Unknown option '${arg}'. See 'codeinspectus ${command} --help'.`);
    } else if (target) {
      throw new CliUsageError(`Unexpected positional argument '${arg}'. Exactly one scan target is allowed.`);
    } else {
      target = arg;
    }
  }

  if (!target) throw new CliUsageError(command === "export" ? "export requires a scan_id." : `${command} requires a file or directory target.`);
  if (outputDirectory && outputFile) throw new CliUsageError("Use either --output <file> or --output-dir <directory>, not both.");
  if (command === "export") {
    if (!outputFormat || outputFormat === "text") throw new CliUsageError("export requires --format json, sarif, or csv.");
    if (scanners.length || severity || maxFindings || outputDirectory || includeCompliance === false || failOnSeverity || baselineScanId || failOnNewSeverity) {
      throw new CliUsageError("export accepts only a scan_id, --format, --output, and --allow-output-in-target.");
    }
  }
  if (command === "preflight" && (outputFormat === "sarif" || outputFormat === "csv")) {
    throw new CliUsageError("preflight supports --format text or --format json; SARIF and CSV are scan/export formats.");
  }
  if (command === "preflight" && failOnSeverity) {
    throw new CliUsageError("--fail-on-severity is available only for scan enforcement.");
  }
  if (command !== "scan" && (baselineScanId || failOnNewSeverity)) throw new CliUsageError("Baseline options are available only for scan.");
  if (command !== "scan" && (diffBase || headRevision || workingTree || workingTreeBase)) throw new CliUsageError("Git scope options are available only for scan.");
  if (diffBase && workingTree) throw new CliUsageError("Use either --diff/--head or --working-tree/--base, not both.");
  if (diffBase && !headRevision) throw new CliUsageError("--diff requires --head REVISION.");
  if (headRevision && !diffBase) throw new CliUsageError("--head requires --diff REVISION.");
  if (workingTree && !workingTreeBase) throw new CliUsageError("--working-tree requires --base REVISION.");
  if (workingTreeBase && !workingTree) throw new CliUsageError("--base requires --working-tree.");
  if (failOnNewSeverity && !baselineScanId) throw new CliUsageError("--fail-on-new-severity requires --baseline SCAN_ID.");
  if (failOnSeverity && failOnNewSeverity) throw new CliUsageError("Use either --fail-on-severity or --fail-on-new-severity, not both.");
  return {
    command,
    target,
    configuration: {
      ...(scanners.length ? { scanners: [...new Set(scanners)] } : {}),
      ...(severity ? { severity_threshold: severity } : {}),
      ...(maxFindings ? { max_findings: maxFindings } : {}),
      ...(outputDirectory ? { output_directory: outputDirectory } : {}),
      ...(outputFile ? { output_file: outputFile } : {}),
      ...(outputFormat ? { output_format: outputFormat } : {}),
      ...(allowOutputInTarget ? { allow_output_in_target: true } : {}),
      ...(failOnSeverity ? { fail_on_severity: failOnSeverity } : {}),
      ...(baselineScanId ? { baseline_scan_id: baselineScanId } : {}),
      ...(failOnNewSeverity ? { fail_on_new_severity: failOnNewSeverity } : {}),
      ...(diffBase ? { git_scope: { mode: "commit_diff" as const, base: diffBase, head: headRevision! } }
        : workingTree ? { git_scope: { mode: "working_tree" as const, base: workingTreeBase! } } : {}),
      include_compliance: includeCompliance,
    },
  };
}

export function cliHelp(command?: "scan" | "preflight" | "export"): string {
  const common = [
    "  --scanner <name[,name]>       Select sast, secret, vuln, misconfig, license, or ai (repeatable).",
    "  --severity <level>            Display findings at or above critical, high, medium, low, or info.",
    "  --max-findings <n>            Maximum displayed findings (default: 200).",
    "  --fail-on-severity <level>    Enforcement mode: exit 1 when a canonical finding meets this level.",
    "  --baseline <scan-id>          Compare the complete raw scan with a compatible stored baseline.",
    "  --fail-on-new-severity <level> Exit 1 only for proven new findings at or above this level.",
    "  --diff <revision>             Scan changes from this exact base commit (requires --head).",
    "  --head <revision>             Exact head commit for --diff; the snapshot is isolated and read-only.",
    "  --working-tree                Scan staged, unstaged, and non-ignored untracked changes.",
    "  --base <revision>             Base commit for --working-tree.",
    "  --format <text|json|sarif|csv> Output format.",
    "  --output <file>               Also write to this exact file atomically.",
    "  --output-dir <path>           Also write the result to this explicit directory.",
    "  --allow-output-in-target      Approve an --output-dir inside the scanned repository.",
    "  --no-compliance               Omit the compliance overview from scan output.",
  ];
  if (command) {
    if (command === "export") return [
      "Usage: codeinspectus export <scan-id> --format <json|sarif|csv> [--output <file>]",
      "",
      "  --format <json|sarif|csv>    Export the complete persisted canonical finding set.",
      "  --output <file>               Write this explicitly named artifact atomically.",
      "",
    ].join("\n");
    return [
      `Usage: codeinspectus ${command} <file-or-directory> [options]`,
      "",
      ...common,
      "",
    ].join("\n");
  }
  return [
    "CodeInspectus, by Synvoya — local-first security MCP server and CLI.",
    "",
    "Usage:",
    "  codeinspectus                              Guided setup in a terminal; MCP server over piped stdio.",
    "  codeinspectus setup [options]              Review and approve external engine downloads.",
    "  codeinspectus scan <target> [options]      Scan a local file or directory.",
    "  codeinspectus preflight <target> [options] Inspect readiness without scanning or writing.",
    "  codeinspectus export <scan-id> --format <json|sarif|csv> [options] Export a stored canonical scan.",
    "  codeinspectus scans <list|show|rerun|compare>   Inspect and compare local scan history.",
    "  codeinspectus triage <add|list|show|update|delete> Manage local finding annotations.",
    "  codeinspectus bundle <create|verify|export|compare> Create and consume sealed scan evidence.",
    "  codeinspectus bulk scan <parent> [options] Scan bounded existing local repositories.",
    "  codeinspectus history scan <repository> [bounds] Scan an explicit bounded commit range.",
    "  codeinspectus issue export <scan-id> <finding-id> [options] Generate review-only tracker JSON.",
    "  codeinspectus repair-engines [options]     Explicitly repair unhealthy engine/DB state.",
    "  codeinspectus install-engines [options]    Backward-compatible repair alias.",
    "  codeinspectus pin-engines [options]        Maintainer-only engine pin generation.",
    "  codeinspectus verify-engines               Verify installed engine hashes.",
    "  codeinspectus --version                    Print version.",
    "",
    "Scan/preflight options:",
    ...common,
    "",
    "Scans are offline. Preflight never downloads, repairs, authenticates, scans, or writes.",
    "Setup options: --status, --all, --select opengrep,gitleaks,trivy, --reset.",
    "No account. No telemetry.",
    "",
  ].join("\n");
}

export function signalExitCode(signal: "SIGINT" | "SIGTERM"): 130 | 143 {
  return signal === "SIGINT" ? 130 : 143;
}

export interface SignalHost {
  once(event: "SIGINT" | "SIGTERM", listener: () => void): unknown;
  removeListener(event: "SIGINT" | "SIGTERM", listener: () => void): unknown;
  exit(code: number): never;
}

export function installCliSignalHandlers(host: SignalHost = process): () => void {
  const onInterrupt = (): void => {
    terminateActiveEngineProcesses("SIGTERM");
    host.exit(signalExitCode("SIGINT"));
  };
  const onTerminate = (): void => {
    terminateActiveEngineProcesses("SIGTERM");
    host.exit(signalExitCode("SIGTERM"));
  };
  host.once("SIGINT", onInterrupt);
  host.once("SIGTERM", onTerminate);
  return () => {
    host.removeListener("SIGINT", onInterrupt);
    host.removeListener("SIGTERM", onTerminate);
  };
}

async function writeAtomic(path: string, content: string): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, content, { encoding: "utf8", flag: "wx" });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

function renderTextScan(result: ScanResult, config: CliScanConfiguration): string {
  const effectiveConfiguration = {
    scanners: config.scanners ?? ALL_SCANNERS,
    severity_threshold: config.severity_threshold ?? "info",
    max_findings: config.max_findings ?? DEFAULT_MAX_FINDINGS,
    output_format: "text" as const,
    ...(config.output_directory ? { output_directory: config.output_directory } : {}),
    allow_output_in_target: config.allow_output_in_target ?? false,
    include_compliance: config.include_compliance ?? true,
    policy_mode: config.fail_on_severity ? "enforcement" : "report_only",
  };
  return (
    `CodeInspectus CLI v${SERVER_VERSION}\n` +
    `Configuration: scanners=${effectiveConfiguration.scanners.join(",")} | ` +
    `severity=${effectiveConfiguration.severity_threshold} | max_findings=${effectiveConfiguration.max_findings} | ` +
    `format=text | policy=${effectiveConfiguration.policy_mode}${config.fail_on_severity ? `:${config.fail_on_severity}` : ""}${effectiveConfiguration.output_directory ? ` | output=${effectiveConfiguration.output_directory}` : ""}\n` +
    `${summarizeScan(result)}\n`
  );
}

async function writeRequestedOutput(
  rendered: string,
  format: CliOutputFormat,
  target: string,
  config: CliScanConfiguration,
): Promise<void> {
  if (!config.output_file && !config.output_directory) return;
  const safeTarget = await requireSafeScanTarget(target);
  const boundary = outputContainmentRoot(safeTarget);
  if (config.output_file) {
    try {
      // Naming one exact artifact is explicit approval for that file, including when it is
      // placed in the scanned worktree (the documented `--output results.sarif` contract).
      await writeExportFile(config.output_file, rendered, boundary, true);
    } catch (error) {
      throw new CliUsageError(error instanceof Error ? error.message : String(error));
    }
  }
  if (!config.output_directory) return;
  let output = await inspectOutputDirectory(
    config.output_directory,
    boundary,
    config.allow_output_in_target ?? false,
  );
  if (!output.safe || !output.resolved_path) throw new CliUsageError(output.error ?? "Unsafe output directory.");
  if (!output.exists) {
    await mkdir(output.resolved_path, { recursive: true });
    output = await inspectOutputDirectory(
      config.output_directory,
      outputContainmentRoot(safeTarget),
      config.allow_output_in_target ?? false,
    );
    if (!output.safe || !output.resolved_path || !output.exists) {
      throw new CliUsageError(output.error ?? "Output directory could not be created safely.");
    }
  }
  const filename = format === "json" ? "scan-result.json" : format === "sarif" ? "results.sarif" : format === "csv" ? "findings.csv" : "scan-report.txt";
  await writeAtomic(join(output.resolved_path, filename), rendered);
}

async function storedTargetBoundary(scan: StoredScanResult): Promise<string> {
  const target = await inspectTargetPath(scan.target);
  return outputContainmentRoot(target) ?? dirname(resolve(scan.target));
}

function renderExport(scan: StoredScanResult, format: ExportFormat): string {
  const rendered = createExport(scan, format);
  return typeof rendered === "string" ? rendered : `${JSON.stringify(rendered, null, 2)}\n`;
}

function renderPolicyDocument(document: ReturnType<typeof createJsonExport>, format: ExportFormat): string {
  if (format === "csv") return createCsvExport(document);
  return `${JSON.stringify(format === "sarif" ? createSarifExport(document) : document, null, 2)}\n`;
}

function baselineText(comparison: BaselineComparison, matchedTriageCount: number): string {
  return `\nBaseline ${comparison.baseline_scan_id}: ${comparison.summary.New} new, ${comparison.summary.Existing} existing, ${comparison.summary["Not rechecked / unknown"]} unknown | coverage=${comparison.coverage}\n` +
    `Triage context: ${matchedTriageCount} matched annotation(s); raw findings unchanged.\n`;
}

function triageText(scan: StoredScanResult, triage: TriageSnapshot): string {
  const matches = matchingTriageAnnotations(scan, triage);
  const partial = !triage.available || triage.truncated || triage.corrupt_record_count > 0;
  const context = matches.length ? `\nTriage annotations (context only; raw findings unchanged):\n${matches.map(({ finding_id, annotation }) =>
    `  ${finding_id}: ${annotation.state} — ${annotation.reason}${annotation.actor ? ` (${annotation.actor})` : ""}`).join("\n")}\n` : "";
  return context + (partial ? "\nTriage warning: annotation context is partial or unavailable; raw findings and scan policy are unchanged.\n" : "");
}

export async function runCli(
  argv: readonly string[],
  io: CliIo = DEFAULT_IO,
  dependencies: CliDependencies = DEFAULT_DEPS,
): Promise<number> {
  try {
    const commandName = argv[0];
    if (commandName === "scans") {
      // `scans rerun` executes the same external engines as `scan`; reuse the established
      // child-process cleanup and 130/143 exit contract. Installing it for read-only history
      // actions as well keeps the subcommand family behavior consistent and is harmless.
      const cleanupSignals = installCliSignalHandlers();
      try {
        return await runHistoryCli(argv.slice(1), io);
      } finally {
        cleanupSignals();
      }
    }
    if (commandName === "triage") return runTriageCli(argv.slice(1), io);
    if (commandName === "bundle") return runBundleCli(argv.slice(1), io);
    if (commandName === "bulk") return runBulkCli(argv.slice(1), io);
    if (commandName === "history") return runRepositoryHistoryCli(argv.slice(1), io);
    if (commandName === "issue") return runIssuePayloadCli(argv.slice(1), io);
    if ((commandName === "scan" || commandName === "preflight" || commandName === "export") && argv.includes("--help")) {
      io.stdout(cliHelp(commandName));
      return 0;
    }
    const parsed = parseCliCommand(argv);
    const format = parsed.configuration.output_format ?? "text";
    if (parsed.command === "export") {
      const validScanId = scanIdSchema.safeParse(parsed.target);
      if (!validScanId.success) throw new CliUsageError(validScanId.error.issues[0]?.message ?? "Invalid scan_id.");
      const scan = await dependencies.loadScan(parsed.target);
      if (!scan || scan.scan_id !== parsed.target) {
        throw new CliUsageError(`No stored CodeInspectus scan found with id '${parsed.target}'.`);
      }
      const rendered = renderExport(scan, format as ExportFormat);
      if (parsed.configuration.output_file) {
        try {
          await writeExportFile(
            parsed.configuration.output_file,
            rendered,
            await storedTargetBoundary(scan),
            true,
          );
        } catch (error) {
          throw new CliUsageError(error instanceof Error ? error.message : String(error));
        }
      }
      io.stdout(rendered);
      return 0;
    }
    const preflight = await dependencies.preflight(parsed.target, parsed.configuration);
    if (parsed.command === "preflight") {
      io.stdout(format === "json" ? `${JSON.stringify(preflight, null, 2)}\n` : summarizePreflight(preflight));
      return preflight.ready ? 0 : 2;
    }
    if (preflight.errors.length) {
      throw new CliUsageError(preflight.errors.join(" "));
    }

    const cleanupSignals = installCliSignalHandlers();
    try {
      const result = await dependencies.scan({
        path: parsed.target,
        ...(parsed.configuration.severity_threshold
          ? { severity_threshold: parsed.configuration.severity_threshold }
          : {}),
        ...(parsed.configuration.scanners ? { scanners: parsed.configuration.scanners } : {}),
        ...(parsed.configuration.max_findings ? { max_findings: parsed.configuration.max_findings } : {}),
        include_compliance: parsed.configuration.include_compliance ?? true,
        ...(parsed.configuration.git_scope ? { git_scope: parsed.configuration.git_scope } : {}),
      });
      const stored = await dependencies.loadScan(result.scan_id);
      let baseline: BaselineComparison | undefined;
      if (parsed.configuration.baseline_scan_id) {
        const baselineScan = await dependencies.loadScan(parsed.configuration.baseline_scan_id);
        if (!baselineScan || baselineScan.scan_id !== parsed.configuration.baseline_scan_id) throw new CliUsageError(`No stored CodeInspectus scan found with id '${parsed.configuration.baseline_scan_id}'.`);
        baseline = compareAgainstBaseline(baselineScan, stored);
      }
      const triage = await (dependencies.inspectTriage ?? inspectTriageStore)(stored);
      const policyDocument = createJsonExport(stored, {
        ...(parsed.configuration.fail_on_severity
          ? { failOnSeverity: parsed.configuration.fail_on_severity }
          : {}),
        ...(parsed.configuration.fail_on_new_severity ? { failOnNewSeverity: parsed.configuration.fail_on_new_severity } : {}),
        ...(baseline ? { baseline } : {}),
        triage,
      });
      const rendered = format === "text"
        ? renderTextScan(result, parsed.configuration) + triageText(stored, triage) + (baseline ? baselineText(baseline, matchingTriageAnnotations(stored, triage).length) : "")
        : renderPolicyDocument(policyDocument, format);
      await writeRequestedOutput(rendered, format, parsed.target, parsed.configuration);
      io.stdout(rendered);
      const policy = baseline
        ? parsed.configuration.fail_on_severity
          ? (baseline.partial ? { exit_code: 2 as const, reason: "Baseline comparison is partial or unknown." } : evaluateCiPolicy(policyDocument, parsed.configuration.fail_on_severity))
          : evaluateNewFindingPolicy(baseline, parsed.configuration.fail_on_new_severity)
        : evaluateCiPolicy(policyDocument, parsed.configuration.fail_on_severity);
      if (policy.exit_code !== 0) io.stderr(`CodeInspectus policy: ${policy.reason}\n`);
      return policy.exit_code;
    } finally {
      cleanupSignals();
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    io.stderr(`CodeInspectus: ${message}\n`);
    return error instanceof CliUsageError ? error.exitCode : 2;
  }
}
