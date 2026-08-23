import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { BaselineComparison } from "../baseline.js";
import type { BundleManifest } from "../bundle/schemas.js";
import type { BulkManifest } from "../bulk/schemas.js";
import type { RepositoryHistoryManifest } from "../repository-history/schemas.js";
import type { DestinationVisibility, IssueAdapter, IssuePayload } from "../issue-payload/schemas.js";
import type { AggregateCoverage, CoverageEvidence, JsonExport, SarifExport } from "../export/schemas.js";
import type { HistoryComparisonResult, HistoryListEntry, HistoryListResult, HistoryScanStatus } from "../scan-history.js";
import type { TriageAnnotation, TriageEvent, TriageState } from "../triage.js";
import type { Finding, ScannerKind, Severity } from "../types.js";
import type {
  RepositoryArtifact,
  RepositoryArtifactConfidence,
  RepositoryArtifactState,
  RepositoryTrustCapability,
  RepositoryTrustChanges,
  RepositoryTrustDocument,
} from "../repository-trust/schemas.js";

export const SDK_API_VERSION = "3.1.0" as const;
export const SDK_COMPATIBILITY = Object.freeze({
  cli_major: 3,
  export_schema: "3.0.0",
  repository_trust_schema: "1.0.0",
  history_schema: "1.0.0",
  baseline_schema: "1.0.0",
  triage_schema: "1.0.0",
  bundle_schema: "1.0.0",
  bulk_schema: "1.0.0",
  repository_history_schema: "1.0.0",
  issue_payload_schema: "1.0.0",
  csv_schema: "1.0.0",
});

export type FindingV3 = JsonExport["findings"][number];
export type CoverageV3 = JsonExport["coverage"];
export type AggregateCoverageV2 = AggregateCoverage;
export type CoverageEvidenceV2 = CoverageEvidence;
export type JsonExportV3 = JsonExport;
export type SarifExportV3 = SarifExport;
/** @deprecated Use FindingV3. Retained as a source-compatibility alias for SDK migrations. */
export type FindingV2 = FindingV3;
/** @deprecated Use CoverageV3. Retained as a source-compatibility alias for SDK migrations. */
export type CoverageV2 = CoverageV3;
/** @deprecated V3 commands return schema 3.0.0. Use JsonExportV3. */
export type JsonExportV2 = JsonExportV3;
/** @deprecated V3 commands return the V3 SARIF profile. Use SarifExportV3. */
export type SarifExportV2 = SarifExportV3;
export type RepositoryTrustDocumentV1 = RepositoryTrustDocument;
export type RepositoryArtifactV1 = RepositoryArtifact;
export type RepositoryTrustChangesV1 = RepositoryTrustChanges;
export type {
  RepositoryArtifactConfidence,
  RepositoryArtifactState,
  RepositoryTrustCapability,
};
export type HistoryListEntryV1 = HistoryListEntry;
export type HistoryListResultV1 = HistoryListResult;
export type HistoryComparisonV1 = Omit<HistoryComparisonResult, "items"> & {
  items: Array<Omit<HistoryComparisonResult["items"][number], "finding"> & { finding: FindingV2 }>;
};
export type BaselineComparisonV1 = BaselineComparison;
export type TriageEventV1 = TriageEvent;
export type TriageAnnotationV1 = TriageAnnotation;
export type BundleManifestV1 = BundleManifest;
export type BulkManifestV1 = BulkManifest;
export type RepositoryHistoryManifestV1 = RepositoryHistoryManifest;
export type IssuePayloadV1 = IssuePayload;
export type { IssueAdapter, DestinationVisibility };
export type { Finding, ScannerKind, Severity, HistoryScanStatus, TriageState };

export interface TriageListV1 {
  schema_version: "1.0.0";
  source_scan_id: string;
  scope: TriageEvent["scope"];
  inspection: {
    available: boolean;
    partial: boolean;
    truncated: boolean;
    candidate_files: number;
    inspected_files: number;
    bytes_read: number;
    corrupt_record_count: number;
    annotation_count: number;
    returned_annotation_count: number;
    limits: { max_events: number; max_store_bytes: number; max_event_bytes: number };
  };
  annotations: TriageAnnotation[];
}

export interface CodeInspectusCommandResult {
  args: readonly string[];
  exitCode: number;
  signal?: string;
  stdout: string;
  stderr: string;
}

export interface CodeInspectusJsonCommandResult<T> extends CodeInspectusCommandResult {
  data: T;
}

export type CodeInspectusSdkErrorCode = "SPAWN_FAILED" | "ABORTED" | "TIMEOUT" | "OUTPUT_LIMIT" | "INVALID_JSON" | "INCOMPATIBLE_CONTRACT";

export class CodeInspectusSdkError extends Error {
  readonly code: CodeInspectusSdkErrorCode;
  readonly result?: CodeInspectusCommandResult;

  constructor(code: CodeInspectusSdkErrorCode, message: string, result?: CodeInspectusCommandResult) {
    super(message);
    this.name = "CodeInspectusSdkError";
    this.code = code;
    this.result = result;
  }
}

export interface CodeInspectusClientOptions {
  /** Executable to invoke. Defaults to the current Node runtime. Never executed through a shell. */
  command?: string;
  /** Prefix arguments. Defaults to the CLI entry in this exact installed CodeInspectus package. */
  commandArgs?: readonly string[];
  cwd?: string;
  env?: Record<string, string | undefined>;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export interface CommandRunOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface ScanOptions extends CommandRunOptions {
  scanners?: readonly ScannerKind[];
  severityThreshold?: Severity;
  maxFindings?: number;
  failOnSeverity?: Severity;
  baselineScanId?: string;
  failOnNewSeverity?: Severity;
  gitScope?: { mode: "commit_diff"; base: string; head: string } | { mode: "working_tree"; base: string };
  includeCompliance?: boolean;
}

export interface HistoryListOptions extends CommandRunOptions {
  repository?: string;
  path?: string;
  since?: string;
  until?: string;
  severity?: Severity;
  status?: HistoryScanStatus;
  limit?: number;
}

export interface RepositoryHistoryScanOptions extends CommandRunOptions {
  from: string;
  to: string;
  since: string;
  until: string;
  maxCommits: number;
  manifestPath?: string;
  scanners?: readonly ScannerKind[];
  maxFindings?: number;
  includeCompliance?: boolean;
}

export interface IssuePayloadOptions extends CommandRunOptions {
  adapter: IssueAdapter;
  visibility: DestinationVisibility;
  output?: string;
}

const DEFAULT_TIMEOUT_MS = 15 * 60 * 1_000;
const DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024 * 1024;
const INSTALLED_CLI_ENTRY = fileURLToPath(new URL("../index.js", import.meta.url));

function mappedExitCode(code: number | null, signal: NodeJS.Signals | null): number {
  if (code !== null) return code;
  if (signal === "SIGINT") return 130;
  if (signal === "SIGTERM") return 143;
  return 2;
}

function appendOption(args: string[], option: string, value: string | number | undefined): void {
  if (value !== undefined) args.push(option, String(value));
}

function parseJsonResult<T>(result: CodeInspectusCommandResult, expectedSchema: string): CodeInspectusJsonCommandResult<T> {
  let data: unknown;
  try { data = JSON.parse(result.stdout); }
  catch { throw new CodeInspectusSdkError("INVALID_JSON", "CodeInspectus did not return valid JSON for the typed SDK operation.", result); }
  if (!data || typeof data !== "object") throw new CodeInspectusSdkError("INVALID_JSON", "CodeInspectus returned a non-object JSON document.", result);
  if ((data as { schema_version?: unknown }).schema_version !== expectedSchema) {
    throw new CodeInspectusSdkError("INCOMPATIBLE_CONTRACT", `Expected CodeInspectus schema ${expectedSchema}.`, result);
  }
  return { ...result, data: data as T };
}

export class CodeInspectusClient {
  readonly options: Readonly<Required<Pick<CodeInspectusClientOptions, "command" | "commandArgs" | "timeoutMs" | "maxOutputBytes">> & Pick<CodeInspectusClientOptions, "cwd" | "env">>;

  constructor(options: CodeInspectusClientOptions = {}) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError("timeoutMs must be a positive safe integer.");
    if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) throw new TypeError("maxOutputBytes must be a positive safe integer.");
    this.options = Object.freeze({
      command: options.command ?? process.execPath,
      commandArgs: Object.freeze([...(options.commandArgs ?? [INSTALLED_CLI_ENTRY])]),
      timeoutMs,
      maxOutputBytes,
      ...(options.cwd ? { cwd: options.cwd } : {}),
      ...(options.env ? { env: { ...options.env } } : {}),
    });
  }

  /** Run an arbitrary local CodeInspectus command. Policy exits 1/2 are returned, not thrown. */
  async run(args: readonly string[], runOptions: CommandRunOptions = {}): Promise<CodeInspectusCommandResult> {
    if (runOptions.signal?.aborted) throw new CodeInspectusSdkError("ABORTED", "CodeInspectus command was aborted before launch.");
    const timeoutMs = runOptions.timeoutMs ?? this.options.timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError("timeoutMs must be a positive safe integer.");
    const commandArgs = [...this.options.commandArgs, ...args];
    return new Promise((resolvePromise, rejectPromise) => {
      const child = spawn(this.options.command, commandArgs, {
        cwd: this.options.cwd,
        env: this.options.env ?? process.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let outputBytes = 0;
      let failure: CodeInspectusSdkError | undefined;
      let settled = false;
      const fail = (error: CodeInspectusSdkError): void => {
        failure ??= error;
        if (!child.killed) child.kill("SIGTERM");
      };
      const collect = (destination: Buffer[]) => (chunk: Buffer): void => {
        outputBytes += chunk.length;
        if (outputBytes > this.options.maxOutputBytes) {
          fail(new CodeInspectusSdkError("OUTPUT_LIMIT", `CodeInspectus output exceeded ${this.options.maxOutputBytes} bytes.`));
          return;
        }
        destination.push(chunk);
      };
      child.stdout.on("data", collect(stdout));
      child.stderr.on("data", collect(stderr));
      const onAbort = (): void => fail(new CodeInspectusSdkError("ABORTED", "CodeInspectus command was aborted."));
      runOptions.signal?.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(() => fail(new CodeInspectusSdkError("TIMEOUT", `CodeInspectus command exceeded ${timeoutMs} ms.`)), timeoutMs);
      const cleanup = (): void => {
        clearTimeout(timer);
        runOptions.signal?.removeEventListener("abort", onAbort);
      };
      child.once("error", (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        rejectPromise(new CodeInspectusSdkError("SPAWN_FAILED", `Could not start CodeInspectus: ${error.message}`));
      });
      child.once("close", (code, signal) => {
        if (settled) return;
        settled = true;
        cleanup();
        const result: CodeInspectusCommandResult = {
          args: [...args],
          exitCode: mappedExitCode(code, signal),
          ...(signal ? { signal } : {}),
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
        };
        if (failure) rejectPromise(new CodeInspectusSdkError(failure.code, failure.message, result));
        else resolvePromise(result);
      });
    });
  }

  async scan(target: string, options: ScanOptions = {}): Promise<CodeInspectusJsonCommandResult<JsonExportV3>> {
    const args = ["scan", target, "--format", "json"];
    if (options.scanners?.length) args.push("--scanner", options.scanners.join(","));
    appendOption(args, "--severity", options.severityThreshold);
    appendOption(args, "--max-findings", options.maxFindings);
    appendOption(args, "--fail-on-severity", options.failOnSeverity);
    appendOption(args, "--baseline", options.baselineScanId);
    appendOption(args, "--fail-on-new-severity", options.failOnNewSeverity);
    if (options.gitScope?.mode === "commit_diff") args.push("--diff", options.gitScope.base, "--head", options.gitScope.head);
    else if (options.gitScope?.mode === "working_tree") args.push("--working-tree", "--base", options.gitScope.base);
    if (options.includeCompliance === false) args.push("--no-compliance");
    return parseJsonResult<JsonExportV3>(await this.run(args, options), SDK_COMPATIBILITY.export_schema);
  }

  async exportScan(scanId: string, options: CommandRunOptions = {}): Promise<CodeInspectusJsonCommandResult<JsonExportV3>> {
    return parseJsonResult<JsonExportV3>(await this.run(["export", scanId, "--format", "json"], options), SDK_COMPATIBILITY.export_schema);
  }

  async listHistory(options: HistoryListOptions = {}): Promise<CodeInspectusJsonCommandResult<HistoryListResultV1>> {
    const args = ["scans", "list", "--format", "json"];
    appendOption(args, "--repository", options.repository);
    appendOption(args, "--path", options.path);
    appendOption(args, "--since", options.since);
    appendOption(args, "--until", options.until);
    appendOption(args, "--severity", options.severity);
    appendOption(args, "--status", options.status);
    appendOption(args, "--limit", options.limit);
    return parseJsonResult<HistoryListResultV1>(await this.run(args, options), SDK_COMPATIBILITY.history_schema);
  }

  async compareHistory(oldScanId: string, newScanId: string, options: CommandRunOptions = {}): Promise<CodeInspectusJsonCommandResult<HistoryComparisonV1>> {
    return parseJsonResult<HistoryComparisonV1>(await this.run(["scans", "compare", oldScanId, newScanId, "--format", "json"], options), SDK_COMPATIBILITY.history_schema);
  }

  async scanRepositoryHistory(repository: string, options: RepositoryHistoryScanOptions): Promise<CodeInspectusJsonCommandResult<RepositoryHistoryManifestV1>> {
    const args = ["history", "scan", repository, "--from", options.from, "--to", options.to, "--since", options.since, "--until", options.until, "--max-commits", String(options.maxCommits), "--format", "json"];
    appendOption(args, "--manifest", options.manifestPath);
    if (options.scanners?.length) args.push("--scanner", options.scanners.join(","));
    appendOption(args, "--max-findings", options.maxFindings);
    if (options.includeCompliance === false) args.push("--no-compliance");
    return parseJsonResult<RepositoryHistoryManifestV1>(await this.run(args, options), SDK_COMPATIBILITY.repository_history_schema);
  }

  async createIssuePayload(scanId: string, findingId: string, options: IssuePayloadOptions): Promise<CodeInspectusJsonCommandResult<IssuePayloadV1>> {
    const args = ["issue", "export", scanId, findingId, "--adapter", options.adapter, "--visibility", options.visibility];
    appendOption(args, "--output", options.output);
    return parseJsonResult<IssuePayloadV1>(await this.run(args, options), SDK_COMPATIBILITY.issue_payload_schema);
  }

  async listTriage(scanId: string, options: CommandRunOptions & { limit?: number } = {}): Promise<CodeInspectusJsonCommandResult<TriageListV1>> {
    const args = ["triage", "list", scanId, "--format", "json"];
    appendOption(args, "--limit", options.limit);
    return parseJsonResult<TriageListV1>(await this.run(args, options), SDK_COMPATIBILITY.triage_schema);
  }

  async verifyBundle(path: string, options: CommandRunOptions = {}): Promise<CodeInspectusJsonCommandResult<BundleManifestV1>> {
    return parseJsonResult<BundleManifestV1>(await this.run(["bundle", "verify", path, "--format", "json"], options), SDK_COMPATIBILITY.bundle_schema);
  }
}
