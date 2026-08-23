import { EventEmitter } from "node:events";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  CliUsageError,
  cliHelp,
  installCliSignalHandlers,
  parseCliCommand,
  runCli,
  signalExitCode,
  type CliDependencies,
  type SignalHost,
} from "./cli.js";
import type { PreflightResult } from "./preflight.js";
import type { ScanResult } from "./types.js";
import { createUnavailableRepositoryTrust } from "./repository-trust/schemas.js";
import type { StoredScanResult } from "./store.js";
import { listNativePacks } from "./packs/registry.js";
import type { TriageSnapshot } from "./triage.js";

const cleanup: string[] = [];

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-cli-"));
  cleanup.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function readyPreflight(target = "/repo"): PreflightResult {
  return {
    schema_version: "1.0.0",
    codeinspectus_version: "2.1.0",
    offline: true,
    writes_repository: false,
    ready: true,
    target: { input: target, resolved_path: target, canonical_path: target, exists: true, supported: true, type: "directory", symlink_safe: true },
    output: { mode: "stdout", exists: true, writable: true, symlink_safe: true, inside_target: false, approved_inside_target: false, safe: true },
    configuration: { scanners: ["sast"], severity_threshold: "info", max_findings: 200, output_format: "text", include_compliance: true },
    effective_limits: { max_findings: 200, engine_timeout_ms: 1, engine_output_max_bytes: 1 },
    detected_technologies: [],
    technology_detection_limitations: [],
    scanner_applicability: [],
    native_pack_applicability: [],
    engine_setup: { state: "ready", platform: "test", engines: [], trivy_db: { state: "ready" }, network_required: false },
    engine_integrity: [],
    trivy_database: { selected: false, state: "ready", provenance: "recorded" },
    repair: { required_for_selected_scope: false, network_required: false },
    errors: [],
    warnings: [],
  };
}

function emptyScan(target = "/repo"): ScanResult {
  return {
    scan_id: "scan-00000000-0000-4000-8000-000000000000",
    target,
    started_at: "2026-07-29T00:00:00.000Z",
    duration_ms: 1,
    engines_run: [],
    engine_details: [],
    offline: true,
    detected_technologies: [],
    pack_coverage: [],
    repository_trust: createUnavailableRepositoryTrust(),
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findings: [],
    truncated: false,
    total_findings_before_limit: 0,
    disclaimer: "test",
    warnings: [],
    git_safety: { state: "clean" },
    scan_config: { max_findings: 200 },
  };
}

function storedScan(target = "/repo", findings: ScanResult["findings"] = []): StoredScanResult {
  const scan = emptyScan(target);
  return {
    ...scan,
    engines_run: ["opengrep@1", "gitleaks@1", "trivy@1"],
    engine_details: ["opengrep", "gitleaks", "trivy"].map((engine) => ({
      engine: engine as "opengrep" | "gitleaks" | "trivy", version: "1", available: true,
      ran: true, finding_count: engine === "opengrep" ? findings.length : 0, duration_ms: 1,
    })),
    pack_coverage: listNativePacks().map((pack) => ({
      pack_id: pack.id, version: pack.version, scanner_kind: pack.scannerKind,
      state: "not_applicable" as const, languages: [], frameworks: [], platforms: [],
      analyzers: { registered: 0, ran: 0 }, rules: { registered: 0, ran: 0 }, limitations: [],
    })),
    secret_coverage: "verified",
    scan_config: { scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 200 },
    storage_schema_version: "2.0.0",
    canonical_findings: true,
    findings,
    summary: { ...scan.summary, total: findings.length },
    total_findings_before_limit: findings.length,
  };
}

function cliFinding(id: string, severity: "high" | "low"): ScanResult["findings"][number] {
  return { id, fingerprint: `fp-${id}`, title: id, severity, engine: "opengrep", engines: ["opengrep"], rule_id: id,
    cwe: ["CWE-1"], location: { file: "x", start_line: 1, end_line: 1 }, message: id,
    remediation: { summary: "fix", steps: [], references: [] }, frameworks: [], confidence: "high", producer_components: ["opengrep@1"] };
}

function dependencies(overrides: Partial<CliDependencies> = {}): CliDependencies {
  return {
    preflight: vi.fn(async () => readyPreflight()),
    scan: vi.fn(async () => emptyScan()),
    loadScan: vi.fn(async () => storedScan()),
    inspectTriage: vi.fn(async () => emptyTriage()),
    ...overrides,
  };
}

function emptyTriage(): TriageSnapshot {
  return { events: [], annotations: [], corrupt_record_count: 0, corrupt_records: [], inspected_files: 0, candidate_files: 0, bytes_read: 0, truncated: false, available: true };
}

function ioCapture(): { stdout: string[]; stderr: string[]; io: { stdout(value: string): void; stderr(value: string): void } } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return { stdout, stderr, io: { stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value) } };
}

describe("CLI parser", () => {
  test("parses the complete scan option contract and preserves a Windows target", () => {
    expect(parseCliCommand([
      "scan", "C:\\work\\repo", "--scanner", "sast,ai", "--scanner", "secret",
      "--severity", "high", "--max-findings", "25", "--format", "json",
      "--output-dir", "C:\\reports", "--allow-output-in-target", "--no-compliance", "--fail-on-severity", "high",
    ])).toEqual({
      command: "scan",
      target: "C:\\work\\repo",
      configuration: {
        scanners: ["sast", "ai", "secret"],
        severity_threshold: "high",
        max_findings: 25,
        output_directory: "C:\\reports",
        output_format: "json",
        allow_output_in_target: true,
        include_compliance: false,
        fail_on_severity: "high",
      },
    });
  });

  test("parses exact commit and working-tree Git scope contracts", () => {
    expect(parseCliCommand(["scan", ".", "--diff", "origin/main", "--head", "HEAD"]).configuration.git_scope)
      .toEqual({ mode: "commit_diff", base: "origin/main", head: "HEAD" });
    expect(parseCliCommand(["scan", ".", "--working-tree", "--base", "HEAD"]).configuration.git_scope)
      .toEqual({ mode: "working_tree", base: "HEAD" });
  });

  test.each([
    [["unknown"], /unknown subcommand/i],
    [["scan"], /requires a file or directory/i],
    [["scan", ".", "--wat"], /unknown option/i],
    [["scan", ".", "--output", "a.json", "--output-dir", "reports"], /either --output.*--output-dir/i],
    [["scan", ".", "--max-findings", "0"], /positive safe integer/i],
    [["scan", ".", "--scanner", "magic"], /unknown scanner/i],
    [["scan", ".", "--fail-on-severity", "urgent"], /invalid fail-on severity/i],
    [["scan", ".", "--diff", "HEAD"], /--diff requires --head/i],
    [["scan", ".", "--head", "HEAD"], /--head requires --diff/i],
    [["scan", ".", "--working-tree"], /--working-tree requires --base/i],
    [["scan", ".", "--base", "HEAD"], /--base requires --working-tree/i],
    [["scan", ".", "--working-tree", "--base", "HEAD", "--diff", "HEAD~1", "--head", "HEAD"], /either --diff.*--working-tree/i],
    [["preflight", ".", "--fail-on-severity", "high"], /only for scan enforcement/i],
    [["preflight", ".", "--format", "csv"], /SARIF and CSV are scan\/export formats/i],
    [["export", "scan-00000000-0000-4000-8000-000000000000", "--format", "json", "--fail-on-severity", "high"], /export accepts only/i],
    [["scan", ".", "extra"], /exactly one/i],
  ])("rejects malformed arguments %#", (argv, expected) => {
    expect(() => parseCliCommand(argv as string[])).toThrow(expected as RegExp);
  });

  test("help documents interactive setup, piped MCP, and the first-class commands", () => {
    expect(cliHelp()).toMatch(/Guided setup in a terminal; MCP server over piped stdio/);
    expect(cliHelp()).toMatch(/codeinspectus setup \[options\]/);
    expect(cliHelp()).toMatch(/codeinspectus scan <target>/);
    expect(cliHelp()).toMatch(/codeinspectus scans <list\|show\|rerun\|compare>/);
    expect(cliHelp()).toMatch(/codeinspectus bundle <create\|verify\|export\|compare>/);
    expect(cliHelp()).toMatch(/codeinspectus bulk scan <parent>/);
    expect(cliHelp()).toMatch(/json\|sarif\|csv/);
    expect(cliHelp("preflight")).toMatch(/Usage: codeinspectus preflight/);
  });
});

describe("CLI stdout/stderr and execution", () => {
  test("baseline new-finding enforcement retains the full raw report and counts only proven new findings", async () => {
    const capture = ioCapture();
    const baselineId = "scan-00000000-0000-4000-8000-000000000001";
    const existing = { ...cliFinding("existing", "high"), producer_components: ["opengrep@1"] };
    const introducedBase = cliFinding("introduced", "high");
    const introduced = { ...introducedBase, location: { ...introducedBase.location, file: "introduced.ts" }, producer_components: ["opengrep@1"] };
    const baseline = { ...storedScan("/repo", [existing]), scan_id: baselineId, started_at: "2026-07-28T00:00:00.000Z", component_signatures: { "opengrep@1": "v1" } };
    const fresh = { ...storedScan("/repo", [existing, introduced]), component_signatures: { "opengrep@1": "v1" } };
    const deps = dependencies({
      scan: vi.fn(async () => ({ ...emptyScan(), findings: [existing, introduced] })),
      loadScan: vi.fn(async (id) => id === baselineId ? baseline : fresh),
      inspectTriage: vi.fn(async () => emptyTriage()),
    });
    expect(await runCli(["scan", ".", "--baseline", baselineId, "--fail-on-new-severity", "high", "--format", "json"], capture.io, deps)).toBe(1);
    const output = JSON.parse(capture.stdout.join(""));
    expect(output.findings).toHaveLength(2);
    expect(output.baseline.summary).toEqual({ New: 1, Existing: 1, "Not rechecked / unknown": 0 });
    expect(output.scan.configuration).toMatchObject({ policy_mode: "new_findings_enforcement", fail_on_new_severity: "high", baseline_scan_id: baselineId });
  });

  test("preflight JSON writes only stdout and returns zero when ready", async () => {
    const capture = ioCapture();
    const deps = dependencies({ preflight: vi.fn(async () => readyPreflight()) });
    const code = await runCli(["preflight", ".", "--format", "json"], capture.io, deps);
    expect(code).toBe(0);
    expect(capture.stderr).toEqual([]);
    expect(JSON.parse(capture.stdout.join(""))).toMatchObject({ offline: true, writes_repository: false });
    expect(deps.scan).not.toHaveBeenCalled();
  });

  test("malformed input writes only stderr and never calls scan", async () => {
    const capture = ioCapture();
    const deps = dependencies({ preflight: vi.fn(), scan: vi.fn() });
    const code = await runCli(["scan", ".", "--scanner", "magic"], capture.io, deps);
    expect(code).toBe(2);
    expect(capture.stdout).toEqual([]);
    expect(capture.stderr.join(" ")).toMatch(/unknown scanner/i);
    expect(deps.scan).not.toHaveBeenCalled();
  });

  test("scanner-narrowed JSON is emitted but exits 2 because whole-product coverage is partial", async () => {
    const capture = ioCapture();
    const deps: CliDependencies = {
      preflight: vi.fn(async () => readyPreflight()),
      scan: vi.fn(async () => emptyScan()),
      loadScan: vi.fn(async () => ({ ...storedScan(), scan_config: { scanners: ["ai" as const], max_findings: 200 } })),
    };
    const code = await runCli(["scan", ".", "--format", "json", "--severity", "high", "--scanner", "ai"], capture.io, deps);
    expect(code).toBe(2);
    expect(capture.stderr.join(" ")).toMatch(/coverage is partial/i);
    expect(JSON.parse(capture.stdout.join(""))).toMatchObject({
      schema_version: "3.0.0",
      scan: { id: expect.stringMatching(/^scan-/), canonical_findings: true },
      coverage: { aggregate: expect.any(String) },
    });
    expect(deps.scan).toHaveBeenCalledWith(expect.objectContaining({ severity_threshold: "high", scanners: ["ai"] }));
  });

  test("explicit output directory is created after scanning and receives an atomic result artifact", async () => {
    const target = await temporaryRoot();
    await writeFile(join(target, "app.ts"), "export {};\n");
    const output = join(await temporaryRoot(), "new-output");
    const capture = ioCapture();
    const deps: CliDependencies = {
      preflight: vi.fn(async () => readyPreflight(target)),
      scan: vi.fn(async () => emptyScan(target)),
      loadScan: vi.fn(async () => storedScan(target)),
    };
    const code = await runCli(["scan", target, "--format", "json", "--output-dir", output], capture.io, deps);
    expect(code).toBe(0);
    expect(JSON.parse(await readFile(join(output, "scan-result.json"), "utf8"))).toMatchObject({ scan: { target } });
  });

  test("an exact output file is itself approval for the documented in-repository artifact", async () => {
    const target = await temporaryRoot();
    await writeFile(join(target, "app.ts"), "export {};\n");
    const output = join(target, "results.sarif");
    const capture = ioCapture();
    const deps = dependencies({
      preflight: vi.fn(async () => readyPreflight(target)),
      scan: vi.fn(async () => emptyScan(target)),
      loadScan: vi.fn(async () => storedScan(target)),
    });

    expect(await runCli(["scan", target, "--format", "sarif", "--output", output], capture.io, deps)).toBe(0);
    expect(JSON.parse(await readFile(output, "utf8"))).toMatchObject({ version: "2.1.0" });
  });

  test("scan SARIF emits a valid canonical export", async () => {
    const capture = ioCapture();
    const deps = dependencies();
    const code = await runCli(["scan", ".", "--format", "sarif"], capture.io, deps);
    expect(code).toBe(0);
    expect(JSON.parse(capture.stdout.join(""))).toMatchObject({ version: "2.1.0", runs: [{ tool: { driver: { name: "CodeInspectus" } } }] });
  });

  test("scan CSV retains the canonical finding set and writes findings.csv atomically", async () => {
    const target = await temporaryRoot();
    await writeFile(join(target, "app.ts"), "export {};\n");
    const output = join(await temporaryRoot(), "csv-output");
    const raw = storedScan(target, [cliFinding("b", "low"), cliFinding("a", "high")]);
    const capture = ioCapture();
    const deps = dependencies({
      preflight: vi.fn(async () => readyPreflight(target)),
      scan: vi.fn(async () => emptyScan(target)),
      loadScan: vi.fn(async () => raw),
    });
    expect(await runCli(["scan", target, "--format", "csv", "--output-dir", output], capture.io, deps)).toBe(0);
    const csv = capture.stdout.join("");
    expect(await readFile(join(output, "findings.csv"), "utf8")).toBe(csv);
    expect(csv).toMatch(/^"record_type","csv_schema_version"/);
    expect(csv.indexOf('"a"')).toBeLessThan(csv.indexOf('"b"'));
    expect(csv).toContain('"complete"');
  });

  test("scan JSON reloads the canonical store and ignores display max for export completeness", async () => {
    const capture = ioCapture();
    const raw = storedScan("/repo", [cliFinding("high", "high"), cliFinding("low", "low")]);
    const display = { ...emptyScan(), findings: [raw.findings[0]!], truncated: true, total_findings_before_limit: 2 };
    const deps = dependencies({ scan: vi.fn(async () => display), loadScan: vi.fn(async () => raw) });
    expect(await runCli(["scan", ".", "--format", "json", "--max-findings", "1"], capture.io, deps)).toBe(0);
    expect(JSON.parse(capture.stdout.join("")).findings.map((item: { id: string }) => item.id)).toEqual(["high", "low"]);
  });

  test("report-only complete scan returns 0 even when findings exist", async () => {
    const capture = ioCapture();
    const raw = storedScan("/repo", [cliFinding("critical", "high")]);
    const deps = dependencies({ loadScan: vi.fn(async () => raw) });
    expect(await runCli(["scan", ".", "--format", "json"], capture.io, deps)).toBe(0);
    expect(capture.stderr).toEqual([]);
    expect(JSON.parse(capture.stdout.join("")).scan.configuration.policy_mode).toBe("report_only");
  });

  test("enforcement returns 1 and still emits SARIF when a finding meets the threshold", async () => {
    const capture = ioCapture();
    const raw = storedScan("/repo", [cliFinding("high", "high")]);
    const deps = dependencies({ loadScan: vi.fn(async () => raw) });
    expect(await runCli(["scan", ".", "--format", "sarif", "--fail-on-severity", "high"], capture.io, deps)).toBe(1);
    expect(capture.stderr.join(" ")).toMatch(/met or exceeded/i);
    expect(JSON.parse(capture.stdout.join("")).runs[0].properties).toMatchObject({ policy_mode: "enforcement", fail_on_severity: "high", aggregate_coverage: "complete" });
  });

  test("enforcement returns 0 when findings are below the threshold", async () => {
    const capture = ioCapture();
    const deps = dependencies({ loadScan: vi.fn(async () => storedScan("/repo", [cliFinding("low", "low")])) });
    expect(await runCli(["scan", ".", "--fail-on-severity", "high"], capture.io, deps)).toBe(0);
  });

  test.each([undefined, "high"] as const)("partial coverage returns 2 with threshold %s", async (threshold) => {
    const capture = ioCapture();
    const incomplete = { ...storedScan("/repo", [cliFinding("high", "high")]), scan_config: { scanners: ["ai" as const], max_findings: 200 } };
    const deps = dependencies({ loadScan: vi.fn(async () => incomplete) });
    const argv = ["scan", ".", "--format", "json", ...(threshold ? ["--fail-on-severity", threshold] : [])];
    expect(await runCli(argv, capture.io, deps)).toBe(2);
    expect(capture.stderr.join(" ")).toMatch(/coverage is partial/i);
    expect(JSON.parse(capture.stdout.join("")).coverage.aggregate).toBe("partial");
  });

  test("runtime scan failure returns 2 without a false report", async () => {
    const capture = ioCapture();
    const deps = dependencies({ scan: vi.fn(async () => { throw new Error("engine crashed"); }) });
    expect(await runCli(["scan", "."], capture.io, deps)).toBe(2);
    expect(capture.stdout).toEqual([]);
    expect(capture.stderr.join(" ")).toMatch(/engine crashed/i);
  });

  test("export rejects traversal/foreign ids before store access", async () => {
    const capture = ioCapture();
    const deps = dependencies();
    expect(await runCli(["export", "../../etc/passwd", "--format", "json"], capture.io, deps)).toBe(2);
    expect(capture.stderr.join(" ")).toMatch(/scan_id must be/i);
    expect(deps.loadScan).not.toHaveBeenCalled();
  });

  test("export emits JSON, SARIF, and CSV from a stored scan", async () => {
    const id = "scan-00000000-0000-4000-8000-000000000000";
    for (const format of ["json", "sarif", "csv"] as const) {
      const capture = ioCapture();
      const deps = dependencies({ loadScan: vi.fn(async () => storedScan()) });
      expect(await runCli(["export", id, "--format", format], capture.io, deps)).toBe(0);
      if (format === "csv") expect(capture.stdout.join("")).toMatch(/^"record_type","csv_schema_version"/);
      else expect(JSON.parse(capture.stdout.join(""))).toMatchObject(format === "json"
        ? {
            schema_version: "3.0.0",
            repository_trust: {
              schema_version: "1.0.0",
              coverage: { state: "unavailable" },
              summary: { total: 0 },
              artifacts: [],
            },
          }
        : { version: "2.1.0" });
    }
  });
});

describe("signal contract", () => {
  test("maps SIGINT and SIGTERM to shell-standard exits", () => {
    expect(signalExitCode("SIGINT")).toBe(130);
    expect(signalExitCode("SIGTERM")).toBe(143);
  });

  test.each([["SIGINT", 130], ["SIGTERM", 143]] as const)("installed %s handler exits %i", (signal, code) => {
    class FakeHost extends EventEmitter implements SignalHost {
      exit(exitCode: number): never {
        throw new CliUsageError(`exit:${exitCode}`);
      }
    }
    const host = new FakeHost();
    const cleanupHandlers = installCliSignalHandlers(host);
    expect(() => host.emit(signal)).toThrow(`exit:${code}`);
    cleanupHandlers();
    expect(host.listenerCount("SIGINT")).toBe(0);
    expect(host.listenerCount("SIGTERM")).toBe(0);
  });
});
