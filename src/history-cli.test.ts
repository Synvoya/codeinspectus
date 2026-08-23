import { join, resolve } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { runHistoryCli, type HistoryCliDependencies } from "./history-cli.js";
import { listNativePacks } from "./packs/registry.js";
import type { ScanStoreSnapshot, StoredScanResult } from "./store.js";
import type { Finding } from "./types.js";

const TEST_REPOSITORY_ROOT = resolve("repo");

function scanId(id: number): string {
  return `scan-00000000-0000-4000-8000-${String(id).padStart(12, "0")}`;
}

function secretFinding(token: string): Finding {
  return {
    id: "CI-secret", fingerprint: "secret-fingerprint", title: `Exposed ${token}`, severity: "critical",
    engine: "gitleaks", engines: ["gitleaks"], rule_id: "generic-api-key", cwe: ["CWE-798"],
    location: { file: "src/config.ts", start_line: 1, end_line: 1, snippet: `token=${token}` },
    message: `credential ${token}`, remediation: { summary: "Rotate it", steps: [], references: [] },
    frameworks: [], confidence: "high", is_secret: true, producer_components: ["gitleaks@1"],
    finding_kind: "secret",
  };
}

function stored(id: number, startedAt: string, findings: Finding[] = []): StoredScanResult {
  const engines = ["opengrep", "gitleaks", "trivy", "codeinspectus-ai"] as const;
  return {
    scan_id: scanId(id), target: TEST_REPOSITORY_ROOT, repository_root: TEST_REPOSITORY_ROOT, started_at: startedAt, duration_ms: 4,
    engines_run: engines.map((engine) => `${engine}@1`),
    engine_details: engines.map((engine) => ({
      engine, version: "1", available: true, ran: true,
      finding_count: findings.filter((finding) => finding.engines.includes(engine)).length, duration_ms: 1,
    })),
    offline: true, detected_technologies: [],
    pack_coverage: listNativePacks().map((pack) => ({
      pack_id: pack.id, version: pack.version, scanner_kind: pack.scannerKind,
      state: "not_applicable" as const, languages: [], frameworks: [], platforms: [],
      analyzers: { registered: 0, ran: 0 }, rules: { registered: 0, ran: 0 }, limitations: [],
    })),
    summary: {
      critical: findings.filter((finding) => finding.severity === "critical").length,
      high: 0, medium: 0, low: 0, info: 0, total: findings.length,
    },
    findings, truncated: false, total_findings_before_limit: findings.length,
    disclaimer: "test", warnings: [], secret_coverage: "verified",
    component_signatures: { "gitleaks@1": "v1" }, git_safety: { state: "clean" },
    scan_config: { scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 200 },
    storage_schema_version: "2.0.0", canonical_findings: true,
  };
}

function snapshot(scans: StoredScanResult[], overrides: Partial<ScanStoreSnapshot> = {}): ScanStoreSnapshot {
  return {
    scans, read_limit: 5000, record_byte_limit: 8 * 1024 * 1024,
    total_byte_limit: 64 * 1024 * 1024, bytes_read: 0,
    inspected_files: scans.length, candidate_files: scans.length, oversized_record_count: 0,
    byte_budget_exhausted: false, omitted_due_to_byte_budget: 0,
    corrupt_records: [], corrupt_record_count: 0, truncated: false, available: true, ...overrides,
  };
}

function capture(): { stdout: string[]; stderr: string[]; io: { stdout(value: string): void; stderr(value: string): void } } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return { stdout, stderr, io: { stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value) } };
}

function dependencies(scans: StoredScanResult[], overrides: Partial<HistoryCliDependencies> = {}): HistoryCliDependencies {
  return {
    loadScan: vi.fn(async (id: string) => {
      const result = scans.find((scan) => scan.scan_id === id);
      if (!result) throw new Error(`missing ${id}`);
      return result;
    }),
    loadHistory: vi.fn(async () => snapshot(scans)),
    rerun: vi.fn(async () => scans.at(-1)!),
    ...overrides,
  };
}

describe("history CLI parsing and failure boundaries", () => {
  test("list accepts every bounded filter and returns deterministic JSON", async () => {
    const older = stored(1, "2026-07-01T00:00:00.000Z");
    const newer = stored(2, "2026-07-02T00:00:00.000Z", [secretFinding("sk_live_0123456789abcdefghij")]);
    const deps = dependencies([older, newer]);
    const result = capture();
    expect(await runHistoryCli([
      "list", "--repository", TEST_REPOSITORY_ROOT, "--path", join(TEST_REPOSITORY_ROOT, "src", "config.ts"),
      "--since", "2026-07-02", "--until", "2026-07-02",
      "--severity", "high", "--status", "findings", "--limit", "1", "--format", "json",
    ], result.io, deps)).toBe(0);
    expect(JSON.parse(result.stdout.join(""))).toMatchObject({
      entries: [{ scan_id: newer.scan_id, status: "findings" }],
      bounds: { requested_limit: 1, returned: 1 }, partial: false,
    });
    expect(result.stderr).toEqual([]);
  });

  test("invalid and traversal-shaped IDs fail before touching the store", async () => {
    const result = capture();
    const deps = dependencies([]);
    expect(await runHistoryCli(["show", "../../etc/passwd"], result.io, deps)).toBe(2);
    expect(result.stderr.join("")).toMatch(/scan_id|generated id/i);
    expect(deps.loadScan).not.toHaveBeenCalled();
  });

  test("foreign records fail closed when the loaded embedded ID differs", async () => {
    const requested = scanId(1);
    const result = capture();
    const deps = dependencies([], { loadScan: vi.fn(async () => stored(2, "2026-07-02T00:00:00.000Z")) });
    expect(await runHistoryCli(["show", requested], result.io, deps)).toBe(2);
    expect(result.stderr.join("")).toMatch(/no stored.*scan/i);
    expect(result.stdout).toEqual([]);
  });

  test("bad filters and reversed date ranges return usage failure", async () => {
    for (const argv of [
      ["list", "--limit", "201"],
      ["list", "--severity", "urgent"],
      ["list", "--since", "2026-07-03T00:00:00Z", "--until", "2026-07-02T00:00:00Z"],
    ]) {
      const result = capture();
      expect(await runHistoryCli(argv, result.io, dependencies([]))).toBe(2);
      expect(result.stdout).toEqual([]);
      expect(result.stderr.join("")).not.toBe("");
    }
  });

  test("corruption or a bounded-out store is visible and returns exit 2", async () => {
    const record = stored(1, "2026-07-01T00:00:00.000Z");
    const result = capture();
    const deps = dependencies([record], {
      loadHistory: vi.fn(async () => snapshot([record], {
        candidate_files: 7000, truncated: true, corrupt_record_count: 1,
        corrupt_records: [{ file: "bad.json", error: "invalid JSON" }],
      })),
    });
    expect(await runHistoryCli(["list"], result.io, deps)).toBe(2);
    expect(result.stdout.join("")).toMatch(/warning/i);
    expect(result.stderr.join("")).toMatch(/bounded|corrupt/i);
  });
});

describe("history CLI output", () => {
  test("show tolerates a V1-shaped stored scan in text mode", async () => {
    const legacy = stored(1, "2026-07-01T00:00:00.000Z");
    const legacyShape = legacy as unknown as Partial<StoredScanResult>;
    delete legacyShape.detected_technologies;
    delete legacyShape.pack_coverage;
    delete legacyShape.git_safety;
    delete legacyShape.storage_schema_version;
    delete legacyShape.canonical_findings;
    const result = capture();
    expect(await runHistoryCli(["show", legacy.scan_id], result.io, dependencies([legacy]))).toBe(0);
    expect(result.stdout.join("")).toContain(`CodeInspectus scan of ${TEST_REPOSITORY_ROOT}`);
    expect(result.stderr).toEqual([]);
  });

  test("show JSON uses the versioned export and redacts secret values", async () => {
    const token = "sk_live_0123456789abcdefghij";
    const record = stored(1, "2026-07-01T00:00:00.000Z", [secretFinding(token)]);
    const result = capture();
    expect(await runHistoryCli(["show", record.scan_id, "--format", "json"], result.io, dependencies([record]))).toBe(0);
    const output = result.stdout.join("");
    expect(output).not.toContain(token);
    expect(JSON.parse(output)).toMatchObject({ schema_version: "3.0.0", scan: { id: record.scan_id } });
  });

  test("show text redacts secret-shaped fields from a schema-valid stored record", async () => {
    const token = "sk_live_0123456789abcdefghij";
    const record = stored(1, "2026-07-01T00:00:00.000Z", [secretFinding(token)]);
    const result = capture();
    expect(await runHistoryCli(["show", record.scan_id], result.io, dependencies([record]))).toBe(0);
    expect(result.stdout.join("")).not.toContain(token);
    expect(result.stdout.join("")).toContain("redacted");
  });

  test("compare redacts findings and reports conservative partial comparisons as exit 2", async () => {
    const token = "sk_live_0123456789abcdefghij";
    const old = stored(1, "2026-07-01T00:00:00.000Z", [secretFinding(token)]);
    delete old.canonical_findings;
    const fresh = stored(2, "2026-07-02T00:00:00.000Z");
    const result = capture();
    expect(await runHistoryCli(["compare", old.scan_id, fresh.scan_id, "--format", "json"], result.io, dependencies([old, fresh]))).toBe(2);
    expect(result.stdout.join("")).not.toContain(token);
    expect(JSON.parse(result.stdout.join(""))).toMatchObject({
      partial: true, summary: { "Not rechecked / unknown": 1 },
    });
  });

  test("rerun compares the explicit scan and emits the redacted versioned fresh result", async () => {
    const old = stored(1, "2026-07-01T00:00:00.000Z");
    const fresh = stored(2, "2026-07-02T00:00:00.000Z");
    const result = capture();
    const deps = dependencies([old, fresh], { rerun: vi.fn(async () => fresh) });
    expect(await runHistoryCli(["rerun", old.scan_id, "--format", "json"], result.io, deps)).toBe(0);
    expect(JSON.parse(result.stdout.join(""))).toMatchObject({
      rerun_of: old.scan_id,
      scan: { schema_version: "3.0.0", scan: { id: fresh.scan_id } },
      comparison: { old_scan_id: old.scan_id, new_scan_id: fresh.scan_id, partial: false },
    });
    expect(deps.rerun).toHaveBeenCalledWith(old);
  });
});
