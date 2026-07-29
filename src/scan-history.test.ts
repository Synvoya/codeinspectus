import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { listNativePacks } from "./packs/registry.js";
import { compareScanHistory, listScanHistory } from "./scan-history.js";
import { inspectScanStore, type ScanStoreSnapshot, type StoredScanResult } from "./store.js";
import type { Engine, Finding, Severity } from "./types.js";

const cleanup: string[] = [];
const TEST_REPOSITORY_ROOT = resolve("repo");
const TEST_OTHER_REPOSITORY_ROOT = resolve("other");
afterEach(async () => Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true }))));

function finding(fingerprint: string, component: string, severity: Severity = "high"): Finding {
  return {
    id: `CI-${fingerprint}`, fingerprint, title: fingerprint, severity,
    engine: "opengrep", engines: ["opengrep"], rule_id: `rule-${fingerprint}`, cwe: ["CWE-1"],
    location: { file: `src/${fingerprint}.ts`, start_line: 1, end_line: 1 }, message: fingerprint,
    remediation: { summary: "fix", steps: [], references: [] }, frameworks: [], confidence: "high",
    producer_components: [component], finding_kind: "sast",
  };
}

function scan(id: number, startedAt: string, findings: Finding[] = [], overrides: Partial<StoredScanResult> = {}): StoredScanResult {
  const engines: Engine[] = ["opengrep", "gitleaks", "trivy", "codeinspectus-ai"];
  return {
    scan_id: `scan-00000000-0000-4000-8000-${String(id).padStart(12, "0")}`,
    target: TEST_REPOSITORY_ROOT, repository_root: TEST_REPOSITORY_ROOT, started_at: startedAt, duration_ms: 1,
    engines_run: engines.map((engine) => `${engine}@1`),
    engine_details: engines.map((engine) => ({ engine, version: "1", available: true, ran: true, finding_count: findings.filter((item) => item.engines.includes(engine)).length, duration_ms: 1 })),
    offline: true, detected_technologies: [],
    pack_coverage: listNativePacks().map((pack) => ({
      pack_id: pack.id, version: pack.version, scanner_kind: pack.scannerKind, state: "not_applicable" as const,
      languages: [], frameworks: [], platforms: [], analyzers: { registered: 0, ran: 0 }, rules: { registered: 0, ran: 0 }, limitations: [],
    })),
    summary: { critical: findings.filter((item) => item.severity === "critical").length, high: findings.filter((item) => item.severity === "high").length, medium: 0, low: findings.filter((item) => item.severity === "low").length, info: 0, total: findings.length },
    findings, truncated: false, total_findings_before_limit: findings.length, disclaimer: "test", warnings: [],
    secret_coverage: "verified", component_signatures: { component: "v1", reopen: "v1", changed: "v1", new: "v1" },
    git_safety: { state: "clean" }, scan_config: { scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 200 },
    storage_schema_version: "2.0.0", canonical_findings: true,
    ...overrides,
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

describe("bounded deterministic history listing", () => {
  test("filters by repository, path, date, severity and honest scan status", () => {
    const old = scan(1, "2026-07-01T00:00:00.000Z", [finding("a", "component", "low")]);
    const wanted = scan(2, "2026-07-02T00:00:00.000Z", [finding("b", "component", "critical")]);
    const otherRepo = scan(3, "2026-07-03T00:00:00.000Z", [], {
      target: TEST_OTHER_REPOSITORY_ROOT, repository_root: TEST_OTHER_REPOSITORY_ROOT,
    });
    const result = listScanHistory(snapshot([otherRepo, wanted, old]), {
      repository: TEST_REPOSITORY_ROOT, path: join(TEST_REPOSITORY_ROOT, "src", "b.ts"), since: "2026-07-02T00:00:00.000Z",
      until: "2026-07-02T23:59:59.000Z", severity: "high", status: "findings", limit: 1,
    });
    expect(result.entries.map((entry) => entry.scan_id)).toEqual([wanted.scan_id]);
    expect(result.partial).toBe(false);
    expect(result.bounds).toMatchObject({ requested_limit: 1, returned: 1, result_truncated: false });
  });

  test("sorts newest first with scan-id tie-break and bounds result output", () => {
    const a = scan(1, "2026-07-02T00:00:00.000Z");
    const b = scan(2, "2026-07-02T00:00:00.000Z");
    const c = scan(3, "2026-07-03T00:00:00.000Z");
    const result = listScanHistory(snapshot([a, c, b]), { limit: 2 });
    expect(result.entries.map((entry) => entry.scan_id)).toEqual([c.scan_id, a.scan_id]);
    expect(result.bounds).toMatchObject({ matching_records: 3, returned: 2, result_truncated: true });
  });

  test("surfaces corruption/store truncation as partial instead of silently claiming complete history", () => {
    const result = listScanHistory(snapshot([scan(1, "2026-07-01T00:00:00.000Z")], {
      truncated: true, candidate_files: 9000, corrupt_record_count: 1,
      corrupt_records: [{ file: "bad.json", error: "invalid JSON" }],
    }));
    expect(result.partial).toBe(true);
    expect(result.bounds).toMatchObject({ store_truncated: true, candidate_files: 9000, store_read_limit: 5000 });
    expect(result.note).toMatch(/corrupt|bounded/i);
  });
});

describe("managed history store isolation", () => {
  test("isolates malformed, foreign, corrupt and symlink entries", async () => {
    const directory = await mkdtemp(join(await realpath(tmpdir()), "ci-history-")); cleanup.push(directory);
    const valid = scan(1, "2026-07-01T00:00:00.000Z");
    await writeFile(join(directory, `${valid.scan_id}.json`), JSON.stringify(valid));
    await writeFile(join(directory, "not-a-scan.json"), JSON.stringify(valid));
    await writeFile(join(directory, "scan-00000000-0000-4000-8000-000000000002.json"), JSON.stringify(valid));
    await writeFile(join(directory, "scan-00000000-0000-4000-8000-000000000003.json"), "{bad");
    const outside = join(directory, "outside"); await mkdir(outside);
    await writeFile(join(outside, "record"), JSON.stringify(valid));
    await symlink(join(outside, "record"), join(directory, "scan-00000000-0000-4000-8000-000000000004.json"));
    const result = await inspectScanStore({ directory, includeMemory: false });
    expect(result.scans.map((item) => item.scan_id)).toEqual([valid.scan_id]);
    expect(result.corrupt_record_count).toBe(4);
    expect(result.corrupt_records.map((item) => item.error).join(" ")).toMatch(/filename|embedded|json|regular/i);
    expect(result.corrupt_records.map((item) => item.file).join(" ")).not.toContain("not-a-scan.json");
  });

  test("caps file reads and exposes that the lexicographic subset is not exhaustive", async () => {
    const directory = await mkdtemp(join(await realpath(tmpdir()), "ci-history-bound-")); cleanup.push(directory);
    for (let id = 1; id <= 4; id++) {
      const record = scan(id, `2026-07-0${id}T00:00:00.000Z`);
      await writeFile(join(directory, `${record.scan_id}.json`), JSON.stringify(record));
    }
    const result = await inspectScanStore({ directory, maxFiles: 2, includeMemory: false });
    expect(result).toMatchObject({ read_limit: 2, inspected_files: 2, candidate_files: 4, truncated: true });
    expect(result.scans).toHaveLength(2);
  });

  test("isolates oversized records before reading their contents", async () => {
    const directory = await mkdtemp(join(await realpath(tmpdir()), "ci-history-oversized-")); cleanup.push(directory);
    const record = scan(1, "2026-07-01T00:00:00.000Z");
    await writeFile(join(directory, `${record.scan_id}.json`), JSON.stringify(record));
    const result = await inspectScanStore({ directory, maxRecordBytes: 100, includeMemory: false });
    expect(result).toMatchObject({
      scans: [], inspected_files: 1, oversized_record_count: 1, corrupt_record_count: 1,
      record_byte_limit: 100, truncated: false,
    });
    expect(result.corrupt_records[0]?.error).toMatch(/above the 100-byte history limit/i);
  });

  test("stops deterministically when the total byte budget is exhausted", async () => {
    const directory = await mkdtemp(join(await realpath(tmpdir()), "ci-history-bytes-")); cleanup.push(directory);
    const records = [1, 2, 3].map((id) => scan(id, `2026-07-0${id}T00:00:00.000Z`));
    const serialized = records.map((record) => JSON.stringify(record));
    for (let index = 0; index < records.length; index++) {
      await writeFile(join(directory, `${records[index]!.scan_id}.json`), serialized[index]!);
    }
    const firstBytes = Buffer.byteLength(serialized[0]!);
    const result = await inspectScanStore({ directory, maxTotalBytes: firstBytes + 1, includeMemory: false });
    expect(result.scans.map((record) => record.scan_id)).toEqual([records[0]!.scan_id]);
    expect(result).toMatchObject({
      bytes_read: firstBytes, byte_budget_exhausted: true,
      omitted_due_to_byte_budget: 2, inspected_files: 2, candidate_files: 3, truncated: true,
    });
    const listed = listScanHistory(result);
    expect(listed.partial).toBe(true);
    expect(listed.note).toMatch(/byte history budget|byte.*budget/i);
  });
});

describe("arbitrary conservative comparison states", () => {
  test("classifies New, Persisting, Reopened, Resolved and unknown with explicit history proof", () => {
    const persistOld = finding("persist", "component");
    const resolved = finding("resolved", "component");
    const unknownOld = finding("unknown-old", "changed");
    const reopenedEarlier = finding("reopen-fp", "reopen");
    const earlier = scan(1, "2026-07-01T00:00:00.000Z", [reopenedEarlier]);
    const old = scan(2, "2026-07-02T00:00:00.000Z", [persistOld, resolved, unknownOld]);
    const persistNew = finding("persist", "component");
    const reopened = finding("reopen-fp", "reopen");
    const brandNew = finding("brand-new", "new");
    const newScan = scan(3, "2026-07-03T00:00:00.000Z", [persistNew, reopened, brandNew], {
      component_signatures: { component: "v1", reopen: "v1", changed: "v2", new: "v1" },
    });
    const result = compareScanHistory(old, newScan, snapshot([newScan, old, earlier]));
    expect(result.summary).toEqual({ New: 1, Reopened: 1, Persisting: 1, Resolved: 1, "Not rechecked / unknown": 1 });
    expect(result.items.find((item) => item.finding.fingerprint === "reopen-fp")?.state).toBe("Reopened");
    expect(result.items.find((item) => item.finding.fingerprint === "unknown-old")?.state).toBe("Not rechecked / unknown");
    expect(result.history_provenance).toMatchObject({ same_canonical_target: true, reopened_proof: "complete" });
  });

  test("a new rule/component absent from OLD is unknown, never New or Reopened", () => {
    const old = scan(1, "2026-07-01T00:00:00.000Z", [], { component_signatures: { component: "v1" } });
    const newScan = scan(2, "2026-07-02T00:00:00.000Z", [finding("new-rule", "new-component")], {
      component_signatures: { component: "v1", "new-component": "v1" },
    });
    const result = compareScanHistory(old, newScan, snapshot([old, newScan]));
    expect(result.items[0]).toMatchObject({ state: "Not rechecked / unknown", finding: { fingerprint: "new-rule" } });
  });

  test.each<Partial<ScanStoreSnapshot>>([{ truncated: true }, { corrupt_record_count: 1, corrupt_records: [{ file: "bad", error: "bad" }] }])(
    "incomplete history never claims Reopened: %o", (historyOverride) => {
      const priorFinding = finding("returned", "reopen");
      const earlier = scan(1, "2026-07-01T00:00:00.000Z", [priorFinding]);
      const old = scan(2, "2026-07-02T00:00:00.000Z");
      const fresh = scan(3, "2026-07-03T00:00:00.000Z", [finding("returned", "reopen")]);
      const result = compareScanHistory(old, fresh, snapshot([earlier, old, fresh], historyOverride));
      expect(result.items[0]?.state).toBe("Not rechecked / unknown");
      expect(result.history_provenance.reopened_proof).toBe("unavailable");
    },
  );

  test("legacy noncanonical V1 records load for comparison but absence is never resolution", () => {
    const old = scan(1, "2026-07-01T00:00:00.000Z", [finding("gone", "component")]);
    delete old.canonical_findings;
    delete old.storage_schema_version;
    const fresh = scan(2, "2026-07-02T00:00:00.000Z");
    const result = compareScanHistory(old, fresh, snapshot([old, fresh]));
    expect(result.items[0]?.state).toBe("Not rechecked / unknown");
    expect(result.summary.Resolved).toBe(0);
  });

  test("empty legacy comparisons remain partial because their coverage is unknown", () => {
    const old = scan(1, "2026-07-01T00:00:00.000Z");
    const fresh = scan(2, "2026-07-02T00:00:00.000Z");
    delete old.canonical_findings;
    delete fresh.canonical_findings;
    const result = compareScanHistory(old, fresh, snapshot([old, fresh]));
    expect(result.items).toEqual([]);
    expect(result.partial).toBe(true);
    expect(result.history_provenance.notes.join(" ")).toMatch(/lack complete canonical/i);
  });

  test("rejects different canonical targets and reversed dates", () => {
    const old = scan(1, "2026-07-02T00:00:00.000Z");
    const other = scan(2, "2026-07-03T00:00:00.000Z", [], { target: TEST_OTHER_REPOSITORY_ROOT });
    expect(() => compareScanHistory(old, other, snapshot([]))).toThrow(/same canonical target/i);
    const earlier = scan(3, "2026-07-01T00:00:00.000Z");
    expect(() => compareScanHistory(old, earlier, snapshot([]))).toThrow(/swap/i);
  });
});
