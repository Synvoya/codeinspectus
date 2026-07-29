import { describe, expect, test, vi } from "vitest";
import { runTriageCli, type TriageCliDependencies } from "./triage-cli.js";
import { createTriageEvent, type TriageSnapshot } from "./triage.js";
import type { Finding } from "./types.js";
import type { StoredScanResult } from "./store.js";

const scanId = "scan-00000000-0000-4000-8000-000000000001";
function finding(): Finding { return { id: "CI-0001", fingerprint: "fp", title: "x", severity: "high", engine: "opengrep", engines: ["opengrep"], rule_id: "rule",
  cwe: ["CWE-1"], location: { file: "src/a.ts", start_line: 1, end_line: 1 }, message: "x", remediation: { summary: "fix", steps: [], references: [] },
  frameworks: [], confidence: "high", producer_components: ["rule:a"] }; }
function scan(): StoredScanResult { const findings = [finding()]; return { scan_id: scanId, target: "/repo", repository_root: "/repo", started_at: "2026-07-30T00:00:00.000Z",
  duration_ms: 1, engines_run: [], engine_details: [], offline: true, detected_technologies: [], pack_coverage: [], summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
  findings, truncated: false, total_findings_before_limit: 1, disclaimer: "test", warnings: [], git_safety: { state: "clean" } }; }
function snapshot(overrides: Partial<TriageSnapshot> = {}): TriageSnapshot { return { events: [], annotations: [], corrupt_record_count: 0, corrupt_records: [], inspected_files: 0,
  candidate_files: 0, bytes_read: 0, truncated: false, available: true, ...overrides }; }
function capture() { const stdout: string[] = []; const stderr: string[] = []; return { stdout, stderr, io: { stdout: (v: string) => stdout.push(v), stderr: (v: string) => stderr.push(v) } }; }
function deps(overrides: Partial<TriageCliDependencies> = {}): TriageCliDependencies { return { loadScan: vi.fn(async () => scan()), inspect: vi.fn(async () => snapshot()), write: vi.fn(async () => {}), ...overrides }; }

describe("triage CLI", () => {
  test("validates action and required options before store access", async () => {
    for (const argv of [["wat"], ["add", scanId, "CI-0001"], ["delete", scanId, "triage-00000000-0000-4000-8000-000000000001", "--state", "accepted", "--reason", "x"]]) {
      const d = deps(); const out = capture(); expect(await runTriageCli(argv, out.io, d)).toBe(2); expect(d.loadScan).not.toHaveBeenCalled();
    }
  });

  test("adds a redacted annotation without changing the raw finding", async () => {
    const token = "sk_live_0123456789abcdefghij"; const d = deps(); const out = capture();
    expect(await runTriageCli(["add", scanId, "CI-0001", "--state", "needs-review", "--reason", `check ${token}`, "--actor", token, "--format", "json"], out.io, d)).toBe(0);
    const written = vi.mocked(d.write).mock.calls[0]?.[0]; expect(JSON.stringify(written)).not.toContain(token); expect(written?.state).toBe("Needs review");
    expect(scan().findings).toHaveLength(1);
  });

  test("rejects duplicate active annotations", async () => {
    const source = scan(); const event = createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Accepted", reason: "existing" });
    const annotation = { ...event, latest_event_id: event.event_id, deleted: false };
    const d = deps({ inspect: vi.fn(async () => snapshot({ events: [event], annotations: [annotation] })) }); const out = capture();
    expect(await runTriageCli(["add", scanId, "CI-0001", "--state", "accepted", "--reason", "again"], out.io, d)).toBe(2);
    expect(d.write).not.toHaveBeenCalled(); expect(out.stderr.join("")).toMatch(/already has/i);
  });

  test("updates and tombstones an exact annotation with an auditable prior-event link", async () => {
    const source = scan(); const created = createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Needs review", reason: "existing" });
    const annotation = { ...created, latest_event_id: created.event_id, deleted: false };
    const d = deps({ inspect: vi.fn(async () => snapshot({ events: [created], annotations: [annotation] })) });
    const updateOut = capture();
    expect(await runTriageCli(["update", scanId, created.annotation_id, "--state", "accepted", "--reason", "verified", "--format", "json"], updateOut.io, d)).toBe(0);
    expect(vi.mocked(d.write).mock.calls[0]?.[0]).toMatchObject({ operation: "update", annotation_id: created.annotation_id, previous_event_id: created.event_id, state: "Accepted" });
    vi.mocked(d.write).mockClear();
    const deleteOut = capture();
    expect(await runTriageCli(["delete", scanId, created.annotation_id, "--reason", "superseded", "--format", "json"], deleteOut.io, d)).toBe(0);
    expect(vi.mocked(d.write).mock.calls[0]?.[0]).toMatchObject({ operation: "delete", annotation_id: created.annotation_id, previous_event_id: created.event_id, state: "Needs review" });
  });

  test.each([{ available: false }, { truncated: true }, { corrupt_record_count: 1 }])("mutations fail closed on incomplete scope: %o", async (override) => {
    const d = deps({ inspect: vi.fn(async () => snapshot(override)) }); const out = capture();
    expect(await runTriageCli(["add", scanId, "CI-0001", "--state", "accepted", "--reason", "x"], out.io, d)).toBe(2);
    expect(d.write).not.toHaveBeenCalled(); expect(out.stderr.join("")).toMatch(/mutation refused/i);
  });

  test("update and delete also fail closed before writing when inspection is partial", async () => {
    const source = scan(); const created = createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Needs review", reason: "existing" });
    const annotation = { ...created, latest_event_id: created.event_id, deleted: false };
    for (const action of [
      ["update", scanId, created.annotation_id, "--state", "accepted", "--reason", "x"],
      ["delete", scanId, created.annotation_id, "--reason", "x"],
    ]) {
      const d = deps({ inspect: vi.fn(async () => snapshot({ truncated: true, events: [created], annotations: [annotation] })) }); const out = capture();
      expect(await runTriageCli(action, out.io, d)).toBe(2); expect(d.write).not.toHaveBeenCalled();
    }
  });

  test("list returns bounded partial output with exit 2 instead of hiding corruption", async () => {
    const d = deps({ inspect: vi.fn(async () => snapshot({ corrupt_record_count: 1, corrupt_records: [{ file: "bad", error: "bad" }] })) }); const out = capture();
    expect(await runTriageCli(["list", scanId, "--format", "json"], out.io, d)).toBe(2);
    expect(JSON.parse(out.stdout.join(""))).toMatchObject({ schema_version: "1.0.0", source_scan_id: scanId, inspection: { partial: true, corrupt_record_count: 1 }, annotations: [] });
    expect(out.stderr.join("")).toMatch(/partial/i);
  });
});
