import { access, mkdtemp, mkdir, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  createTriageEvent, inspectTriageStore, matchingTriageAnnotations, triageScopeForScan,
  writeTriageEvent, TRIAGE_EVENT_MAX_BYTES, triagePersistenceDisabled,
} from "./triage.js";
import { MANAGED_TRIAGE } from "./config.js";
import type { Finding } from "./types.js";
import type { StoredScanResult } from "./store.js";

const cleanup: string[] = [];
afterEach(async () => Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true }))));

function finding(fp = "fp"): Finding {
  return { id: `CI-${fp}`, fingerprint: fp, title: fp, severity: "high", engine: "opengrep", engines: ["opengrep"], rule_id: "rule",
    cwe: ["CWE-1"], location: { file: "src/a.ts", start_line: 1, end_line: 1 }, message: fp,
    remediation: { summary: "fix", steps: [], references: [] }, frameworks: [], confidence: "high", producer_components: ["rule:a"] };
}

function scan(id = 1, target = "/repo", findings = [finding()]): StoredScanResult {
  return { scan_id: `scan-00000000-0000-4000-8000-${String(id).padStart(12, "0")}`, target, repository_root: target,
    started_at: "2026-07-30T00:00:00.000Z", duration_ms: 1, engines_run: [], engine_details: [], offline: true,
    detected_technologies: [], pack_coverage: [], summary: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, total: findings.length },
    findings, truncated: false, total_findings_before_limit: findings.length, disclaimer: "test", warnings: [], git_safety: { state: "clean" } };
}

async function root(): Promise<string> {
  const value = await mkdtemp(join(await realpath(tmpdir()), "ci-triage-")); cleanup.push(value); return value;
}

describe("append-only triage store", () => {
  test("projects create, update and delete events without deleting audit history", async () => {
    const directory = await root(); const source = scan(); const item = source.findings[0]!;
    const created = createTriageEvent({ scan: source, finding: item, state: "Needs review", reason: "investigate", recordedAt: "2026-07-30T00:00:00.000Z" });
    const updated = createTriageEvent({ scan: source, finding: item, annotationId: created.annotation_id, previousEventId: created.event_id, operation: "update", state: "Accepted", reason: "verified", recordedAt: "2026-07-30T00:01:00.000Z" });
    const deleted = createTriageEvent({ scan: source, finding: item, annotationId: created.annotation_id, previousEventId: updated.event_id, operation: "delete", state: "Accepted", reason: "superseded", recordedAt: "2026-07-30T00:02:00.000Z" });
    await writeTriageEvent(created, { root: directory }); await writeTriageEvent(updated, { root: directory }); await writeTriageEvent(deleted, { root: directory });
    const snapshot = await inspectTriageStore(source, { root: directory, includeMemory: false });
    expect(snapshot.events).toHaveLength(3);
    expect(snapshot.annotations[0]).toMatchObject({ annotation_id: created.annotation_id, deleted: true, reason: "superseded" });
  });

  test("rejects standalone updates and immutable identity changes during projection", async () => {
    const directory = await root(); const source = scan(); const item = source.findings[0]!;
    const standalone = createTriageEvent({ scan: source, finding: item, annotationId: "triage-00000000-0000-4000-8000-000000000011", previousEventId: "event-00000000-0000-4000-8000-000000000099", operation: "update", state: "Accepted", reason: "bad" });
    await writeTriageEvent(standalone, { root: directory });
    const created = createTriageEvent({ scan: source, finding: item, state: "Needs review", reason: "ok", recordedAt: "2026-07-30T00:00:00.000Z" });
    await writeTriageEvent(created, { root: directory });
    const changed = { ...createTriageEvent({ scan: source, finding: item, annotationId: created.annotation_id, previousEventId: created.event_id, operation: "update", state: "Accepted", reason: "bad", recordedAt: "2026-07-30T00:01:00.000Z" }), finding_identity: { ...created.finding_identity, fingerprint: "changed" } };
    await writeTriageEvent(changed, { root: directory });
    const snapshot = await inspectTriageStore(source, { root: directory, includeMemory: false });
    expect(snapshot.corrupt_record_count).toBe(2);
    expect(snapshot.annotations).toHaveLength(1);
    expect(snapshot.annotations[0]?.state).toBe("Needs review");
  });

  test("scope digest prevents annotations leaking between repositories", async () => {
    const directory = await root(); const first = scan(1, "/one"); const second = scan(2, "/two");
    await writeTriageEvent(createTriageEvent({ scan: first, finding: first.findings[0]!, state: "Accepted", reason: "one" }), { root: directory });
    expect((await inspectTriageStore(first, { root: directory, includeMemory: false })).annotations).toHaveLength(1);
    expect((await inspectTriageStore(second, { root: directory, includeMemory: false })).annotations).toHaveLength(0);
  });

  test("atomic no-replace rejects collisions and cleans temporary files", async () => {
    const directory = await root(); const source = scan();
    const event = createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Accepted", reason: "one", eventId: "event-00000000-0000-4000-8000-000000000001" });
    await writeTriageEvent(event, { root: directory });
    await expect(writeTriageEvent(event, { root: directory })).rejects.toMatchObject({ code: "EEXIST" });
    const failed = createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Accepted", reason: "two" });
    await expect(writeTriageEvent(failed, { root: directory, linkFile: vi.fn(async () => { throw new Error("injected link failure"); }) as never })).rejects.toThrow(/injected/);
    const eventDir = join(directory, triageScopeForScan(source).scope_id, "events");
    expect((await readdir(eventDir)).filter((name) => name.includes(".tmp"))).toEqual([]);
    expect((await inspectTriageStore(source, { root: directory, includeMemory: false })).events).toHaveLength(1);
  });

  test("isolates corrupt, symlinked and oversized records", async () => {
    const directory = await root(); const source = scan();
    const valid = createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Accepted", reason: "ok" });
    await writeTriageEvent(valid, { root: directory });
    const eventDir = join(directory, triageScopeForScan(source).scope_id, "events");
    await writeFile(join(eventDir, "event-00000000-0000-4000-8000-000000000002.json"), "{bad");
    await writeFile(join(eventDir, "event-00000000-0000-4000-8000-000000000003.json"), "x".repeat(TRIAGE_EVENT_MAX_BYTES + 1));
    await symlink(join(eventDir, `${valid.event_id}.json`), join(eventDir, "event-00000000-0000-4000-8000-000000000004.json"));
    const snapshot = await inspectTriageStore(source, { root: directory, includeMemory: false });
    expect(snapshot.events).toHaveLength(1); expect(snapshot.corrupt_record_count).toBe(3);
  });

  test("redacts forged-store secrets and rejects malicious control characters", async () => {
    const directory = await root(); const source = scan(); const token = "sk_live_0123456789abcdefghij";
    expect(() => createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Accepted", reason: "bad\nline" })).toThrow(/control/i);
    const forged = createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Accepted", reason: "safe" });
    const eventDir = join(directory, triageScopeForScan(source).scope_id, "events"); await mkdir(eventDir, { recursive: true });
    await writeFile(join(eventDir, `${forged.event_id}.json`), JSON.stringify({ ...forged, reason: `found ${token}`, actor: token }));
    const blob = JSON.stringify(await inspectTriageStore(source, { root: directory, includeMemory: false }));
    expect(blob).not.toContain(token); expect(blob).toContain("redacted");
  });

  test("matching is exact and never mutates raw findings or counts", async () => {
    const directory = await root(); const source = scan(); const original = JSON.stringify(source.findings);
    await writeTriageEvent(createTriageEvent({ scan: source, finding: source.findings[0]!, state: "False positive", reason: "context" }), { root: directory });
    const snapshot = await inspectTriageStore(source, { root: directory, includeMemory: false });
    expect(matchingTriageAnnotations(source, snapshot)).toHaveLength(1);
    expect(JSON.stringify(source.findings)).toBe(original); expect(source.summary.total).toBe(1);
    expect(matchingTriageAnnotations(scan(2, "/repo", [finding("different")]), snapshot)).toHaveLength(0);
  });

  test("verification mode keeps default-root triage in memory and off disk", async () => {
    expect(triagePersistenceDisabled()).toBe(true);
    const source = scan(991); const event = createTriageEvent({ scan: source, finding: source.findings[0]!, state: "Needs review", reason: "verification only" });
    await writeTriageEvent(event);
    const snapshot = await inspectTriageStore(source);
    expect(snapshot.events.some((candidate) => candidate.event_id === event.event_id)).toBe(true);
    await expect(access(join(MANAGED_TRIAGE, triageScopeForScan(source).scope_id, "events", `${event.event_id}.json`))).rejects.toMatchObject({ code: "ENOENT" });
  });
});
