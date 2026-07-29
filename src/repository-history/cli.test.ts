import { describe, expect, test, vi } from "vitest";
import { runRepositoryHistoryCli, type RepositoryHistoryCliDependencies } from "./cli.js";
import type { RepositoryHistoryManifest } from "./schemas.js";

function manifest(coverage: "complete" | "partial"): RepositoryHistoryManifest {
  return {
    $schema: "https://codeinspectus.com/schemas/repository-history/1.0.0/manifest.schema.json", schema_version: "1.0.0",
    run_id: "history-00000000-0000-4000-8000-000000000001", repository: "/repository",
    created_at: "2026-07-30T00:00:00.000Z", updated_at: "2026-07-30T00:00:01.000Z",
    bounds: { from: { requested: "HEAD", commit: "a".repeat(40) }, to: { requested: "HEAD", commit: "a".repeat(40) }, since: "2026-07-01T00:00:00.000Z", until: "2026-07-31T00:00:00.000Z", max_commits: 1, max_findings: 200, include_compliance: true },
    discovery: { selected_commits: 1, available_at_least: coverage === "partial" ? 2 : 1, truncated: coverage === "partial", shallow_repository: false, partial: coverage === "partial", limitations: coverage === "partial" ? ["bounded"] : [] },
    commits: [{ commit: "a".repeat(40), parents: [], committer_at: "2026-07-30T00:00:00.000Z", temporal_scope: "selected_head", interpretation: "offline snapshot", state: "complete", changes: [], change_metadata_partial: false, scan_id: "scan-00000000-0000-4000-8000-000000000001", aggregate_coverage: "complete", finding_count: 0, started_at: "2026-07-30T00:00:00.000Z", completed_at: "2026-07-30T00:00:01.000Z" }],
    aggregate: { coverage, total: 1, pending: 0, complete: 1, partial: 0, unknown: 0, failed: 0, cancelled: 0, finding_count: 0 },
  };
}

function capture() { const stdout: string[] = []; const stderr: string[] = []; return { stdout, stderr, io: { stdout: (value: string) => stdout.push(value), stderr: (value: string) => stderr.push(value) } }; }
const exact = ["scan", "/repository", "--from", "v1", "--to", "HEAD", "--since", "2026-07-01T00:00:00Z", "--until", "2026-07-31T00:00:00Z", "--max-commits", "10", "--format", "json"];

describe("repository-history CLI", () => {
  test("requires and maps every explicit bound", async () => {
    const output = capture(); const run = vi.fn(async () => ({ manifest_path: "/evidence/history.json", manifest: manifest("complete") }));
    expect(await runRepositoryHistoryCli(exact, output.io, { run })).toBe(0);
    expect(run).toHaveBeenCalledWith(expect.objectContaining({ repository: "/repository", from: "v1", to: "HEAD", since: "2026-07-01T00:00:00Z", until: "2026-07-31T00:00:00Z", maxCommits: 10, signal: expect.any(AbortSignal) }));
    expect(JSON.parse(output.stdout.join(""))).toMatchObject({ schema_version: "1.0.0", manifest_path: "/evidence/history.json" });
  });

  test("fails closed for partial history", async () => {
    const output = capture(); const deps: RepositoryHistoryCliDependencies = { run: vi.fn(async () => ({ manifest_path: "/evidence/history.json", manifest: manifest("partial") })) };
    expect(await runRepositoryHistoryCli(exact, output.io, deps)).toBe(2);
    expect(output.stderr.join(" ")).toMatch(/aggregate coverage is partial/i);
  });

  test.each([
    [[], /requires explicit/i], [["scan", "/repository"], /--from.*--to.*--since.*--until.*--max-commits/i],
    [["scan", "/repository", "--from", "a", "--to", "b", "--since", "x", "--until", "y", "--max-commits", "51"], /1 to 50/i],
    [["clone", "/repository"], /unknown history subcommand/i],
    [[...exact, "--github-org", "Synvoya"], /unknown history option/i],
  ])("rejects disabled, missing, remote or unbounded mode %#", async (argv, expected) => {
    const output = capture(); const run = vi.fn();
    expect(await runRepositoryHistoryCli(argv as string[], output.io, { run })).toBe(2);
    expect(`${output.stdout.join(" ")} ${output.stderr.join(" ")}`).toMatch(expected as RegExp);
    expect(run).not.toHaveBeenCalled();
  });
});
