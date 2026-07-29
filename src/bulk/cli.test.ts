import { describe, expect, test, vi } from "vitest";
import { runBulkCli, type BulkCliDependencies } from "./cli.js";
import type { BulkManifest } from "./schemas.js";

function manifest(coverage: "complete" | "partial" | "unknown"): BulkManifest {
  return {
    $schema: "https://codeinspectus.com/schemas/bulk/1.0.0/manifest.schema.json", schema_version: "1.0.0",
    run_id: "bulk-00000000-0000-4000-8000-000000000001", parent: "/repositories",
    created_at: "2026-07-30T00:00:00.000Z", updated_at: "2026-07-30T00:00:01.000Z",
    configuration: { concurrency: 2, max_repositories: 50, max_attempts: 2, scanners: ["ai"], max_findings: 200, include_compliance: false },
    discovery: { entry_limit: 10000, candidate_entries: 1, repositories_found: 1, repositories_selected: 1, repositories_omitted: 0, partial: coverage !== "complete", limitations: coverage === "complete" ? [] : ["bounded"] },
    repositories: [{ repository: "/repositories/a", relative_path: "a", state: coverage, attempts: 1, aggregate_coverage: coverage, finding_count: 0 }],
    aggregate: { coverage, total: 1, pending: 0, running: 0, complete: coverage === "complete" ? 1 : 0, partial: coverage === "partial" ? 1 : 0, unknown: coverage === "unknown" ? 1 : 0, failed: 0, cancelled: 0, finding_count: 0 },
  };
}

function capture() { const stdout: string[] = []; const stderr: string[] = []; return { stdout, stderr, io: { stdout: (value: string) => stdout.push(value), stderr: (value: string) => stderr.push(value) } }; }

describe("bulk CLI", () => {
  test("maps the bounded local options and emits a complete JSON result", async () => {
    const output = capture(); const run = vi.fn(async () => ({ manifest_path: "/evidence/bulk.json", resumed: false, manifest: manifest("complete") }));
    const deps: BulkCliDependencies = { run };
    expect(await runBulkCli(["scan", "/repositories", "--manifest", "/evidence/bulk.json", "--concurrency", "2", "--max-repositories", "50", "--max-attempts", "2", "--scanner", "ai", "--max-findings", "200", "--no-compliance", "--format", "json"], output.io, deps)).toBe(0);
    expect(run).toHaveBeenCalledWith(expect.objectContaining({ parent: "/repositories", manifestPath: "/evidence/bulk.json", concurrency: 2, maxRepositories: 50, maxAttempts: 2, scanners: ["ai"], maxFindings: 200, includeCompliance: false, signal: expect.any(AbortSignal) }));
    expect(JSON.parse(output.stdout.join(""))).toMatchObject({ schema_version: "1.0.0", manifest_path: "/evidence/bulk.json", resumed: false, aggregate: { coverage: "complete" } });
    expect(output.stderr).toEqual([]);
  });

  test("fails closed when any repository or discovery scope is partial", async () => {
    const output = capture();
    expect(await runBulkCli(["scan", "/repositories"], output.io, { run: vi.fn(async () => ({ manifest_path: "/evidence/bulk.json", resumed: true, manifest: manifest("partial") })) })).toBe(2);
    expect(output.stderr.join(" ")).toMatch(/aggregate coverage is partial/i);
  });

  test.each([
    [[], /usage/i],
    [["clone", "/repositories"], /unknown bulk subcommand/i],
    [["scan"], /requires a parent/i],
    [["scan", "/repositories", "extra"], /exactly one/i],
    [["scan", "/repositories", "--concurrency", "9"], /1 to 8/i],
    [["scan", "/repositories", "--scanner", "magic"], /must contain/i],
    [["scan", "/repositories", "--github-org", "Synvoya"], /unknown bulk option/i],
  ])("rejects unsupported or unbounded command %#", async (argv, expected) => {
    const output = capture(); const run = vi.fn();
    expect(await runBulkCli(argv as string[], output.io, { run })).toBe(2);
    expect(`${output.stdout.join(" ")} ${output.stderr.join(" ")}`).toMatch(expected as RegExp);
    expect(run).not.toHaveBeenCalled();
  });
});
