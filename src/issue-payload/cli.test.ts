import { access, mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import { runIssuePayloadCli } from "./cli.js";
import { createIssuePayload } from "./index.js";
import { issueTestScan } from "./test-fixture.js";

const cleanup: string[] = [];
afterEach(async () => { await Promise.all(cleanup.splice(0).map((entry) => rm(entry, { recursive: true, force: true }))); });
function capture() { const stdout: string[] = []; const stderr: string[] = []; return { stdout, stderr, io: { stdout: (value: string) => stdout.push(value), stderr: (value: string) => stderr.push(value) } }; }

describe("issue-payload CLI", () => {
  test("maps one exact finding and emits the mandatory warning without submitting", async () => {
    const output = capture(); const scan = issueTestScan(); const load = vi.fn(async () => scan); const create = vi.fn(createIssuePayload);
    expect(await runIssuePayloadCli(["export", scan.scan_id, "CI-0001", "--adapter", "github", "--visibility", "public"], output.io, { load, create })).toBe(0);
    expect(load).toHaveBeenCalledWith(scan.scan_id); expect(create).toHaveBeenCalledWith(scan, "CI-0001", "github", "public");
    expect(JSON.parse(output.stdout.join(""))).toMatchObject({ adapter: "github", destination: { visibility: "public", submission: "not_performed" } });
    expect(output.stderr.join(" ")).toMatch(/PUBLIC DESTINATION.*No network submission/i);
  });

  test("rejects repository-contained output", async () => {
    const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-issue-cli-")); cleanup.push(root);
    const repository = join(root, "repository"); await mkdir(repository); const scan = issueTestScan(repository); const destination = join(repository, "issue.json"); const output = capture();
    expect(await runIssuePayloadCli(["export", scan.scan_id, "CI-0001", "--adapter", "jira", "--visibility", "private", "--output", destination], output.io, { load: async () => scan, create: createIssuePayload })).toBe(2);
    await expect(access(destination)).rejects.toThrow();
    expect(output.stderr.join(" ")).toMatch(/inside the scan target/i);
  });

  test.each([
    [[], /usage/i],
    [["submit", "scan-00000000-0000-4000-8000-000000000001", "CI-0001"], /submission is not supported/i],
    [["export", "../../bad", "CI-0001", "--adapter", "github", "--visibility", "private"], /scan_id must be|generated id/i],
    [["export", "scan-00000000-0000-4000-8000-000000000001", "CI-0001", "--adapter", "github"], /requires explicit.*visibility/i],
    [["export", "scan-00000000-0000-4000-8000-000000000001", "CI-0001", "--adapter", "slack", "--visibility", "private"], /adapter must be/i],
  ])("rejects unsafe or unsupported operation %#", async (argv, expected) => {
    const output = capture(); const load = vi.fn(); const create = vi.fn();
    expect(await runIssuePayloadCli(argv as string[], output.io, { load, create })).toBe(2);
    expect(`${output.stdout.join(" ")} ${output.stderr.join(" ")}`).toMatch(expected as RegExp);
    expect(load).not.toHaveBeenCalled(); expect(create).not.toHaveBeenCalled();
  });
});
