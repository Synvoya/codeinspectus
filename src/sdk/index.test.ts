import { access, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { CodeInspectusClient, CodeInspectusSdkError, SDK_COMPATIBILITY } from "./index.js";

const cleanup: string[] = [];
// This case launches six short-lived Node processes in sequence. Bound only that integration-style
// assertion for slower or heavily contended CI hosts; keep Vitest's unit-test default everywhere else.
const SDK_MULTI_PROCESS_TEST_TIMEOUT_MS = 30_000;

async function fakeCli(source: string): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-sdk-test-"));
  cleanup.push(root);
  const path = join(root, "fake.mjs");
  await writeFile(path, source);
  return path;
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("public SDK process wrapper", () => {
  test("passes arguments without a shell and returns valid partial-policy JSON at exit 2", async () => {
    const script = await fakeCli(`
      const args = process.argv.slice(2);
      process.stdout.write(JSON.stringify({ schema_version: "3.0.0", scan: { target: args[1] }, coverage: { aggregate: "partial" }, repository_trust: { schema_version: "1.0.0" }, findings: [] }));
      process.stderr.write("partial coverage\\n");
      process.exitCode = 2;
    `);
    const target = "; touch /tmp/sdk-shell-injection-must-not-exist";
    const client = new CodeInspectusClient({ command: process.execPath, commandArgs: [script] });
    const result = await client.scan(target, { scanners: ["ai"], includeCompliance: false });
    expect(result.exitCode).toBe(2);
    expect(result.data).toMatchObject({ schema_version: "3.0.0", scan: { target }, coverage: { aggregate: "partial" }, repository_trust: { schema_version: "1.0.0" } });
    expect(result.args).toEqual(["scan", target, "--format", "json", "--scanner", "ai", "--no-compliance"]);
    await expect(access("/tmp/sdk-shell-injection-must-not-exist")).rejects.toThrow();
  });

  test("rejects incompatible typed contracts with the bounded process result attached", async () => {
    const script = await fakeCli(`process.stdout.write(JSON.stringify({ schema_version: "9.0.0" }));`);
    const client = new CodeInspectusClient({ command: process.execPath, commandArgs: [script] });
    await expect(client.exportScan("scan-00000000-0000-4000-8000-000000000001")).rejects.toMatchObject({
      code: "INCOMPATIBLE_CONTRACT", result: { exitCode: 0 },
    });
  });

  test("maps history, repository-history, triage, and bundle helpers to their versioned JSON commands", async () => {
    const script = await fakeCli(`
      const args = process.argv.slice(2);
      const family = args[0];
      const data = family === "bundle"
        ? { schema_version: "1.0.0", bundle_id: "bundle-test" }
        : family === "triage"
          ? { schema_version: "1.0.0", annotations: [] }
          : { schema_version: "1.0.0", entries: [], items: [] };
      process.stdout.write(JSON.stringify(data));
    `);
    const client = new CodeInspectusClient({ command: process.execPath, commandArgs: [script] });
    const history = await client.listHistory({ repository: "/repo", limit: 5 });
    expect(history.args).toEqual(["scans", "list", "--format", "json", "--repository", "/repo", "--limit", "5"]);
    const comparison = await client.compareHistory("scan-00000000-0000-4000-8000-000000000001", "scan-00000000-0000-4000-8000-000000000002");
    expect(comparison.args.slice(0, 2)).toEqual(["scans", "compare"]);
    const repositoryHistory = await client.scanRepositoryHistory("/repo", { from: "v1", to: "HEAD", since: "2026-07-01T00:00:00Z", until: "2026-07-31T00:00:00Z", maxCommits: 10, scanners: ["ai"], includeCompliance: false });
    expect(repositoryHistory.args).toEqual(["history", "scan", "/repo", "--from", "v1", "--to", "HEAD", "--since", "2026-07-01T00:00:00Z", "--until", "2026-07-31T00:00:00Z", "--max-commits", "10", "--format", "json", "--scanner", "ai", "--no-compliance"]);
    const issue = await client.createIssuePayload("scan-00000000-0000-4000-8000-000000000001", "CI-0001", { adapter: "github", visibility: "private", output: "/evidence/issue.json" });
    expect(issue.args).toEqual(["issue", "export", "scan-00000000-0000-4000-8000-000000000001", "CI-0001", "--adapter", "github", "--visibility", "private", "--output", "/evidence/issue.json"]);
    const triage = await client.listTriage("scan-00000000-0000-4000-8000-000000000001", { limit: 2 });
    expect(triage.args).toContain("triage");
    const bundle = await client.verifyBundle("/evidence/bundle");
    expect(bundle.args).toEqual(["bundle", "verify", "/evidence/bundle", "--format", "json"]);
  }, SDK_MULTI_PROCESS_TEST_TIMEOUT_MS);

  test("bounds output and timeout independently", async () => {
    const noisy = await fakeCli(`process.stdout.write("x".repeat(4096)); setTimeout(() => {}, 10_000);`);
    const bounded = new CodeInspectusClient({ command: process.execPath, commandArgs: [noisy], maxOutputBytes: 128, timeoutMs: 5_000 });
    await expect(bounded.run(["--version"])).rejects.toMatchObject({ code: "OUTPUT_LIMIT" });

    const slow = await fakeCli(`setTimeout(() => process.stdout.write("late"), 10_000);`);
    const timed = new CodeInspectusClient({ command: process.execPath, commandArgs: [slow], timeoutMs: 25 });
    await expect(timed.run(["--version"])).rejects.toMatchObject({ code: "TIMEOUT" });
  });

  test("fails before launch for an already-aborted operation and exports exact compatibility metadata", async () => {
    const controller = new AbortController(); controller.abort();
    const client = new CodeInspectusClient();
    await expect(client.run(["--version"], { signal: controller.signal })).rejects.toBeInstanceOf(CodeInspectusSdkError);
    await expect(client.run(["--version"], { signal: controller.signal })).rejects.toMatchObject({ code: "ABORTED" });
    expect(SDK_COMPATIBILITY).toMatchObject({ export_schema: "3.0.0", repository_trust_schema: "1.0.0", bundle_schema: "1.0.0", repository_history_schema: "1.0.0", issue_payload_schema: "1.0.0", cli_major: 3 });
  });
});
