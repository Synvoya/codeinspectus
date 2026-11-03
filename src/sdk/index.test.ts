import { access, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { CodeInspectusClient, CodeInspectusSdkError, SDK_COMPATIBILITY, type Finding } from "./index.js";
import { runBundleCli } from "../bundle/cli.js";
import { createSealedBundle, verifySealedBundle } from "../bundle/index.js";
import { BUNDLE_SCHEMA_VERSION } from "../bundle/schemas.js";

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
  test("a CLI usage error reports its exit code and stderr reason", async () => {
    const script = await fakeCli(`process.stderr.write("CodeInspectus history: History --format must be text or json.\\n"); process.exitCode = 2;`);
    const client = new CodeInspectusClient({ command: process.execPath, commandArgs: [script] });
    await expect(client.exportScan("scan-1")).rejects.toMatchObject({ code: "INVALID_JSON", message: expect.stringContaining("(exit 2): CodeInspectus history: History --format must be text or json.") });
  });

  test("never lets a path or identifier operand parse as a CLI option", async () => {
    const script = await fakeCli(`process.stdout.write(JSON.stringify({ schema_version: "3.0.0", scan: {}, coverage: { aggregate: "complete" }, repository_trust: { schema_version: "1.0.0" }, findings: [] }));`);
    const client = new CodeInspectusClient({ command: process.execPath, commandArgs: [script], cwd: tmpdir() });
    const result = await client.scan("--working-tree");
    expect(result.args[1]).toBe(resolve(tmpdir(), "--working-tree"));
    await expect(client.exportScan("--format=csv")).rejects.toThrow(TypeError);
    await expect(client.createIssuePayload("scan-1", "--output=/tmp/x", { adapter: "github", visibility: "private" })).rejects.toThrow(TypeError);
  });

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
    expect(result.data).toMatchObject({ schema_version: "3.0.0", scan: { target: resolve(target) }, coverage: { aggregate: "partial" }, repository_trust: { schema_version: "1.0.0" } });
    expect(result.args).toEqual(["scan", resolve(target), "--format", "json", "--scanner", "ai", "--no-compliance"]);
    await expect(access("/tmp/sdk-shell-injection-must-not-exist")).rejects.toThrow();
    // Final review I-2: the typed scan can opt in to accepting declared coverage gaps.
    const accepted = await client.scan(target, { acceptGaps: ["php-sast", "deno-lock"] });
    expect(accepted.args).toEqual(["scan", resolve(target), "--format", "json", "--accept-gaps", "php-sast,deno-lock"]);
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
    expect(repositoryHistory.args).toEqual(["history", "scan", resolve("/repo"), "--from", "v1", "--to", "HEAD", "--since", "2026-07-01T00:00:00Z", "--until", "2026-07-31T00:00:00Z", "--max-commits", "10", "--format", "json", "--scanner", "ai", "--no-compliance"]);
    const issue = await client.createIssuePayload("scan-00000000-0000-4000-8000-000000000001", "CI-0001", { adapter: "github", visibility: "private", output: "/evidence/issue.json" });
    expect(issue.args).toEqual(["issue", "export", "scan-00000000-0000-4000-8000-000000000001", "CI-0001", "--adapter", "github", "--visibility", "private", "--output", "/evidence/issue.json"]);
    const triage = await client.listTriage("scan-00000000-0000-4000-8000-000000000001", { limit: 2 });
    expect(triage.args).toContain("triage");
    const bundle = await client.verifyBundle("/evidence/bundle");
    expect(bundle.args).toEqual(["bundle", "verify", resolve("/evidence/bundle"), "--format", "json"]);
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
    expect(SDK_COMPATIBILITY).toMatchObject({ export_schema: "3.0.0", repository_trust_schema: "1.0.0", cleanup_schema: "1.0.0", bundle_schema: "1.1.0", bundle_schemas_verified: ["1.0.0", "1.1.0"], repository_history_schema: "1.0.0", issue_payload_schema: "1.0.0", cli_major: 3 });
    // The SDK keeps literals (no runtime import of the bundle schemas); they must match what this release seals.
    expect(SDK_COMPATIBILITY.bundle_schema).toBe(BUNDLE_SCHEMA_VERSION);
    expect(Object.isFrozen(SDK_COMPATIBILITY.bundle_schemas_verified)).toBe(true);
  });
});

describe("SDK finding type", () => {
  test("accepts the synvoya engine id and the optional engine_family display field", () => {
    // Compile-time contract (checked by tsc): both fields are part of the public Finding type.
    const finding: Finding = {
      id: "CI-0001", fingerprint: "fp", title: "t", severity: "high", engine: "synvoya", engines: ["synvoya", "trivy"],
      engine_family: "synvoya", rule_id: "GHSA-aaaa-bbbb-cccc", cwe: ["CWE-1395"],
      location: { file: "package.json", start_line: 1, end_line: 1 }, message: "m",
      remediation: { summary: "s", steps: [], references: [] }, frameworks: [], confidence: "high",
    };
    const upstream: Finding = { ...finding, engine: "trivy", engines: ["trivy"], engine_family: undefined };
    expect([finding.engine, finding.engine_family, upstream.engine_family]).toEqual(["synvoya", "synvoya", undefined]);
  });
});

describe("SDK bundle verification against real sealed bundles", () => {
  const BUNDLE_SEALED_BY_3_3_2 = "fixtures/sealed-bundle-3.3.2/bundle";

  /**
   * Runs the real `bundle verify --format json` in-process (full seal and artifact verification), then
   * hands its exact stdout to the SDK through a process that replays it only for the expected argv.
   */
  async function verifyThroughSdk(directory: string) {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const exit = await runBundleCli(["verify", directory, "--format", "json"], { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) });
    expect(exit, stderr.join("")).toBe(0);
    const expectedArgs = ["bundle", "verify", resolve(directory), "--format", "json"];
    const replay = await fakeCli(`
      if (JSON.stringify(process.argv.slice(2)) !== ${JSON.stringify(JSON.stringify(expectedArgs))}) { process.stderr.write("unexpected argv\\n"); process.exitCode = 9; }
      else process.stdout.write(${JSON.stringify(stdout.join(""))});
    `);
    const result = await new CodeInspectusClient({ command: process.execPath, commandArgs: [replay] }).verifyBundle(directory);
    return { result, manifest: JSON.parse(stdout.join("")) as unknown };
  }

  test("verifyBundle accepts a 1.0.0 bundle sealed by 3.3.2 and a 1.1.0 bundle sealed by this release", async () => {
    const legacy = await verifyThroughSdk(BUNDLE_SEALED_BY_3_3_2);
    expect(legacy.result.data).toEqual(legacy.manifest);
    expect(legacy.result.data).toMatchObject({ schema_version: "1.0.0", created_by: { version: "3.3.2" } });

    const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-sdk-bundle-"));
    cleanup.push(root);
    const resealed = join(root, "bundle");
    await createSealedBundle((await verifySealedBundle(BUNDLE_SEALED_BY_3_3_2)).scan, resealed);
    const current = await verifyThroughSdk(resealed);
    expect(current.result.data).toEqual(current.manifest);
    expect(current.result.data).toMatchObject({ schema_version: "1.1.0", schemas: { bundle: "1.1.0" } });
    expect(current.result.data.commodity_engines.map((engine) => engine.engine)).toEqual(["opengrep", "gitleaks", "trivy", "osv-scanner"]);
  }, SDK_MULTI_PROCESS_TEST_TIMEOUT_MS);

  test("verifyBundle fails closed on an unknown bundle schema version", async () => {
    const script = await fakeCli(`process.stdout.write(JSON.stringify({ schema_version: "2.0.0", bundle_id: "bundle-test" }));`);
    const client = new CodeInspectusClient({ command: process.execPath, commandArgs: [script] });
    await expect(client.verifyBundle("/evidence/bundle")).rejects.toMatchObject({
      code: "INCOMPATIBLE_CONTRACT",
      message: expect.stringMatching(/1\.0\.0.*1\.1\.0/),
      result: { exitCode: 0 },
    });
  });
});
