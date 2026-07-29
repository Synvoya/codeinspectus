import { execFile } from "node:child_process";
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, test } from "vitest";
import { INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV } from "./store.js";
import { runGitScopedScan } from "./git-scope.js";

const execute = promisify(execFile);
const cleanup: string[] = [];
// These are integration tests: each case creates a real repository and some cases run a native scan.
// Keep their allowance local so a slow CI filesystem cannot trip Vitest's 5s unit-test default.
const GIT_INTEGRATION_TEST_TIMEOUT_MS = 30_000;

async function git(root: string, ...args: string[]): Promise<string> {
  const result = await execute("git", ["-C", root, ...args], { encoding: "utf8" });
  return result.stdout.trim();
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codeinspectus-git-scope-test-"));
  cleanup.push(root);
  await git(root, "init", "-q");
  await git(root, "config", "user.email", "test@codeinspectus.invalid");
  await git(root, "config", "user.name", "CodeInspectus Test");
  await writeFile(join(root, ".gitignore"), "ignored/\n");
  await writeFile(join(root, "package.json"), '{"name":"fixture","private":true}\n');
  await writeFile(join(root, "app.ts"), "export const safe = true;\n");
  await git(root, "add", ".");
  await git(root, "commit", "-qm", "base");
  return root;
}

afterEach(async () => {
  delete process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV];
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("read-only Git-scoped scans", () => {
  test("working-tree mode enumerates tracked, untracked, ignored, generated, and binary state without mutation", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    await writeFile(join(root, "app.ts"), "export const changed = true;\n");
    await writeFile(join(root, "untracked.ts"), "export const newFile = true;\n");
    await mkdir(join(root, "generated"));
    await writeFile(join(root, "generated", "client.ts"), "generated\n");
    await writeFile(join(root, "asset.bin"), Buffer.from([1, 0, 2, 3]));
    await symlink("app.ts", join(root, "linked.ts"));
    await mkdir(join(root, "ignored"));
    await writeFile(join(root, "ignored", "secret.ts"), "ignored\n");
    const before = await git(root, "status", "--porcelain=v1", "-z");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "working_tree", base: "HEAD" },
    );

    expect(result.target).toBe(await realpath(root));
    expect(result.git_scope).toMatchObject({ mode: "working_tree", supporting_context_scanned: true, completeness: "partial" });
    expect(result.git_scope?.base.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(result.git_scope?.entries).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: "modified", path: "app.ts", inspected: true }),
      expect.objectContaining({ status: "untracked", path: "untracked.ts", inspected: true }),
      expect.objectContaining({ status: "untracked", path: "generated/client.ts", generated: true, inspected: false }),
      expect.objectContaining({ status: "untracked", path: "asset.bin", binary: true, inspected: false }),
      expect.objectContaining({ status: "untracked", path: "linked.ts", inspected: false, note: expect.stringMatching(/symbolic-link/i) }),
      expect.objectContaining({ status: "ignored", path: "ignored/secret.ts", inspected: false }),
    ]));
    expect(await git(root, "status", "--porcelain=v1", "-z")).toBe(before);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("commit mode resolves exact revisions, materializes the head snapshot, tags changed findings, and leaves HEAD untouched", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    const base = await git(root, "rev-parse", "HEAD");
    await mkdir(join(root, ".github", "workflows"), { recursive: true });
    await writeFile(join(root, ".github", "workflows", "pwn.yml"), [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - run: npm test",
      ""].join("\n"));
    await git(root, "mv", "app.ts", "renamed.ts");
    await rm(join(root, ".gitignore"));
    await git(root, "add", ".");
    await git(root, "commit", "-qm", "head");
    const head = await git(root, "rev-parse", "HEAD");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "commit_diff", base, head },
    );

    expect(result.git_scope).toMatchObject({
      mode: "commit_diff", completeness: "complete",
      base: { requested: base, commit: base }, head: { requested: head, commit: head },
      primary_paths: [".github/workflows/pwn.yml", "renamed.ts"],
    });
    expect(result.git_scope?.entries).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: "added", path: ".github/workflows/pwn.yml" }),
      expect.objectContaining({ status: "deleted", path: ".gitignore", inspected: false }),
      expect.objectContaining({ status: "renamed", old_path: "app.ts", path: "renamed.ts" }),
    ]));
    expect(result.findings.some((finding) => finding.location.file === ".github/workflows/pwn.yml" && finding.scope_role === "primary")).toBe(true);
    expect(await git(root, "rev-parse", "HEAD")).toBe(head);
    expect(await git(root, "status", "--porcelain=v1")).toBe("");
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("rejects option-like and missing revisions before scanning", async () => {
    const root = await repository();
    await expect(runGitScopedScan({ path: root, scanners: ["ai"] }, { mode: "working_tree", base: "--help" }))
      .rejects.toThrow(/non-option Git revision/);
    await expect(runGitScopedScan({ path: root, scanners: ["ai"] }, { mode: "commit_diff", base: "HEAD" }))
      .rejects.toThrow(/requires an exact head revision/);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("keeps change status and submodule classification as separate exact dimensions", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    const base = await git(root, "rev-parse", "HEAD");
    await git(root, "update-index", "--add", "--cacheinfo", `160000,${base},vendor/component`);
    await git(root, "commit", "-qm", "add gitlink");
    const head = await git(root, "rev-parse", "HEAD");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "commit_diff", base, head },
    );

    expect(result.git_scope?.entries).toContainEqual(expect.objectContaining({
      status: "added", path: "vendor/component", submodule: true, inspected: false,
    }));
    expect(result.git_scope).toMatchObject({ completeness: "partial" });
    expect(result.git_scope?.limitations.join(" ")).toMatch(/submodule/i);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);
});
