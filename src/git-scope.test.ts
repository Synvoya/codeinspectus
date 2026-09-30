import { execFile } from "node:child_process";
import { access, mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
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

describe("Git-scoped enforcement cannot be bypassed", () => {
  const SECRET_FILE = `export const key = "sk_live_${"4eC39HqLyjWDarjtT1zdp7dc"}";\n`;

  test("a finding introduced in an unchanged file by deleting another file is primary", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "0001_init.sql"),
      "create table public.payments (\n  id uuid primary key,\n  user_id uuid not null\n);\n");
    await writeFile(join(root, "supabase", "migrations", "0002_rls.sql"),
      "alter table public.payments enable row level security;\ncreate policy own on public.payments for select using (auth.uid() = user_id);\n");
    await git(root, "add", ".");
    await git(root, "commit", "-qm", "rls");
    await git(root, "rm", "-q", "supabase/migrations/0002_rls.sql");
    await git(root, "commit", "-qm", "drop rls");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "commit_diff", base: "HEAD~1", head: "HEAD" },
    );

    const rls = result.findings.filter((finding) => finding.rule_id === "ci-ai-rls-missing");
    expect(rls.length).toBeGreaterThan(0);
    expect(rls.every((finding) => finding.scope_role === "primary")).toBe(true);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test.each([["skip-worktree", "--skip-worktree"], ["assume-unchanged", "--assume-unchanged"]])(
    "an edited %s file is still in working-tree scope",
    async (_label, flag) => {
      process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
      const root = await repository();
      await git(root, "update-index", flag, "app.ts");
      await writeFile(join(root, "app.ts"), SECRET_FILE);

      const result = await runGitScopedScan(
        { path: root, scanners: ["ai"], include_compliance: false },
        { mode: "working_tree", base: "HEAD" },
      );

      expect(result.git_scope?.primary_paths).toContain("app.ts");
    },
    GIT_INTEGRATION_TEST_TIMEOUT_MS,
  );

  test("a file untracked with git rm --cached and gitignored is still in working-tree scope", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    await git(root, "rm", "-q", "--cached", "app.ts");
    await writeFile(join(root, ".gitignore"), "ignored/\napp.ts\n");
    await writeFile(join(root, "app.ts"), SECRET_FILE);

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "working_tree", base: "HEAD" },
    );

    expect(result.git_scope?.primary_paths).toContain("app.ts");
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("a monorepo package scan never promotes findings from another package", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    await mkdir(join(root, "packages", "app"), { recursive: true });
    await mkdir(join(root, "packages", "other"), { recursive: true });
    await writeFile(join(root, "packages", "app", "index.ts"), "export const app = 1;\n");
    await git(root, "add", ".");
    await git(root, "commit", "-qm", "packages");
    await writeFile(join(root, "packages", "app", "index.ts"), "export const app = 2;\n");
    await writeFile(join(root, "packages", "other", "config.ts"), SECRET_FILE);
    await git(root, "add", ".");
    await git(root, "commit", "-qm", "change both");

    const result = await runGitScopedScan(
      { path: join(root, "packages", "app"), scanners: ["ai"], include_compliance: false },
      { mode: "commit_diff", base: "HEAD~1", head: "HEAD" },
    );

    expect(result.findings.filter((finding) => finding.location.file.startsWith("packages/other")).every((finding) => finding.scope_role === "supporting_context")).toBe(true);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("a committed in-repo symlink does not make working-tree scope partial", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    await writeFile(join(root, "AGENTS.md"), "# agents\n");
    await symlink("AGENTS.md", join(root, "CLAUDE.md"));
    await writeFile(join(root, "legacy.ts"), SECRET_FILE);
    await git(root, "add", ".");
    await git(root, "commit", "-qm", "docs and legacy");
    await writeFile(join(root, "app.ts"), "export const changed = true;\n");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "working_tree", base: "HEAD" },
    );

    expect(result.git_scope?.completeness).toBe("complete");
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("a committed code-named symlink in the base fails closed instead of risking a hidden finding", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    await writeFile(join(root, "real.ts"), "export const real = 1;\n");
    await symlink("real.ts", join(root, "alias.ts"));
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "0001_init.sql"),
      "create table public.payments (\n  id uuid primary key,\n  user_id uuid not null\n);\n");
    await git(root, "add", ".");
    await git(root, "commit", "-qm", "alias and existing finding");
    await writeFile(join(root, "app.ts"), "export const changed = true;\n");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "working_tree", base: "HEAD" },
    );

    expect(result.git_scope?.completeness).toBe("partial");
    expect(result.git_scope?.limitations.join(" ")).toMatch(/alias\.ts/);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("findings inside a submodule are never promoted as introduced", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const upstream = await repository();
    await mkdir(join(upstream, "supabase", "migrations"), { recursive: true });
    await writeFile(join(upstream, "supabase", "migrations", "0001_init.sql"),
      "create table public.payments (\n  id uuid primary key,\n  user_id uuid not null\n);\n");
    await git(upstream, "add", ".");
    await git(upstream, "commit", "-qm", "table without rls");
    const root = await repository();
    await git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "libs/shared");
    await git(root, "commit", "-qm", "add submodule");
    await writeFile(join(root, "app.ts"), "export const changed = true;\n");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "working_tree", base: "HEAD" },
    );

    const inSubmodule = result.findings.filter((finding) => finding.location.file.startsWith("libs/shared/"));
    expect(inSubmodule.length).toBeGreaterThan(0);
    expect(inSubmodule.every((finding) => finding.scope_role !== "primary")).toBe(true);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("findings in git-ignored files are never promoted to primary", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    await mkdir(join(root, "ignored"), { recursive: true });
    await writeFile(join(root, "ignored", "local.ts"), SECRET_FILE);
    await writeFile(join(root, "app.ts"), "export const changed = true;\n");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "working_tree", base: "HEAD" },
    );

    expect(result.findings.filter((finding) => finding.location.file.startsWith("ignored/")).every((finding) => finding.scope_role !== "primary")).toBe(true);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("a submodule pointer change is not hidden by .gitmodules ignore=all", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const upstream = await repository();
    const root = await repository();
    await git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "vendor/lib");
    await git(root, "config", "-f", ".gitmodules", "submodule.vendor/lib.ignore", "all");
    await git(root, "add", ".gitmodules");
    await git(root, "commit", "-qm", "add submodule");
    await writeFile(join(upstream, "app.ts"), "export const upstreamChange = true;\n");
    await git(upstream, "commit", "-qam", "upstream change");
    await git(join(root, "vendor/lib"), "pull", "-q", "origin", await git(upstream, "rev-parse", "--abbrev-ref", "HEAD"));
    // Newer git skips staging an ignore=all submodule unless forced.
    await git(root, "add", "--force", "vendor/lib");
    await git(root, "commit", "-qm", "bump submodule");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "commit_diff", base: "HEAD~1", head: "HEAD" },
    );

    expect(result.git_scope?.entries.some((entry) => entry.path === "vendor/lib" && entry.submodule)).toBe(true);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

  test("a commit diff is measured from the merge-base, so base-only changes are not attributed to the branch", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    const main = await git(root, "rev-parse", "--abbrev-ref", "HEAD");
    await git(root, "checkout", "-q", "-b", "feature");
    await writeFile(join(root, "feature.ts"), "export const feature = true;\n");
    await git(root, "add", "feature.ts");
    await git(root, "commit", "-qm", "feature");
    await git(root, "checkout", "-q", main);
    await writeFile(join(root, "app.ts"), "export const changedOnMain = true;\n");
    await git(root, "add", "app.ts");
    await git(root, "commit", "-qm", "main change");

    const result = await runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "commit_diff", base: main, head: "feature" },
    );

    expect(result.git_scope?.primary_paths).toEqual(["feature.ts"]);
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);
});

describe("read-only Git-scoped scans", () => {
  test("refuses a working-tree comparison instead of running repository filter drivers", async () => {
    process.env[INTERNAL_DISABLE_SCAN_PERSISTENCE_ENV] = "1";
    const root = await repository();
    const marker = `${root}-filter-executed`;
    const script = `${root}-filter.sh`;
    cleanup.push(marker, script);
    await writeFile(script, `#!/bin/sh\ntouch '${marker}'\ncat\n`, { mode: 0o755 });
    await writeFile(join(root, ".gitattributes"), "*.ts filter=evil\n");
    await git(root, "config", "filter.evil.clean", script);
    await writeFile(join(root, "app.ts"), "export const changed = true;\n");

    await expect(runGitScopedScan(
      { path: root, scanners: ["ai"], include_compliance: false },
      { mode: "working_tree", base: "HEAD" },
    )).rejects.toThrow(/filter driver/i);
    await expect(access(marker)).rejects.toThrow();
  }, GIT_INTEGRATION_TEST_TIMEOUT_MS);

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
