/**
 * A scanned repository is untrusted input. Its .git/config can name programs that git would run
 * (fsmonitor hooks, signature verifiers, filter drivers). Scans must never execute them and must
 * never write to .git. Each test points such a key at a script that leaves a marker file.
 */
import { describe, expect, test } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { access, chmod, mkdtemp, readFile, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { detectGitSafety } from "./git-safety.js";
import { runScan } from "./scan.js";
import { gitHardenedEnv } from "./util/git.js";
import { defaultGitHistoryReader } from "./repository-trust/ai-provenance.js";

const git = promisify(execFile);

async function repo(): Promise<{ dir: string; marker: string; script: string }> {
  const dir = await mkdtemp(join(tmpdir(), "ci-git-hardening-"));
  const marker = join(dirname(dir), `${basename(dir)}-executed`);
  const script = join(dirname(dir), `${basename(dir)}-hook.sh`);
  await writeFile(script, `#!/bin/sh\ntouch '${marker}'\ncat\n`);
  await chmod(script, 0o755);
  await git("git", ["-C", dir, "init", "-q"]);
  await git("git", ["-C", dir, "config", "user.email", "t@example.com"]);
  await git("git", ["-C", dir, "config", "user.name", "t"]);
  await git("git", ["-C", dir, "config", "commit.gpgsign", "false"]);
  await writeFile(join(dir, "a.txt"), "one\n");
  await git("git", ["-C", dir, "add", "a.txt"]);
  await git("git", ["-C", dir, "commit", "-q", "-m", "init\n\nCo-authored-by: Claude <noreply@anthropic.com>"]);
  return { dir, marker, script };
}

async function executed(marker: string): Promise<boolean> {
  return access(marker).then(() => true, () => false);
}

async function makeStatDirty(dir: string): Promise<void> {
  const later = new Date(Date.now() + 60_000);
  await utimes(join(dir, "a.txt"), later, later);
}

// The hooks below are POSIX shell scripts; Git for Windows does not run them the same way.
describe.skipIf(process.platform === "win32")("git invocations treat the scanned repository's config as untrusted", () => {
  test("does not run a repository-configured fsmonitor hook", async () => {
    const { dir, marker, script } = await repo();
    await git("git", ["-C", dir, "config", "core.fsmonitor", script]);
    await makeStatDirty(dir);

    await detectGitSafety(dir);

    expect(await executed(marker)).toBe(false);
  });

  test("engine processes (Opengrep's own git ls-files) do not run a repository fsmonitor hook", async () => {
    const { dir, marker, script } = await repo();
    await writeFile(join(dir, "app.ts"), "export const q = (id: string) => db.query(`SELECT * FROM t WHERE id = ${id}`);\n");
    await git("git", ["-C", dir, "add", "app.ts"]);
    await git("git", ["-C", dir, "commit", "-q", "-m", "app"]);
    await git("git", ["-C", dir, "config", "core.fsmonitor", script]);
    await makeStatDirty(dir);

    const result = await runScan({ path: dir, scanners: ["sast"] });
    if (!result.engine_details.some((engine) => engine.engine === "opengrep" && engine.ran)) return; // engine not installed

    expect(await executed(marker)).toBe(false);
  }, 60_000);

  test("a parent's git -c parameters cannot override the hardening", () => {
    const env = gitHardenedEnv({ GIT_CONFIG_PARAMETERS: "'core.fsmonitor'='/tmp/hook.sh'", PATH: "/usr/bin" });

    expect(env.GIT_CONFIG_PARAMETERS).toBeUndefined();
  });

  test("pathspec semantics do not depend on the caller's environment", () => {
    const env = gitHardenedEnv({ GIT_LITERAL_PATHSPECS: "1", GIT_GLOB_PATHSPECS: "1", GIT_NOGLOB_PATHSPECS: "1", GIT_ICASE_PATHSPECS: "1", PATH: "/usr/bin" });

    for (const name of ["GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_ICASE_PATHSPECS"]) expect(env[name]).toBeUndefined();
  });

  test("does not refresh or lock the index while checking git safety", async () => {
    const { dir } = await repo();
    await makeStatDirty(dir);
    const before = createHash("sha256").update(await readFile(join(dir, ".git", "index"))).digest("hex");

    await detectGitSafety(dir);

    expect(createHash("sha256").update(await readFile(join(dir, ".git", "index"))).digest("hex")).toBe(before);
  });

  test("does not run a repository-configured signature program while reading trailers", async () => {
    const { dir, marker, script } = await repo();
    const tree = (await git("git", ["-C", dir, "rev-parse", "HEAD^{tree}"])).stdout.trim();
    const parent = (await git("git", ["-C", dir, "rev-parse", "HEAD"])).stdout.trim();
    const signed = [
      `tree ${tree}`, `parent ${parent}`,
      "author t <t@example.com> 1700000000 +0000", "committer t <t@example.com> 1700000000 +0000",
      "gpgsig -----BEGIN PGP SIGNATURE-----", " AAAA", " -----END PGP SIGNATURE-----",
      "", "signed", "", "Co-authored-by: Claude <noreply@anthropic.com>", "",
    ].join("\n");
    const child = execFile("git", ["-C", dir, "hash-object", "-t", "commit", "-w", "--stdin"]);
    child.stdin!.end(signed);
    const object = await new Promise<string>((resolve) => { let out = ""; child.stdout!.on("data", (d) => (out += d)); child.on("close", () => resolve(out.trim())); });
    await git("git", ["-C", dir, "update-ref", "HEAD", object]);
    await git("git", ["-C", dir, "config", "log.showSignature", "true"]);
    await git("git", ["-C", dir, "config", "gpg.program", script]);

    await defaultGitHistoryReader(dir, 10);

    expect(await executed(marker)).toBe(false);
  });

  test("does not run a filter driver configured inside a submodule", async () => {
    const { dir, marker, script } = await repo();
    const upstream = await mkdtemp(join(tmpdir(), "ci-git-hardening-sub-"));
    await git("git", ["-C", upstream, "init", "-q"]);
    await git("git", ["-C", upstream, "config", "user.email", "t@example.com"]);
    await git("git", ["-C", upstream, "config", "user.name", "t"]);
    await writeFile(join(upstream, "a.txt"), "hello\n");
    await writeFile(join(upstream, ".gitattributes"), "* filter=evil\n");
    await git("git", ["-C", upstream, "add", "."]);
    await git("git", ["-C", upstream, "commit", "-q", "-m", "s"]);
    await git("git", ["-C", dir, "-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "sub"]);
    await git("git", ["-C", dir, "commit", "-q", "-m", "sub"]);
    await git("git", ["-C", join(dir, "sub"), "config", "filter.evil.clean", script]);
    const later = new Date(Date.now() + 60_000);
    await utimes(join(dir, "sub", "a.txt"), later, later);

    await detectGitSafety(dir);

    expect(await executed(marker)).toBe(false);
  });

  test("ignores GIT_DIR and GIT_WORK_TREE inherited from a parent git hook", async () => {
    const { dir } = await repo();
    const other = await repo();
    await writeFile(join(other.dir, "untracked.txt"), "dirty\n");
    const saved = { dir: process.env.GIT_DIR, tree: process.env.GIT_WORK_TREE };
    process.env.GIT_DIR = join(other.dir, ".git");
    process.env.GIT_WORK_TREE = other.dir;
    try {
      expect((await detectGitSafety(dir)).state).toBe("clean");
    } finally {
      if (saved.dir === undefined) delete process.env.GIT_DIR; else process.env.GIT_DIR = saved.dir;
      if (saved.tree === undefined) delete process.env.GIT_WORK_TREE; else process.env.GIT_WORK_TREE = saved.tree;
    }
  });

  test("reports unknown instead of running repository filter drivers", async () => {
    const { dir, marker, script } = await repo();
    await writeFile(join(dir, ".gitattributes"), "*.txt filter=evil\n");
    await git("git", ["-C", dir, "config", "filter.evil.clean", script]);
    await writeFile(join(dir, "a.txt"), "two\n");

    const safety = await detectGitSafety(dir);

    expect(await executed(marker)).toBe(false);
    expect(safety.state).toBe("unknown");
  });
});
