import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

const seen = vi.hoisted(() => ({ cwd: "", ignoreFile: "", ignoreList: "", failStderr: "" }));

vi.mock("./resolve.js", () => ({
  EngineUnavailableError: class EngineUnavailableError extends Error {},
  resolveEngine: vi.fn(async () => ({ path: "/test/opengrep", version: "1.33.1", sha256: "a".repeat(64) })),
}));

vi.mock("./exec.js", () => ({
  execBinary: vi.fn(async (_binary: string, args: string[], options: { cwd?: string; env?: Record<string, string> }) => {
    seen.cwd = options.cwd ?? "";
    seen.ignoreFile = options.env?.SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE ?? "";
    seen.ignoreList = await readFile(seen.ignoreFile, "utf8").catch(() => "");
    if (seen.failStderr) return { code: 2, stdout: "", stderr: seen.failStderr, timedOut: false };
    const sarif = args.find((arg) => arg.startsWith("--sarif-output="))!.slice("--sarif-output=".length);
    await writeFile(sarif, JSON.stringify({ version: "2.1.0", runs: [] }), "utf8");
    return { code: 0, stdout: "", stderr: "", timedOut: false };
  }),
}));

const { runOpengrep, OPENGREP_IGNORE_FILE, OPENGREP_EFFECTIVE_IGNORE_NAME } = await import("./opengrep.js");

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("Opengrep ignore policy", () => {
  test("runs in the target with the managed default ignore list, never the repository's", async () => {
    // Field re-test fixture semgrepignore-suppress: `.semgrepignore: src/` hid the only SAST finding.
    // Review C1: running elsewhere matched the defaults against the target's absolute path, so a
    // checkout under a `build/` folder lost all SAST. The target stays the working directory.
    const parent = await mkdtemp(join(tmpdir(), "ci-opengrep-ignore-"));
    const scratch = await mkdtemp(join(tmpdir(), "ci-opengrep-scratch-"));
    roots.push(parent, scratch);
    const target = join(parent, "build", "app");
    await mkdir(join(target, "src"), { recursive: true });
    await writeFile(join(target, ".semgrepignore"), "src/\n", "utf8");

    const output = await runOpengrep(target, scratch);

    expect(output.ran).toBe(true);
    expect(seen.cwd).toBe(target);
    expect(seen.ignoreFile).toBe(join(scratch, OPENGREP_EFFECTIVE_IGNORE_NAME));
    // A Windows checkout may have CRLF defaults; the effective list is always LF.
    expect(seen.ignoreList.startsWith((await readFile(OPENGREP_IGNORE_FILE, "utf8")).replace(/\r\n?/g, "\n"))).toBe(true);
    for (const pattern of ["node_modules/", "build/", "vendor/", "dist/", "test/", "tests/", "*.min.js"]) {
      expect(seen.ignoreList.split("\n")).toContain(pattern);
    }
    expect(output.componentSignatures?.["opengrep:invocation"]).toMatch(/^sha256:/);
  });

  // Review I-4 (fix round 3): build output is skipped exactly where file routing drops Opengrep
  // findings (BUILD_DIRS), never where routing would keep them (.vercel/, .turbo/, coverage/ …).
  test("the effective list adds exactly the BUILD_DIRS folders", async () => {
    const { BUILD_DIRS } = await import("../config.js");
    const scratch = await mkdtemp(join(tmpdir(), "ci-opengrep-scratch-"));
    const target = await mkdtemp(join(tmpdir(), "ci-opengrep-build-dirs-"));
    roots.push(scratch, target);
    await runOpengrep(target, scratch);
    const defaults = new Set((await readFile(OPENGREP_IGNORE_FILE, "utf8")).replace(/\r\n?/g, "\n").split("\n"));
    const added = seen.ignoreList.split("\n").filter((line) => line && !line.startsWith("#") && !defaults.has(line));
    expect(new Set(added)).toEqual(new Set([...BUILD_DIRS].map((folder) => `${folder}/`).filter((pattern) => !defaults.has(pattern))));
    for (const kept of [".vercel/", ".turbo/", ".parcel-cache/", "coverage/"]) expect(seen.ignoreList.split("\n")).not.toContain(kept);
  });

  // Review M2: the --verbose preamble (with the install path) came first and hid the actual error.
  test("a failed run reports the end of stderr, not the --verbose preamble", async () => {
    const scratch = await mkdtemp(join(tmpdir(), "ci-opengrep-scratch-"));
    const target = await mkdtemp(join(tmpdir(), "ci-opengrep-failed-"));
    roots.push(scratch, target);
    seen.failStderr = `running 20 rules from 1 config\nRules:\n${"- Users.someone.codeinspectus.rule\n".repeat(40)}` +
      "Fatal error: out of memory while parsing src/app.js\n";
    try {
      const output = await runOpengrep(target, scratch);
      expect(output.ran).toBe(false);
      expect(output.note).toMatch(/^Opengrep produced no SARIF \(exit 2\)\. stderr: …/);
      expect(output.note).toMatch(/Fatal error: out of memory while parsing src\/app\.js$/);
      expect(output.note).not.toContain("running 20 rules");
    } finally {
      seen.failStderr = "";
    }
  });
});
