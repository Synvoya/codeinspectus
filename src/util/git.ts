/**
 * CG-41 — the single READ-ONLY git spawn layer. Every git invocation in CodeInspectus goes
 * through here: `git -C <target> <args…>`, stdout captured, stderr swallowed, and the promise
 * rejected ONLY when git cannot be spawned (e.g. not installed → ENOENT). The tool issues
 * read-only plumbing only (check-ignore / rev-parse / status) — never a mutating subcommand.
 * Reused by file-routing (CG-30 ignore detection) and git-safety (CG-41 state detection) so
 * there is one git layer, not two.
 */

import { spawn } from "node:child_process";

/**
 * A scanned repository is untrusted input: its local config can name programs git would execute
 * (fsmonitor hooks, signature verifiers, pagers). Command-line `-c` overrides take precedence over
 * repository config. `--no-optional-locks` stops read commands such as `status` from refreshing
 * and rewriting `.git/index`. Filter drivers cannot be neutralized generically; callers that
 * compare the working tree must check `repositoryFilterDrivers` first.
 */
export const GIT_HARDENING_ARGS: readonly string[] = [
  "-c", "core.fsmonitor=false",
  "-c", "core.hooksPath=/dev/null",
  "-c", "core.pager=cat",
  "-c", "log.showSignature=false",
  "-c", "gpg.program=false",
  "-c", "gpg.openpgp.program=false",
  "-c", "gpg.x509.program=false",
  "-c", "gpg.ssh.program=false",
  // Never descend into submodule work trees (their own config can define filter drivers).
  "-c", "diff.ignoreSubmodules=dirty",
  "--no-optional-locks",
];

// Repository-location variables inherited from a parent git process (for example when the CLI runs
// inside a git hook) would redirect every read to that other repository.
const INHERITED_REPOSITORY_ENV = [
  "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_PREFIX", "GIT_EXTERNAL_DIFF",
  // A parent's `git -c` parameters are applied after GIT_CONFIG_* and would override the hardening.
  "GIT_CONFIG_PARAMETERS",
  // Pathspec semantics must not depend on the caller's shell (CodeInspectus passes `:(literal)` paths).
  "GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_ICASE_PATHSPECS",
];

// The same overrides as GIT_HARDENING_ARGS, expressed as command-scope config in the environment so
// they also bind git processes we do not spawn ourselves (for example Opengrep's `git ls-files`).
const GIT_ENV_OVERRIDES: ReadonlyArray<readonly [string, string]> = [
  ["core.fsmonitor", "false"],
  ["core.hooksPath", "/dev/null"],
  ["core.pager", "cat"],
  ["log.showSignature", "false"],
  ["gpg.program", "false"],
  ["gpg.openpgp.program", "false"],
  ["gpg.x509.program", "false"],
  ["gpg.ssh.program", "false"],
  ["diff.ignoreSubmodules", "dirty"],
];

/**
 * Environment for any process that may run git against a scanned repository: no inherited
 * repository location, no optional index locks, and command-scope config overrides appended after
 * any the parent already set (later entries win).
 */
export function gitHardenedEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base, GIT_OPTIONAL_LOCKS: "0", GIT_PAGER: "cat", GIT_TERMINAL_PROMPT: "0" };
  for (const name of INHERITED_REPOSITORY_ENV) delete env[name];
  const existing = Number.parseInt(env.GIT_CONFIG_COUNT ?? "0", 10);
  let count = Number.isSafeInteger(existing) && existing > 0 ? existing : 0;
  for (const [key, value] of GIT_ENV_OVERRIDES) {
    env[`GIT_CONFIG_KEY_${count}`] = key;
    env[`GIT_CONFIG_VALUE_${count}`] = value;
    count++;
  }
  env.GIT_CONFIG_COUNT = String(count);
  return env;
}

function hardenedEnv(): NodeJS.ProcessEnv {
  return gitHardenedEnv();
}

/**
 * Working-tree comparisons must not descend into submodule work trees: each submodule has its own
 * config (and filter drivers) that `repositoryFilterDrivers` cannot see. `dirty` still reports
 * changed submodule commits.
 */
export const IGNORE_SUBMODULE_WORKTREES = "--ignore-submodules=dirty";

function spawnGit(target: string, args: string[]) {
  return spawn("git", ["-C", target, ...GIT_HARDENING_ARGS, ...args], { stdio: ["pipe", "pipe", "pipe"], env: hardenedEnv() });
}

export interface GitReadResult {
  /** Process exit code (null if killed by signal). 0 ok · 1 = "no match" for check-ignore · 128 = not a repo. */
  code: number | null;
  /** Captured stdout. */
  stdout: string;
}

export interface GitReadBufferResult {
  code: number | null;
  stdout: Buffer;
  stderr: string;
}

export const DEFAULT_GIT_OUTPUT_LIMIT = 16 * 1024 * 1024;

/**
 * Binary-safe, bounded read-only Git execution for NUL-delimited plumbing. The caller must
 * provide a read-only subcommand. Output beyond `maxBytes` terminates the child and rejects;
 * this prevents a hostile or unexpectedly large repository from exhausting agent memory.
 */
export function runGitReadBuffer(
  target: string,
  args: string[],
  options: { input?: Buffer | string; maxBytes?: number } = {},
): Promise<GitReadBufferResult> {
  const maxBytes = options.maxBytes ?? DEFAULT_GIT_OUTPUT_LIMIT;
  return new Promise((resolve, reject) => {
    const child = spawnGit(target, args);
    const chunks: Buffer[] = [];
    const errors: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      reject(error);
    };
    child.stdout.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxBytes) return fail(new Error(`Git output exceeded the ${maxBytes}-byte safety limit.`));
      chunks.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (errors.reduce((total, entry) => total + entry.length, 0) < 64 * 1024) errors.push(chunk);
    });
    child.on("error", fail);
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      resolve({ code, stdout: Buffer.concat(chunks), stderr: Buffer.concat(errors).toString("utf8").trim() });
    });
    child.stdin.on("error", () => {});
    if (options.input !== undefined) child.stdin.write(options.input);
    child.stdin.end();
  });
}

/**
 * Run a read-only git command in `target`. Resolves { code, stdout }; rejects only when git
 * cannot be spawned. Optional `input` is written to the child's stdin (for `--stdin` plumbing).
 * Uses spawn, never execFile's async form — whose `input` option is silently ignored, which
 * would hang `--stdin` forever (CG-30).
 */
export function runGitRead(target: string, args: string[], input?: string): Promise<GitReadResult> {
  return new Promise((resolve, reject) => {
    const child = spawnGit(target, args);
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", () => {});
    child.on("error", reject); // git missing / cannot spawn
    child.on("close", (code) => resolve({ code, stdout }));
    child.stdin.on("error", () => {}); // ignore EPIPE if git exits before reading all input
    if (input !== undefined) child.stdin.write(input);
    child.stdin.end();
  });
}

/**
 * Filter drivers (`filter.<name>.clean|smudge|process`) defined by the repository's own config.
 * Git runs them when comparing the working tree (`status`, `diff <rev>`), so callers must not
 * perform those comparisons while any are defined. Fails closed when config cannot be read.
 */
export async function repositoryFilterDrivers(target: string): Promise<string[]> {
  const result = await runGitReadBuffer(target, ["config", "--list", "--includes", "--show-scope", "--name-only"], { maxBytes: 1024 * 1024 });
  if (result.code !== 0) return ["(repository git config could not be inspected)"];
  const drivers = new Set<string>();
  for (const line of result.stdout.toString("utf8").split("\n")) {
    const [scope, key] = line.split("\t");
    if ((scope === "local" || scope === "worktree") && key && /^filter\.[^\n]+\.(?:clean|smudge|process)$/i.test(key)) drivers.add(key.toLowerCase());
  }
  return [...drivers].sort();
}
