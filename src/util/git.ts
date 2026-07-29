/**
 * CG-41 — the single READ-ONLY git spawn layer. Every git invocation in CodeInspectus goes
 * through here: `git -C <target> <args…>`, stdout captured, stderr swallowed, and the promise
 * rejected ONLY when git cannot be spawned (e.g. not installed → ENOENT). The tool issues
 * read-only plumbing only (check-ignore / rev-parse / status) — never a mutating subcommand.
 * Reused by file-routing (CG-30 ignore detection) and git-safety (CG-41 state detection) so
 * there is one git layer, not two.
 */

import { spawn } from "node:child_process";

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
    const child = spawn("git", ["-C", target, ...args], { stdio: ["pipe", "pipe", "pipe"] });
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
    const child = spawn("git", ["-C", target, ...args], { stdio: ["pipe", "pipe", "pipe"] });
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
