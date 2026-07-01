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
