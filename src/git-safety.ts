/**
 * CG-41 — Git-safety rail (READ-ONLY). The scan → surface → consent → fix → rescan loop ends
 * with the USER'S AGENT applying fixes to the user's files. A non-expert with uncommitted work
 * — or no git repo at all — has no clean rollback point if a fix goes wrong. This DETECTS the
 * scan target's git state and EMITS a plain-language recommendation to checkpoint first.
 *
 * HARD LINE: the tool NEVER runs `git init` / `git commit` / `git stash` or any mutating
 * command, and never writes to the user's repo. It only READS (rev-parse --is-inside-work-tree,
 * status --porcelain) via the shared read-only git layer. Acting on the recommendation is the
 * user's agent's job, on user approval (see agent-rules/*).
 *
 * States:
 *   - unknown — git could not be spawned (not installed) or returned an unexpected exit. Degrade
 *               SILENTLY: no recommendation, no scary text. "Could not determine."
 *   - no_git  — rev-parse says not a repository (exit 128) or reports no work tree (bare/gitdir).
 *   - dirty   — inside a work tree and `status --porcelain` is non-empty (untracked non-ignored
 *               files OR uncommitted tracked changes). Ignored-only diffs are NOT listed by
 *               porcelain → they read as clean (no nagging about ignored noise).
 *   - clean   — inside a work tree with nothing uncommitted. Silent (no recommendation).
 */

import { runGitRead, type GitReadResult } from "./util/git.js";
import type { GitSafety } from "./types.js";

export type { GitSafety, GitSafetyState } from "./types.js";

export const NO_GIT_RECOMMENDATION =
  "No git repository detected here. Before applying any fixes, consider initializing git and committing a checkpoint so changes can be undone.";
export const DIRTY_RECOMMENDATION =
  "You have uncommitted changes. Before applying fixes, consider committing or stashing them so a fix can be rolled back cleanly.";

/** Read-only git runner shape — injectable so the degrade path is unit-testable without git. */
export type GitRunner = (target: string, args: string[]) => Promise<GitReadResult>;

/**
 * Detect the git-safety state of `target`, read-only. Never mutates git or the repo. Returns a
 * recommendation string only for no_git / dirty. Any failure to run git degrades to "unknown".
 */
export async function detectGitSafety(
  target: string,
  run: GitRunner = runGitRead,
): Promise<GitSafety> {
  // 1. Is the target inside a git work tree? (read-only plumbing)
  let insideWorkTree: GitReadResult;
  try {
    insideWorkTree = await run(target, ["rev-parse", "--is-inside-work-tree"]);
  } catch {
    return { state: "unknown" }; // git not installed / cannot spawn — degrade silently
  }
  if (insideWorkTree.code === 128) return withNoGit(); // definitively not a git repository
  if (insideWorkTree.code !== 0) return { state: "unknown" }; // unexpected exit — could not determine
  if (insideWorkTree.stdout.trim() !== "true") return withNoGit(); // bare repo / inside .git — no work tree

  // 2. Inside a work tree — is it dirty? `status --porcelain` lists modified/staged tracked files
  //    and untracked NON-ignored files, and by default OMITS ignored files, so a repo that differs
  //    only in gitignored files reads as clean (deliberate: don't nag about ignored noise).
  let status: GitReadResult;
  try {
    status = await run(target, ["status", "--porcelain"]);
  } catch {
    return { state: "unknown" };
  }
  if (status.code !== 0) return { state: "unknown" };
  const dirty = status.stdout.split("\n").some((line) => line.trim().length > 0);
  return dirty ? { state: "dirty", recommendation: DIRTY_RECOMMENDATION } : { state: "clean" };
}

function withNoGit(): GitSafety {
  return { state: "no_git", recommendation: NO_GIT_RECOMMENDATION };
}
