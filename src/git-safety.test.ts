/**
 * CG-41 — Git-safety rail. The scan target's git state (no_git / dirty / clean / unknown)
 * is DETECTED read-only and surfaced as an advisory recommendation. The tool NEVER runs a
 * git-mutating command; it only reads (rev-parse / status --porcelain). These tests lock all
 * five directions on throwaway temp repos (never a real repo, never resumetuning).
 */

import { describe, test, expect } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  detectGitSafety,
  NO_GIT_RECOMMENDATION,
  DIRTY_RECOMMENDATION,
} from "./git-safety.js";
import { runScan } from "./scan.js";
import { summarizeScan } from "./summarize.js";

const execFileP = promisify(execFile);

async function tmp(prefix = "ci-gitsafety-"): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

/** SETUP only — writes to a throwaway repo. The code under test never does this. */
async function gitInit(dir: string): Promise<void> {
  await execFileP("git", ["-C", dir, "init", "-q"]);
  await execFileP("git", ["-C", dir, "config", "user.email", "test@codeinspectus.local"]);
  await execFileP("git", ["-C", dir, "config", "user.name", "CI Test"]);
}
async function gitCommitAll(dir: string, msg = "init"): Promise<void> {
  await execFileP("git", ["-C", dir, "add", "-A"]);
  await execFileP("git", ["-C", dir, "commit", "-q", "-m", msg]);
}

describe("detectGitSafety — read-only git state detection", () => {
  test("no git repo → state no_git + the init recommendation, no crash", async () => {
    const dir = await tmp();
    await writeFile(join(dir, "app.ts"), "export const x = 1;\n");
    const r = await detectGitSafety(dir);
    expect(r.state).toBe("no_git");
    expect(r.recommendation).toBe(NO_GIT_RECOMMENDATION);
  });

  test("dirty repo — untracked non-ignored file → state dirty + recommendation", async () => {
    const dir = await tmp();
    await gitInit(dir);
    await writeFile(join(dir, "committed.ts"), "export const a = 1;\n");
    await gitCommitAll(dir);
    await writeFile(join(dir, "untracked.ts"), "export const b = 2;\n");
    const r = await detectGitSafety(dir);
    expect(r.state).toBe("dirty");
    expect(r.recommendation).toBe(DIRTY_RECOMMENDATION);
  });

  test("dirty repo — modified tracked file → state dirty", async () => {
    const dir = await tmp();
    await gitInit(dir);
    await writeFile(join(dir, "committed.ts"), "export const a = 1;\n");
    await gitCommitAll(dir);
    await writeFile(join(dir, "committed.ts"), "export const a = 999;\n");
    const r = await detectGitSafety(dir);
    expect(r.state).toBe("dirty");
  });

  test("clean repo — nothing uncommitted → state clean, NO recommendation", async () => {
    const dir = await tmp();
    await gitInit(dir);
    await writeFile(join(dir, "committed.ts"), "export const a = 1;\n");
    await gitCommitAll(dir);
    const r = await detectGitSafety(dir);
    expect(r.state).toBe("clean");
    expect(r.recommendation).toBeUndefined();
  });

  test("repo dirty ONLY in gitignored files → treated as clean (no false alarm)", async () => {
    const dir = await tmp();
    await gitInit(dir);
    await writeFile(join(dir, ".gitignore"), "*.log\n");
    await writeFile(join(dir, "committed.ts"), "export const a = 1;\n");
    await gitCommitAll(dir);
    await writeFile(join(dir, "debug.log"), "ignored noise\n"); // ignored → must NOT warn
    const r = await detectGitSafety(dir);
    expect(r.state).toBe("clean");
    expect(r.recommendation).toBeUndefined();
  });

  test("subdirectory of a dirty repo → dirty (reflects the containing work tree)", async () => {
    const dir = await tmp();
    await gitInit(dir);
    await writeFile(join(dir, "committed.ts"), "1\n");
    await gitCommitAll(dir);
    const sub = join(dir, "sub");
    await mkdir(sub);
    await writeFile(join(dir, "untracked.ts"), "2\n"); // dirties the containing repo
    const r = await detectGitSafety(sub);
    expect(r.state).toBe("dirty");
  });

  test("git cannot be spawned (ENOENT) → state unknown, no crash, no recommendation", async () => {
    const dir = await tmp();
    const enoent = async () => {
      throw Object.assign(new Error("spawn git ENOENT"), { code: "ENOENT" });
    };
    const r = await detectGitSafety(dir, enoent);
    expect(r.state).toBe("unknown");
    expect(r.recommendation).toBeUndefined();
  });

  test("unexpected git exit code → state unknown (could not determine)", async () => {
    const dir = await tmp();
    const weird = async () => ({ code: 2, stdout: "" });
    const r = await detectGitSafety(dir, weird);
    expect(r.state).toBe("unknown");
    expect(r.recommendation).toBeUndefined();
  });
});

describe("scan envelope carries git_safety without perturbing finding counts", () => {
  test("no-git target: advisory present, under 'Before you fix:' (NOT warnings), not counted", async () => {
    const dir = await tmp("ci-gitsafety-scan-");
    await writeFile(join(dir, "app.ts"), "export const x = 1;\n");
    const res = await runScan({ path: dir, scanners: ["ai"] });
    expect(res.git_safety).toBeDefined();
    expect(res.git_safety.state).toBe("no_git");
    expect(res.git_safety.recommendation).toBe(NO_GIT_RECOMMENDATION);
    // advisory is metadata, NOT a security finding: the summary total equals the finding count.
    expect(res.summary.total).toBe(res.findings.length);
    // CG-42 human half: rendered under its own "Before you fix:" line, NOT in `warnings`.
    expect(res.warnings).not.toContain(NO_GIT_RECOMMENDATION);
    expect(summarizeScan(res)).toContain(`Before you fix:\n  ${NO_GIT_RECOMMENDATION}`);
  });
});
