/**
 * Trivy lockfile findings at the package's own entry (4.1 M5, Ruling 4).
 *
 * Trivy 0.76.1 reports no `Locations` for `pnpm-lock.yaml`, and field output put `go.mod` and `uv.lock`
 * findings at line 1 as well, so every such finding pointed at the top of the lockfile. After normalization
 * (the fingerprint is already computed from Trivy's own line 1 and stays that way, so baselines, triage and
 * SARIF alerts keep following it), a Trivy vulnerability finding with a package at line 1 moves to the line
 * `packageEntryLine` finds for its name and installed version, when that is a line after 1. Its line-1 snippet,
 * if any, is dropped, so a snippet never shows a different line than `start_line`.
 *
 * Read-only and bounded, like osv-scanner's line lookup: each lockfile is read at most once per call, only
 * from inside the target (the target itself when it is that lockfile), and a path with an empty, `.` or `..`
 * segment, an absolute path, a path through a link that leaves the target, a symlink, a special file or a file
 * over 16 MiB is never read (the line stays 1).
 */

import { realpath, stat } from "node:fs/promises";
import { basename, isAbsolute, join, relative, sep } from "node:path";

import { packageEntryLine, readLockfileLines, type LockfileLines } from "../osv/package-line.js";
import type { Finding } from "../types.js";

function safeSegments(file: string): boolean {
  if (!file || isAbsolute(file) || /^[A-Za-z]:/.test(file) || file.includes("\\")) return false;
  return file.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

function inside(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

/** The absolute lockfile to read for a target-relative file, or undefined when it must not be read. */
async function lockfilePath(target: string, targetIsFile: boolean, file: string): Promise<string | undefined> {
  if (!safeSegments(file)) return undefined;
  if (targetIsFile) return file === basename(target) ? target : undefined;
  const candidate = join(target, file);
  try {
    // The leaf itself is checked by readLockfileLines (lstat: never a symlink); a linked directory on the
    // way must not lead out of the target.
    const [root, parent] = await Promise.all([realpath(target), realpath(join(candidate, ".."))]);
    return inside(root, parent) ? candidate : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A reader of target-relative lockfiles under the bounds above, each file read at most once. Undefined for a
 * file that must not or cannot be read. Shared with the requirements.txt declared-minimum pass.
 */
export function targetLockfileReader(target: string): (file: string) => Promise<LockfileLines | undefined> {
  const targetIsFile = stat(target).then((info) => info.isFile(), () => false);
  const cache = new Map<string, Promise<LockfileLines | undefined>>();
  return (file: string): Promise<LockfileLines | undefined> => {
    let lines = cache.get(file);
    if (!lines) {
      lines = targetIsFile
        .then((isFile) => lockfilePath(target, isFile, file))
        .then((path) => (path ? readLockfileLines(path) : undefined));
      cache.set(file, lines);
    }
    return lines;
  };
}

export async function relocateTrivyPackageFindings(
  findings: Finding[],
  target: string,
): Promise<{ findings: Finding[]; relocated: number }> {
  const eligible = (finding: Finding) => finding.engine === "trivy" && finding.finding_kind === "vulnerability" &&
    Boolean(finding.package?.name) && finding.location.start_line === 1;
  if (!findings.some(eligible)) return { findings, relocated: 0 };
  const linesFor = targetLockfileReader(target);
  let relocated = 0;
  const out: Finding[] = [];
  for (const finding of findings) {
    if (!eligible(finding)) {
      out.push(finding);
      continue;
    }
    const lines = await linesFor(finding.location.file);
    const line = lines ? packageEntryLine(lines, finding.location.file, finding.package!.name, finding.package!.version || undefined) : 1;
    if (line <= 1) {
      out.push(finding);
      continue;
    }
    relocated += 1;
    // A snippet Trivy took from line 1 would show a different line than the finding points at: drop it.
    const { snippet: _lineOneSnippet, ...location } = finding.location;
    out.push({ ...finding, location: { ...location, start_line: line, end_line: line } });
  }
  return { findings: out, relocated };
}
