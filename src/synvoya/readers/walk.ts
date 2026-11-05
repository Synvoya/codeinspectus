/**
 * Bounded, read-only file discovery shared by the Synvoya declaration readers.
 *
 * Never follows symlinks, skips dependency and build-output folders, and caps depth, entries
 * visited and per-file size. A candidate that is a symlink or over the size cap is reported in
 * `skipped` instead of being read.
 */

import { lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { BUILD_DIRS } from "../../config.js";

export interface WalkMatcher {
  /**
   * File name to match. A single `*` is a wildcard (`*.csproj`, `Dockerfile.*`, `docker-compose*.yml`);
   * an array matches any of its entries.
   */
  basename?: string | readonly string[];
  /** The target-relative path (forward slashes) ends with this text, e.g. `.yml`. */
  suffix?: string;
  /** The target-relative path (forward slashes) starts with this text, e.g. `.github/workflows/`. */
  prefix?: string;
}

export interface WalkLimits {
  maxDepth: number;
  maxEntries: number;
  maxFileBytes: number;
}

export const DEFAULT_WALK_LIMITS: WalkLimits = {
  maxDepth: 12,
  maxEntries: 20_000,
  maxFileBytes: 1024 * 1024,
};

/** Opt-in descent into `vendor/` (never `node_modules/`), under one depth and entry budget shared by every vendor directory in the walk. */
export interface WalkOptions {
  vendor?: { maxDepth: number; maxEntries: number };
  /** Directory names the `vendor` option enters (default `["vendor"]`); `node_modules` is never one of them. */
  vendorNames?: readonly string[];
  /** Shared Synvoya reader deadline: once aborted, no further directory is listed and no file is added. */
  signal?: AbortSignal;
  /**
   * A single-file scan: consider only this target-relative path (forward slashes) instead of walking,
   * under the same matcher, symlink and size rules.
   */
  only?: string;
}

export interface WalkResult {
  /** Target-relative paths with forward slashes, sorted. */
  files: string[];
  skipped: Array<{ file: string; reason: string }>;
}

/** `vendors/` holds bundled third-party SDKs (e.g. a WordPress plugin's `includes/vendors/<sdk>`), never the project's own pins. */
const SKIPPED_DIRS: ReadonlySet<string> = new Set(["node_modules", "vendor", "vendors", ".git", ...BUILD_DIRS]);

function nameMatches(pattern: string, name: string): boolean {
  const star = pattern.indexOf("*");
  if (star < 0) return pattern === name;
  const head = pattern.slice(0, star);
  const tail = pattern.slice(star + 1);
  return name.length >= head.length + tail.length && name.startsWith(head) && name.endsWith(tail);
}

/** A matcher's set fields must all hold; an empty matcher matches nothing. */
export function matchesCandidate(matcher: WalkMatcher, relPath: string): boolean {
  if (matcher.basename === undefined && matcher.suffix === undefined && matcher.prefix === undefined) return false;
  if (matcher.prefix !== undefined && !relPath.startsWith(matcher.prefix)) return false;
  if (matcher.suffix !== undefined && !relPath.endsWith(matcher.suffix)) return false;
  if (matcher.basename !== undefined) {
    const name = relPath.slice(relPath.lastIndexOf("/") + 1);
    const patterns = typeof matcher.basename === "string" ? [matcher.basename] : matcher.basename;
    if (!patterns.some((pattern) => nameMatches(pattern, name))) return false;
  }
  return true;
}

export async function walkCandidates(
  target: string,
  matchers: readonly WalkMatcher[],
  limits: Partial<WalkLimits> = {},
  options: WalkOptions = {},
): Promise<WalkResult> {
  const { maxDepth, maxEntries, maxFileBytes } = { ...DEFAULT_WALK_LIMITS, ...limits };
  const files: string[] = [];
  const skipped: WalkResult["skipped"] = [];
  let visited = 0;
  let capped = false;

  /**
   * One entry budget shared by every vendor directory in the walk (nested ones included), so neither a
   * huge vendor tree nor thousands of small ones can starve or multiply the main walk's bounded work.
   */
  const vendor = { visited: 0, capped: false };
  const vendorNames: ReadonlySet<string> = new Set((options.vendorNames ?? ["vendor"]).filter((name) => name !== "node_modules"));
  let expired = false;
  const deadlineReached = (relDir: string): boolean => {
    if (expired) return true;
    if (!options.signal?.aborted) return false;
    expired = true;
    skipped.push({ file: relDir || ".", reason: "deadline" });
    return true;
  };

  /** `vendorDepth` is undefined outside vendor/ and counts directory levels below the entered vendor/ inside it. */
  async function visit(absDir: string, relDir: string, depth: number, vendorDepth?: number): Promise<void> {
    if (deadlineReached(relDir)) return;
    let entries;
    try {
      entries = await readdir(absDir, { withFileTypes: true });
    } catch {
      skipped.push({ file: relDir || ".", reason: "unreadable" });
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (deadlineReached(relDir)) return;
      if (vendorDepth !== undefined) {
        if (vendor.capped) return;
        if (++vendor.visited > options.vendor!.maxEntries) {
          vendor.capped = true;
          skipped.push({ file: relDir, reason: "entry-limit" });
          return;
        }
      } else {
        if (capped) return;
        if (++visited > maxEntries) {
          capped = true;
          skipped.push({ file: relDir || ".", reason: "entry-limit" });
          return;
        }
      }
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        // Never followed; only a link that a reader would have opened is worth reporting.
        if (matchers.some((matcher) => matchesCandidate(matcher, rel))) skipped.push({ file: rel, reason: "symlink" });
      } else if (entry.isDirectory()) {
        if (vendorNames.has(entry.name) && options.vendor !== undefined) {
          // A nested vendor/x/vendor is entered too, under the same budget and one extra level of depth.
          if (vendorDepth === undefined) {
            if (!vendor.capped && depth + 1 <= maxDepth) await visit(join(absDir, entry.name), rel, depth + 1, 0);
          } else if (vendorDepth + 1 < options.vendor.maxDepth) {
            await visit(join(absDir, entry.name), rel, depth + 1, vendorDepth + 1);
          }
          continue;
        }
        if (SKIPPED_DIRS.has(entry.name)) continue;
        if (vendorDepth !== undefined) {
          // Inside vendor the depth bound is silent: dependency trees are not the user's code.
          if (vendorDepth + 1 < options.vendor!.maxDepth) await visit(join(absDir, entry.name), rel, depth + 1, vendorDepth + 1);
          continue;
        }
        if (depth + 1 > maxDepth) {
          skipped.push({ file: rel, reason: "depth-limit" });
          continue;
        }
        await visit(join(absDir, entry.name), rel, depth + 1);
      } else if (entry.isFile() && matchers.some((matcher) => matchesCandidate(matcher, rel))) {
        try {
          if ((await lstat(join(absDir, entry.name))).size > maxFileBytes) {
            skipped.push({ file: rel, reason: "oversized" });
            continue;
          }
        } catch {
          skipped.push({ file: rel, reason: "unreadable" });
          continue;
        }
        files.push(rel);
      }
    }
  }

  if (options.only !== undefined) {
    const rel = options.only;
    if (!matchers.some((matcher) => matchesCandidate(matcher, rel))) return { files, skipped };
    if (deadlineReached(rel)) return { files, skipped };
    try {
      const metadata = await lstat(join(target, ...rel.split("/")));
      if (metadata.isSymbolicLink()) skipped.push({ file: rel, reason: "symlink" });
      else if (!metadata.isFile()) skipped.push({ file: rel, reason: "unreadable" });
      else if (metadata.size > maxFileBytes) skipped.push({ file: rel, reason: "oversized" });
      else files.push(rel);
    } catch {
      skipped.push({ file: rel, reason: "unreadable" });
    }
    return { files, skipped };
  }

  await visit(target, "", 0);
  return { files, skipped };
}

/** The text of a file the walk returned, or undefined when it vanished, grew or is unreadable. */
export async function readCandidate(target: string, rel: string, maxBytes = DEFAULT_WALK_LIMITS.maxFileBytes): Promise<string | undefined> {
  const path = join(target, ...rel.split("/"));
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.size > maxBytes) return undefined;
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
}
