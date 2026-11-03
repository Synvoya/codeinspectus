/**
 * Read-only discovery of Trivy's in-source ignore comments (review I-6). Trivy 0.76.1 honours
 * `trivy:ignore:<id>` and `tfsec:ignore:<id>` comments in infrastructure files (a `#trivy:ignore:*`
 * above a Terraform resource hid all eight of its AWS findings; `# trivy:ignore:DS-0025` above a
 * Dockerfile `RUN` hid DS-0025) and has no flag to disregard them. They are disclosed the way
 * `gitleaks:allow` is, and make misconfiguration coverage unverified. Counts and paths only.
 *
 * Fail closed. The walk covers what Trivy 0.76.1's misconfiguration scan reads (verified: every
 * folder, including node_modules/, vendor/, .venv/ and hidden ones, except .git/). A candidate file
 * that is not a regular file or cannot be read, an unreadable folder, or reaching the entry bound
 * makes the result unverified rather than "no comments". Files are streamed, so size never skips one.
 */

import { createReadStream } from "node:fs";
import { lstat, opendir } from "node:fs/promises";
import { basename, join, posix, relative } from "node:path";

import { isDisplayablePath } from "./display-path.js";

const INLINE_IGNORE = /\b(?:trivy|tfsec):ignore:/gi;
/** Longer than any match plus the one character `\b` looks back at. */
const CARRY = 16;
/** Files Trivy's misconfiguration scanners read: Terraform/OpenTofu, CloudFormation, Kubernetes, Helm, ARM. */
const IAC_EXTENSIONS = new Set([
  ".tf", ".tofu", ".tfvars", ".hcl", ".json", ".yaml", ".yml", ".template", ".tpl", ".dockerfile",
]);
const DOCKERFILE = /^(?:dockerfile|containerfile)(?:[.-].*)?$/i;
/** Trivy 0.76.1 does not descend into .git/ (verified); it walks every other folder. */
const SKIPPED_DIRS = new Set([".git"]);
/**
 * Final review I-3: the bound counts candidate files (what Trivy parses for misconfiguration), not
 * directory entries, so an installed checkout (node_modules/.pnpm with hundreds of thousands of
 * entries) does not hit it. The entry bound is only a safety stop far above real trees.
 */
const MAX_CANDIDATES = 200_000;
const MAX_ENTRIES = 5_000_000;
const READ_CONCURRENCY = 16;
const MAX_EXAMPLES = 5;

export interface TrivyInlineIgnores {
  comments: number;
  /** Target-relative POSIX paths of files with at least one comment, sorted by code point. */
  paths: string[];
  /** Candidate files and folders that could not be checked (not regular, unreadable), sorted. */
  unchecked: string[];
  /** Set when discovery stopped at the candidate-file or entry bound. */
  bounded?: "candidates" | "entries";
}

function candidate(name: string): boolean {
  return IAC_EXTENSIONS.has(posix.extname(name).toLowerCase()) || DOCKERFILE.test(name);
}

/** Number of ignore comments in a file of any size, or undefined when it cannot be read. */
async function countComments(path: string): Promise<number | undefined> {
  try {
    let count = 0;
    let carry = "";
    const stream = createReadStream(path, { encoding: "utf8", highWaterMark: 1024 * 1024 });
    for await (const chunk of stream as AsyncIterable<string>) {
      const text = carry + chunk;
      for (const match of text.matchAll(INLINE_IGNORE)) {
        // A match wholly inside the carried tail was counted with the previous chunk.
        if (match.index + match[0].length > carry.length) count++;
      }
      carry = text.slice(-CARRY);
    }
    return count;
  } catch {
    return undefined;
  }
}

const byCodePoint = (left: string, right: string): number => (left < right ? -1 : left > right ? 1 : 0);

export async function detectTrivyInlineIgnores(
  target: string,
  limits: { candidates?: number; entries?: number } = {},
): Promise<TrivyInlineIgnores> {
  const maxCandidates = limits.candidates ?? MAX_CANDIDATES;
  const maxEntries = limits.entries ?? MAX_ENTRIES;
  const found: TrivyInlineIgnores = { comments: 0, paths: [], unchecked: [] };
  let entries = 0;
  const candidates: Array<{ absolute: string; rel: string }> = [];
  const inspect = async (absolute: string, rel: string): Promise<void> => {
    const count = await countComments(absolute);
    if (count === undefined) found.unchecked.push(rel);
    else if (count) {
      found.comments += count;
      found.paths.push(rel);
    }
  };
  async function walk(directory: string): Promise<void> {
    const rel = relative(target, directory).replace(/\\/g, "/") || ".";
    let handle;
    try {
      handle = await opendir(directory);
      for await (const entry of handle) {
        if (found.bounded) return;
        if (++entries > maxEntries) {
          found.bounded = "entries";
          return;
        }
        const absolute = join(directory, entry.name);
        if (entry.isDirectory()) {
          if (!SKIPPED_DIRS.has(entry.name)) await walk(absolute);
        } else if (candidate(entry.name)) {
          if (candidates.length >= maxCandidates) {
            found.bounded = "candidates";
            return;
          }
          const path = relative(target, absolute).replace(/\\/g, "/");
          // Trivy 0.76.1 does not follow symlinks; a non-regular candidate is still reported unchecked.
          if (entry.isFile()) candidates.push({ absolute, rel: path });
          else found.unchecked.push(path);
        }
      }
    } catch {
      found.unchecked.push(rel);
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }
  const root = await lstat(target).catch(() => undefined);
  if (root?.isFile()) await inspect(target, basename(target));
  else if (root?.isDirectory()) {
    await walk(target);
    if (!found.bounded) {
      let next = 0;
      await Promise.all(Array.from({ length: READ_CONCURRENCY }, async () => {
        while (next < candidates.length) {
          const item = candidates[next++]!;
          await inspect(item.absolute, item.rel);
        }
      }));
    }
  } else found.unchecked.push(".");
  found.paths.sort(byCodePoint);
  found.unchecked.sort(byCodePoint);
  return found;
}

function examples(paths: readonly string[]): string {
  const shown = paths.filter(isDisplayablePath).slice(0, MAX_EXAMPLES);
  return shown.length ? `: ${shown.join(", ")}${paths.length > shown.length ? ", …" : ""}` : "";
}

/** A coverage warning ("unverified" makes coverage partial), or undefined when nothing was found. */
export function trivyInlineIgnoreWarning(found: TrivyInlineIgnores): string | undefined {
  if (found.bounded) {
    return `Trivy misconfiguration coverage unverified: the search for trivy:ignore and tfsec:ignore comments stopped at the ${
      found.bounded === "candidates" ? `${MAX_CANDIDATES}-file` : `${MAX_ENTRIES}-entry`} bound.`;
  }
  const parts = [
    found.comments
      ? `${found.comments} trivy:ignore or tfsec:ignore comment(s) in ${found.paths.length} file(s) can hide ` +
        `misconfiguration findings, and Trivy cannot be told to disregard them${examples(found.paths)}`
      : "",
    found.unchecked.length
      ? `${found.unchecked.length} infrastructure file(s) or folder(s) could not be checked for such comments ` +
        `(not a regular file, or unreadable)${examples(found.unchecked)}`
      : "",
  ].filter(Boolean);
  return parts.length ? `Trivy misconfiguration coverage unverified: ${parts.join("; ")}.` : undefined;
}
