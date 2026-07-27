/** Read-only, bounded JavaScript/TypeScript loading for native SAST shadow comparison. */

import { constants, type BigIntStats, type Dirent } from "node:fs";
import { lstat, open, opendir, realpath, type FileHandle } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";

import {
  parseJavaScriptSource,
  type JsDocument,
} from "../react-native/javascript.js";

export const JAVASCRIPT_BASELINE_MAX_SOURCE_BYTES = 2 * 1024 * 1024;
export const JAVASCRIPT_BASELINE_MAX_SOURCE_FILES = 10_000;
export const JAVASCRIPT_BASELINE_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
export const JAVASCRIPT_BASELINE_MAX_TOTAL_TOKENS = 1_000_000;
export const JAVASCRIPT_BASELINE_MAX_DEPTH = 32;
export const JAVASCRIPT_BASELINE_MAX_DISCOVERY_ENTRIES = 50_000;

const MAX_LIMITATIONS = 24;
const EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"]);
const EXCLUDED_DIRS = new Set([".git", ".hg", ".svn", "node_modules"]);

export interface JavaScriptBaselineProject {
  target: string;
  root: string;
  files: JsDocument[];
  limitations?: string[];
}

export type JavaScriptBaselineProjectInput =
  | string
  | JavaScriptBaselineProject
  | Promise<JavaScriptBaselineProject>;

export interface JavaScriptBaselineProjectBounds {
  maxSourceBytes: number;
  maxSourceFiles: number;
  maxTotalBytes: number;
  maxTotalTokens: number;
  maxDepth: number;
  maxDiscoveryEntries: number;
}

const DEFAULT_BOUNDS: JavaScriptBaselineProjectBounds = {
  maxSourceBytes: JAVASCRIPT_BASELINE_MAX_SOURCE_BYTES,
  maxSourceFiles: JAVASCRIPT_BASELINE_MAX_SOURCE_FILES,
  maxTotalBytes: JAVASCRIPT_BASELINE_MAX_TOTAL_BYTES,
  maxTotalTokens: JAVASCRIPT_BASELINE_MAX_TOTAL_TOKENS,
  maxDepth: JAVASCRIPT_BASELINE_MAX_DEPTH,
  maxDiscoveryEntries: JAVASCRIPT_BASELINE_MAX_DISCOVERY_ENTRIES,
};

interface Identity {
  dev: bigint;
  ino: bigint;
}

interface LoadedFile {
  document?: JsDocument;
  size?: number;
  limitation?: string;
  totalBoundExceeded?: boolean;
}

function sameIdentity(left: Identity, right: Identity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function unchangedFile(before: BigIntStats, after: BigIntStats): boolean {
  return sameIdentity(before, after) && before.size === after.size &&
    before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

function normalizedBounds(
  overrides: Partial<JavaScriptBaselineProjectBounds>,
): JavaScriptBaselineProjectBounds {
  const bounds = { ...DEFAULT_BOUNDS, ...overrides };
  for (const [name, value] of Object.entries(bounds)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new Error(`Invalid JavaScript baseline project bound ${name}.`);
    }
  }
  return bounds;
}

function sourceExtension(file: string): boolean {
  const lower = file.toLowerCase();
  return [...EXTENSIONS].some((extension) => lower.endsWith(extension));
}

function notesCollector(): { add: (note: string) => void; finish: () => string[] } {
  const notes = new Set<string>();
  let omitted = 0;
  return {
    add(note) {
      if (notes.size < MAX_LIMITATIONS - 1) notes.add(note);
      else omitted++;
    },
    finish() {
      return [
        ...notes,
        ...(omitted ? [`${omitted} additional JavaScript baseline limitations omitted.`] : []),
      ].sort();
    },
  };
}

async function symbolicLinkAncestor(absoluteTarget: string): Promise<boolean> {
  const canonical = await realpath(absoluteTarget).catch(() => undefined);
  return canonical !== undefined && canonical !== absoluteTarget;
}

function documentLimitation(document: JsDocument): string | undefined {
  if (!document.balanced || document.lexicalIssues.length) {
    return `Skipped structurally malformed JavaScript/TypeScript source ${document.path}.`;
  }
  return undefined;
}

async function loadFile(
  absolute: string,
  displayPath: string,
  remainingTotalBytes: number,
  maxSourceBytes: number,
): Promise<LoadedFile> {
  let handle: FileHandle | undefined;
  try {
    const before = await lstat(absolute, { bigint: true });
    if (before.isSymbolicLink()) {
      return { limitation: `Skipped symbolic-link JavaScript/TypeScript source ${displayPath}.` };
    }
    if (!before.isFile()) return {};
    if (before.size > BigInt(maxSourceBytes)) {
      return { limitation: `Skipped oversized JavaScript/TypeScript source ${displayPath}.` };
    }
    if (before.size > BigInt(remainingTotalBytes)) return { totalBoundExceeded: true };

    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    handle = await open(absolute, constants.O_RDONLY | noFollow);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(before, opened)) {
      return { limitation: `Skipped changed JavaScript/TypeScript source ${displayPath}.` };
    }
    const size = Number(opened.size);
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(bytes, offset, size - offset, offset);
      if (bytesRead === 0) {
        return { limitation: `Skipped changed JavaScript/TypeScript source ${displayPath}.` };
      }
      offset += bytesRead;
    }
    if (!unchangedFile(opened, await handle.stat({ bigint: true }))) {
      return { limitation: `Skipped changed JavaScript/TypeScript source ${displayPath}.` };
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return { limitation: `Skipped non-UTF-8 JavaScript/TypeScript source ${displayPath}.` };
    }
    const document = parseJavaScriptSource(displayPath.replace(/\\/g, "/"), content);
    const limitation = documentLimitation(document);
    return limitation ? { size, limitation } : { size, document };
  } catch {
    return { limitation: `Skipped unreadable JavaScript/TypeScript source ${displayPath}.` };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function loadUncached(
  target: string,
  overrides: Partial<JavaScriptBaselineProjectBounds> = {},
): Promise<JavaScriptBaselineProject> {
  const bounds = normalizedBounds(overrides);
  const absoluteTarget = resolve(target);
  const notes = notesCollector();
  let metadata;
  try {
    metadata = await lstat(absoluteTarget);
  } catch {
    return { target: absoluteTarget, root: absoluteTarget, files: [], limitations: ["JavaScript baseline target was unreadable."] };
  }
  if (metadata.isSymbolicLink() || await symbolicLinkAncestor(absoluteTarget)) {
    return {
      target: absoluteTarget,
      root: metadata.isFile() ? dirname(absoluteTarget) : absoluteTarget,
      files: [],
      limitations: ["Skipped JavaScript baseline target with a symbolic-link path."],
    };
  }
  if (metadata.isFile()) {
    if (!sourceExtension(absoluteTarget)) return { target: absoluteTarget, root: dirname(absoluteTarget), files: [] };
    const loaded = await loadFile(absoluteTarget, basename(absoluteTarget), bounds.maxTotalBytes, bounds.maxSourceBytes);
    if (loaded.limitation) notes.add(loaded.limitation);
    if (loaded.document && loaded.document.tokens.length > bounds.maxTotalTokens) {
      notes.add(`Stopped JavaScript baseline parsing at the ${bounds.maxTotalTokens}-token project bound.`);
    }
    return {
      target: absoluteTarget,
      root: dirname(absoluteTarget),
      files: loaded.document && loaded.document.tokens.length <= bounds.maxTotalTokens ? [loaded.document] : [],
      limitations: notes.finish(),
    };
  }
  if (!metadata.isDirectory()) return { target: absoluteTarget, root: absoluteTarget, files: [] };

  const files: JsDocument[] = [];
  let sourceFiles = 0;
  let totalBytes = 0;
  let totalTokens = 0;
  let entriesSeen = 0;
  let stopped = false;

  async function walk(directory: string, depth: number): Promise<void> {
    if (stopped) return;
    if (depth > bounds.maxDepth) {
      notes.add(`Stopped JavaScript baseline discovery at the ${bounds.maxDepth}-level depth bound.`);
      stopped = true;
      return;
    }
    let before: BigIntStats;
    let entries: Dirent[] = [];
    let handle;
    try {
      before = await lstat(directory, { bigint: true });
      if (!before.isDirectory() || before.isSymbolicLink()) {
        notes.add(`Skipped changed JavaScript/TypeScript directory ${relative(absoluteTarget, directory) || "."}.`);
        return;
      }
      handle = await opendir(directory);
      for await (const entry of handle) entries.push(entry);
      const after = await lstat(directory, { bigint: true });
      if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(before, after)) {
        notes.add(`Skipped changed JavaScript/TypeScript directory ${relative(absoluteTarget, directory) || "."}.`);
        return;
      }
    } catch {
      notes.add(`Skipped unreadable JavaScript/TypeScript directory ${relative(absoluteTarget, directory) || "."}.`);
      return;
    } finally {
      await handle?.close().catch(() => undefined);
    }
    entries = entries.sort((left, right) => left.name.localeCompare(right.name));
    entriesSeen += entries.length;
    if (entriesSeen > bounds.maxDiscoveryEntries) {
      notes.add(`Stopped JavaScript baseline discovery at the ${bounds.maxDiscoveryEntries}-entry project bound.`);
      stopped = true;
      return;
    }
    for (const entry of entries) {
      if (stopped) return;
      const absolute = join(directory, entry.name);
      const rel = relative(absoluteTarget, absolute).replace(/\\/g, "/");
      if (entry.isSymbolicLink()) {
        notes.add(`Skipped symbolic-link JavaScript/TypeScript path ${rel}.`);
      } else if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name.toLowerCase())) await walk(absolute, depth + 1);
      } else if (entry.isFile() && sourceExtension(entry.name)) {
        sourceFiles++;
        if (sourceFiles > bounds.maxSourceFiles) {
          notes.add(`Stopped JavaScript baseline discovery at the ${bounds.maxSourceFiles}-file project bound.`);
          stopped = true;
          return;
        }
        const loaded = await loadFile(absolute, rel, bounds.maxTotalBytes - totalBytes, bounds.maxSourceBytes);
        if (loaded.totalBoundExceeded) {
          notes.add(`Stopped JavaScript baseline discovery at the ${bounds.maxTotalBytes}-byte project bound.`);
          stopped = true;
          return;
        }
        if (loaded.limitation) {
          notes.add(loaded.limitation);
          continue;
        }
        if (!loaded.document || loaded.size === undefined) continue;
        if (totalTokens + loaded.document.tokens.length > bounds.maxTotalTokens) {
          notes.add(`Stopped JavaScript baseline parsing at the ${bounds.maxTotalTokens}-token project bound.`);
          stopped = true;
          return;
        }
        totalBytes += loaded.size;
        totalTokens += loaded.document.tokens.length;
        files.push(loaded.document);
      }
    }
  }

  await walk(absoluteTarget, 0);
  files.sort((left, right) => left.path.localeCompare(right.path));
  return { target: absoluteTarget, root: absoluteTarget, files, limitations: notes.finish() };
}

export function loadJavaScriptBaselineProject(
  target: string,
  bounds: Partial<JavaScriptBaselineProjectBounds> = {},
): Promise<JavaScriptBaselineProject> {
  return loadUncached(target, bounds);
}

export function resolveJavaScriptBaselineProject(
  input: JavaScriptBaselineProjectInput,
): Promise<JavaScriptBaselineProject> {
  return typeof input === "string" ? loadUncached(input) : Promise.resolve(input);
}
