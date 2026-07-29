/** Read-only, bounded Go source loading for first-party native analyzers. */

import { constants, type BigIntStats } from "node:fs";
import { lstat, open, readdir, type FileHandle } from "node:fs/promises";
import { basename, dirname, extname, join, parse, relative, resolve } from "node:path";

export const GO_MAX_SOURCE_BYTES = 2 * 1024 * 1024;
export const GO_MAX_SOURCE_FILES = 10_000;
export const GO_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
export const GO_MAX_DEPTH = 32;
export const GO_MAX_DISCOVERY_ENTRIES = 50_000;

const MAX_LIMITATIONS = 24;
const IGNORED_DIRS = new Set([
  ".cache", ".git", ".hg", ".idea", ".svn", ".vscode", "bin", "build",
  "coverage", "dist", "node_modules", "out", "target", "vendor",
]);
const NON_PRODUCTION_DIRS = new Set([
  "demo", "demos", "example", "examples", "fixture", "fixtures", "generated",
  "integration_test", "integration_tests", "sample", "samples", "test", "testdata", "tests",
]);

export interface GoDocument {
  path: string;
  content: string;
}

export interface GoProject {
  target: string;
  root: string;
  files: GoDocument[];
  limitations?: string[];
}

export type GoProjectInput = string | GoProject | Promise<GoProject>;

function generatedSource(name: string, content: string): boolean {
  const lower = name.toLowerCase();
  if (lower.endsWith("_test.go") || lower.endsWith(".pb.go") || lower.endsWith("_gen.go")) {
    return true;
  }
  const header = content.split(/\r?\n/, 8).join("\n");
  return /^\/\/ Code generated .* DO NOT EDIT\.$/m.test(header);
}

function sourcePath(path: string): boolean {
  return extname(path).toLowerCase() === ".go";
}

function collector(): { add: (value: string) => void; finish: () => string[] } {
  const values = new Set<string>();
  let omitted = 0;
  return {
    add(value) {
      if (values.size < MAX_LIMITATIONS - 1) values.add(value);
      else omitted++;
    },
    finish() {
      return [
        ...values,
        ...(omitted ? [`${omitted} additional Go source limitations omitted.`] : []),
      ].sort();
    },
  };
}

function normalized(path: string): string {
  return path.replace(/\\/g, "/");
}

function sameIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function unchangedFile(before: BigIntStats, after: BigIntStats): boolean {
  return sameIdentity(before, after) && before.size === after.size &&
    before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

async function hasSymbolicLinkAncestor(absoluteTarget: string): Promise<boolean> {
  const filesystemRoot = parse(absoluteTarget).root;
  const ancestors: string[] = [];
  let current = dirname(absoluteTarget);
  while (current !== filesystemRoot) {
    ancestors.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  for (const ancestor of ancestors.reverse()) {
    const metadata = await lstat(ancestor).catch(() => undefined);
    if (!metadata) break;
    if (metadata.isSymbolicLink()) return true;
  }
  return false;
}

async function readGoFile(
  absolute: string,
  displayPath: string,
  remainingBytes: number,
): Promise<{ document?: GoDocument; bytes?: number; limitation?: string; totalExceeded?: boolean }> {
  let handle: FileHandle | undefined;
  try {
    const before = await lstat(absolute, { bigint: true });
    if (before.isSymbolicLink()) {
      return { limitation: `Skipped symbolic-link Go source ${displayPath}.` };
    }
    if (!before.isFile()) return {};
    if (before.size > BigInt(GO_MAX_SOURCE_BYTES)) {
      return { limitation: `Skipped oversized Go source ${displayPath} (limit: ${GO_MAX_SOURCE_BYTES} bytes).` };
    }
    if (before.size > BigInt(remainingBytes)) {
      return { bytes: Number(before.size), totalExceeded: true };
    }

    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    handle = await open(absolute, constants.O_RDONLY | noFollow);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(before, opened)) {
      return { limitation: `Skipped changed Go source ${displayPath}.` };
    }
    if (opened.size > BigInt(GO_MAX_SOURCE_BYTES)) {
      return { limitation: `Skipped oversized Go source ${displayPath} (limit: ${GO_MAX_SOURCE_BYTES} bytes).` };
    }
    if (opened.size > BigInt(remainingBytes)) {
      return { bytes: Number(opened.size), totalExceeded: true };
    }
    const size = Number(opened.size);
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(bytes, offset, size - offset, offset);
      if (bytesRead === 0) return { limitation: `Skipped changed Go source ${displayPath}.` };
      offset += bytesRead;
    }
    if (!unchangedFile(opened, await handle.stat({ bigint: true }))) {
      return { bytes: size, limitation: `Skipped changed Go source ${displayPath}.` };
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return { bytes: size, limitation: `Skipped non-UTF-8 Go source ${displayPath}.` };
    }
    if (generatedSource(basename(absolute), content)) return { bytes: size };
    return { document: { path: normalized(displayPath), content }, bytes: size };
  } catch {
    return { limitation: `Skipped unreadable Go source ${displayPath}.` };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function loadUncached(target: string): Promise<GoProject> {
  const absoluteTarget = resolve(target);
  const limitations = collector();
  if (await hasSymbolicLinkAncestor(absoluteTarget)) {
    return {
      target: absoluteTarget,
      root: sourcePath(absoluteTarget) ? dirname(absoluteTarget) : absoluteTarget,
      files: [],
      limitations: [
        "Skipped Go source target because a symbolic-link ancestor would be followed; symbolic-link ancestors are never allowed.",
      ],
    };
  }
  let metadata;
  try {
    metadata = await lstat(absoluteTarget);
  } catch {
    return {
      target: absoluteTarget,
      root: absoluteTarget,
      files: [],
      limitations: ["Go source target was unreadable."],
    };
  }
  if (metadata.isSymbolicLink()) {
    return {
      target: absoluteTarget,
      root: dirname(absoluteTarget),
      files: [],
      limitations: ["Skipped symbolic-link Go source target; symbolic links are never followed."],
    };
  }
  if (metadata.isFile()) {
    if (!sourcePath(absoluteTarget)) {
      return { target: absoluteTarget, root: dirname(absoluteTarget), files: [] };
    }
    const loaded = await readGoFile(absoluteTarget, basename(absoluteTarget), GO_MAX_TOTAL_BYTES);
    if (loaded.limitation) limitations.add(loaded.limitation);
    return {
      target: absoluteTarget,
      root: dirname(absoluteTarget),
      files: loaded.document ? [loaded.document] : [],
      limitations: limitations.finish(),
    };
  }
  if (!metadata.isDirectory()) {
    return { target: absoluteTarget, root: absoluteTarget, files: [] };
  }

  const files: GoDocument[] = [];
  let entriesInspected = 0;
  let totalBytes = 0;
  let stopped = false;

  async function walk(directory: string, depth: number): Promise<void> {
    if (stopped) return;
    if (depth > GO_MAX_DEPTH) {
      limitations.add(`Skipped Go source below ${normalized(relative(absoluteTarget, directory)) || "."} beyond the ${GO_MAX_DEPTH}-level depth bound.`);
      return;
    }
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      limitations.add(`Skipped unreadable Go source directory ${normalized(relative(absoluteTarget, directory)) || "."}.`);
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (stopped) break;
      entriesInspected++;
      if (entriesInspected > GO_MAX_DISCOVERY_ENTRIES) {
        limitations.add(`Stopped Go source discovery at the ${GO_MAX_DISCOVERY_ENTRIES}-entry bound.`);
        stopped = true;
        break;
      }
      const absolute = join(directory, entry.name);
      const display = normalized(relative(absoluteTarget, absolute));
      if (entry.isSymbolicLink()) {
        limitations.add(`Skipped symbolic-link Go source entry ${display}.`);
        continue;
      }
      if (entry.isDirectory()) {
        const lower = entry.name.toLowerCase();
        if (IGNORED_DIRS.has(lower) || NON_PRODUCTION_DIRS.has(lower)) continue;
        await walk(absolute, depth + 1);
        continue;
      }
      if (!entry.isFile() || !sourcePath(entry.name)) continue;
      if (files.length >= GO_MAX_SOURCE_FILES) {
        limitations.add(`Stopped Go source discovery at the ${GO_MAX_SOURCE_FILES}-file bound.`);
        stopped = true;
        break;
      }
      const loaded = await readGoFile(absolute, display, GO_MAX_TOTAL_BYTES - totalBytes);
      if (loaded.limitation) limitations.add(loaded.limitation);
      if (loaded.totalExceeded) {
        limitations.add(`Stopped Go source discovery at the ${GO_MAX_TOTAL_BYTES}-byte project bound.`);
        stopped = true;
        break;
      }
      totalBytes += loaded.bytes ?? 0;
      if (loaded.document) files.push(loaded.document);
    }
  }

  await walk(absoluteTarget, 0);
  return {
    target: absoluteTarget,
    root: absoluteTarget,
    files,
    limitations: limitations.finish(),
  };
}

export function resolveGoProject(input: GoProjectInput): Promise<GoProject> {
  return typeof input === "string" ? loadUncached(input) : Promise.resolve(input);
}

export function createCachedGoProjectLoader(target: string): () => Promise<GoProject> {
  let cached: Promise<GoProject> | undefined;
  return () => cached ??= loadUncached(target);
}
