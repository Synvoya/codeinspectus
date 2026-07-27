/** Read-only, bounded Python project loading shared by Python native packs. */

import { constants, type BigIntStats, type Dirent } from "node:fs";
import { lstat, open, opendir, type FileHandle } from "node:fs/promises";
import { basename, dirname, extname, join, parse, relative, resolve } from "node:path";

import { parsePythonSource, type PythonDocument } from "./python.js";

export const PYTHON_MAX_SOURCE_BYTES = 2 * 1024 * 1024;
export const PYTHON_MAX_SOURCE_FILES = 10_000;
export const PYTHON_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
export const PYTHON_MAX_TOTAL_TOKENS = 1_000_000;
export const PYTHON_MAX_TOTAL_CST_NODES = 1_000_000;
export const PYTHON_MAX_DEPTH = 32;
export const PYTHON_MAX_DISCOVERY_ENTRIES = 50_000;

const MAX_LIMITATIONS = 24;
const EXTENSIONS = new Set([".py", ".pyw"]);
const IGNORED_DIRS = new Set([
  ".cache", ".git", ".hg", ".idea", ".mypy_cache", ".nox", ".pytest_cache",
  ".ruff_cache", ".svn", ".tox", ".venv", ".vscode", "__pycache__", "build",
  "coverage", "dist", "env", "htmlcov", "node_modules", "site-packages", "target",
  "venv", "vendor",
]);
const NON_PRODUCTION_DIRS = new Set([
  "__fixtures__", "__generated__", "__mocks__", "__tests__", "demo", "demos",
  "example", "examples", "fixture", "fixtures", "generated", "sample", "samples",
  "integration_test", "integration_tests", "migrations", "test", "tests",
]);

export interface PythonProject {
  target: string;
  root: string;
  files: PythonDocument[];
  limitations?: string[];
}

export type PythonProjectInput = string | PythonProject | Promise<PythonProject>;

export interface PythonProjectBounds {
  maxSourceBytes: number;
  maxSourceFiles: number;
  maxTotalBytes: number;
  maxTotalTokens: number;
  maxTotalCstNodes: number;
  maxDepth: number;
  maxDiscoveryEntries: number;
}

const DEFAULT_BOUNDS: PythonProjectBounds = {
  maxSourceBytes: PYTHON_MAX_SOURCE_BYTES,
  maxSourceFiles: PYTHON_MAX_SOURCE_FILES,
  maxTotalBytes: PYTHON_MAX_TOTAL_BYTES,
  maxTotalTokens: PYTHON_MAX_TOTAL_TOKENS,
  maxTotalCstNodes: PYTHON_MAX_TOTAL_CST_NODES,
  maxDepth: PYTHON_MAX_DEPTH,
  maxDiscoveryEntries: PYTHON_MAX_DISCOVERY_ENTRIES,
};

function normalizedBounds(overrides: Partial<PythonProjectBounds>): PythonProjectBounds {
  const values = { ...DEFAULT_BOUNDS, ...overrides };
  for (const [name, value] of Object.entries(values)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`Invalid Python project bound ${name}.`);
  }
  return values;
}

function sourceExtension(path: string): boolean {
  return EXTENSIONS.has(extname(path).toLowerCase());
}

function generatedSource(name: string): boolean {
  const lower = name.toLowerCase();
  return /(?:^|[._-])generated\.pyw?$/.test(lower) ||
    /(?:_pb2|_pb2_grpc|_grpc)\.py$/.test(lower);
}

function nonProductionSourceName(name: string): boolean {
  const lower = name.toLowerCase();
  return lower === "conftest.py" || lower === "tests.py" ||
    lower.startsWith("test_") || lower.endsWith("_test.py");
}

function limitationCollector(): { add: (message: string) => void; finish: () => string[] } {
  const values = new Set<string>();
  let omitted = 0;
  return {
    add(message) {
      if (values.size < MAX_LIMITATIONS - 1) values.add(message);
      else omitted++;
    },
    finish() {
      return [
        ...values,
        ...(omitted ? [`${omitted} additional Python source limitations omitted.`] : []),
      ].sort();
    },
  };
}

interface Identity {
  dev: bigint;
  ino: bigint;
}

interface DirectoryListing {
  entries: Dirent[];
  identity: BigIntStats;
}

interface LoadedFile {
  document?: PythonDocument;
  size?: number;
  limitation?: string;
  totalBoundExceeded?: boolean;
}

interface FileReadGuards {
  rootPath?: string;
  rootIdentity?: Identity;
  parentPath: string;
  parentIdentity: Identity;
  fileIdentity?: Identity;
}

function decodePythonSource(bytes: Buffer): { content?: string; limitation?: string } {
  const header = bytes.subarray(0, Math.min(bytes.length, 1024)).toString("latin1");
  const declaration = header.split(/\r?\n/, 2).join("\n")
    .match(/coding[=:]\s*([-\w.]+)/i)?.[1]?.toLowerCase().replace(/_/g, "-");
  const supported = new Set(["ascii", "us-ascii", "utf-8", "utf8", "utf-8-sig"]);
  if (declaration && !supported.has(declaration)) {
    return { limitation: `declares unsupported ${declaration} encoding` };
  }
  if ((declaration === "ascii" || declaration === "us-ascii") && bytes.some((byte) => byte > 0x7f)) {
    return { limitation: "declares ASCII but contains non-ASCII bytes" };
  }
  try {
    return { content: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch {
    return { limitation: "is not valid UTF-8" };
  }
}

function sameIdentity(left: Identity, right: Identity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function unchangedFile(before: BigIntStats, after: BigIntStats): boolean {
  return sameIdentity(before, after) && before.size === after.size &&
    before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

/** Inspect ancestors top-down so no descendant beneath a symbolic link is touched. */
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
  ancestors.reverse();
  for (const ancestor of ancestors) {
    const metadata = await lstat(ancestor, { bigint: true }).catch(() => undefined);
    if (!metadata) break;
    if (metadata.isSymbolicLink()) return true;
  }
  return false;
}

async function guardsUnchanged(guards: FileReadGuards): Promise<boolean> {
  const parent = await lstat(guards.parentPath, { bigint: true }).catch(() => undefined);
  if (!parent?.isDirectory() || parent.isSymbolicLink() || !sameIdentity(parent, guards.parentIdentity)) {
    return false;
  }
  if (guards.rootPath && guards.rootIdentity) {
    const root = await lstat(guards.rootPath, { bigint: true }).catch(() => undefined);
    if (!root?.isDirectory() || root.isSymbolicLink() || !sameIdentity(root, guards.rootIdentity)) {
      return false;
    }
  }
  return true;
}

async function loadFile(
  absolute: string,
  displayPath: string,
  remainingTotalBytes: number,
  maxSourceBytes: number,
  guards: FileReadGuards,
): Promise<LoadedFile> {
  let handle: FileHandle | undefined;
  try {
    if (!(await guardsUnchanged(guards))) {
      return { limitation: `Skipped changed Python source parent for ${displayPath}.` };
    }
    const metadata = await lstat(absolute, { bigint: true });
    if (guards.fileIdentity && !sameIdentity(metadata, guards.fileIdentity)) {
      return { limitation: `Skipped changed Python source ${displayPath}.` };
    }
    if (metadata.isSymbolicLink()) {
      return { limitation: `Skipped symbolic-link Python source ${displayPath}.` };
    }
    if (!metadata.isFile()) return {};
    if (metadata.size > BigInt(maxSourceBytes)) {
      return { limitation: `Skipped oversized Python source ${displayPath} (limit: ${maxSourceBytes} bytes).` };
    }
    if (metadata.size > BigInt(remainingTotalBytes)) {
      return { size: Number(metadata.size), totalBoundExceeded: true };
    }
    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    handle = await open(absolute, constants.O_RDONLY | noFollow);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(metadata, opened)) {
      return { limitation: `Skipped changed Python source ${displayPath}.` };
    }
    if (opened.size > BigInt(maxSourceBytes)) {
      return { limitation: `Skipped oversized Python source ${displayPath} (limit: ${maxSourceBytes} bytes).` };
    }
    if (opened.size > BigInt(remainingTotalBytes)) {
      return { size: Number(opened.size), totalBoundExceeded: true };
    }
    if (!(await guardsUnchanged(guards))) {
      return { limitation: `Skipped changed Python source parent for ${displayPath}.` };
    }
    const size = Number(opened.size);
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(bytes, offset, size - offset, offset);
      if (bytesRead === 0) return { limitation: `Skipped changed Python source ${displayPath}.` };
      offset += bytesRead;
    }
    const afterRead = await handle.stat({ bigint: true });
    if (!unchangedFile(opened, afterRead) || !(await guardsUnchanged(guards))) {
      return { size, limitation: `Skipped changed Python source ${displayPath}.` };
    }
    const decoded = decodePythonSource(bytes);
    if (decoded.limitation || decoded.content === undefined) {
      return {
        size,
        limitation: `Skipped Python source ${displayPath}: ${decoded.limitation ?? "unsupported encoding"}.`,
      };
    }
    const header = decoded.content.split(/\r?\n/, 6).join("\n");
    if (
      /(?:generated|autogenerated).{0,80}(?:do not edit|do not modify)/is.test(header) ||
      /(?:do not edit|do not modify).{0,80}(?:generated|autogenerated)/is.test(header)
    ) {
      return { size, limitation: `Skipped generated Python source ${displayPath}.` };
    }
    return {
      document: parsePythonSource(displayPath.replace(/\\/g, "/"), decoded.content),
      size,
    };
  } catch {
    return { limitation: `Skipped unreadable Python source ${displayPath}.` };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function documentLimitations(document: PythonDocument): string[] {
  if (document.tokenLimitExceeded) {
    return [`Skipped Python source ${document.path} beyond the 200,000-token file bound.`];
  }
  if (document.nestingLimitExceeded) {
    return [`Skipped Python source ${document.path} beyond the 64-level structural bound.`];
  }
  if (document.cstNodeLimitExceeded) {
    return [`Skipped Python source ${document.path} beyond the 200,000-node syntax-tree bound.`];
  }
  if (document.cstDepthLimitExceeded) {
    return [`Skipped Python source ${document.path} beyond the 128-level syntax-tree bound.`];
  }
  if (document.formatStringUnsupported) {
    return [`Skipped Python source ${document.path} containing an unsupported format string.`];
  }
  if (document.tabIndentationUnsupported) {
    return [`Skipped Python source ${document.path} containing unsupported tab indentation.`];
  }
  if (document.syntaxError) {
    return [`Skipped parser-invalid Python source ${document.path}.`];
  }
  if (!document.balanced) {
    return [`Skipped structurally malformed Python source ${document.path}.`];
  }
  return [];
}

async function loadUncached(
  target: string,
  boundOverrides: Partial<PythonProjectBounds> = {},
): Promise<PythonProject> {
  const bounds = normalizedBounds(boundOverrides);
  const absoluteTarget = resolve(target);
  const limitations = limitationCollector();
  if (await hasSymbolicLinkAncestor(absoluteTarget)) {
    return {
      target: absoluteTarget,
      root: sourceExtension(absoluteTarget) ? dirname(absoluteTarget) : absoluteTarget,
      files: [],
      limitations: [
        "Skipped Python source target because a symbolic-link ancestor would be followed; symbolic-link ancestors are never allowed.",
      ],
    };
  }
  const targetMetadata = await lstat(absoluteTarget, { bigint: true }).catch(() => undefined);
  if (!targetMetadata) {
    return {
      target: absoluteTarget,
      root: absoluteTarget,
      files: [],
      limitations: ["Python source target was unreadable."],
    };
  }
  if (targetMetadata.isSymbolicLink()) {
    return {
      target: absoluteTarget,
      root: dirname(absoluteTarget),
      files: [],
      limitations: ["Skipped symbolic-link Python source target; symbolic links are never followed."],
    };
  }
  if (targetMetadata.isFile()) {
    if (!sourceExtension(absoluteTarget)) {
      return { target: absoluteTarget, root: dirname(absoluteTarget), files: [] };
    }
    const loaded = await loadFile(
      absoluteTarget,
      basename(absoluteTarget),
      bounds.maxTotalBytes,
      bounds.maxSourceBytes,
      {
        parentPath: dirname(absoluteTarget),
        parentIdentity: await lstat(dirname(absoluteTarget), { bigint: true }),
        fileIdentity: targetMetadata,
      },
    );
    if (loaded.totalBoundExceeded) {
      limitations.add(`Stopped Python source discovery at the ${bounds.maxTotalBytes}-byte total-source project bound.`);
    }
    if (loaded.limitation) limitations.add(loaded.limitation);
    if (loaded.document) documentLimitations(loaded.document).forEach(limitations.add);
    const withinTokenBound = Boolean(
      loaded.document && loaded.document.balanced &&
      loaded.document.tokens.length <= bounds.maxTotalTokens &&
      loaded.document.cstNodeCount <= bounds.maxTotalCstNodes,
    );
    if (loaded.document && loaded.document.tokens.length > bounds.maxTotalTokens) {
      limitations.add(`Stopped Python source discovery at the ${bounds.maxTotalTokens}-token project bound.`);
    }
    if (loaded.document && loaded.document.cstNodeCount > bounds.maxTotalCstNodes) {
      limitations.add(`Stopped Python source discovery at the ${bounds.maxTotalCstNodes}-node project bound.`);
    }
    return {
      target: absoluteTarget,
      root: dirname(absoluteTarget),
      files: withinTokenBound ? [loaded.document!] : [],
      limitations: limitations.finish(),
    };
  }
  if (!targetMetadata.isDirectory()) {
    return { target: absoluteTarget, root: absoluteTarget, files: [] };
  }

  const files: PythonDocument[] = [];
  let totalBytes = 0;
  let totalTokens = 0;
  let totalCstNodes = 0;
  let sourceCandidates = 0;
  let discoveryEntries = 0;
  let boundsExhausted = false;
  let boundReason: "entries" | "files" | "bytes" | "tokens" | "nodes" | undefined;

  async function boundedDirectoryEntries(directory: string): Promise<DirectoryListing | undefined> {
    const remainingEntries = bounds.maxDiscoveryEntries - discoveryEntries;
    const displayPath = relative(absoluteTarget, directory).replace(/\\/g, "/") || ".";
    if (remainingEntries <= 0) {
      boundsExhausted = true;
      boundReason = "entries";
      return undefined;
    }
    const before = await lstat(directory, { bigint: true }).catch(() => undefined);
    if (!before) {
      limitations.add(`Skipped unreadable Python source directory ${displayPath}.`);
      return undefined;
    }
    if (before.isSymbolicLink()) {
      limitations.add(`Skipped symbolic-link Python source directory ${displayPath}.`);
      return undefined;
    }
    if (!before.isDirectory()) {
      limitations.add(`Skipped changed Python source directory ${displayPath}.`);
      return undefined;
    }
    let handle;
    try {
      handle = await opendir(directory);
      const opened = await lstat(directory, { bigint: true });
      if (!opened.isDirectory() || opened.isSymbolicLink() || !sameIdentity(before, opened)) {
        limitations.add(`Skipped changed Python source directory ${displayPath}.`);
        return undefined;
      }
      const entries: Dirent[] = [];
      while (true) {
        const entry = await handle.read();
        if (!entry) break;
        if (entries.length >= remainingEntries) {
          boundsExhausted = true;
          boundReason = "entries";
          return undefined;
        }
        entries.push(entry);
      }
      const afterRead = await lstat(directory, { bigint: true });
      if (!afterRead.isDirectory() || afterRead.isSymbolicLink() || !sameIdentity(before, afterRead)) {
        limitations.add(`Skipped changed Python source directory ${displayPath}.`);
        return undefined;
      }
      discoveryEntries += entries.length;
      return {
        entries: entries.sort((left, right) => left.name.localeCompare(right.name)),
        identity: before,
      };
    } catch {
      limitations.add(`Skipped unreadable Python source directory ${displayPath}.`);
      return undefined;
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  async function walk(directory: string, depth: number): Promise<void> {
    if (boundsExhausted) return;
    if (depth > bounds.maxDepth) {
      limitations.add(`Skipped Python source below the ${bounds.maxDepth}-level discovery bound.`);
      return;
    }
    const listing = await boundedDirectoryEntries(directory);
    if (!listing) return;
    for (const entry of listing.entries) {
      if (boundsExhausted) break;
      const current = await lstat(directory, { bigint: true }).catch(() => undefined);
      if (!current?.isDirectory() || current.isSymbolicLink() || !sameIdentity(listing.identity, current)) {
        const displayPath = relative(absoluteTarget, directory).replace(/\\/g, "/") || ".";
        limitations.add(`Skipped changed Python source directory ${displayPath}.`);
        return;
      }
      const absolute = join(directory, entry.name);
      const lower = entry.name.toLowerCase();
      if (entry.isSymbolicLink()) {
        const displayPath = relative(absoluteTarget, absolute).replace(/\\/g, "/");
        limitations.add(`Skipped symbolic-link Python source path ${displayPath}.`);
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(lower) || NON_PRODUCTION_DIRS.has(lower)) continue;
        await walk(absolute, depth + 1);
        continue;
      }
      if (
        !entry.isFile() || !sourceExtension(entry.name) || generatedSource(entry.name) ||
        nonProductionSourceName(entry.name)
      ) continue;
      const reachedAggregateBound = totalBytes >= bounds.maxTotalBytes
        ? "bytes"
        : totalTokens >= bounds.maxTotalTokens
          ? "tokens"
          : totalCstNodes >= bounds.maxTotalCstNodes
            ? "nodes"
            : undefined;
      if (reachedAggregateBound) {
        boundsExhausted = true;
        boundReason = reachedAggregateBound;
        break;
      }
      sourceCandidates++;
      if (sourceCandidates > bounds.maxSourceFiles) {
        boundsExhausted = true;
        boundReason = "files";
        break;
      }
      const displayPath = relative(absoluteTarget, absolute).replace(/\\/g, "/");
      const loaded = await loadFile(
        absolute,
        displayPath,
        bounds.maxTotalBytes - totalBytes,
        bounds.maxSourceBytes,
        {
          rootPath: absoluteTarget,
          rootIdentity: targetMetadata,
          parentPath: directory,
          parentIdentity: listing.identity,
        },
      );
      if (loaded.totalBoundExceeded) {
        boundsExhausted = true;
        boundReason = "bytes";
        break;
      }
      if (loaded.size !== undefined) totalBytes += loaded.size;
      if (loaded.limitation) {
        limitations.add(loaded.limitation);
        continue;
      }
      if (!loaded.document || loaded.size === undefined) continue;
      documentLimitations(loaded.document).forEach(limitations.add);
      totalTokens += loaded.document.tokens.length;
      totalCstNodes += loaded.document.cstNodeCount;
      if (totalTokens > bounds.maxTotalTokens) {
        boundsExhausted = true;
        boundReason = "tokens";
        break;
      }
      if (totalCstNodes > bounds.maxTotalCstNodes) {
        boundsExhausted = true;
        boundReason = "nodes";
        break;
      }
      if (!loaded.document.balanced) continue;
      files.push(loaded.document);
    }
  }

  await walk(absoluteTarget, 0);
  if (boundReason === "entries") limitations.add(
    `Stopped Python source discovery at the ${bounds.maxDiscoveryEntries}-entry project bound.`,
  );
  if (boundReason === "files") limitations.add(
    `Stopped Python source discovery at the ${bounds.maxSourceFiles}-file project bound.`,
  );
  if (boundReason === "bytes") limitations.add(
    `Stopped Python source discovery at the ${bounds.maxTotalBytes}-byte total-source project bound.`,
  );
  if (boundReason === "tokens") limitations.add(
    `Stopped Python source discovery at the ${bounds.maxTotalTokens}-token project bound.`,
  );
  if (boundReason === "nodes") limitations.add(
    `Stopped Python source discovery at the ${bounds.maxTotalCstNodes}-node project bound.`,
  );
  files.sort((left, right) => left.path.localeCompare(right.path));
  return {
    target: absoluteTarget,
    root: absoluteTarget,
    files,
    limitations: limitations.finish(),
  };
}

export function loadPythonProject(
  target: string,
  bounds: Partial<PythonProjectBounds> = {},
): Promise<PythonProject> {
  return loadUncached(target, bounds);
}

export function createCachedPythonProjectLoader(target: string): () => Promise<PythonProject> {
  let cached: Promise<PythonProject> | undefined;
  return () => cached ??= loadUncached(target);
}

export function resolvePythonProject(input: PythonProjectInput): Promise<PythonProject> {
  if (typeof input === "string") return loadUncached(input);
  return Promise.resolve(input);
}
