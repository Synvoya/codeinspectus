/** Read-only, bounded React Native JavaScript/TypeScript project loading. */

import { constants, type BigIntStats, type Dirent } from "node:fs";
import { lstat, open, opendir, type FileHandle } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";

import { parseJavaScriptSource, type JsDocument } from "./javascript.js";

export const REACT_NATIVE_MAX_SOURCE_BYTES = 2 * 1024 * 1024;
export const REACT_NATIVE_MAX_SOURCE_FILES = 10_000;
export const REACT_NATIVE_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
export const REACT_NATIVE_MAX_TOTAL_TOKENS = 1_000_000;
export const REACT_NATIVE_MAX_DEPTH = 32;
export const REACT_NATIVE_MAX_DISCOVERY_ENTRIES = 50_000;

const MAX_LIMITATIONS = 24;
const EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"]);
const IGNORED_DIRS = new Set([
  ".cache", ".expo", ".git", ".gradle", ".idea", ".next", ".nuxt", ".output",
  ".turbo", ".vscode", "build", "coverage", "deriveddata", "dist", "node_modules",
  "pods", "vendor",
]);
const NON_PRODUCTION_DIRS = new Set([
  "__fixtures__", "__generated__", "__mocks__", "__tests__", "demo", "demos", "example", "examples",
  "fixture", "fixtures", "generated", "sample", "samples", "test", "tests",
]);

export interface ReactNativeProject {
  target: string;
  root: string;
  files: JsDocument[];
  limitations?: string[];
}

export type ReactNativeProjectInput = string | ReactNativeProject | Promise<ReactNativeProject>;

export interface ReactNativeProjectBounds {
  maxSourceBytes: number;
  maxSourceFiles: number;
  maxTotalBytes: number;
  maxTotalTokens: number;
  maxDepth: number;
  maxDiscoveryEntries: number;
}

const DEFAULT_BOUNDS: ReactNativeProjectBounds = {
  maxSourceBytes: REACT_NATIVE_MAX_SOURCE_BYTES,
  maxSourceFiles: REACT_NATIVE_MAX_SOURCE_FILES,
  maxTotalBytes: REACT_NATIVE_MAX_TOTAL_BYTES,
  maxTotalTokens: REACT_NATIVE_MAX_TOTAL_TOKENS,
  maxDepth: REACT_NATIVE_MAX_DEPTH,
  maxDiscoveryEntries: REACT_NATIVE_MAX_DISCOVERY_ENTRIES,
};

function normalizedBounds(overrides: Partial<ReactNativeProjectBounds> = {}): ReactNativeProjectBounds {
  const values = { ...DEFAULT_BOUNDS, ...overrides };
  for (const [name, value] of Object.entries(values)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`Invalid React Native project bound ${name}.`);
  }
  return values;
}

function sourceExtension(path: string): boolean {
  const lower = path.toLowerCase();
  return [...EXTENSIONS].some((extension) => lower.endsWith(extension));
}

function generatedSource(name: string): boolean {
  const lower = name.toLowerCase();
  return lower.endsWith(".min.js") || lower.endsWith(".bundle.js") ||
    /(?:^|\.)(?:generated|gen)\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/.test(lower);
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
        ...(omitted ? [`${omitted} additional React Native source limitations omitted.`] : []),
      ].sort();
    },
  };
}

interface LoadedFile {
  document?: JsDocument;
  size?: number;
  limitation?: string;
}

interface Identity {
  dev: bigint;
  ino: bigint;
}

interface DirectoryListing {
  entries: Dirent[];
  identity: BigIntStats;
}

function sameIdentity(left: Identity, right: Identity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function unchangedFile(before: BigIntStats, after: BigIntStats): boolean {
  // A same-size in-place rewrite is rejected as well as inode/size swaps.
  return sameIdentity(before, after) && before.size === after.size &&
    before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

async function loadFile(
  absolute: string,
  displayPath: string,
  remainingTotalBytes: number,
  maxSourceBytes: number,
): Promise<LoadedFile & { totalBoundExceeded?: boolean }> {
  let handle: FileHandle | undefined;
  try {
    const metadata = await lstat(absolute, { bigint: true });
    if (metadata.isSymbolicLink()) {
      return { limitation: `Skipped symbolic-link React Native source ${displayPath}.` };
    }
    if (!metadata.isFile()) return {};
    if (metadata.size > BigInt(maxSourceBytes)) {
      return { limitation: `Skipped oversized React Native source ${displayPath} (limit: ${maxSourceBytes} bytes).` };
    }
    if (metadata.size > BigInt(remainingTotalBytes)) {
      return { size: Number(metadata.size), totalBoundExceeded: true };
    }
    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    handle = await open(absolute, constants.O_RDONLY | noFollow);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(metadata, opened)) {
      return { limitation: `Skipped changed React Native source ${displayPath}.` };
    }
    if (opened.size > BigInt(maxSourceBytes)) {
      return { limitation: `Skipped oversized React Native source ${displayPath} (limit: ${maxSourceBytes} bytes).` };
    }
    if (opened.size > BigInt(remainingTotalBytes)) {
      return { size: Number(opened.size), totalBoundExceeded: true };
    }
    const size = Number(opened.size);
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(bytes, offset, size - offset, offset);
      if (bytesRead === 0) return { limitation: `Skipped changed React Native source ${displayPath}.` };
      offset += bytesRead;
    }
    const afterRead = await handle.stat({ bigint: true });
    if (!unchangedFile(opened, afterRead)) {
      return { limitation: `Skipped changed React Native source ${displayPath}.` };
    }
    const content = bytes.toString("utf8");
    const document = parseJavaScriptSource(displayPath.replace(/\\/g, "/"), content);
    return { document, size };
  } catch {
    return { limitation: `Skipped unreadable React Native source ${displayPath}.` };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function documentLimitations(document: JsDocument): string[] {
  const notes: string[] = [];
  if (!document.balanced) {
    notes.push(`Skipped structurally malformed JavaScript/TypeScript source ${document.path}.`);
  }
  if (document.hasDynamicJsxSpread) {
    notes.push(`Dynamic JSX spread props in ${document.path} were not interpreted.`);
  }
  return notes;
}

async function loadUncached(
  target: string,
  boundOverrides: Partial<ReactNativeProjectBounds> = {},
): Promise<ReactNativeProject> {
  const bounds = normalizedBounds(boundOverrides);
  const absoluteTarget = resolve(target);
  const limitations = limitationCollector();
  let targetMetadata;
  try {
    targetMetadata = await lstat(absoluteTarget);
  } catch {
    return {
      target: absoluteTarget,
      root: absoluteTarget,
      files: [],
      limitations: ["React Native source target was unreadable."],
    };
  }
  if (targetMetadata.isSymbolicLink()) {
    return {
      target: absoluteTarget,
      root: dirname(absoluteTarget),
      files: [],
      limitations: ["Skipped symbolic-link React Native source target; symbolic links are never followed."],
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
    );
    if (loaded.limitation) limitations.add(loaded.limitation);
    if (loaded.document) documentLimitations(loaded.document).forEach(limitations.add);
    if (loaded.document && loaded.document.tokens.length > bounds.maxTotalTokens) {
      limitations.add(
        `Stopped React Native source discovery at the ${bounds.maxTotalTokens}-token project bound.`,
      );
    }
    return {
      target: absoluteTarget,
      root: dirname(absoluteTarget),
      files: loaded.document && loaded.document.tokens.length <= bounds.maxTotalTokens ? [loaded.document] : [],
      limitations: limitations.finish(),
    };
  }
  if (!targetMetadata.isDirectory()) {
    return { target: absoluteTarget, root: absoluteTarget, files: [] };
  }

  const files: JsDocument[] = [];
  let totalBytes = 0;
  let totalTokens = 0;
  let sourceCandidates = 0;
  let discoveryEntries = 0;
  let boundsExhausted = false;
  let boundReason: "entries" | "files" | "bytes" | "tokens" | undefined;

  async function boundedDirectoryEntries(directory: string): Promise<DirectoryListing | undefined> {
    const remainingEntries = bounds.maxDiscoveryEntries - discoveryEntries;
    if (remainingEntries <= 0) {
      boundsExhausted = true;
      boundReason = "entries";
      return undefined;
    }
    let before;
    try {
      before = await lstat(directory, { bigint: true });
    } catch {
      const rel = relative(absoluteTarget, directory).replace(/\\/g, "/") || ".";
      limitations.add(`Skipped unreadable React Native source directory ${rel}.`);
      return undefined;
    }
    const rel = relative(absoluteTarget, directory).replace(/\\/g, "/") || ".";
    if (before.isSymbolicLink()) {
      limitations.add(`Skipped symbolic-link React Native source directory ${rel}.`);
      return undefined;
    }
    if (!before.isDirectory()) {
      limitations.add(`Skipped changed React Native source directory ${rel}.`);
      return undefined;
    }
    let directoryHandle;
    try {
      directoryHandle = await opendir(directory);
      const afterOpen = await lstat(directory, { bigint: true });
      if (!afterOpen.isDirectory() || afterOpen.isSymbolicLink() || !sameIdentity(before, afterOpen)) {
        limitations.add(`Skipped changed React Native source directory ${rel}.`);
        return undefined;
      }
      const entries: Dirent[] = [];
      while (true) {
        const entry = await directoryHandle.read();
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
        limitations.add(`Skipped changed React Native source directory ${rel}.`);
        return undefined;
      }
      discoveryEntries += entries.length;
      return {
        entries: entries.sort((left, right) => left.name.localeCompare(right.name)),
        identity: before,
      };
    } catch {
      limitations.add(`Skipped unreadable React Native source directory ${rel}.`);
      return undefined;
    } finally {
      await directoryHandle?.close().catch(() => undefined);
    }
  }

  async function walk(directory: string, depth: number): Promise<void> {
    if (boundsExhausted) return;
    if (depth > bounds.maxDepth) {
      limitations.add(`Skipped React Native source below the ${bounds.maxDepth}-level discovery bound.`);
      return;
    }
    const listing = await boundedDirectoryEntries(directory);
    if (!listing) return;
    for (const entry of listing.entries) {
      if (boundsExhausted) break;
      const currentDirectory = await lstat(directory, { bigint: true }).catch(() => undefined);
      if (
        !currentDirectory?.isDirectory() || currentDirectory.isSymbolicLink() ||
        !sameIdentity(listing.identity, currentDirectory)
      ) {
        const rel = relative(absoluteTarget, directory).replace(/\\/g, "/") || ".";
        limitations.add(`Skipped changed React Native source directory ${rel}.`);
        return;
      }
      const absolute = join(directory, entry.name);
      const lower = entry.name.toLowerCase();
      if (entry.isSymbolicLink()) {
        const rel = relative(absoluteTarget, absolute).replace(/\\/g, "/");
        limitations.add(`Skipped symbolic-link React Native source path ${rel}.`);
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(lower) || NON_PRODUCTION_DIRS.has(lower)) continue;
        await walk(absolute, depth + 1);
        continue;
      }
      if (!entry.isFile() || !sourceExtension(entry.name) || generatedSource(entry.name)) continue;
      sourceCandidates++;
      if (sourceCandidates > bounds.maxSourceFiles) {
        boundsExhausted = true;
        boundReason = "files";
        break;
      }
      const rel = relative(absoluteTarget, absolute).replace(/\\/g, "/");
      const loaded = await loadFile(
        absolute,
        rel,
        bounds.maxTotalBytes - totalBytes,
        bounds.maxSourceBytes,
      );
      if (loaded.totalBoundExceeded) {
        boundsExhausted = true;
        boundReason = "bytes";
        break;
      }
      if (loaded.limitation) {
        limitations.add(loaded.limitation);
        continue;
      }
      if (!loaded.document || loaded.size === undefined) continue;
      if (totalTokens + loaded.document.tokens.length > bounds.maxTotalTokens) {
        boundsExhausted = true;
        boundReason = "tokens";
        break;
      }
      totalBytes += loaded.size;
      totalTokens += loaded.document.tokens.length;
      files.push(loaded.document);
      documentLimitations(loaded.document).forEach(limitations.add);
    }
  }

  await walk(absoluteTarget, 0);
  if (boundReason === "entries") limitations.add(
    `Stopped React Native source discovery at the ${bounds.maxDiscoveryEntries}-entry project bound.`,
  );
  if (boundReason === "files") limitations.add(
    `Stopped React Native source discovery at the ${bounds.maxSourceFiles}-file project bound.`,
  );
  if (boundReason === "bytes") limitations.add(
    `Stopped React Native source discovery at the ${bounds.maxTotalBytes}-byte total-source project bound.`,
  );
  if (boundReason === "tokens") limitations.add(
    `Stopped React Native source discovery at the ${bounds.maxTotalTokens}-token project bound.`,
  );
  files.sort((left, right) => left.path.localeCompare(right.path));
  return {
    target: absoluteTarget,
    root: absoluteTarget,
    files,
    limitations: limitations.finish(),
  };
}

export function loadReactNativeProject(
  target: string,
  bounds: Partial<ReactNativeProjectBounds> = {},
): Promise<ReactNativeProject> {
  return loadUncached(target, bounds);
}

export function createCachedReactNativeProjectLoader(
  target: string,
): () => Promise<ReactNativeProject> {
  let cached: Promise<ReactNativeProject> | undefined;
  return () => cached ??= loadUncached(target);
}

export function resolveReactNativeProject(input: ReactNativeProjectInput): Promise<ReactNativeProject> {
  if (typeof input === "string") return loadUncached(input);
  return Promise.resolve(input);
}
