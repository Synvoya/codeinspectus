/** Read-only Dart project loading shared by every Flutter analyzer in one pack run. */

import { readdir, readFile, stat } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";

import { parseDartSource, type DartDocument } from "./dart.js";

const MAX_DART_BYTES = 2 * 1024 * 1024;
const MAX_DART_FILES = 10_000;
const MAX_DART_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_LIMITATIONS = 20;
const ALWAYS_IGNORED_DIRS = new Set([
  ".cache",
  ".dart_tool",
  ".git",
  ".gradle",
  ".idea",
  ".pub-cache",
  ".vscode",
  "build",
  "coverage",
  "node_modules",
  "pods",
  "vendor",
]);
const PROJECT_CORPUS_DIRS = new Set(["test", "integration_test", "example", "examples"]);

export interface FlutterProject {
  target: string;
  root: string;
  files: DartDocument[];
  /** Bounded, project-relative omissions that qualify pack execution coverage. */
  limitations?: string[];
}

export type FlutterProjectInput = string | FlutterProject | Promise<FlutterProject>;

function generatedDart(name: string): boolean {
  return name.endsWith(".g.dart") || name.endsWith(".freezed.dart");
}

interface LoadFileResult {
  document?: DartDocument;
  size?: number;
  limitation?: string;
}

async function loadFile(abs: string, rel: string): Promise<LoadFileResult> {
  try {
    const metadata = await stat(abs);
    if (!metadata.isFile()) return {};
    if (metadata.size > MAX_DART_BYTES) {
      return { limitation: `Skipped oversized Dart file ${rel} (limit: 2 MiB).` };
    }
    const content = await readFile(abs, "utf8");
    return {
      document: parseDartSource(rel.replace(/\\/g, "/"), content),
      size: metadata.size,
    };
  } catch {
    return { limitation: `Skipped unreadable Dart file ${rel}.` };
  }
}

function limitationCollector(): {
  add: (message: string) => void;
  finish: () => string[];
} {
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
        ...(omitted ? [`${omitted} additional Flutter source limitations omitted.`] : []),
      ].sort();
    },
  };
}

async function loadUncached(target: string): Promise<FlutterProject> {
  const absoluteTarget = resolve(target);
  const limitations = limitationCollector();
  const metadata = await stat(absoluteTarget).catch(() => undefined);
  if (!metadata) {
    return {
      target: absoluteTarget,
      root: absoluteTarget,
      files: [],
      limitations: ["Flutter source target was unreadable."],
    };
  }

  if (metadata.isFile()) {
    if (!absoluteTarget.toLowerCase().endsWith(".dart")) {
      return { target: absoluteTarget, root: dirname(absoluteTarget), files: [] };
    }
    const root = dirname(absoluteTarget);
    const loaded = await loadFile(absoluteTarget, basename(absoluteTarget));
    if (loaded.limitation) limitations.add(loaded.limitation);
    return {
      target: absoluteTarget,
      root,
      files: loaded.document ? [loaded.document] : [],
      limitations: limitations.finish(),
    };
  }

  if (!metadata.isDirectory()) return { target: absoluteTarget, root: absoluteTarget, files: [] };
  const files: DartDocument[] = [];
  let totalBytes = 0;
  let boundedFilesSkipped = 0;

  async function walk(directory: string, depth: number): Promise<void> {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      const rel = relative(absoluteTarget, directory).replace(/\\/g, "/") || ".";
      limitations.add(`Skipped unreadable Flutter source directory ${rel}.`);
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const abs = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (ALWAYS_IGNORED_DIRS.has(entry.name.toLowerCase())) continue;
        // A caller can intentionally scan test/, integration_test/, or examples/ as
        // the target root. A normal project-root scan excludes those corpora.
        if (depth === 0 && PROJECT_CORPUS_DIRS.has(entry.name)) continue;
        if (PROJECT_CORPUS_DIRS.has(entry.name)) continue;
        await walk(abs, depth + 1);
      } else if (
        entry.isFile() &&
        entry.name.toLowerCase().endsWith(".dart") &&
        !generatedDart(entry.name.toLowerCase())
      ) {
        if (files.length >= MAX_DART_FILES) {
          boundedFilesSkipped++;
          continue;
        }
        const rel = relative(absoluteTarget, abs).replace(/\\/g, "/");
        const loaded = await loadFile(abs, rel);
        if (loaded.limitation) {
          limitations.add(loaded.limitation);
          continue;
        }
        if (!loaded.document || loaded.size === undefined) continue;
        if (totalBytes + loaded.size > MAX_DART_TOTAL_BYTES) {
          boundedFilesSkipped++;
          continue;
        }
        totalBytes += loaded.size;
        files.push(loaded.document);
      }
    }
  }

  await walk(absoluteTarget, 0);
  if (boundedFilesSkipped) {
    limitations.add(
      `Skipped ${boundedFilesSkipped} Dart file(s) beyond the 10,000-file/64 MiB Flutter source bounds.`,
    );
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  return { target: absoluteTarget, root: absoluteTarget, files, limitations: limitations.finish() };
}

/** Uncached loader for independently invoked rules and explicit refreshes/rescans. */
export function loadFlutterProject(target: string): Promise<FlutterProject> {
  return loadUncached(target);
}

/**
 * Per-pack promise cache: the six analyzers share one filesystem walk and parse, while a
 * later scan gets a fresh loader and therefore sees user fixes.
 */
export function createCachedFlutterProjectLoader(target: string): () => Promise<FlutterProject> {
  let cached: Promise<FlutterProject> | undefined;
  return () => cached ??= loadUncached(target);
}

export function resolveFlutterProject(input: FlutterProjectInput): Promise<FlutterProject> {
  if (typeof input === "string") return loadUncached(input);
  return Promise.resolve(input);
}
