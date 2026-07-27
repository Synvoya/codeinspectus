/**
 * Bounded, dependency-free parser and repository discovery for Dart pubspec.lock files.
 *
 * This intentionally implements only the stable shape emitted by `dart pub get`. It is not a
 * general YAML parser: ambiguous or unsupported YAML is rejected instead of guessed at. Native
 * Pub SCA can therefore trust exact package/version/source fields, while SBOM generation retains
 * every resolved hosted, git, path, and SDK dependency.
 */

import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";

export const PUB_LOCKFILE_LIMITS = Object.freeze({
  max_bytes_per_lockfile: 2 * 1024 * 1024,
  max_total_bytes: 32 * 1024 * 1024,
  max_lockfiles: 256,
  max_packages_per_lockfile: 10_000,
  max_visited_entries: 50_000,
  max_directory_depth: 32,
  max_notes: 40,
});

const IGNORED_DIRECTORIES = new Set([
  ".cache",
  ".dart_tool",
  ".git",
  ".gradle",
  ".idea",
  ".pub-cache",
  ".symlinks",
  ".vscode",
  "build",
  "coverage",
  "deriveddata",
  "dist",
  "node_modules",
  "pods",
  "vendor",
]);

const OFFICIAL_HOSTS = new Set(["pub.dev", "pub.dartlang.org"]);
const PACKAGE_NAME_RE = /^[a-z_][a-z0-9_]*$/;
const PUB_VERSION_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const DESCRIPTION_KEY_RE = /^[A-Za-z0-9_.+-]+$/;

export type PubDependencyKind =
  | "direct main"
  | "direct dev"
  | "direct overridden"
  | "transitive";

export type PubPackageSource = "hosted" | "git" | "path" | "sdk";
export type PubPackageRegistry = "official" | "custom" | "non_hosted";

export interface PubPackageDescription {
  name?: string;
  url?: string;
  sha256?: string;
}

export interface PubResolvedPackage {
  name: string;
  version: string;
  version_line: number;
  dependency: PubDependencyKind;
  direct: boolean;
  source: PubPackageSource;
  description: PubPackageDescription;
  registry: PubPackageRegistry;
  /** Project-relative lockfile containing this resolved package. */
  lockfile_path: string;
}

export interface PubLockfileParseError {
  line?: number;
  message: string;
}

export type PubLockfileParseResult =
  | { ok: true; packages: PubResolvedPackage[] }
  | { ok: false; error: PubLockfileParseError };

export interface PubLockfileCandidate {
  absolute_path: string;
  path: string;
}

export interface PubLockfileSkippedCounts {
  symlinked_lockfiles: number;
  symlinked_paths: number;
  oversized_lockfiles: number;
  unreadable_lockfiles: number;
  malformed_lockfiles: number;
  lockfiles_beyond_limit: number;
  lockfiles_beyond_total_bytes: number;
  unreadable_directories: number;
  directories_beyond_depth: number;
  traversal_limit_reached: number;
  unsupported_targets: number;
  custom_hosted_packages: number;
  git_packages: number;
  path_packages: number;
  sdk_packages: number;
}

export interface PubLockfileDiscovery {
  target: string;
  root: string;
  lockfiles: PubLockfileCandidate[];
  skipped: PubLockfileSkippedCounts;
  notes: string[];
}

export interface LoadedPubLockfile {
  absolute_path: string;
  path: string;
  status: "parsed" | "malformed" | "skipped";
  packages: PubResolvedPackage[];
  error?: string;
}

export interface PubLockfileLoadResult {
  target: string;
  root: string;
  lockfiles: LoadedPubLockfile[];
  packages: PubResolvedPackage[];
  skipped: PubLockfileSkippedCounts;
  notes: string[];
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function forwardSlash(value: string): string {
  return value.replace(/\\/g, "/");
}

function within(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function emptySkippedCounts(): PubLockfileSkippedCounts {
  return {
    symlinked_lockfiles: 0,
    symlinked_paths: 0,
    oversized_lockfiles: 0,
    unreadable_lockfiles: 0,
    malformed_lockfiles: 0,
    lockfiles_beyond_limit: 0,
    lockfiles_beyond_total_bytes: 0,
    unreadable_directories: 0,
    directories_beyond_depth: 0,
    traversal_limit_reached: 0,
    unsupported_targets: 0,
    custom_hosted_packages: 0,
    git_packages: 0,
    path_packages: 0,
    sdk_packages: 0,
  };
}

function noteCollector(initial: string[] = []): {
  add: (message: string) => void;
  finish: () => string[];
} {
  const notes = new Set<string>();
  let omitted = 0;
  for (const message of initial) {
    if (notes.has(message)) continue;
    if (notes.size < PUB_LOCKFILE_LIMITS.max_notes - 1) notes.add(message);
    else omitted++;
  }
  return {
    add(message) {
      if (notes.has(message)) return;
      if (notes.size < PUB_LOCKFILE_LIMITS.max_notes - 1) notes.add(message);
      else omitted++;
    },
    finish() {
      return [
        ...notes,
        ...(omitted ? [`${omitted} additional Pub lockfile limitation(s) omitted.`] : []),
      ].sort(compareText);
    },
  };
}

interface ParsedLine {
  indent: number;
  key: string;
  value?: string;
}

class ParseFailure extends Error {
  constructor(
    message: string,
    readonly line?: number,
  ) {
    super(message);
  }
}

function withoutInlineComment(raw: string, line: number): string {
  let quote: "single" | "double" | undefined;
  let escaped = false;
  for (let index = 0; index < raw.length; index++) {
    const character = raw[index];
    if (quote === "double") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === "\"") quote = undefined;
      continue;
    }
    if (quote === "single") {
      if (character !== "'") continue;
      if (raw[index + 1] === "'") index++;
      else quote = undefined;
      continue;
    }
    if (character === "\"") quote = "double";
    else if (character === "'") quote = "single";
    else if (character === "#" && (index === 0 || /\s/.test(raw[index - 1] ?? ""))) {
      return raw.slice(0, index).trimEnd();
    }
  }
  if (quote) throw new ParseFailure("unterminated quoted scalar", line);
  return raw.trimEnd();
}

function parseLine(raw: string, line: number): ParsedLine | undefined {
  if (raw.includes("\t")) throw new ParseFailure("tabs are not supported", line);
  const content = withoutInlineComment(raw, line);
  if (!content.trim()) return undefined;
  const indent = content.length - content.trimStart().length;
  if (indent % 2 !== 0) throw new ParseFailure("indentation must use two-space levels", line);
  const body = content.slice(indent);
  if (body.startsWith("<<:")) throw new ParseFailure("YAML merge keys are not supported", line);
  const match = /^([A-Za-z0-9_.+-]+):(.*)$/.exec(body);
  if (!match) throw new ParseFailure("expected a simple mapping entry", line);
  const key = match[1] ?? "";
  const remainder = match[2] ?? "";
  if (remainder && !remainder.startsWith(" ")) {
    throw new ParseFailure("mapping values must be separated by a space", line);
  }
  const value = remainder.trim();
  if (/^[&*!]/.test(value)) {
    throw new ParseFailure("YAML anchors, aliases, and tags are not supported", line);
  }
  if ((value.startsWith("{") || value.startsWith("[")) && value !== "{}") {
    throw new ParseFailure("flow-style YAML is not supported", line);
  }
  return { indent, key, ...(value ? { value } : {}) };
}

function scalar(value: string | undefined, line: number, field: string): string {
  if (value === undefined) throw new ParseFailure(`${field} must be a scalar`, line);
  let decoded: string;
  if (value.startsWith("\"")) {
    try {
      const parsed: unknown = JSON.parse(value);
      if (typeof parsed !== "string") throw new Error("not a string");
      decoded = parsed;
    } catch {
      throw new ParseFailure(`${field} has an invalid double-quoted scalar`, line);
    }
  } else if (value.startsWith("'")) {
    if (value.length < 2 || !value.endsWith("'")) {
      throw new ParseFailure(`${field} has an invalid single-quoted scalar`, line);
    }
    const inner = value.slice(1, -1);
    if (/(^|[^'])'([^']|$)/.test(inner)) {
      throw new ParseFailure(`${field} has an invalid single-quoted scalar`, line);
    }
    decoded = inner.replace(/''/g, "'");
  } else {
    if (/^[\-?:,\[\]{}#&*!|>'\"%@`]/.test(value)) {
      throw new ParseFailure(`${field} uses an unsupported YAML scalar`, line);
    }
    decoded = value;
  }
  if (!decoded || decoded.length > 4096 || /[\u0000-\u001f\u007f]/.test(decoded)) {
    throw new ParseFailure(`${field} is empty or outside the supported scalar bounds`, line);
  }
  return decoded;
}

interface PendingPackage {
  name: string;
  line: number;
  seenFields: Set<string>;
  dependency?: PubDependencyKind;
  description?: PubPackageDescription;
  descriptionIsMap?: boolean;
  descriptionFields: Set<string>;
  descriptionOpen: boolean;
  source?: PubPackageSource;
  version?: string;
  versionLine?: number;
}

function officialHostedUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && !url.username
      && !url.password
      && !url.port
      && OFFICIAL_HOSTS.has(url.hostname.toLowerCase())
      && (url.pathname === "" || url.pathname === "/")
      && !url.search
      && !url.hash;
  } catch {
    return false;
  }
}

function validPubVersion(value: string): boolean {
  const match = PUB_VERSION_RE.exec(value);
  if (!match) return false;
  const prerelease = match[4];
  return !prerelease?.split(".").some(
    (identifier) => /^\d+$/.test(identifier) && /^0\d+/.test(identifier),
  );
}

function finishPackage(pending: PendingPackage, lockfilePath: string): PubResolvedPackage {
  if (!pending.dependency) {
    throw new ParseFailure(`package ${pending.name} is missing dependency`, pending.line);
  }
  if (!pending.description) {
    throw new ParseFailure(`package ${pending.name} is missing description`, pending.line);
  }
  if (pending.descriptionIsMap && pending.descriptionFields.size === 0) {
    throw new ParseFailure(`package ${pending.name} has an empty description map`, pending.line);
  }
  if (!pending.source) {
    throw new ParseFailure(`package ${pending.name} is missing source`, pending.line);
  }
  if (!pending.version || !pending.versionLine) {
    throw new ParseFailure(`package ${pending.name} is missing version`, pending.line);
  }
  if (!validPubVersion(pending.version)) {
    throw new ParseFailure(`package ${pending.name} has an invalid Pub version`, pending.versionLine);
  }
  if (pending.description.sha256 && !/^[A-Fa-f0-9]{64}$/.test(pending.description.sha256)) {
    throw new ParseFailure(`package ${pending.name} has an invalid sha256`, pending.line);
  }

  let registry: PubPackageRegistry = "non_hosted";
  if (pending.source === "hosted") {
    const descriptionName = pending.description.name;
    if (!descriptionName || descriptionName !== pending.name) {
      throw new ParseFailure(
        `hosted package ${pending.name} has a missing or mismatched description name`,
        pending.line,
      );
    }
    if (pending.descriptionIsMap && !pending.description.url) {
      throw new ParseFailure(`hosted package ${pending.name} is missing its registry URL`, pending.line);
    }
    if (pending.description.url) {
      try {
        // Validate custom URLs too; a malformed URL must never become trusted input downstream.
        new URL(pending.description.url);
      } catch {
        throw new ParseFailure(`hosted package ${pending.name} has an invalid registry URL`, pending.line);
      }
    }
    registry = !pending.description.url || officialHostedUrl(pending.description.url)
      ? "official"
      : "custom";
  }

  return {
    name: pending.name,
    version: pending.version,
    version_line: pending.versionLine,
    dependency: pending.dependency,
    direct: pending.dependency !== "transitive",
    source: pending.source,
    description: {
      ...pending.description,
      ...(pending.description.sha256
        ? { sha256: pending.description.sha256.toLowerCase() }
        : {}),
    },
    registry,
    lockfile_path: lockfilePath,
  };
}

/** Parse one standard generated pubspec.lock without accepting general YAML features. */
export function parsePubLockfile(input: {
  path: string;
  content: string;
}): PubLockfileParseResult {
  try {
    if (Buffer.byteLength(input.content, "utf8") > PUB_LOCKFILE_LIMITS.max_bytes_per_lockfile) {
      throw new ParseFailure("lockfile exceeds the 2 MiB parser bound");
    }
    if (input.content.includes("\uFFFD")) {
      throw new ParseFailure("lockfile is not valid UTF-8 text");
    }
    const text = input.content.startsWith("\uFEFF") ? input.content.slice(1) : input.content;
    const lines = text.split(/\r?\n/);
    const packages: PubResolvedPackage[] = [];
    const packageNames = new Set<string>();
    const rootKeys = new Set<string>();
    const sdkKeys = new Set<string>();
    let section: "none" | "packages" | "empty-packages" | "sdks" = "none";
    let explicitlyEmptyPackages = false;
    let pending: PendingPackage | undefined;

    const flush = (): void => {
      if (!pending) return;
      packages.push(finishPackage(pending, input.path));
      pending = undefined;
    };

    for (let index = 0; index < lines.length; index++) {
      const lineNumber = index + 1;
      const parsed = parseLine(lines[index] ?? "", lineNumber);
      if (!parsed) continue;

      if (parsed.indent === 0) {
        flush();
        if (rootKeys.has(parsed.key)) {
          throw new ParseFailure(`duplicate top-level key ${parsed.key}`, lineNumber);
        }
        rootKeys.add(parsed.key);
        if (parsed.key === "packages") {
          if (parsed.value !== undefined && parsed.value !== "{}") {
            throw new ParseFailure("packages must be a block map or an empty map", lineNumber);
          }
          section = parsed.value === "{}" ? "empty-packages" : "packages";
          explicitlyEmptyPackages = parsed.value === "{}";
        } else if (parsed.key === "sdks") {
          if (parsed.value !== undefined && parsed.value !== "{}") {
            throw new ParseFailure("sdks must be a block map or an empty map", lineNumber);
          }
          section = "sdks";
        } else {
          throw new ParseFailure(`unsupported top-level key ${parsed.key}`, lineNumber);
        }
        continue;
      }

      if (section === "none") {
        throw new ParseFailure("nested content appears before packages", lineNumber);
      }
      if (section === "empty-packages") {
        throw new ParseFailure("empty packages map cannot contain entries", lineNumber);
      }
      if (section === "sdks") {
        if (parsed.indent !== 2) {
          throw new ParseFailure("SDK entries must be scalar two-space mappings", lineNumber);
        }
        if (sdkKeys.has(parsed.key)) {
          throw new ParseFailure(`duplicate SDK key ${parsed.key}`, lineNumber);
        }
        sdkKeys.add(parsed.key);
        scalar(parsed.value, lineNumber, `SDK ${parsed.key}`);
        continue;
      }

      if (parsed.indent === 2) {
        flush();
        if (parsed.value !== undefined) {
          throw new ParseFailure("package entries must be block maps", lineNumber);
        }
        if (!PACKAGE_NAME_RE.test(parsed.key)) {
          throw new ParseFailure(`invalid package name ${parsed.key}`, lineNumber);
        }
        if (packageNames.has(parsed.key)) {
          throw new ParseFailure(`duplicate package ${parsed.key}`, lineNumber);
        }
        if (packageNames.size >= PUB_LOCKFILE_LIMITS.max_packages_per_lockfile) {
          throw new ParseFailure(
            `lockfile exceeds the ${PUB_LOCKFILE_LIMITS.max_packages_per_lockfile.toLocaleString("en-US")}-package parser bound`,
            lineNumber,
          );
        }
        packageNames.add(parsed.key);
        pending = {
          name: parsed.key,
          line: lineNumber,
          seenFields: new Set(),
          descriptionFields: new Set(),
          descriptionOpen: false,
        };
        continue;
      }

      if (!pending) throw new ParseFailure("package field appears without a package", lineNumber);
      if (parsed.indent === 4) {
        pending.descriptionOpen = false;
        if (!new Set(["dependency", "description", "source", "version"]).has(parsed.key)) {
          throw new ParseFailure(`unsupported package field ${parsed.key}`, lineNumber);
        }
        if (pending.seenFields.has(parsed.key)) {
          throw new ParseFailure(`duplicate package field ${parsed.key}`, lineNumber);
        }
        pending.seenFields.add(parsed.key);
        if (parsed.key === "dependency") {
          const value = scalar(parsed.value, lineNumber, "dependency") as PubDependencyKind;
          if (!["direct main", "direct dev", "direct overridden", "transitive"].includes(value)) {
            throw new ParseFailure(`unsupported dependency kind ${value}`, lineNumber);
          }
          pending.dependency = value;
        } else if (parsed.key === "description") {
          if (parsed.value === undefined) {
            pending.description = {};
            pending.descriptionIsMap = true;
            pending.descriptionOpen = true;
          } else {
            const value = scalar(parsed.value, lineNumber, "description");
            pending.description = { name: value };
            pending.descriptionIsMap = false;
          }
        } else if (parsed.key === "source") {
          const value = scalar(parsed.value, lineNumber, "source") as PubPackageSource;
          if (!["hosted", "git", "path", "sdk"].includes(value)) {
            throw new ParseFailure(`unsupported package source ${value}`, lineNumber);
          }
          pending.source = value;
        } else {
          pending.version = scalar(parsed.value, lineNumber, "version");
          pending.versionLine = lineNumber;
        }
        continue;
      }

      if (parsed.indent === 6 && pending.descriptionOpen && pending.description) {
        if (!DESCRIPTION_KEY_RE.test(parsed.key)) {
          throw new ParseFailure(`invalid description field ${parsed.key}`, lineNumber);
        }
        if (pending.descriptionFields.has(parsed.key)) {
          throw new ParseFailure(`duplicate description field ${parsed.key}`, lineNumber);
        }
        pending.descriptionFields.add(parsed.key);
        const value = scalar(parsed.value, lineNumber, `description.${parsed.key}`);
        if (parsed.key === "name") pending.description.name = value;
        else if (parsed.key === "url") pending.description.url = value;
        else if (parsed.key === "sha256") pending.description.sha256 = value;
        continue;
      }

      throw new ParseFailure("unsupported or ambiguous package structure", lineNumber);
    }
    flush();

    if (!rootKeys.has("packages")) throw new ParseFailure("missing top-level packages map");
    if (!explicitlyEmptyPackages && packageNames.size === 0) {
      throw new ParseFailure("packages block map is empty; use packages: {} for an empty lockfile");
    }
    packages.sort((left, right) =>
      compareText(left.name, right.name)
      || compareText(left.version, right.version)
      || left.version_line - right.version_line
    );
    return { ok: true, packages };
  } catch (error) {
    if (error instanceof ParseFailure) {
      return {
        ok: false,
        error: { message: error.message, ...(error.line ? { line: error.line } : {}) },
      };
    }
    return { ok: false, error: { message: "unexpected lockfile parse failure" } };
  }
}

interface PubLockfileDiscoveryOptions {
  /** Test seam for deterministic unreadable-directory coverage; production uses fs.readdir. */
  readDirectory?: (directory: string) => Promise<Dirent[]>;
}

/** Discover pubspec.lock files without following symlinks or leaving the requested root. */
export async function discoverPubLockfiles(
  target: string,
  options: PubLockfileDiscoveryOptions = {},
): Promise<PubLockfileDiscovery> {
  const absoluteTarget = resolve(target);
  const skipped = emptySkippedCounts();
  const notes = noteCollector();
  const targetMetadata = await lstat(absoluteTarget).catch(() => undefined);
  const root = targetMetadata?.isFile() || basename(absoluteTarget).toLowerCase() === "pubspec.lock"
    ? dirname(absoluteTarget)
    : absoluteTarget;
  const lockfiles: PubLockfileCandidate[] = [];

  if (!targetMetadata) {
    skipped.unsupported_targets++;
    notes.add("Pub lockfile target was unreadable.");
    return { target: absoluteTarget, root, lockfiles, skipped, notes: notes.finish() };
  }
  if (targetMetadata.isSymbolicLink()) {
    skipped.symlinked_lockfiles++;
    notes.add("Skipped symbolic-link Pub lockfile target.");
    return { target: absoluteTarget, root, lockfiles, skipped, notes: notes.finish() };
  }
  if (targetMetadata.isFile()) {
    if (basename(absoluteTarget).toLowerCase() !== "pubspec.lock") {
      skipped.unsupported_targets++;
      notes.add("Direct Pub lockfile target must be named pubspec.lock.");
    } else {
      lockfiles.push({ absolute_path: absoluteTarget, path: basename(absoluteTarget) });
    }
    return { target: absoluteTarget, root, lockfiles, skipped, notes: notes.finish() };
  }
  if (!targetMetadata.isDirectory()) {
    skipped.unsupported_targets++;
    notes.add("Pub lockfile target was not a regular file or directory.");
    return { target: absoluteTarget, root, lockfiles, skipped, notes: notes.finish() };
  }

  let visitedEntries = 0;
  let traversalStopped = false;
  const readDirectory = options.readDirectory ?? ((directory: string) =>
    readdir(directory, { withFileTypes: true }));
  async function walk(directory: string, depth: number): Promise<void> {
    if (traversalStopped) return;
    let entries;
    try {
      entries = await readDirectory(directory);
    } catch {
      skipped.unreadable_directories++;
      notes.add(`Skipped unreadable Pub lockfile directory ${forwardSlash(relative(root, directory)) || "."}.`);
      return;
    }
    entries.sort((left, right) => compareText(left.name, right.name));
    for (const entry of entries) {
      if (++visitedEntries > PUB_LOCKFILE_LIMITS.max_visited_entries) {
        skipped.traversal_limit_reached = 1;
        notes.add(
          `Stopped Pub lockfile discovery after ${PUB_LOCKFILE_LIMITS.max_visited_entries.toLocaleString("en-US")} filesystem entries.`,
        );
        traversalStopped = true;
        return;
      }
      const absolutePath = join(directory, entry.name);
      const lower = entry.name.toLowerCase();
      if (!within(root, absolutePath)) {
        notes.add("Skipped an out-of-root Pub lockfile path.");
        continue;
      }
      if (entry.isSymbolicLink()) {
        if (lower === "pubspec.lock") {
          skipped.symlinked_lockfiles++;
          notes.add(`Skipped symbolic-link Pub lockfile ${forwardSlash(relative(root, absolutePath))}.`);
        } else if (!IGNORED_DIRECTORIES.has(lower)) {
          skipped.symlinked_paths++;
          notes.add(`Skipped symbolic-link path ${forwardSlash(relative(root, absolutePath))} during Pub lockfile discovery.`);
        }
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(lower)) continue;
        if (depth >= PUB_LOCKFILE_LIMITS.max_directory_depth) {
          skipped.directories_beyond_depth++;
          notes.add(
            `Skipped Pub lockfile directory ${forwardSlash(relative(root, absolutePath))} beyond depth ${PUB_LOCKFILE_LIMITS.max_directory_depth}.`,
          );
          continue;
        }
        await walk(absolutePath, depth + 1);
      } else if (entry.isFile() && lower === "pubspec.lock") {
        if (lockfiles.length >= PUB_LOCKFILE_LIMITS.max_lockfiles) {
          skipped.lockfiles_beyond_limit++;
          continue;
        }
        lockfiles.push({
          absolute_path: absolutePath,
          path: forwardSlash(relative(root, absolutePath)),
        });
      }
    }
  }
  await walk(absoluteTarget, 0);
  if (skipped.lockfiles_beyond_limit) {
    notes.add(
      `Skipped ${skipped.lockfiles_beyond_limit} pubspec.lock file(s) beyond the ${PUB_LOCKFILE_LIMITS.max_lockfiles}-file bound.`,
    );
  }
  lockfiles.sort((left, right) => compareText(left.path, right.path));
  if (!lockfiles.length && !skipped.symlinked_lockfiles && !skipped.lockfiles_beyond_limit) {
    notes.add("No pubspec.lock files found.");
  }
  return { target: absoluteTarget, root, lockfiles, skipped, notes: notes.finish() };
}

type BoundedRead =
  | { ok: true; content: string; bytes: number }
  | { ok: false; reason: "symlink" | "oversized" | "unreadable" };

async function readLockfileBounded(path: string): Promise<BoundedRead> {
  const before = await lstat(path).catch(() => undefined);
  if (!before) return { ok: false, reason: "unreadable" };
  if (before.isSymbolicLink()) return { ok: false, reason: "symlink" };
  if (!before.isFile()) return { ok: false, reason: "unreadable" };
  if (before.size > PUB_LOCKFILE_LIMITS.max_bytes_per_lockfile) {
    return { ok: false, reason: "oversized" };
  }

  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const after = await handle.stat();
    if (!after.isFile()) return { ok: false, reason: "unreadable" };
    const buffer = Buffer.allocUnsafe(PUB_LOCKFILE_LIMITS.max_bytes_per_lockfile + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const read = await handle.read(buffer, bytes, buffer.length - bytes, bytes);
      if (!read.bytesRead) break;
      bytes += read.bytesRead;
    }
    if (bytes > PUB_LOCKFILE_LIMITS.max_bytes_per_lockfile) {
      return { ok: false, reason: "oversized" };
    }
    return { ok: true, content: buffer.subarray(0, bytes).toString("utf8"), bytes };
  } catch {
    return { ok: false, reason: "unreadable" };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function parseErrorText(error: PubLockfileParseError): string {
  return error.line ? `line ${error.line}: ${error.message}` : error.message;
}

/** Discover, bounded-read, and parse every Pub lockfile under a repository or direct-file target. */
export async function loadPubLockfiles(target: string): Promise<PubLockfileLoadResult> {
  const discovery = await discoverPubLockfiles(target);
  const skipped = { ...discovery.skipped };
  const notes = noteCollector(discovery.notes);
  const lockfiles: LoadedPubLockfile[] = [];
  const packages: PubResolvedPackage[] = [];
  let totalBytes = 0;

  for (const candidate of discovery.lockfiles) {
    const read = await readLockfileBounded(candidate.absolute_path);
    if (!read.ok) {
      if (read.reason === "symlink") skipped.symlinked_lockfiles++;
      else if (read.reason === "oversized") skipped.oversized_lockfiles++;
      else skipped.unreadable_lockfiles++;
      const error = read.reason === "symlink"
        ? "symbolic-link lockfile was not followed"
        : read.reason === "oversized"
          ? "lockfile exceeds the 2 MiB read bound"
          : "lockfile was unreadable or not a regular file";
      lockfiles.push({
        ...candidate,
        status: "skipped",
        packages: [],
        error,
      });
      notes.add(`Skipped Pub lockfile ${candidate.path}: ${error}.`);
      continue;
    }
    if (totalBytes + read.bytes > PUB_LOCKFILE_LIMITS.max_total_bytes) {
      skipped.lockfiles_beyond_total_bytes++;
      const error = "lockfile exceeds the 32 MiB aggregate read bound";
      lockfiles.push({ ...candidate, status: "skipped", packages: [], error });
      continue;
    }
    totalBytes += read.bytes;
    const parsed = parsePubLockfile({ path: candidate.path, content: read.content });
    if (!parsed.ok) {
      skipped.malformed_lockfiles++;
      const error = parseErrorText(parsed.error);
      lockfiles.push({ ...candidate, status: "malformed", packages: [], error });
      notes.add(`Rejected malformed Pub lockfile ${candidate.path}: ${error}.`);
      continue;
    }
    lockfiles.push({ ...candidate, status: "parsed", packages: parsed.packages });
    packages.push(...parsed.packages);
  }

  if (skipped.lockfiles_beyond_total_bytes) {
    notes.add(
      `Skipped ${skipped.lockfiles_beyond_total_bytes} pubspec.lock file(s) beyond the 32 MiB aggregate read bound.`,
    );
  }
  for (const pkg of packages) {
    if (pkg.registry === "custom") skipped.custom_hosted_packages++;
    else if (pkg.source === "git") skipped.git_packages++;
    else if (pkg.source === "path") skipped.path_packages++;
    else if (pkg.source === "sdk") skipped.sdk_packages++;
  }
  const scaExcluded = skipped.custom_hosted_packages
    + skipped.git_packages
    + skipped.path_packages
    + skipped.sdk_packages;
  if (scaExcluded) {
    notes.add(
      `Retained ${scaExcluded} non-official dependency instance(s) for coverage and source accounting but excluded them from native Pub vulnerability matching and native Pub SBOM components (${skipped.custom_hosted_packages} custom-hosted, ${skipped.git_packages} git, ${skipped.path_packages} path, ${skipped.sdk_packages} SDK).`,
    );
  }

  lockfiles.sort((left, right) => compareText(left.path, right.path));
  packages.sort((left, right) =>
    compareText(left.lockfile_path, right.lockfile_path)
    || compareText(left.name, right.name)
    || compareText(left.version, right.version)
  );
  return {
    target: discovery.target,
    root: discovery.root,
    lockfiles,
    packages,
    skipped,
    notes: notes.finish(),
  };
}
