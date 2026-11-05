/**
 * File-level completeness of an Opengrep run, from its structured JSON output (`--json --verbose`).
 * Opengrep 1.33.1 still exits 0 and writes SARIF when it skips a file over its 1,000,000-byte target
 * limit, cannot read a file, or gives up on a file after a parse error, timeout, memory limit or
 * internal matching error; those files contribute no findings (or none from the unparsed code). They
 * arrive as `errors[]` and as `paths.skipped[]` with a machine-readable `reason`. The debug log is not
 * read: repository-controlled paths are written into it and could forge its section headers.
 *
 * Files whose only errors are parser limits (Ruling 14) become the acceptable declared gap
 * `sast-parse-errors`. A missing or malformed report, an unknown skip reason, or any other error
 * (timeout, memory limit, internal matching error) is a coverage warning that no gap id can accept.
 * Nothing here can mark coverage covered.
 */

import { basename, isAbsolute, relative } from "node:path";

import type { CoverageGap } from "../coverage-gaps.js";
import { isDisplayablePath } from "../display-path.js";

const MAX_EXAMPLES = 5;
/**
 * Skip reasons that come from CodeInspectus's own scan policy: the managed default ignore list
 * (disclosed separately) and files no bundled rule applies to. Every other reason, including
 * `gitignore_patterns_match` (git-ignored files are scanned, see `--no-git-ignore`), is lost coverage.
 */
const POLICY_SKIPS = new Set(["semgrepignore_patterns_match", "wrong_language", "irrelevant_rule"]);
const SIZE_SKIPS = new Set(["exceeded_size_limit", "too_big"]);
/**
 * Field run 2026-11-05: the pack pass's generic rules make Opengrep list a size skip for every large file,
 * and 22/40 repos read SAST-partial only for images, PDFs, binaries and lockfiles. A size skip of a file with
 * one of these extensions (or a lockfile name) is no source of any language a bundled rule reads (JavaScript,
 * TypeScript, Python, PHP, and the generic rules' deploy and environment files): an informational note, never
 * partial. Any other size skip, an unlisted extension included, stays partial.
 */
const NON_SOURCE_EXTENSIONS: ReadonlySet<string> = new Set([
  // images
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".icns", ".tif", ".tiff", ".avif", ".heic", ".psd", ".svg", ".svgz",
  // fonts
  ".ttf", ".otf", ".woff", ".woff2", ".eot",
  // audio and video
  ".mp3", ".mp4", ".m4a", ".m4v", ".wav", ".ogg", ".oga", ".ogv", ".webm", ".mov", ".avi", ".mkv", ".flac",
  // archives (`.phar`: Opengrep does not read it as PHP; measured with Opengrep 1.33.1)
  ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".phar",
  // documents
  ".pdf",
  // compiled binaries
  ".node", ".dylib", ".so", ".dll", ".exe", ".bin", ".wasm", ".class", ".o", ".a", ".pyc",
  // lockfiles, source maps and data dumps
  ".lock", ".lockb", ".map", ".sql", ".csv",
]);
const NON_SOURCE_NAMES: ReadonlySet<string> = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"]);

/** Whether a target-relative path names a file no bundled Opengrep rule reads as source (by extension or lockfile name). */
export function nonSourceFile(rel: string): boolean {
  const name = rel.slice(rel.lastIndexOf("/") + 1).toLowerCase();
  const dot = name.lastIndexOf(".");
  return NON_SOURCE_NAMES.has(name) || (dot > 0 && NON_SOURCE_EXTENSIONS.has(name.slice(dot)));
}
/**
 * Error types for code Opengrep's parsers could not read (`ParseError`, `LexicalError` and
 * `PartialParsing` in Opengrep's output schema). "Other syntax error", timeouts, memory limits and
 * internal matching errors are not parser limits and stay non-acceptable.
 */
const PARSE_ERRORS = new Set(["Syntax error", "Lexical error", "PartialParsing"]);

/** Target-relative POSIX path of a file inside the target, or undefined. */
function targetPath(path: unknown, target: string): string | undefined {
  if (typeof path !== "string") return undefined;
  if (path === target) return basename(path);
  if (!isAbsolute(path)) return undefined;
  const rel = relative(target, path);
  return rel && !rel.startsWith("..") && !isAbsolute(rel) ? rel.replace(/\\/g, "/") : undefined;
}

/** Target-relative path, or undefined: an unrelated or unsafe (control, bidi) path is never echoed. */
function displayPath(path: unknown, target: string): string | undefined {
  const rel = targetPath(path, target);
  return rel !== undefined && isDisplayablePath(rel) ? rel : undefined;
}

/** `type` is a string, or a tagged array such as `["PartialParsing", [locations]]`. */
function errorKind(type: unknown): string | undefined {
  if (typeof type === "string") return type;
  return Array.isArray(type) && typeof type[0] === "string" ? type[0] : undefined;
}

function records(value: unknown): Record<string, unknown>[] | undefined {
  return Array.isArray(value) && value.every((item) => item !== null && typeof item === "object")
    ? value as Record<string, unknown>[]
    : undefined;
}

export interface OpengrepFileCoverage {
  /** Lost coverage no gap id can accept; makes SAST coverage partial. */
  warning?: string;
  /** Files whose only errors are parser limits: the declared gap `sast-parse-errors`. */
  parseErrors?: CoverageGap;
  /** Non-source files skipped for size (nonSourceFile): an informational coverage note, never partial. */
  note?: string;
}

/**
 * One report for several Opengrep passes over the same target (the baseline and Synvoya pack passes): their
 * errors and paths side by side, so a file both passes report is counted once. Undefined (a coverage warning)
 * when any report is missing or malformed.
 */
export function mergeOpengrepReports(reports: readonly unknown[]): unknown {
  const errors: Record<string, unknown>[] = [];
  const scanned: unknown[] = [];
  const skipped: Record<string, unknown>[] = [];
  for (const report of reports) {
    const root = report !== null && typeof report === "object" ? report as Record<string, unknown> : {};
    const paths = root.paths !== null && typeof root.paths === "object" ? root.paths as Record<string, unknown> : {};
    const reportErrors = records(root.errors);
    const reportSkipped = records(paths.skipped);
    if (!reportErrors || !reportSkipped || !Array.isArray(paths.scanned)) return undefined;
    for (const error of reportErrors) errors.push(error);
    for (const path of paths.scanned as unknown[]) scanned.push(path);
    for (const entry of reportSkipped) skipped.push(entry);
  }
  return { errors, paths: { scanned, skipped } };
}

/** Target-relative paths a report says the managed ignore list skipped, or undefined for a malformed report. */
function ignoreSkips(report: unknown, target: string): Set<string> | undefined {
  const root = report !== null && typeof report === "object" ? report as Record<string, unknown> : {};
  const paths = root.paths !== null && typeof root.paths === "object" ? root.paths as Record<string, unknown> : {};
  const skipped = records(paths.skipped);
  if (!skipped) return undefined;
  const out = new Set<string>();
  for (const entry of skipped) {
    if (entry.reason !== "semgrepignore_patterns_match") continue;
    const rel = targetPath(entry.path, target);
    // A skip outside the target (or of the target itself) cannot be checked against routing: count it as unexpected.
    out.add(rel ?? `\u0000${String(entry.path)}`);
  }
  return out;
}

export interface PackSkipCheck {
  /** Chosen bundles the pack pass did skip (a chosen file it still scanned is no gap). */
  skipped: string[];
  /** Files the pack pass skipped that neither the managed ignore list nor bundle routing names. */
  unexpected: string[];
}

/**
 * Fail-closed check of the pack pass's skip list (M4 Task 4 review): every `semgrepignore` skip must be a
 * chosen bundle or a path the managed list ignores (`managedIgnored`). The baseline pass's own report is no
 * reference: Opengrep lists only skips of files some loaded rule's language could read, and the pack's
 * generic rules read every file. Undefined when the report is missing or malformed.
 */
export function checkPackSkips(
  packReport: unknown,
  bundles: readonly string[],
  target: string,
  managedIgnored: (rel: string) => boolean,
): PackSkipCheck | undefined {
  const pack = ignoreSkips(packReport, target);
  if (!pack) return undefined;
  const chosen = new Set(bundles);
  return {
    skipped: bundles.filter((rel) => pack.has(rel)),
    unexpected: [...pack].filter((rel) => !chosen.has(rel) && (rel.startsWith("\u0000") || !managedIgnored(rel))).sort(),
  };
}

export function opengrepFileCoverage(report: unknown, target: string): OpengrepFileCoverage {
  const root = report !== null && typeof report === "object" ? report as Record<string, unknown> : {};
  const paths = root.paths !== null && typeof root.paths === "object" ? root.paths as Record<string, unknown> : {};
  const errors = records(root.errors);
  const skipped = records(paths.skipped);
  if (!errors || !skipped || !Array.isArray(paths.scanned)) {
    return { warning: "Opengrep SAST coverage partial: Opengrep's structured skip and error report was missing or malformed, so skipped files are unknown." };
  }
  const groups = { size: new Set<string>(), nonSource: new Set<string>(), errors: new Set<string>(), unreadable: new Set<string>(), other: new Set<string>() };
  let unnamed = 0;
  const add = (group: Set<string>, path: unknown, key: string): void => {
    const shown = displayPath(path, target);
    if (shown) group.add(shown);
    else group.add(`\u0000${key}:${unnamed++}`);
  };
  // Per file inside the target: true while every error reported for it is a parser limit.
  const parseOnly = new Map<string, boolean>();
  for (const error of errors) {
    const parse = PARSE_ERRORS.has(errorKind(error.type) ?? "");
    if (typeof error.path !== "string" || targetPath(error.path, target) === undefined) {
      add(groups.errors, error.path, "error");
      continue;
    }
    parseOnly.set(error.path, (parseOnly.get(error.path) ?? true) && parse);
  }
  for (const entry of skipped) {
    const reason = typeof entry.reason === "string" ? entry.reason : "";
    if (POLICY_SKIPS.has(reason)) continue;
    if (reason === "analysis_failed_parser_or_internal_error" && typeof entry.path === "string" && parseOnly.has(entry.path)) {
      continue; // classified by its errors below
    }
    const rel = targetPath(entry.path, target);
    const group = SIZE_SKIPS.has(reason) ? (rel !== undefined && nonSourceFile(rel) ? groups.nonSource : groups.size)
      : reason === "analysis_failed_parser_or_internal_error" ? groups.errors
        : reason === "insufficient_permissions" ? groups.unreadable
          : groups.other;
    add(group, entry.path, "skip");
  }
  const parseFiles: string[] = [];
  for (const [path, onlyParse] of parseOnly) {
    if (onlyParse) parseFiles.push(path);
    else add(groups.errors, path, "error");
  }

  const parts = [
    groups.size.size ? `${groups.size.size} over Opengrep's file size limit` : "",
    groups.unreadable.size ? `${groups.unreadable.size} unreadable` : "",
    groups.errors.size ? `${groups.errors.size} with a timeout, memory limit or engine error` : "",
    groups.other.size ? `${groups.other.size} skipped for another reason` : "",
  ].filter(Boolean);
  const files = [...new Set([...groups.size, ...groups.unreadable, ...groups.errors, ...groups.other])]
    .filter((path) => !path.startsWith("\u0000"));
  const examples = files.slice(0, MAX_EXAMPLES).join(", ");
  const shownParseFiles = parseFiles.flatMap((path) => displayPath(path, target) ?? []).sort();
  const nonSource = [...groups.nonSource].filter((path) => !path.startsWith("\u0000"));
  const nonSourceExamples = nonSource.slice(0, MAX_EXAMPLES).join(", ");
  return {
    ...(parts.length
      ? { warning: `Opengrep SAST coverage partial: ${parts.join("; ")}${examples ? `: ${examples}${files.length > MAX_EXAMPLES ? ", …" : ""}` : ""}.` }
      : {}),
    ...(parseFiles.length
      ? { parseErrors: { id: "sast-parse-errors" as const, files: parseFiles.length, examples: shownParseFiles.slice(0, MAX_EXAMPLES) } }
      : {}),
    ...(groups.nonSource.size
      ? {
        note: `Opengrep skipped ${groups.nonSource.size} non-source file(s) over its file size limit (images, fonts, media, archives, ` +
          "documents, binaries, lockfiles, source maps or data dumps); no bundled SAST rule reads them (informational, not a coverage gap)" +
          `${nonSourceExamples ? `: ${nonSourceExamples}${nonSource.length > MAX_EXAMPLES ? ", …" : ""}` : ""}.`,
      }
      : {}),
  };
}
