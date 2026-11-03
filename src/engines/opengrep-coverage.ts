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
}

export function opengrepFileCoverage(report: unknown, target: string): OpengrepFileCoverage {
  const root = report !== null && typeof report === "object" ? report as Record<string, unknown> : {};
  const paths = root.paths !== null && typeof root.paths === "object" ? root.paths as Record<string, unknown> : {};
  const errors = records(root.errors);
  const skipped = records(paths.skipped);
  if (!errors || !skipped || !Array.isArray(paths.scanned)) {
    return { warning: "Opengrep SAST coverage partial: Opengrep's structured skip and error report was missing or malformed, so skipped files are unknown." };
  }
  const groups = { size: new Set<string>(), errors: new Set<string>(), unreadable: new Set<string>(), other: new Set<string>() };
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
    const group = SIZE_SKIPS.has(reason) ? groups.size
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
  return {
    ...(parts.length
      ? { warning: `Opengrep SAST coverage partial: ${parts.join("; ")}${examples ? `: ${examples}${files.length > MAX_EXAMPLES ? ", …" : ""}` : ""}.` }
      : {}),
    ...(parseFiles.length
      ? { parseErrors: { id: "sast-parse-errors" as const, files: parseFiles.length, examples: shownParseFiles.slice(0, MAX_EXAMPLES) } }
      : {}),
  };
}
