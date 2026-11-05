/**
 * The 1-based line of a lockfile that opens a package's own entry, for a finding's location (osv-scanner and
 * Synvoya package findings). Neither engine's fingerprint includes the line. Read-only and bounded: a symlink,
 * a special file or a file over 16 MiB is never read, and the line is then 1.
 */

import { lstat, readFile } from "node:fs/promises";

import { normalizePackageName } from "./ecosystems.js";

const MAX_LOCKFILE_BYTES = 16 * 1024 * 1024;

/** One lockfile's lines, lowercased once per file; the separator-normalised form is built on first need. */
export interface LockfileLines {
  lower: string[];
  loose?: string[];
}

export async function readLockfileLines(path: string | undefined): Promise<LockfileLines | undefined> {
  if (!path) return undefined;
  try {
    const metadata = await lstat(path);
    // A symlink or special file is never read just to find a line number.
    if (!metadata.isFile() || metadata.size > MAX_LOCKFILE_BYTES) return undefined;
    return { lower: (await readFile(path, "utf8")).toLowerCase().split(/\r?\n/) };
  } catch {
    return undefined;
  }
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Per lockfile format: patterns (on the lowercased line) for the line that opens the package's own entry,
 * in priority order. `loose` formats compare PEP 503-style names (`-`, `_`, `.` alike).
 */
const ENTRY_KEYS: ReadonlyArray<{ file: RegExp; loose?: boolean; keys: (name: string) => RegExp[] }> = [
  // npm v2/v3 "node_modules/<name>" (nested too), then v1 "<name>": { under dependencies.
  { file: /^(?:package-lock|npm-shrinkwrap)\.json$/, keys: (n) => [new RegExp(`^\\s*"(?:[^"]*/)?node_modules/${n}"\\s*:\\s*\\{`), new RegExp(`^\\s*"${n}"\\s*:\\s*\\{`)] },
  // `electron@^42`, `"electron@npm:^42"`, or a later alias on a comma-joined key line (never indented).
  { file: /^yarn\.lock$/, keys: (n) => [new RegExp(`^(?:[^\\s].*,\\s*)?"?${n}@`)] },
  // v9 `electron@42.11.16:`, v6 `/electron@42.11.16:`, v5 `/electron/42.11.16:` (importers say `electron:`).
  { file: /^pnpm-lock\.ya?ml$/, keys: (n) => [new RegExp(`^\\s*['"]?/?${n}[@/]\\d`)] },
  { file: /^bun\.lockb?$/, keys: (n) => [new RegExp(`^\\s*"${n}"\\s*:\\s*\\[`)] },
  { file: /^composer\.lock$/, keys: (n) => [new RegExp(`^\\s*"name"\\s*:\\s*"${n}"`)] },
  { file: /^(?:poetry|uv|pdm)\.lock$/, loose: true, keys: (n) => [new RegExp(`^\\s*name\\s*=\\s*"${n}"`)] },
  { file: /^pipfile\.lock$/, loose: true, keys: (n) => [new RegExp(`^\\s*"${n}"\\s*:\\s*\\{`)] },
  { file: /^requirements.*\.txt$/, loose: true, keys: (n) => [new RegExp(`^\\s*${n}\\s*(?:[=<>~!;\\[]|$)`)] },
  { file: /^cargo\.lock$/, keys: (n) => [new RegExp(`^\\s*name\\s*=\\s*"${n}"`)] },
  { file: /^gemfile\.lock$/, keys: (n) => [new RegExp(`^ {4}${n} \\(`)] },
  { file: /^go\.(?:sum|mod)$/, keys: (n) => [new RegExp(`^\\s*(?:require\\s+)?${n}\\s+v\\d`)] },
  { file: /^packages\.lock\.json$/, keys: (n) => [new RegExp(`^\\s*"${n}"\\s*:\\s*\\{`)] },
  { file: /^(?:gradle\.lockfile|.*\.lockfile)$/, keys: (n) => [new RegExp(`^\\s*${n}:`)] },
];

/** Characters that continue a package name: a match bounded by none of them on either side is the whole name. */
const NAME_CHAR = "[a-z0-9._@/-]";

/** How many lines after an entry's key are searched for its `version` line. */
const VERSION_WINDOW = 6;
/** A version line inside an entry: `"version": "7.5.2"`, `version "7.5.2"`, `version: 7.5.2`, `version = "2.2.3"`. */
const VERSION_LINE = /^\s*"?version"?\s*[:=]?\s*["']?v?\d/;

/**
 * Whether the entry whose key is at `at` resolves `version`: the entry's own `version` line decides (a yarn key
 * carries ranges, not the resolved version); without one, the key line itself (`tar@7.5.2:`, `rack (3.1.8)`,
 * `golang.org/x/net v0.33.0`). The block ends at a blank line or a line indented less than the key.
 */
function entryResolves(lower: readonly string[], at: number, version: RegExp): boolean {
  const indent = lower[at]!.search(/\S/);
  for (let index = at + 1; index < Math.min(lower.length, at + 1 + VERSION_WINDOW); index += 1) {
    const line = lower[index]!;
    if (!line.trim() || line.search(/\S/) < indent) break;
    if (VERSION_LINE.test(line)) return version.test(line);
  }
  return version.test(lower[at]!);
}

/**
 * 1-based line of the package's own entry in a lockfile: the format's exact key (`"node_modules/electron"`,
 * never `"electron-updater"`), preferring the entry that resolves `version` when one is given (a lockfile can
 * lock `tar@6.2.1` and `tar@7.5.2`), else the first such key, else the first line naming it as a whole word,
 * else 1.
 */
export function packageEntryLine(lines: LockfileLines | undefined, file: string, name: string, version?: string): number {
  if (!lines) return 1;
  const base = file.slice(file.lastIndexOf("/") + 1).toLowerCase();
  const exact = escapeRegExp(name.toLowerCase());
  const format = ENTRY_KEYS.find((entry) => entry.file.test(base));
  const bare = version?.toLowerCase().replace(/^v/, "");
  const versioned = bare ? new RegExp(`(?<![0-9a-z.])v?${escapeRegExp(bare)}(?![0-9a-z.+-])`) : undefined;
  const normalized = escapeRegExp(normalizePackageName(name));
  const looseLines = (): string[] => (lines.loose ??= lines.lower.map(normalizePackageName));
  if (format) {
    // A loose format also compares PEP 503-style names on the normalised lines (`Typing_Extensions` is
    // `typing-extensions`), even when the normalised name is spelled like the exact one.
    const candidates = format.loose ? [{ key: exact, loose: false }, { key: normalized, loose: true }] : [{ key: exact, loose: false }];
    for (const { key, loose } of candidates) {
      const searched = loose ? looseLines() : lines.lower;
      for (const pattern of format.keys(key)) {
        let first = -1;
        for (let at = 0; at < searched.length; at += 1) {
          if (!pattern.test(searched[at]!)) continue;
          if (!versioned || entryResolves(lines.lower, at, versioned)) return at + 1;
          if (first < 0) first = at;
        }
        if (first >= 0) return first + 1;
      }
    }
  }
  const word = (key: string) => new RegExp(`(?<!${NAME_CHAR})${key}(?!${NAME_CHAR.replace("/", "")})`);
  const exactWord = word(exact);
  const at = lines.lower.findIndex((line) => exactWord.test(line));
  if (at >= 0) return at + 1;
  // Then ignoring `-`/`_`/`.` differences, still as a whole name.
  const looseWord = word(normalized);
  const loose = looseLines().findIndex((line) => looseWord.test(line));
  return loose >= 0 ? loose + 1 : 1;
}
