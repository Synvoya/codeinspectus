/**
 * The 1-based line of a lockfile that names a package, for a finding's location: `packageLine` for
 * osv-scanner findings (unchanged, the line feeds their fingerprint), `packageEntryLine` for Synvoya package
 * findings (the package's own entry key). Read-only and bounded: a symlink, a special file or a file over
 * 16 MiB is never read, and the line is then 1.
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

/** 1-based first line naming the package (case-insensitive; then ignoring `-`/`_`/`.` differences), else 1. */
export function packageLine(lines: LockfileLines | undefined, name: string): number {
  if (!lines) return 1;
  const needle = name.toLowerCase();
  const direct = lines.lower.findIndex((line) => line.includes(needle));
  if (direct >= 0) return direct + 1;
  const normalized = normalizePackageName(name);
  lines.loose ??= lines.lower.map(normalizePackageName);
  const loose = lines.loose.findIndex((line) => line.includes(normalized));
  return loose >= 0 ? loose + 1 : 1;
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

/**
 * 1-based line of the package's own entry in a lockfile (Synvoya package findings): the format's exact key
 * (`"node_modules/electron"`, never `"electron-updater"`), else the first line naming it as a whole word,
 * else 1. osv-scanner findings keep `packageLine`, because their line is a fingerprint input.
 */
export function packageEntryLine(lines: LockfileLines | undefined, file: string, name: string): number {
  if (!lines) return 1;
  const base = file.slice(file.lastIndexOf("/") + 1).toLowerCase();
  const exact = escapeRegExp(name.toLowerCase());
  const format = ENTRY_KEYS.find((entry) => entry.file.test(base));
  if (format) {
    const candidates = format.loose ? [exact, escapeRegExp(normalizePackageName(name))] : [exact];
    for (const key of candidates) {
      const loose = key !== exact;
      const searched = loose ? (lines.loose ??= lines.lower.map(normalizePackageName)) : lines.lower;
      for (const pattern of format.keys(key)) {
        const at = searched.findIndex((line) => pattern.test(line));
        if (at >= 0) return at + 1;
      }
    }
  }
  const word = new RegExp(`(?<!${NAME_CHAR})${exact}(?!${NAME_CHAR.replace("/", "")})`);
  const at = lines.lower.findIndex((line) => word.test(line));
  return at >= 0 ? at + 1 : 1;
}
