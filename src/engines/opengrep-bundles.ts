/**
 * Synvoya pack routing for third-party bundles (M4 Task 4, controller ruling).
 *
 * The Synvoya PHP and Node Opengrep packs (`syn-php-*`, `syn-node-*`) use taint mode. On minified browser
 * bundles (a 600 KB one-line ckeditor.js, a 300 KB freemius-pricing.js) their rules run past any per-rule
 * timeout and SAST coverage read partial with no gap the user could accept. The packs therefore run in their
 * own Opengrep pass whose ignore list also names the files classified here; the baseline rules keep scanning
 * those files exactly as before. The skipped files become the acceptable gap `third-party-bundles`.
 *
 * Classification is target-relative and conservative:
 * - only files Opengrep would hand to the pack pass are considered: pack languages, outside the managed
 *   ignore list (which already holds `vendor/`, `node_modules/`, `*.min.js`, build output), and at most
 *   Opengrep's 1,000,000-byte target limit (larger files are Opengrep's own, already reported, size skip);
 * - a file is a bundle when its name says so (`*.min.js` or a case-sensitive `vendor/` folder below the
 *   target, both normally ignored already, or a `vendors/` folder of a bundled SDK) or its content is
 *   minified: long dense code lines hold at least 80% of its code bytes. Comment-only lines never count,
 *   so a long comment line (an inline source map, a licence blob) cannot make a first-party file
 *   "minified". A dense line over the native packs' 64 KiB line cap is such a line, so the native
 *   "oversized" files Opengrep still reads (at most 1,000,000 bytes) fall under this test.
 * Read-only and bounded: no symbolic link is followed, the walk stops at a fixed entry bound and a total read
 * bound; whatever is not classified simply stays in the pack pass, as before this routing existed.
 */

import { lstat, opendir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";

import type { CoverageGap } from "../coverage-gaps.js";
import { isDisplayablePath } from "../display-path.js";
import { log } from "../logger.js";

/** Rule folders under the bundled ruleset that form the Synvoya pack pass; every other entry is baseline. */
export const PACK_RULE_DIR_PREFIX = "synvoya-";
/**
 * Baseline rule files that join the pack pass (M4 perf fix): taint-mode rules, named `*-taint.yaml`. Taint
 * analysis of a minified bundle is not bounded by the per-rule timeout (field: 54 s on one 300 KB bundle with
 * no timeout reported), and one taint rule makes every JS/TS file of a pass pay for intrafile dataflow, which
 * the pack pass already does. Their ids are listed in OPENGREP_BUNDLE_SKIPPING_BASELINE_RULES (provenance.ts).
 */
export const PACK_RULE_FILE_PATTERN = /-taint\.ya?ml$/i;
/** Opengrep `--timeout` (seconds per rule per file) for the pack pass; the baseline pass keeps Opengrep's default. */
export const PACK_TIMEOUT_SECONDS = 30;
/** Bumped whenever classification changes, so a rescan never compares pack findings across classifiers. */
export const BUNDLE_CLASSIFIER_REVISION = "2:minified-80pct-code-bytes-dense-lines-open-no-comment";
export const MAX_BUNDLE_EXAMPLES = 20;

/** Extensions Opengrep parses as JavaScript, TypeScript or PHP: the pack languages. */
const PACK_EXTENSIONS: ReadonlySet<string> = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".php", ".phtml",
]);
/** Opengrep 1.33.1 skips (and reports) larger targets itself. */
const OPENGREP_MAX_TARGET_BYTES = 1_000_000;
const LONG_LINE_CHARS = 1_000;
/** A dense line is code-shaped: at most 20% blanks and at least 8% structural punctuation (prose has ~1%). */
const DENSE_MAX_WHITESPACE = 0.2;
const DENSE_MIN_PUNCTUATION = 0.08;
const DENSE_SHARE = 0.8;
const MAX_WALK_ENTRIES = 200_000;
const MAX_READ_BYTES = 256 * 1024 * 1024;
/** Beyond this many bundles the rest stay in the pack pass (Opengrep matches every pattern against every path). */
const MAX_EXCLUDED = 5_000;

function denseLine(code: string): boolean {
  let blanks = 0;
  let punctuation = 0;
  for (let index = 0; index < code.length; index++) {
    const char = code.charCodeAt(index);
    if (char === 0x20 || char === 0x09) blanks++;
    // { } ( ) [ ] ; , =
    else if (char === 0x7b || char === 0x7d || char === 0x28 || char === 0x29 || char === 0x5b || char === 0x5d ||
      char === 0x3b || char === 0x2c || char === 0x3d) punctuation++;
  }
  return blanks <= code.length * DENSE_MAX_WHITESPACE && punctuation >= code.length * DENSE_MIN_PUNCTUATION;
}

/**
 * True when long dense code lines hold at least 80% of the file's code bytes. Comment-only lines (`//`, a
 * block comment, and in PHP `#` but not an attribute `#[`) are not code; a leading block comment that closes
 * on its line (a `/*! licence *\/` banner before minified code) is dropped and the rest of the line counts.
 * A block comment opened after code on a line (`x = 1; /*`) is tracked approximately: until a line holds
 * `*\/`, its lines still count as code bytes but never as dense ones. A long dense line never opens one:
 * minified code holds `/*` inside strings (`accept:"image/*"`, `"text/html, *\/*"`), and a minifier does not
 * leave a comment open across lines (field run 2026-11-05: a concatenated 890 KB bundle stayed in the pack
 * pass for 438 s). Elsewhere a `/*` inside a string can only make a file look less minified, never more.
 */
export function minifiedSource(content: string, options: { php?: boolean } = {}): boolean {
  let codeBytes = 0;
  let denseBytes = 0;
  let inBlock = false;
  /** Inside a block comment that opened after code on an earlier line. */
  let inTrailingBlock = false;
  let start = 0;
  while (start <= content.length) {
    let end = content.indexOf("\n", start);
    if (end < 0) end = content.length;
    let code = content.slice(start, end).trim();
    start = end + 1;
    if (inTrailingBlock) {
      if (code.includes("*/")) inTrailingBlock = false;
      codeBytes += code.length;
      continue;
    }
    for (;;) {
      if (inBlock) {
        const close = code.indexOf("*/");
        if (close < 0) { code = ""; break; }
        inBlock = false;
        code = code.slice(close + 2).trimStart();
        continue;
      }
      if (code.startsWith("/*")) {
        inBlock = true;
        code = code.slice(2);
        continue;
      }
      if (code.startsWith("//") || (code.startsWith("#") && (options.php ? !code.startsWith("#[") : code.startsWith("#!")))) code = "";
      break;
    }
    if (!code) continue;
    codeBytes += code.length;
    if (code.length >= LONG_LINE_CHARS && denseLine(code)) {
      denseBytes += code.length;
      continue;
    }
    const opened = code.lastIndexOf("/*");
    if (opened >= 0 && code.indexOf("*/", opened + 2) < 0) inTrailingBlock = true;
  }
  return denseBytes > 0 && denseBytes >= codeBytes * DENSE_SHARE;
}

/**
 * Folders of copied third-party code, case-sensitive (Laravel's `app/Http/Controllers/Vendor/` is
 * first-party): `vendor/` as Opengrep's default list names it, and `vendors/`, where a WordPress plugin
 * bundles an SDK (`includes/vendors/<sdk>`) and the Synvoya readers (synvoya/readers/walk.ts) already
 * treat it as third-party. Field run: the 990 KB Freemius SDK class there exceeds even the pack timeout.
 */
const VENDORED_DIRS: ReadonlySet<string> = new Set(["vendor", "vendors"]);

/** Name-based classification on a target-relative path: `*.min.js`, or a folder of copied third-party code. */
function bundleByName(rel: string): boolean {
  return rel.endsWith(".min.js") || rel.split("/").slice(0, -1).some((segment) => VENDORED_DIRS.has(segment));
}

/**
 * Characters Opengrep 1.33.1 treats as glob syntax in an ignore pattern even when escaped (review Critical 1,
 * measured: `/src/c\*.js` also skipped `src/cX.js`, `\?` matched any character, and neither `\[` nor `[[]`
 * names a literal `[`). A path holding one is never put on the skip list, or it would hide its siblings.
 * Measured literal there (only the named file was skipped): `{ } , ! # ( ) ^ $ +` and inner spaces.
 */
const GLOB_METACHARACTERS = /[*?[\]\\]/;

/**
 * The ignore-list pattern naming exactly one target-relative file, anchored at the scan root (Opengrep runs
 * in the target). Undefined when that pattern could match anything else or cannot be written: a glob
 * metacharacter, a control character (a line break) or a trailing blank. Such a file stays in the pack pass.
 */
export function anchoredIgnorePattern(rel: string): string | undefined {
  if (!rel || GLOB_METACHARACTERS.test(rel) || /[\u0000-\u001f\u007f]/.test(rel) || /\s$/.test(rel)) return undefined;
  return `/${rel}`;
}

/** The pack pass's ignore list: the baseline list plus one anchored line per bundle it can name. */
export function packIgnoreList(baseline: string, bundles: readonly string[]): string {
  const lines = bundles.flatMap((rel) => anchoredIgnorePattern(rel) ?? []);
  return `${baseline.replace(/\r\n?/g, "\n").replace(/\n*$/, "\n")}\n` +
    "# Synvoya pack pass only: vendored or minified bundles (the baseline rules still scan them).\n" +
    `${lines.join("\n")}\n`;
}

export interface IgnoreListMatcher {
  /** Whether a target-relative path (a directory when `directory`) is ignored by a pattern this matcher understands. */
  ignored(rel: string, directory: boolean): boolean;
  /** Patterns it cannot evaluate; files under them are classified anyway (they only ever leave the pack pass). */
  unsupported: string[];
}

/**
 * A matcher for the forms the managed ignore list uses: `name`, `name/` and a basename glob with `*`, each
 * unanchored (matching at any depth, case-sensitive, like Opengrep). Anchored or nested patterns are listed
 * as unsupported rather than guessed; a test keeps the managed list free of them.
 */
export function ignoreListMatcher(list: string): IgnoreListMatcher {
  const unsupported: string[] = [];
  const names = new Set<string>();
  const directories = new Set<string>();
  const globs: RegExp[] = [];
  for (const raw of list.replace(/\r\n?/g, "\n").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const directory = line.endsWith("/");
    const body = directory ? line.slice(0, -1) : line;
    if (!body || body.includes("/") || /[\\?[\]!]/.test(body) || body.includes("**")) {
      unsupported.push(line);
      continue;
    }
    if (body.includes("*")) {
      if (directory) { unsupported.push(line); continue; }
      globs.push(new RegExp(`^${body.split("*").map((part) => part.replace(/[.+^${}()|]/g, "\\$&")).join("[^/]*")}$`));
    } else if (directory) {
      directories.add(body);
    } else {
      names.add(body);
    }
  }
  return {
    unsupported,
    ignored(rel, directory) {
      const name = rel.slice(rel.lastIndexOf("/") + 1);
      return names.has(name) || (directory && directories.has(name)) || globs.some((glob) => glob.test(name));
    },
  };
}

/**
 * Whether the managed list skips a target-relative path Opengrep reported (a file, or a folder it did not
 * enter): the path itself, as file or folder, or any folder above it.
 */
export function managedIgnorePredicate(list: string): (rel: string) => boolean {
  const matcher = ignoreListMatcher(list);
  return (rel) => {
    const segments = rel.split("/");
    for (let index = 1; index < segments.length; index++) {
      if (matcher.ignored(segments.slice(0, index).join("/"), true)) return true;
    }
    return matcher.ignored(rel, false) || matcher.ignored(rel, true);
  };
}

export interface PackBundles {
  /** Paths relative to Opengrep's working directory (the target, or a file target's folder), sorted. */
  bundles: string[];
}

/**
 * Walk the target the way Opengrep's pack pass would see it (the managed ignore list applied, no symbolic
 * links) and return the files classified as vendored or minified bundles.
 */
export async function findPackBundles(target: string, ignoreList: string): Promise<PackBundles> {
  const matcher = ignoreListMatcher(ignoreList);
  const bundles: string[] = [];
  let entries = 0;
  let readBytes = 0;
  let stopped = false;

  const classify = async (absolute: string, rel: string): Promise<void> => {
    const extension = extname(rel).toLowerCase();
    // A file the ignore syntax cannot name stays in the pack pass, so it is neither skipped nor listed.
    if (!PACK_EXTENSIONS.has(extension) || matcher.ignored(rel, false) || anchoredIgnorePattern(rel) === undefined) return;
    const metadata = await lstat(absolute).catch(() => undefined);
    if (!metadata?.isFile() || metadata.size > OPENGREP_MAX_TARGET_BYTES) return;
    if (bundleByName(rel)) { bundles.push(rel); return; }
    if (metadata.size < LONG_LINE_CHARS) return;
    if (readBytes + metadata.size > MAX_READ_BYTES) { stopped = true; return; }
    readBytes += metadata.size;
    const content = await readFile(absolute, "utf8").catch(() => undefined);
    if (content !== undefined && minifiedSource(content, { php: extension === ".php" || extension === ".phtml" })) bundles.push(rel);
  };

  const visit = async (absoluteDir: string, relDir: string): Promise<void> => {
    let directory;
    try {
      directory = await opendir(absoluteDir);
    } catch {
      return;
    }
    for await (const entry of directory) {
      if (stopped) break;
      if (++entries > MAX_WALK_ENTRIES) { stopped = true; break; }
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!matcher.ignored(rel, true)) await visit(join(absoluteDir, entry.name), rel);
      } else if (entry.isFile()) {
        await classify(join(absoluteDir, entry.name), rel);
      }
    }
  };

  // A file target is never skipped: Opengrep scans an explicit target whatever its ignore list says.
  if ((await lstat(target)).isDirectory()) await visit(target, "");
  if (stopped) {
    log.warn(`Synvoya pack routing stopped classifying bundles at its bound (${MAX_WALK_ENTRIES} entries, ${MAX_READ_BYTES} bytes read); the rest stay in the pack pass.`);
  }
  bundles.sort();
  return { bundles: bundles.slice(0, MAX_EXCLUDED) };
}

/** `third-party-bundles`: every file the pack pass skipped, with up to 20 displayable examples. */
export function thirdPartyBundlesGap(skipped: readonly string[]): CoverageGap | undefined {
  if (!skipped.length) return undefined;
  return {
    id: "third-party-bundles",
    files: skipped.length,
    examples: skipped.filter(isDisplayablePath).slice(0, MAX_BUNDLE_EXAMPLES),
  };
}
