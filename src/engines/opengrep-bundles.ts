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
 * - (4.1 M6) or it belongs to an identified third-party library (opengrep-libraries.ts): a package of a
 *   Composer vendor tree under another folder name (never the target itself), from Composer's own
 *   `installed.json`, or a readable `.js` / `.mjs` copy whose file name and licence banner name the same Synvoya
 *   library-table entry and whose SHA-256 equals a recorded release (a minified copy is skipped by the rule
 *   above anyway; its identity only labels it).
 * Read-only and bounded: no symbolic link is followed, the walk stops at a fixed entry bound and a total read
 * bound; whatever is not classified simply stays in the pack pass, as before this routing existed.
 */

import { lstat, opendir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";

import type { CoverageGap } from "../coverage-gaps.js";
import { isDisplayablePath } from "../display-path.js";
import { log } from "../logger.js";
import { OPENGREP_BUNDLE_SKIPPING_RULES_LABEL } from "../provenance.js";
import { LIBRARY_HEAD_BYTES } from "../synvoya/readers/libraries.js";
import type { LibraryTable } from "../synvoya/types.js";

import { composerVendorTree, jsLibraryCorroborated, jsLibraryIdentity, type LibraryRelease, type PackLibrary } from "./opengrep-libraries.js";

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
export const BUNDLE_CLASSIFIER_REVISION = "3:minified-80pct-code-bytes-dense-lines-open-no-comment+composer-installed+js-library-name-banner";
export const MAX_BUNDLE_EXAMPLES = 20;
/** Libraries named in the identified-libraries coverage note; the rest are counted. */
const MAX_NOTE_LIBRARIES = 10;

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

/** Why a file left the pack pass: its name, minified content, or an identified library (Composer package, JS library). */
export type BundleReason = "name" | "minified" | "composer-package" | "js-library";

export interface PackBundles {
  /** Paths relative to Opengrep's working directory (the target, or a file target's folder), sorted. */
  bundles: string[];
  /** The reason of every file in `bundles`. */
  reasons: ReadonlyMap<string, BundleReason>;
  /** The library of every `composer-package` and `js-library` file in `bundles`. */
  libraries: ReadonlyMap<string, PackLibrary>;
  /** Identified library files the skip-list cap left in the pack pass (name and minified files are kept first). */
  libraryOverflow: number;
}

/**
 * Walk the target the way Opengrep's pack pass would see it (the managed ignore list applied, no symbolic
 * links) and return the files classified as vendored or minified bundles or identified library files. The JS
 * library rule needs the Synvoya library table (`libraryTable`); without it only the other rules run.
 */
export async function findPackBundles(
  target: string,
  ignoreList: string,
  options: {
    libraryTable?: LibraryTable;
    /** Recorded releases for the readable-copy hash check; the shipped KNOWN_LIBRARY_RELEASES by default (tests). */
    libraryReleases?: readonly LibraryRelease[];
    /** The skip-list cap; MAX_EXCLUDED by default (tests). */
    maxExcluded?: number;
  } = {},
): Promise<PackBundles> {
  const matcher = ignoreListMatcher(ignoreList);
  const bundles: string[] = [];
  const reasons = new Map<string, BundleReason>();
  const libraries = new Map<string, PackLibrary>();
  /** Composer package roots (target-relative) found so far: a file's innermost enclosing root names it. */
  const packageRoots = new Map<string, PackLibrary>();
  const budget: { bytes: number; exhausted?: boolean } = { bytes: MAX_READ_BYTES };
  let entries = 0;
  let stopped = false;

  const add = (rel: string, reason: BundleReason, library?: PackLibrary): void => {
    bundles.push(rel);
    reasons.set(rel, reason);
    if (library) libraries.set(rel, library);
  };
  const enclosingPackage = (rel: string): PackLibrary | undefined => {
    if (packageRoots.size === 0) return undefined;
    for (let cut = rel.lastIndexOf("/"); cut > 0; cut = rel.lastIndexOf("/", cut - 1)) {
      const library = packageRoots.get(rel.slice(0, cut));
      if (library) return library;
    }
    return undefined;
  };

  const classify = async (absolute: string, rel: string): Promise<void> => {
    const extension = extname(rel).toLowerCase();
    // A file the ignore syntax cannot name stays in the pack pass, so it is neither skipped nor listed.
    if (!PACK_EXTENSIONS.has(extension) || matcher.ignored(rel, false) || anchoredIgnorePattern(rel) === undefined) return;
    const metadata = await lstat(absolute).catch(() => undefined);
    if (!metadata?.isFile() || metadata.size > OPENGREP_MAX_TARGET_BYTES) return;
    if (bundleByName(rel)) { add(rel, "name"); return; }
    const library = enclosingPackage(rel);
    if (library) { add(rel, "composer-package", library); return; }
    if (metadata.size < LONG_LINE_CHARS) return;
    if (metadata.size > budget.bytes) { stopped = true; return; }
    budget.bytes -= metadata.size;
    const buffer = await readFile(absolute).catch(() => undefined);
    if (buffer === undefined) return;
    const content = buffer.toString("utf8");
    const minified = minifiedSource(content, { php: extension === ".php" || extension === ".phtml" });
    if (options.libraryTable && (extension === ".js" || extension === ".mjs")) {
      const head = buffer.toString("utf8", 0, Math.min(buffer.length, LIBRARY_HEAD_BYTES));
      const identity = jsLibraryIdentity(rel, head, buffer.length > LIBRARY_HEAD_BYTES, options.libraryTable);
      // Name and banner are text anyone can write: a readable copy needs a release-hash match (a minified one is skipped anyway).
      const library = identity && jsLibraryCorroborated(identity, buffer, minified, options.libraryReleases);
      if (library) { add(rel, "js-library", library); return; }
    }
    if (minified) add(rel, "minified");
  };

  const visit = async (absoluteDir: string, relDir: string): Promise<void> => {
    let directory;
    try {
      directory = await opendir(absoluteDir);
    } catch {
      return;
    }
    // A Composer vendor tree under any folder name: its packages are found before the walk enters them.
    for (const library of await composerVendorTree(absoluteDir, relDir, budget)) packageRoots.set(library.location, library);
    if (budget.exhausted) stopped = true;
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
  // Under the cap the 4.0 entries (name, minified) come first, each group in sorted order (fix round 1).
  const cap = options.maxExcluded ?? MAX_EXCLUDED;
  const sorted = (list: string[]): string[] => list.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  const plain = sorted(bundles.filter((rel) => !isLibraryReason(reasons.get(rel)))).slice(0, cap);
  const libraryFiles = sorted(bundles.filter((rel) => isLibraryReason(reasons.get(rel))));
  const keptLibraries = libraryFiles.slice(0, cap - plain.length);
  const kept = sorted([...plain, ...keptLibraries]);
  return {
    libraryOverflow: libraryFiles.length - keptLibraries.length,
    bundles: kept,
    reasons: new Map(kept.map((rel) => [rel, reasons.get(rel)!])),
    libraries: new Map(kept.flatMap((rel) => {
      const library = libraries.get(rel);
      return library ? [[rel, library] as const] : [];
    })),
  };
}

const isLibraryReason = (reason: BundleReason | undefined): boolean => reason === "composer-package" || reason === "js-library";

/**
 * `third-party-bundles`: every file the pack pass skipped, with up to 20 displayable examples. Files skipped
 * for their name or minified content come first (weakest evidence: a content-classified first-party file
 * cannot hide behind hundreds of library files), then identified library files; each group stays sorted.
 */
export function thirdPartyBundlesGap(skipped: readonly string[], reasons?: ReadonlyMap<string, BundleReason>): CoverageGap | undefined {
  if (!skipped.length) return undefined;
  const library = (rel: string): boolean => isLibraryReason(reasons?.get(rel));
  const plain = skipped.filter((rel) => !library(rel) && isDisplayablePath(rel));
  const libraryFiles = skipped.filter((rel) => library(rel) && isDisplayablePath(rel));
  // At least one example per evidence label present (fix round 1): each library label keeps a slot.
  const labels = [...new Set(libraryFiles.map((rel) => reasons!.get(rel)!))];
  const plainShown = plain.slice(0, MAX_BUNDLE_EXAMPLES - labels.length);
  const slots = MAX_BUNDLE_EXAMPLES - plainShown.length;
  const firsts = labels.map((label) => libraryFiles.find((rel) => reasons!.get(rel) === label)!);
  const rest = libraryFiles.filter((rel) => !firsts.includes(rel)).slice(0, Math.max(0, slots - firsts.length));
  const libraryShown = libraryFiles.filter((rel) => firsts.includes(rel) || rest.includes(rel));
  const ordered = [...plainShown, ...libraryShown];
  // Identified library files say on what evidence they left the pass; name and minified files stay bare paths (4.0).
  const label = (rel: string): string => {
    const reason = reasons?.get(rel);
    return reason === "js-library" ? `${rel} (identified by name and banner)`
      : reason === "composer-package" ? `${rel} (identified by Composer installed.json)`
        : rel;
  };
  return {
    id: "third-party-bundles",
    files: skipped.length,
    examples: ordered.map(label),
  };
}

/**
 * The coverage note naming the identified libraries among the skipped files (`skipped`: the files the pack
 * pass was confirmed to skip), one item per library location (a Composer package root, or a JS file), sorted;
 * ten are named and the rest counted, and a location that cannot be displayed is only counted. Undefined
 * when no skipped file belongs to a library.
 */
export function packLibrariesNote(skipped: readonly string[], libraries: ReadonlyMap<string, PackLibrary>): string | undefined {
  const byLocation = new Map<string, { library: PackLibrary; files: number }>();
  let files = 0;
  for (const rel of skipped) {
    const library = libraries.get(rel);
    if (!library) continue;
    files++;
    const location = library.ecosystem === "composer" ? `${library.location}/` : library.location;
    const entry = byLocation.get(location);
    if (entry) entry.files++;
    else byLocation.set(location, { library, files: 1 });
  }
  if (byLocation.size === 0) return undefined;
  const locations = [...byLocation.keys()].sort();
  const shown = locations.filter(isDisplayablePath).slice(0, MAX_NOTE_LIBRARIES).map((location) => {
    const { library, files: count } = byLocation.get(location)!;
    return `${library.name}${library.version !== undefined ? ` ${library.version}` : ""} (${location}${count > 1 ? `, ${count} files` : ""})`;
  });
  const rest = locations.length - shown.length;
  const items = shown.length
    ? `${shown.join(", ")}${rest > 0 ? `, and ${rest} more` : ""}`
    : `${rest} not shown (their paths cannot be displayed)`;
  const k = byLocation.size;
  return `Bundle routing identified ${k} third-party ${k === 1 ? "library" : "libraries"} by name and version; the bundle-skipping Opengrep pass ` +
    `(${OPENGREP_BUNDLE_SKIPPING_RULES_LABEL}) skipped their ${files} file(s), part of third-party-bundles (the other baseline rules still scanned them): ${items}.`;
}

/** The coverage note for identified library files the skip-list cap left in the pack pass; undefined when none. */
export function packLibraryOverflowNote(count: number): string | undefined {
  if (count <= 0) return undefined;
  return `Bundle routing identified ${count} more third-party library file(s) than the bundle-skipping Opengrep pass can skip ` +
    `(at most ${MAX_EXCLUDED} files); those files stayed in that pass.`;
}
