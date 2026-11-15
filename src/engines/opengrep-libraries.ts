/**
 * Identified third-party libraries for the bundle-skipping Opengrep pass (4.1 M6). Two signals only, each
 * naming a library and its version from evidence the product already trusts:
 * - Composer's own install metadata: a folder holding `autoload.php`, `composer/ClassLoader.php` and
 *   `composer/installed.json` is a Composer vendor tree whatever it is called (lobbywatch keeps mPDF in
 *   `libs/mpdf/mpdf_8/`). Each package installed from a repository (an archive dist or a VCS source) whose
 *   root is `<tree>/<name>` is a library; a `path` repository (first-party code mirrored in) and an
 *   installer path outside the tree never are.
 * - A front-end library copy: a `.js` / `.mjs` file whose name is a stem of the Synvoya library table and
 *   whose head banner names the same library (and the same version, when the name has one). Name and banner
 *   alone are text anyone can write (security review): a readable copy leaves the pass only when its SHA-256
 *   equals a recorded release; a minified copy is skipped by the 4.0 minified rule anyway, and the library
 *   identity only labels it, when it holds no code a front-end library has no reason to hold.
 * Everything else (folder names, docblocks, code shapes, a nested `composer.json`) is no signal. Read-only,
 * no symbolic link is followed, every read is bounded; any failure leaves the files in the pack pass.
 */

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join, posix } from "node:path";

import { log } from "../logger.js";
import { bannerMatches, classifyLibraryVersion, libraryStem } from "../synvoya/readers/libraries.js";
import type { LibraryTable } from "../synvoya/types.js";

export const COMPOSER_INSTALLED_MAX_BYTES = 8 * 1024 * 1024;
export const COMPOSER_MAX_PACKAGES = 2_000;
/**
 * Composer's package-name pattern (vendor and package of lower-case letters and digits, separated by single
 * `_`, `.` or `-` and, in the package part, also `--`), written without the nested optional-separator
 * quantifiers of Composer's own regex: the same language (a test checks the two agree), but linear on a
 * hostile name, where the original backtracks exponentially.
 */
export const COMPOSER_PACKAGE_NAME = /^[a-z0-9]+(?:[_.-][a-z0-9]+)*\/[a-z0-9]+(?:(?:[_.]|-{1,2})[a-z0-9]+)*$/;
const COMPOSER_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
/** Packages installed from a repository: Composer's archive dist types and VCS source types. */
const ARCHIVE_DIST_TYPES: ReadonlySet<string> = new Set(["zip", "tar", "xz", "gzip"]);
const VCS_SOURCE_TYPES: ReadonlySet<string> = new Set(["git", "hg", "svn"]);

export interface PackLibrary {
  ecosystem: "composer" | "npm";
  name: string;
  /** Absent for a JS library whose banner carries no usable version (a bare integer). */
  version?: string;
  /** Target-relative: the package root (Composer) or the file (npm). */
  location: string;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function typeOf(value: unknown): string | undefined {
  const type = record(value)?.type;
  return typeof type === "string" ? type : undefined;
}

/**
 * The library packages of one Composer vendor tree from its parsed `installed.json` (`relDir`: the tree's
 * target-relative folder, `""` for the target root). Composer 1 writes a top-level array, Composer 2 an
 * object with a `packages` array; any other shape, or more than COMPOSER_MAX_PACKAGES entries, classifies
 * nothing. Sorted by location; a second package at the same location is dropped.
 */
export function composerPackageRoots(installed: unknown, relDir: string): PackLibrary[] {
  const entries = Array.isArray(installed) ? installed : record(installed)?.packages;
  if (!Array.isArray(entries) || entries.length > COMPOSER_MAX_PACKAGES) return [];
  const out: PackLibrary[] = [];
  const seen = new Set<string>();
  for (const entry of entries) {
    const item = record(entry);
    if (!item) continue;
    const { name, version } = item;
    if (typeof name !== "string" || !COMPOSER_PACKAGE_NAME.test(name)) continue;
    if (typeof version !== "string" || !COMPOSER_VERSION.test(version)) continue;
    const distType = typeOf(item.dist);
    const sourceType = typeOf(item.source);
    if (!(distType !== undefined && ARCHIVE_DIST_TYPES.has(distType)) && !(sourceType !== undefined && VCS_SOURCE_TYPES.has(sourceType))) continue;
    const root = posix.join(relDir, name);
    if ("install-path" in item) {
      const installPath = item["install-path"];
      if (typeof installPath !== "string" || posix.normalize(posix.join(relDir, "composer", installPath)) !== root) continue;
    }
    if (seen.has(root)) continue;
    seen.add(root);
    out.push({ ecosystem: "composer", name, version, location: root });
  }
  return out.sort((left, right) => (left.location < right.location ? -1 : left.location > right.location ? 1 : 0));
}

async function regularFile(path: string): Promise<boolean> {
  const metadata = await lstat(path).catch(() => undefined);
  return metadata?.isFile() === true;
}

/**
 * The library packages of `absoluteDir` when it is a Composer vendor tree (its three marker files are
 * regular files, never links), else `[]`. `installed.json` is read once, without following a link, when it
 * is at most COMPOSER_INSTALLED_MAX_BYTES and fits `budget.bytes` (debited; `exhausted` set when it did not).
 */
export async function composerVendorTree(
  absoluteDir: string,
  relDir: string,
  budget: { bytes: number; exhausted?: boolean },
): Promise<PackLibrary[]> {
  const composerDir = join(absoluteDir, "composer");
  const installedPath = join(composerDir, "installed.json");
  // The scan target itself is never a vendor tree (fix round 1): planted markers at the root, or an explicit
  // `scan /proj/vendor`, leave the whole target in the pack pass as in 4.0.
  if (relDir === "") return [];
  // One lstat per directory in the common case: the other markers are looked at only when this one exists.
  if (!(await regularFile(installedPath))) return [];
  const composerMetadata = await lstat(composerDir).catch(() => undefined);
  if (!composerMetadata?.isDirectory()) return [];
  if (!(await regularFile(join(absoluteDir, "autoload.php"))) || !(await regularFile(join(composerDir, "ClassLoader.php")))) return [];
  const shown = posix.join(relDir, "composer", "installed.json");
  let handle;
  let text: string;
  try {
    handle = await open(installedPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const info = await handle.stat();
    if (!info.isFile()) return [];
    if (info.size > COMPOSER_INSTALLED_MAX_BYTES) {
      log.warn(`Synvoya pack routing did not read ${shown}: larger than ${COMPOSER_INSTALLED_MAX_BYTES} bytes; its packages stay in the pack pass.`);
      return [];
    }
    if (info.size > budget.bytes) {
      budget.exhausted = true;
      return [];
    }
    budget.bytes -= info.size;
    const buffer = Buffer.allocUnsafe(info.size);
    let filled = 0;
    while (filled < info.size) {
      const { bytesRead } = await handle.read(buffer, filled, info.size - filled, filled);
      if (bytesRead === 0) break;
      filled += bytesRead;
    }
    text = buffer.toString("utf8", 0, filled);
  } catch {
    return [];
  } finally {
    await handle?.close().catch(() => undefined);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    log.warn(`Synvoya pack routing could not parse ${shown}; its packages stay in the pack pass.`);
    return [];
  }
  return composerPackageRoots(parsed, relDir);
}

const withoutV = (version: string): string => version.replace(/^v(?=\d)/i, "");

/**
 * The table library a readable `.js` / `.mjs` file copies, or undefined. Its name must be a table stem
 * (libraryStem), the line-start comments of its head (the first LIBRARY_HEAD_BYTES, `headTruncated` when the
 * file goes on) must hold a banner of that library and of no other (a concatenation stays in the pack pass),
 * every banner must carry the same exact or floating version, and a version in the file name must equal it.
 * A bare integer (`Bootstrap v345`) is no version: the library is identified without one, and then a file
 * name with a version cannot be confirmed.
 */
export function jsLibraryIdentity(rel: string, head: string, headTruncated: boolean, table: LibraryTable): PackLibrary | undefined {
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  if (!/\.m?js$/.test(base)) return undefined;
  const stem = libraryStem(base, table);
  if (stem === undefined) return undefined;
  const matches = bannerMatches(head.replace(/^\uFEFF/, ""), headTruncated, table);
  if (matches.length === 0) return undefined;
  /** The agreed banner version; "" while every banner so far carries a bare integer. */
  let version: string | undefined;
  for (const match of matches) {
    if (match.npm !== stem.npm || match.raw === undefined) return undefined;
    const banner = withoutV(match.raw.trim());
    const value = /^\d+$/.test(banner) ? "" : banner;
    if (value !== "" && classifyLibraryVersion(match.raw).precision === "unresolved") return undefined;
    if (version !== undefined && value !== version) return undefined;
    version = value;
  }
  if (version === undefined) return undefined;
  if (stem.version !== undefined && (version === "" || withoutV(stem.version) !== version)) return undefined;
  return version === "" ? { ecosystem: "npm", name: stem.npm, location: rel } : { ecosystem: "npm", name: stem.npm, version, location: rel };
}

/** A library release whose exact bytes are known (fix round 1: readable copies need a hash match). */
export interface LibraryRelease {
  npm: string;
  version: string;
  /** SHA-256 of the file, lower-case hex. */
  sha256: string;
  provenance: string;
}

/**
 * Releases of the readable library copies the 4.1 field set holds (no offline source in the product holds
 * release hashes). Each hash is of the field copy named in `provenance`, whose banner and file name agree;
 * it was not compared with the upstream release file (no network), so it matches that exact copy only.
 */
export const KNOWN_LIBRARY_RELEASES: readonly LibraryRelease[] = [
  { npm: "bootstrap", version: "3.3.7", sha256: "0abe8deb334de1ba743b04d0399e99eba336afed9da72fc4c0a302c99f9238c8", provenance: "field copy lobbywatch public_html/bearbeitung/components/js/libs/bootstrap.js (69,707 bytes)" },
  { npm: "moment", version: "2.29.4", sha256: "c33f09a4e1230f3075be8d2a94081108d52f62d3c30b9a238941fe80790267c6", provenance: "field copy lobbywatch public_html/bearbeitung/components/js/libs/moment.js (174,604 bytes)" },
  { npm: "select2", version: "4.0.5", sha256: "5122fa0060a73698bc07e530d3e93a092fedcda3bfaeec9a7feff841521fb9ff", provenance: "field copy freescout public/js/select2/select2.js (142,768 bytes)" },
];

/**
 * Code a copied front-end library has no reason to hold, anywhere in the file: process spawning, file-system
 * access, dynamic code (`eval(`, `new Function(`), and a `fetch(` whose first argument is not a relative URL
 * literal (an absolute, protocol-relative or computed URL). Text heuristics, not proof: they only decide
 * whether a file may leave the pack pass, and any hit keeps it there.
 */
const RISKY_LIBRARY_CODE: ReadonlyArray<[string, RegExp]> = [
  ["child_process", /child_process/],
  ["require('fs')", /require\s*\(\s*["'`](?:node:)?fs["'`]\s*\)/],
  ["eval(", /eval\s*\(/],
  ["new Function(", /new\s+Function\s*\(/],
  ["fetch( to a non-relative URL", /fetch\s*\(\s*(?!["'`](?:\.\.?)?\/(?!\/))/],
];

/** The first risky construct `text` holds (RISKY_LIBRARY_CODE), or undefined. */
export function riskyLibraryCode(text: string): string | undefined {
  return RISKY_LIBRARY_CODE.find(([, pattern]) => pattern.test(text))?.[0];
}

/**
 * The library an identified JS file is taken to be, or undefined (it stays in the pack pass). A readable copy
 * needs a SHA-256 equal to a recorded release of that library (and of its banner version, when it has one;
 * a banner without one takes the release's). The pattern check is redundant there (the bytes are known) and is
 * not applied. A minified copy (`minified`: minifiedSource) is skipped by the 4.0 minified rule whatever it
 * holds; here it is only labelled as the library when it holds none of RISKY_LIBRARY_CODE.
 */
export function jsLibraryCorroborated(
  library: PackLibrary,
  content: Buffer,
  minified: boolean,
  releases: readonly LibraryRelease[] = KNOWN_LIBRARY_RELEASES,
): PackLibrary | undefined {
  if (minified) return riskyLibraryCode(content.toString("utf8")) === undefined ? library : undefined;
  const candidates = releases.filter((entry) => entry.npm === library.name && (library.version === undefined || entry.version === library.version));
  if (candidates.length === 0) return undefined;
  const sha256 = createHash("sha256").update(content).digest("hex");
  const release = candidates.find((entry) => entry.sha256 === sha256);
  return release ? { ...library, version: release.version } : undefined;
}
