/**
 * OSV database ecosystems CodeInspectus may download, and the lockfile names that say a
 * repository uses one.
 *
 * The allow-list is language ecosystems only. Distro ecosystems (Debian, Alpine, Ubuntu, Wolfi,
 * Chainguard, ...) are deliberately absent: osv-scanner scans package manifests here, and a
 * distro database would be a large download that no lockfile in a source repository can use.
 *
 * Detection reads file names only. It never opens a file, follows a symlink, or touches the network.
 */

import { lstat, opendir } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { basename, join } from "node:path";

import { DEFAULT_DETECTION_LIMITS, IGNORED_DIRECTORIES } from "../technology-detection.js";

/** Display and download order. */
export const OSV_ECOSYSTEMS = [
  "npm",
  "PyPI",
  "Packagist",
  "Go",
  "crates.io",
  "RubyGems",
  "Maven",
  "NuGet",
  "Pub",
] as const;

export type OsvEcosystem = (typeof OSV_ECOSYSTEMS)[number];

/** Size of each `all.zip`, in bytes, measured 2026-10-30. Estimates only: the databases change upstream. */
export const OSV_DB_SIZE_ESTIMATES: Record<OsvEcosystem, number> = {
  npm: 219_599_455,
  PyPI: 37_544_046,
  Packagist: 11_063_339,
  Go: 12_675_916,
  "crates.io": 3_737_559,
  RubyGems: 5_203_275,
  Maven: 10_466_352,
  NuGet: 2_680_919,
  Pub: 25_896,
};

/**
 * Every ecosystem OSV publishes a database for, from
 * https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt (fetched 2026-10-31). Never a download
 * list: the scan overlay gives each one that is not allow-listed (or not installed) an empty database,
 * because osv-scanner 2.7.0 fails the whole run when it cannot load the database for any ecosystem it
 * saw (a `Package.resolved` needs SwiftURL). Static, so a scan makes no network request.
 * Omitted: `[EMPTY]`, the bucket for records with no ecosystem, which osv-scanner never loads. No other
 * name contains `/`, `\` or `:`, so each is a single path segment.
 */
export const OSV_PUBLISHED_ECOSYSTEMS: readonly string[] = [
  "AlmaLinux",
  "Alpaquita",
  "Alpine",
  "Android",
  "Azure Linux",
  "BellSoft Hardened Containers",
  "Bitnami",
  "CRAN",
  "Chainguard",
  "CleanStart",
  "Debian",
  "Echo",
  "GHC",
  "GIT",
  "GSD",
  "GitHub Actions",
  "Go",
  "Hackage",
  "Hex",
  "Julia",
  "Linux",
  "Mageia",
  "Maven",
  "MinimOS",
  "NuGet",
  "OSS-Fuzz",
  "Packagist",
  "Pub",
  "PyPI",
  "Red Hat",
  "Red Hat Lightwell",
  "Rocky Linux",
  "Root",
  "RubyGems",
  "SUSE",
  "SwiftURL",
  "TuxCare",
  "UVI",
  "Ubuntu",
  "VSCode",
  "Wolfi",
  "crates.io",
  "npm",
  "opam",
  "openEuler",
  "openSUSE",
];

/**
 * Every ecosystem name the OSV schema defines: `$defs.ecosystemName.enum` in
 * https://github.com/ossf/osv-schema/blob/6410c13304f9bde44b522350b244f1f51e1c18a6/validation/schema.json
 * (main at 6410c13, 2026-10-26; the file last changed in cfe7014, 2026-10-14), fetched 2026-10-31, in schema
 * order. The bucket list above lacks some of these (ConanCenter, vcpkg, Homebrew, ...), and a `conan.lock`
 * next to a `requirements.txt` made osv-scanner 2.7.0 stop at the missing ConanCenter database. Scan
 * overlay only, like OSV_PUBLISHED_ECOSYSTEMS.
 */
export const OSV_SCHEMA_ECOSYSTEMS: readonly string[] = [
  "AlmaLinux",
  "Alpaquita",
  "Alpine",
  "Android",
  "Azure Linux",
  "BellSoft Hardened Containers",
  "Bioconductor",
  "Bitnami",
  "Chainguard",
  "CleanStart",
  "ConanCenter",
  "CRAN",
  "crates.io",
  "Debian",
  "Docker Hardened Images",
  "Echo",
  "FreeBSD",
  "GHC",
  "GitHub Actions",
  "Go",
  "Hackage",
  "Hex",
  "Homebrew",
  "Julia",
  "Kubernetes",
  "Linux",
  "Mageia",
  "Maven",
  "MinimOS",
  "npm",
  "NuGet",
  "opam",
  "openEuler",
  "openSUSE",
  "OSS-Fuzz",
  "Packagist",
  "Photon OS",
  "Pub",
  "PyPI",
  "Raspberry Pi OS",
  "Red Hat",
  "Red Hat Lightwell",
  "Rocky Linux",
  "Root",
  "RubyGems",
  "SUSE",
  "SwiftURL",
  "TuxCare",
  "Ubuntu",
  "vcpkg",
  "VSCode",
  "Wolfi",
  "WordPress",
];

/**
 * Every ecosystem the scan overlay gives a database (installed or empty): the allow-list, the bucket list
 * and the schema enum. An ecosystem newer than both snapshots is handled by one retry in the wrapper.
 */
export const OSV_OVERLAY_ECOSYSTEMS: readonly string[] = [
  ...new Set<string>([...OSV_ECOSYSTEMS, ...OSV_PUBLISHED_ECOSYSTEMS, ...OSV_SCHEMA_ECOSYSTEMS]),
];

/**
 * Whether a name is safe as one overlay directory: one plain path segment, never `/`, `\`, `:` or `..`,
 * no trailing dot or space (Windows drops those, so `Go.` would name the `Go` directory), and not a Windows
 * reserved device name (`CON`, `NUL`, `COM1`, ... with or without an extension).
 */
export function isOverlaySegment(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(name) && !name.includes("..") && !/[. ]$/.test(name) &&
    !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(name);
}

export function isOsvEcosystem(value: unknown): value is OsvEcosystem {
  return typeof value === "string" && (OSV_ECOSYSTEMS as readonly string[]).includes(value);
}

/** Parse a user-supplied comma-separated list, canonicalising case. Result is in allow-list order. */
export function parseOsvEcosystems(value: string): OsvEcosystem[] {
  const requested = value.split(",").map((item) => item.trim()).filter(Boolean);
  const unknown = requested.filter(
    (item) => !OSV_ECOSYSTEMS.some((ecosystem) => ecosystem.toLowerCase() === item.toLowerCase()),
  );
  if (!requested.length || unknown.length) {
    throw new Error(
      `Expected a comma-separated list of OSV ecosystems from: ${OSV_ECOSYSTEMS.join(", ")}` +
      `${unknown.length ? ` (unknown: ${unknown.join(", ")})` : ""}.`,
    );
  }
  const wanted = new Set(requested.map((item) => item.toLowerCase()));
  return OSV_ECOSYSTEMS.filter((ecosystem) => wanted.has(ecosystem.toLowerCase()));
}

const LOCKFILE_ECOSYSTEMS: ReadonlyMap<string, OsvEcosystem> = new Map([
  ["package-lock.json", "npm"],
  ["npm-shrinkwrap.json", "npm"],
  ["yarn.lock", "npm"],
  ["pnpm-lock.yaml", "npm"],
  ["bun.lock", "npm"],
  ["poetry.lock", "PyPI"],
  ["pipfile.lock", "PyPI"],
  ["uv.lock", "PyPI"],
  ["pdm.lock", "PyPI"],
  ["composer.lock", "Packagist"],
  ["go.mod", "Go"],
  ["cargo.lock", "crates.io"],
  ["gemfile.lock", "RubyGems"],
  ["pom.xml", "Maven"],
  ["gradle.lockfile", "Maven"],
  ["packages.lock.json", "NuGet"],
  ["pubspec.lock", "Pub"],
]);

/** The ecosystem a lockfile or manifest file name belongs to (base name only), if it is an allow-listed one. */
export function osvEcosystemForFile(name: string): OsvEcosystem | undefined {
  const lower = basename(name.replace(/\\/g, "/")).toLowerCase();
  if (/^requirements.*\.txt$/.test(lower)) return "PyPI";
  return LOCKFILE_ECOSYSTEMS.get(lower);
}

/** A lockfile or manifest of an allow-listed ecosystem, found by name. */
export interface OsvLockfile {
  /** Relative to the scanned directory, `/`-separated; the file name when the target is a file. */
  path: string;
  ecosystem: OsvEcosystem;
}

/**
 * Lockfiles of allow-listed ecosystems under `target`, sorted by path.
 *
 * The walk is bounded by the same entry and depth limits as technology detection and skips the same
 * generated, dependency and VCS directories, so a vendored package's own lockfile never counts.
 */
export async function detectOsvLockfiles(target: string): Promise<OsvLockfile[]> {
  const found: OsvLockfile[] = [];
  let info;
  try {
    info = await lstat(target);
  } catch {
    return [];
  }
  if (info.isFile()) {
    const ecosystem = osvEcosystemForFile(target);
    return ecosystem ? [{ path: basename(target), ecosystem }] : [];
  }
  if (!info.isDirectory()) return [];

  const { maxEntries, maxDepth } = DEFAULT_DETECTION_LIMITS;
  const pending: Array<{ directory: string; relative: string; depth: number }> = [{ directory: target, relative: "", depth: 0 }];
  let inspected = 0;
  while (pending.length && inspected < maxEntries) {
    const { directory, relative, depth } = pending.pop()!;
    const entries: Dirent[] = [];
    try {
      for await (const entry of await opendir(directory)) {
        entries.push(entry);
        if (inspected + entries.length >= maxEntries) break;
      }
    } catch {
      continue; // unreadable directory: skip it, never fail detection
    }
    inspected += entries.length;
    // Sorted so that, if the entry limit cuts the walk short, the same files are seen every time.
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
    for (const entry of entries) {
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      // Dirent reports a symlink as a symlink, so linked files and directories are never followed.
      if (entry.isDirectory()) {
        if (depth < maxDepth && !IGNORED_DIRECTORIES.has(entry.name.toLowerCase())) {
          pending.push({ directory: join(directory, entry.name), relative: path, depth: depth + 1 });
        }
      } else if (entry.isFile()) {
        const ecosystem = osvEcosystemForFile(entry.name);
        if (ecosystem) found.push({ path, ecosystem });
      }
    }
  }
  return found.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
}

/** Ecosystems whose lockfiles appear under `target` (see detectOsvLockfiles), in allow-list order. */
export async function detectOsvEcosystems(target: string): Promise<OsvEcosystem[]> {
  const found = new Set((await detectOsvLockfiles(target)).map((lockfile) => lockfile.ecosystem));
  return OSV_ECOSYSTEMS.filter((ecosystem) => found.has(ecosystem));
}

/** PEP 503 style name normalisation: lowercase, with each run of `-`, `_` or `.` collapsed to one `-`. */
export function normalizePackageName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}
