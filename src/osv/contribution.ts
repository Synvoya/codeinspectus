/**
 * How an osv-scanner run joins the scan envelope: which engine record, coverage entries and warnings
 * it adds, and how detected lockfiles reconcile against the structured output. Never reads stderr.
 */

import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";

import { parseDocument } from "yaml";

import type { OsvScanResult } from "../engines/osv-scanner.js";
import type { DependencyCoverage, EngineRunInfo } from "../types.js";
import { OSV_ECOSYSTEMS, type OsvEcosystem, type OsvLockfile } from "./ecosystems.js";

const NATIVE_PUB_COVERS = "Pub dependencies are still checked by the native codeinspectus-pub engine.";

export interface OsvContribution {
  /** Whether the run belongs in engine_details, findings and component signatures. */
  include: boolean;
  info: EngineRunInfo;
  coverage: DependencyCoverage[];
  warnings: string[];
  /**
   * Rescan proof (M6 fix round 2): lockfiles found by name that osv-scanner listed no packages from, and
   * ecosystems it checked only partially or not at all without naming the files (`partial` or `unavailable`
   * from the run itself, not only through those lockfiles).
   */
  unchecked?: { files: string[]; ecosystems: string[] };
}

/**
 * C0/C1 controls, line and paragraph separators, bidirectional controls and invisible format characters:
 * a crafted directory name could otherwise break a note into lines or visually reorder it.
 */
const UNPRINTABLE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]+/g;

/** Lockfile paths come from the scanned repository: printable, and at most three named. */
function nameLockfiles(files: readonly string[]): string {
  const shown = files.slice(0, 3).map((file) => file.replace(UNPRINTABLE, ""));
  return files.length > shown.length ? `${shown.join(", ")} and ${files.length - shown.length} more` : shown.join(", ");
}

function unextractedLimitation(ecosystem: string): string {
  return `A ${ecosystem} lockfile or manifest was found by name, but osv-scanner listed no packages from it ` +
    "(an empty file, an unsupported layout, or an extraction error), so osv-scanner checked none of them.";
}

function unextractedNote(files: readonly string[]): string {
  return `no packages extracted from ${nameLockfiles(files)} (empty lockfile or unsupported format)`;
}

/**
 * Lockfiles found by name that osv-scanner's JSON output lists no packages from: `partial`, with a note.
 * Usually an empty lockfile (a package-lock.json with only the root entry), so it is not a scan warning;
 * it is never derived from osv-scanner's progress output, whose lines embed repository-controlled paths.
 * For an ecosystem the output lists through another lockfile, the checked entry becomes `partial` too.
 */
function withUnextracted(ecosystem: OsvEcosystem, entry: DependencyCoverage | undefined, files: readonly string[]): DependencyCoverage {
  if (!entry) {
    return {
      ecosystem,
      engine: "osv-scanner",
      state: "partial",
      lockfiles: { discovered: 0, analyzed: 0 },
      packages: { resolved: 0, eligible: 0, skipped: 0 },
      matching: "osv-scanner-offline",
      limitations: [unextractedLimitation(ecosystem)],
      note: unextractedNote(files),
    };
  }
  // An unavailable ecosystem was not checked at all; its existing note already says so.
  if (entry.state !== "ran" && entry.state !== "partial") return entry;
  return {
    ...entry,
    state: "partial",
    limitations: [...entry.limitations, unextractedLimitation(ecosystem)],
    note: entry.note ? `${entry.note} ${unextractedNote(files)}` : unextractedNote(files),
  };
}

function osvCoverageOrder(entry: DependencyCoverage): number {
  const index = (OSV_ECOSYSTEMS as readonly string[]).indexOf(entry.ecosystem);
  return index < 0 ? OSV_ECOSYSTEMS.length : index;
}

/**
 * How one osv-scanner run joins the scan. osv-scanner is additive: when it is not installed it only says
 * so (no engine record, no coverage), so a declined install never changes aggregate coverage. A run that
 * completed but found no package sources is still recorded (ran, no findings): that is what lets rescan
 * prove that removing the last lockfile resolved its findings. The wrapper's `warnings` already carry
 * everything to tell the user, including a failure note, so `info.note` is never warned a second time.
 *  - Ruling 12: when native Pub ran (or ran partially), a missing OSV Pub database is a note on the
 *    osv-scanner Pub coverage entry, not a scan warning.
 *  - Ruling 13 (softened by Ruling 31): once osv-scanner has executed and reported, a lockfile of an
 *    allow-listed ecosystem that was detected by name but that its JSON output lists no packages from
 *    makes that ecosystem `partial`, with a coverage note naming the lockfile and no scan warning (most
 *    often an empty lockfile). Never a silent miss: aggregate coverage stays partial.
 */
export function osvContribution(
  osv: OsvScanResult,
  lockfiles: readonly OsvLockfile[],
  nativePubCovers: boolean,
): OsvContribution {
  if (!osv.info.available) return { include: false, info: osv.info, coverage: [], warnings: osv.warnings };
  const detected = OSV_ECOSYSTEMS.filter((ecosystem) => lockfiles.some((lockfile) => lockfile.ecosystem === ecosystem));

  // The run failed, so there is no package output to reconcile: it stays a failure (ran:false) with its
  // warning. Its note quotes osv-scanner's stderr, which is never read as coverage (Ruling 32).
  if (!osv.info.ran && !osv.coverage.length) return { include: true, info: osv.info, coverage: [], warnings: osv.warnings };

  const warnings = [...osv.warnings];
  // Ecosystems the run itself reported partial or unavailable: their findings are not provable either way.
  const gated = [...new Set(osv.coverage.filter((entry) => entry.state === "partial" || entry.state === "unavailable").map((entry) => entry.ecosystem))].sort();
  const unextracted: string[] = [];
  let pubNoted = false;
  const coverage = osv.coverage.map((entry) => {
    if (!nativePubCovers || entry.ecosystem !== "Pub" || entry.state !== "unavailable" || !entry.note) return entry;
    const index = warnings.indexOf(entry.note);
    if (index >= 0) warnings.splice(index, 1);
    pubNoted = true;
    return { ...entry, note: `${entry.note} ${NATIVE_PUB_COVERS}` };
  });
  // When Pub was the only thing osv-scanner could have checked, its run note would repeat the setup nag.
  const info = pubNoted && !osv.info.ran
    ? { ...osv.info, note: [...warnings, `osv-scanner did not check Pub: the optional OSV Pub database is not installed. ${NATIVE_PUB_COVERS}`].join(" ") }
    : osv.info;

  // Per lockfile, from the structured output: a second, empty lockfile is noted even when the first was read.
  const extracted = new Set(osv.lockfiles);
  for (const ecosystem of detected) {
    const missed = lockfiles
      .filter((lockfile) => lockfile.ecosystem === ecosystem && !extracted.has(lockfile.path))
      .map((lockfile) => lockfile.path);
    if (!missed.length) continue;
    unextracted.push(...missed);
    const index = coverage.findIndex((entry) => entry.ecosystem === ecosystem);
    if (index < 0) coverage.push(withUnextracted(ecosystem, undefined, missed));
    else coverage[index] = withUnextracted(ecosystem, coverage[index], missed);
  }
  coverage.sort((left, right) => osvCoverageOrder(left) - osvCoverageOrder(right));
  return {
    include: osv.applicable || coverage.length > 0, info, coverage, warnings,
    unchecked: { files: [...new Set(unextracted)].sort(), ecosystems: gated },
  };
}

/** A YAML mapping parsed strictly (YAML 1.2, unique keys) with no error or warning, else undefined. */
function strictYamlMap(text: string): Record<string, unknown> | undefined {
  try {
    const document = parseDocument(text, { prettyErrors: false, strict: true, uniqueKeys: true, version: "1.2" });
    if (document.errors.length > 0 || document.warnings.length > 0) return undefined;
    const value: unknown = document.toJS({ maxAliasCount: 0 });
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/** A yarn Berry descriptor `name@range` (scoped names start with `@`) whose own range is a workspace. */
function workspaceDescriptor(descriptor: string): boolean {
  const at = descriptor.indexOf("@", descriptor.startsWith("@") ? 1 : 0);
  return at > 0 && descriptor.slice(at + 1).startsWith("workspace:");
}

/** Lockfiles larger than this are never read for the empty-lockfile test (they then stay unchecked). */
const EMPTY_LOCKFILE_MAX_BYTES = 8 * 1024 * 1024;

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const emptyCollection = (value: unknown): boolean =>
  value === undefined || value === null || (Array.isArray(value) ? value.length === 0 : isRecord(value) && Object.keys(value).length === 0);

/**
 * Whether a lockfile lists no dependency at all, so osv-scanner listing no packages from it is a real "nothing
 * to check" (M6 final cleanup), recognised for the cheap cases only: an npm `package-lock.json` or
 * `npm-shrinkwrap.json` whose `packages` holds only the root `""` entry and with no `dependencies`; a
 * `composer.lock` with empty `packages` and `packages-dev`; a yarn Berry `yarn.lock` (strict YAML) whose keys are
 * `__metadata` and workspace descriptors only; a `pnpm-lock.yaml` (strict YAML) with no `packages`, `snapshots` or
 * importer dependencies. Anything else (unreadable, yarn v1, a YAML error or warning, an unknown layout) is not
 * empty: the lockfile then stays unchecked.
 */
export function isEmptyLockfile(name: string, text: string): boolean {
  if (name === "package-lock.json" || name === "npm-shrinkwrap.json" || name === "composer.lock") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return false;
    }
    if (!isRecord(parsed)) return false;
    if (name === "composer.lock") {
      return Array.isArray(parsed.packages) && parsed.packages.length === 0 && emptyCollection(parsed["packages-dev"]);
    }
    const packages = parsed.packages;
    const rootOnly = packages === undefined || (isRecord(packages) && Object.keys(packages).every((key) => key === ""));
    return "lockfileVersion" in parsed && rootOnly && emptyCollection(parsed.dependencies);
  }
  if (name === "yarn.lock") {
    // Berry only: strict YAML whose every top-level key but `__metadata` lists workspace descriptors only.
    // yarn v1 (not YAML) and anything that does not parse cleanly are never empty (security review: fail closed).
    const lock = strictYamlMap(text);
    if (!lock || !("__metadata" in lock)) return false;
    return Object.keys(lock).every((key) => key === "__metadata" || key.split(",").every((descriptor) => workspaceDescriptor(descriptor.trim())));
  }
  if (name === "pnpm-lock.yaml") {
    const lock = strictYamlMap(text);
    if (!lock || !("lockfileVersion" in lock)) return false;
    const dependencyMaps = ["dependencies", "devDependencies", "optionalDependencies"];
    if (!emptyCollection(lock.packages) || !emptyCollection(lock.snapshots)) return false;
    if (dependencyMaps.some((key) => !emptyCollection(lock[key]))) return false;
    if (lock.importers === undefined || lock.importers === null) return true;
    if (!isRecord(lock.importers)) return false;
    return Object.values(lock.importers).every((importer) =>
      importer === null || (isRecord(importer) && dependencyMaps.every((key) => emptyCollection(importer[key]))));
  }
  return false;
}

/** The target-relative lockfiles among `files` that list no dependency (isEmptyLockfile); bounded, no link followed. */
export async function emptyLockfiles(target: string, files: readonly string[]): Promise<Set<string>> {
  const empty = new Set<string>();
  for (const rel of files) {
    const path = join(target, ...rel.split("/"));
    let handle;
    try {
      if (!(await lstat(path)).isFile()) continue;
      handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const info = await handle.stat();
      if (!info.isFile() || info.size > EMPTY_LOCKFILE_MAX_BYTES) continue;
      const text = (await handle.readFile()).toString("utf8");
      if (isEmptyLockfile(rel.slice(rel.lastIndexOf("/") + 1), text)) empty.add(rel);
    } catch {
      // Unreadable: it stays unchecked.
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }
  return empty;
}
