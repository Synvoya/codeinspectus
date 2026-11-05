/**
 * How an osv-scanner run joins the scan envelope: which engine record, coverage entries and warnings
 * it adds, and how detected lockfiles reconcile against the structured output. Never reads stderr.
 */

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
    const index = coverage.findIndex((entry) => entry.ecosystem === ecosystem);
    if (index < 0) coverage.push(withUnextracted(ecosystem, undefined, missed));
    else coverage[index] = withUnextracted(ecosystem, coverage[index], missed);
  }
  coverage.sort((left, right) => osvCoverageOrder(left) - osvCoverageOrder(right));
  return { include: osv.applicable || coverage.length > 0, info, coverage, warnings };
}
