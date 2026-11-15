/**
 * Display ids (4.1): `CI-` + the first 10 hex characters of a hash of the finding's fingerprint and package.
 *
 * Positional ids (`CI-0001`, 4.0 and earlier) changed whenever another finding appeared or disappeared above
 * them. A display id now depends only on the finding itself, so it is exactly as stable as the fingerprint: it
 * still changes when the fingerprint does (a SAST finding whose line moves, a dedup survivor that flips).
 *
 * The package joins the basis because Trivy's legacy line-1 fingerprints are shared by different packages in
 * one lockfile; a finding keeps its package for life. Two findings with the same 10-hex id (an identical basis
 * or a prefix clash) are told apart deterministically: the group is ordered by a fixed list of fields (package
 * version before any location) and the
 * first keeps the base id, the rest get `-2`, `-3`, ... Ids are unique per scan and independent of input order.
 *
 * Ids are never matched across scans (baselines, history, triage, rescan and git-scope match on fingerprint and
 * dedup identity); every id lookup is scoped to one stored scan, so scans stored before 4.1 keep their ids.
 */

import { dedupKey } from "./dedup.js";
import { normalizePackageName } from "./osv/ecosystems.js";
import type { Finding } from "./types.js";
import { sha256Hex } from "./util/hash.js";

export const DISPLAY_ID_HEX_LENGTH = 10;
export const DISPLAY_ID_PATTERN = /^CI-[0-9a-f]{10}(?:-[1-9][0-9]*)?$/;
/** Positional ids of scans stored before 4.1. A 4.1 id always has 10 characters after `CI-`. */
export const LEGACY_DISPLAY_ID_PATTERN = /^CI-\d{4,9}$/;

const DOMAIN = "codeinspectus-display-id/1\0";

function basisPackage(finding: Finding): string {
  return finding.package?.name ? normalizePackageName(finding.package.name) : "";
}

/** `fingerprint \0 normalized package name` (empty when the finding names no package). */
export function displayIdBasis(finding: Finding): string {
  return `${finding.fingerprint}\0${basisPackage(finding)}`;
}

/** The id before collision suffixes. `hash` maps the full hashed input to hex (sha256 by default). */
export function baseDisplayId(finding: Finding, hash: (input: string) => string = sha256Hex): string {
  return `CI-${hash(`${DOMAIN}${displayIdBasis(finding)}`).slice(0, DISPLAY_ID_HEX_LENGTH).toLowerCase()}`;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** A package version for ordering: one leading `v` before a digit is ignored (`v1.2.3` is `1.2.3`). */
function basisVersion(finding: Finding): string {
  return (finding.package?.version ?? "").replace(/^v(?=\d)/, "");
}

/**
 * The documented collision order: fingerprint, package, package version, dedup key, file, lines, rule, title,
 * message. The version comes before any location, so two versions that share a fingerprint (Trivy's line-1
 * pnpm findings) keep their order (by version text) and their ids, whatever lines they move to.
 */
function collisionOrder(left: Finding, right: Finding): number {
  return compareText(left.fingerprint, right.fingerprint) ||
    compareText(basisPackage(left), basisPackage(right)) ||
    compareText(basisVersion(left), basisVersion(right)) ||
    compareText(dedupKey(left), dedupKey(right)) ||
    compareText(left.location.file, right.location.file) ||
    left.location.start_line - right.location.start_line ||
    left.location.end_line - right.location.end_line ||
    compareText(left.rule_id, right.rule_id) ||
    compareText(left.title, right.title) ||
    compareText(left.message, right.message);
}

/** Sets every finding's `id`. The result does not depend on the order of `findings`. */
export function assignDisplayIds(findings: Finding[], options: { hash?: (input: string) => string } = {}): void {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const id = baseDisplayId(finding, options.hash);
    const group = groups.get(id);
    if (group) group.push(finding);
    else groups.set(id, [finding]);
  }
  for (const [id, group] of groups) {
    group.sort(collisionOrder);
    group.forEach((finding, index) => {
      finding.id = index === 0 ? id : `${id}-${index + 1}`;
    });
  }
}

/**
 * One sentence for a "finding not found" error when the requested id and the scan's ids come from different
 * releases (a 4.0 id asked of a 4.1 scan, or the reverse); "" otherwise.
 */
export function displayIdHint(requested: string, scan: { findings: readonly Finding[] }): string {
  const scanIsNew = scan.findings.some((finding) => DISPLAY_ID_PATTERN.test(finding.id));
  const scanIsLegacy = scan.findings.some((finding) => LEGACY_DISPLAY_ID_PATTERN.test(finding.id));
  if (LEGACY_DISPLAY_ID_PATTERN.test(requested) && scanIsNew) {
    return "Ids like CI-0007 come from scans stored before CodeInspectus 4.1; this scan's ids are derived from each finding's fingerprint. ";
  }
  if (DISPLAY_ID_PATTERN.test(requested) && scanIsLegacy) {
    return "This scan was stored before CodeInspectus 4.1 and uses positional ids such as CI-0001. ";
  }
  return "";
}
