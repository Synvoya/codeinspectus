/**
 * 4.1 M9 (addendum A5): a dependency upgrade summary. Many advisories on one locked package are one task for the
 * user ("upgrade next 16.3.3 → 16.4.1"), so the scan also lists them per package: the current version, the lowest
 * version that fixes every advisory with a listed fix on the current release line, how many findings that
 * upgrade resolves, and the highest severity among them. Additive and derived: findings are unchanged.
 */

import type { Finding, Severity, UpgradeAction } from "./types.js";

export type { UpgradeAction };
import { compareVersions, stripV, type VersionScheme } from "./synvoya/versions.js";

const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

const SCHEMES: Readonly<Record<string, VersionScheme>> = {
  npm: "semver",
  PyPI: "pep440",
  Go: "go",
  RubyGems: "ruby",
  NuGet: "dotnet",
  Maven: "maven",
  Packagist: "php",
  "GitHub Actions": "semver",
};

/** Fix round 2: GitHub Actions refs compare as semver without `v`, padded to three parts (`v45` → `45.0.0`). */
function comparable(ecosystem: string, version: string): string {
  if (ecosystem !== "GitHub Actions") return version;
  const bare = stripV(version);
  return /^\d+$/.test(bare) ? `${bare}.0.0` : /^\d+\.\d+$/.test(bare) ? `${bare}.0` : bare;
}

/** A version comparator for one ecosystem; undefined when either side does not parse. */
function comparatorFor(ecosystem: string): (a: string, b: string) => number | undefined {
  const scheme = SCHEMES[ecosystem] ?? "generic";
  return (a, b) => compareVersions(scheme, comparable(ecosystem, a), comparable(ecosystem, b));
}

/**
 * Fix round 2: merge the fixed versions two engines report for one advisory. Per release line (major), the needed
 * fix is the highest of each engine's minimum on that line; a line only one engine lists keeps that engine's minimum.
 */
export function mergeFixedVersions(ecosystem: string, left: readonly string[], right: readonly string[]): string[] {
  const compare = comparatorFor(ecosystem);
  const minimumPerLine = (versions: readonly string[]): Map<string, string> => {
    const lines = new Map<string, string>();
    for (const version of versions) {
      const line = majorOf(comparable(ecosystem, version));
      const current = lines.get(line);
      if (current === undefined || (compare(version, current) ?? 1) < 0) lines.set(line, version);
    }
    return lines;
  };
  const a = minimumPerLine(left);
  const b = minimumPerLine(right);
  const merged: string[] = [];
  for (const line of new Set([...a.keys(), ...b.keys()])) {
    const x = a.get(line);
    const y = b.get(line);
    merged.push(x === undefined ? y! : y === undefined ? x : (compare(y, x) ?? 0) > 0 ? y : x);
  }
  return merged;
}

/**
 * The fixed versions named by a dependency remediation summary. Both wordings are produced by this codebase
 * (`dependencyRemediation` in remediation.ts for Trivy, `osv-scanner.ts` for osv-scanner); anything else
 * yields no versions, so the finding counts as unresolved rather than guessed.
 */
export function fixedVersionsFromRemediation(summary: string): string[] {
  const list = /\bto a fixed (?:version|release listed upstream) \(([^;)]+)(?:;[^)]*)?\)/.exec(summary);
  if (list) return list[1]!.split(",").map((value) => value.trim()).filter(Boolean);
  // Synvoya packages ("Upgrade X to A or B or later, or remove the package.") and GitHub Actions
  // ("Update X to A or later, pinned by its full commit SHA.").
  const orLater = /^(?:Upgrade|Update) \S+ to (.+?) or later(?:,|\.)/.exec(summary);
  if (orLater) return orLater[1]!.split(/\s+or\s+/).map((value) => value.trim()).filter(Boolean);
  const single = /^Upgrade \S+ (?:from \S+ )?to (\S+?)(?:, the fixed release listed upstream|, then rebuild the lockfile)/.exec(summary);
  return single ? [single[1]!] : [];
}

function majorOf(version: string): string {
  return /^v?(\d+)/.exec(version)?.[1] ?? "";
}

/** The fix for one advisory: the lowest listed version above `current`, preferring the current major line. */
function fixFor(ecosystem: string, current: string, fixed: readonly string[]): string | undefined {
  const compare = comparatorFor(ecosystem);
  const above = fixed.filter((version) => (compare(version, current) ?? -1) > 0);
  const line = (version: string) => majorOf(comparable(ecosystem, version));
  const sameLine = above.filter((version) => line(version) === line(current));
  const pool = sameLine.length ? sameLine : above;
  return pool.reduce<string | undefined>(
    (lowest, version) => (lowest === undefined || (compare(version, lowest) ?? 1) < 0 ? version : lowest),
    undefined,
  );
}

export function upgradeActions(findings: readonly Finding[]): UpgradeAction[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (finding.finding_kind !== "vulnerability" || !finding.package) continue;
    const { ecosystem, name, version } = finding.package;
    const key = JSON.stringify([ecosystem, name, version]);
    groups.set(key, [...(groups.get(key) ?? []), finding]);
  }
  const actions: UpgradeAction[] = [];
  for (const group of groups.values()) {
    const { ecosystem, name, version } = group[0]!.package!;
    const compare = comparatorFor(ecosystem);
    const line = (value: string) => majorOf(comparable(ecosystem, value));
    const fixedLists = group.map((finding) => finding.fixed_versions?.length
      ? finding.fixed_versions
      : fixedVersionsFromRemediation(finding.remediation.summary));
    // The target: the highest per-advisory fix (each advisory's lowest fix above the current version, preferring
    // the current major line).
    let upgradeTo: string | undefined;
    for (const fixed of fixedLists) {
      const fix = fixFor(ecosystem, version, fixed);
      if (fix && (upgradeTo === undefined || (compare(fix, upgradeTo) ?? 0) > 0)) upgradeTo = fix;
    }
    // Fix round 3: on the chosen target line, raise the target to the highest fix any advisory needs there.
    const neededOnLine = (fixed: readonly string[], targetLine: string): string | undefined =>
      fixed.filter((value) => line(value) === targetLine && (compare(value, version) ?? -1) > 0).reduce<string | undefined>(
        (lowest, value) => (lowest === undefined || (compare(value, lowest) ?? 1) < 0 ? value : lowest),
        undefined,
      );
    if (upgradeTo) {
      const targetLine = line(upgradeTo);
      for (const fixed of fixedLists) {
        const needed = neededOnLine(fixed, targetLine);
        if (needed !== undefined && (compare(needed, upgradeTo) ?? 0) > 0) upgradeTo = needed;
      }
    }
    // Fix round 1: an advisory is resolved only if the target is at least its fix on the target's own line.
    let resolves = 0;
    const otherLines = new Set<string>();
    for (const fixed of fixedLists) {
      if (!upgradeTo) break;
      const target = upgradeTo;
      const needed = neededOnLine(fixed, line(target));
      if (needed !== undefined && (compare(target, needed) ?? -1) >= 0) resolves++;
      else {
        for (const value of fixed) {
          // The target's own line is never "only on another line".
          if ((compare(value, version) ?? -1) > 0 && line(value) && line(value) !== line(target)) otherLines.add(`${line(value)}.x`);
        }
      }
    }
    // NIT (fix round 3): an Action pinned by commit SHA cannot be compared; carry the highest listed fix for a
    // manual check (the text report says so).
    if (!upgradeTo && ecosystem === "GitHub Actions" && /^[0-9a-f]{7,40}$/i.test(version)) {
      for (const fixed of fixedLists) {
        for (const value of fixed) if (upgradeTo === undefined || (compare(value, upgradeTo) ?? 0) > 0) upgradeTo = value;
      }
    }
    const highest = SEVERITY_ORDER.find((severity) => group.some((finding) => finding.severity === severity)) ?? "info";
    actions.push({
      ecosystem,
      name,
      version,
      ...(upgradeTo ? { upgrade_to: upgradeTo } : {}),
      resolves,
      unresolved: group.length - resolves,
      ...(otherLines.size ? { unresolved_fix_lines: [...otherLines].sort() } : {}),
      highest_severity: highest,
      dev_only: group.every((finding) => finding.dependency_scope === "dev"),
    });
  }
  return actions.sort((left, right) =>
    SEVERITY_ORDER.indexOf(left.highest_severity) - SEVERITY_ORDER.indexOf(right.highest_severity) ||
    (right.resolves + right.unresolved) - (left.resolves + left.unresolved) ||
    left.name.localeCompare(right.name) ||
    left.version.localeCompare(right.version));
}
