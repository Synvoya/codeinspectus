/**
 * Dependency scope and one-level lower severity for development-only dependencies (4.1 M5, Rulings 5 and 6).
 *
 * Evidence, per (target-relative lockfile, normalized package name, version without one leading `v`):
 * - Trivy's `Packages[].Dev` (its `--list-all-pkgs` report) for npm, Yarn, pnpm, Bun and Composer lockfiles;
 * - osv-scanner's `dependency_groups` for `package-lock.json`, `npm-shrinkwrap.json` and `composer.lock`, the
 *   only formats where it emits groups (`"dev"` listed = dev, listed without = not dev).
 * A package is dev only when there is evidence and every entry says dev; any entry that says otherwise makes
 * it production. Doubt reads production, and other formats get no scope.
 *
 * Runs after dedup, so neither the scope nor the lowered severity can change which finding survives a merge
 * (severity is `preferred()`'s first key). A dev vulnerability is labelled (title tag and DEV_SCOPE_NOTE, the
 * 4.0 text) and lowered one level, never below low, except malware, known-exploited (the Synvoya dataset's
 * `exploited: true` advisories, the only offline list) and Synvoya-curated findings. Without the dataset
 * nothing is lowered and a coverage note says why (fail closed).
 */

import type { CoverageNote } from "./coverage-gaps.js";
import { absorbedPackages } from "./dedup.js";
import type { OsvScanResult } from "./engines/osv-scanner.js";
import type { TrivyReportPackage } from "./engines/trivy.js";
import { DEV_SCOPE_NOTE } from "./engines/trivy-dev-scope.js";
import { normalizePackageName } from "./osv/ecosystems.js";
import type { Finding, Severity } from "./types.js";

export type DependencyScope = "dev" | "prod";

export interface ScopeEvidence {
  file: string;
  name: string;
  version: string;
  dev: boolean;
  source: "trivy" | "osv-scanner";
}

/** Lockfiles whose packages Trivy 0.76.1 marks `Dev` (measured; `npm-shrinkwrap.json` shares the npm parser). */
export const TRIVY_SCOPE_LOCKFILES = /^(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.ya?ml|bun\.lock|composer\.lock)$/i;
/** Lockfiles osv-scanner 2.7.0 writes `dependency_groups` for. */
export const OSV_SCOPE_LOCKFILES = /^(?:package-lock\.json|npm-shrinkwrap\.json|composer\.lock)$/i;

export const SCOPE_NOTE_COMPONENT = "scope:dependencies";

const basename = (file: string): string => file.slice(file.lastIndexOf("/") + 1);

export function scopeKey(file: string, name: string, version: string): string {
  return `${file}\0${normalizePackageName(name)}\0${version.replace(/^v(?=\d)/, "")}`;
}

export function scopeEvidence(trivy?: readonly TrivyReportPackage[], osv?: OsvScanResult["packages"]): ScopeEvidence[] {
  const evidence: ScopeEvidence[] = [];
  for (const pkg of trivy ?? []) {
    if (!TRIVY_SCOPE_LOCKFILES.test(basename(pkg.file))) continue;
    evidence.push({ file: pkg.file, name: pkg.name, version: pkg.version, dev: pkg.dev === true, source: "trivy" });
  }
  for (const pkg of osv ?? []) {
    // A source outside the target names only its file, never a target-relative path.
    if (pkg.outside || pkg.dev === undefined || !OSV_SCOPE_LOCKFILES.test(basename(pkg.file))) continue;
    evidence.push({ file: pkg.file, name: pkg.name, version: pkg.version, dev: pkg.dev, source: "osv-scanner" });
  }
  return evidence;
}

export function buildScopeIndex(evidence: readonly ScopeEvidence[]): Map<string, DependencyScope> {
  const index = new Map<string, DependencyScope>();
  for (const entry of evidence) {
    const key = scopeKey(entry.file, entry.name, entry.version);
    index.set(key, entry.dev && index.get(key) !== "prod" ? "dev" : "prod");
  }
  return index;
}

const LOWER: Record<Severity, Severity> = { critical: "high", high: "medium", medium: "low", low: "low", info: "info" };

export function lowerOneLevel(severity: Severity): Severity {
  return LOWER[severity];
}

function identities(finding: Finding): string[] {
  return [finding.rule_id, ...(finding.vulnerability_aliases ?? [])].map((identity) => identity.toUpperCase());
}

function isMalware(finding: Finding): boolean {
  return identities(finding).some((identity) => identity.startsWith("MAL-")) || finding.cwe.includes("CWE-506");
}

/** A Synvoya advisory, or an upstream finding Synvoya merged with (engines) or enriched (its remediation step). */
function isSynvoyaCurated(finding: Finding): boolean {
  return finding.engines.includes("synvoya") || finding.engine === "synvoya" ||
    finding.remediation.steps.some((step) => /^Synvoya SYN-\d{4}-\d{3,}: /.test(step));
}

/**
 * A merged finding is dev only when its own package version and every one it absorbed in dedup are dev; any
 * other known scope makes it production, and with no evidence at all it has none.
 */
function mergedScope(finding: Finding, scopes: ReadonlyMap<string, DependencyScope>): DependencyScope | undefined {
  const all = [finding.package!, ...absorbedPackages(finding)]
    .map((pkg) => scopes.get(scopeKey(finding.location.file, pkg.name, pkg.version)));
  if (all.every((scope) => scope === "dev")) return "dev";
  return all.some((scope) => scope !== undefined) ? "prod" : undefined;
}

function devTitle(finding: Finding): string {
  const tag = finding.package ? ` (${finding.package.name}@${finding.package.version})` : undefined;
  return tag && finding.title.endsWith(tag) ? `${finding.title.slice(0, -1)}, dev dependency)` : `${finding.title} (dev dependency)`;
}

export interface DependencyScopeResult {
  findings: Finding[];
  lowered: number;
  keptMalware: number;
  keptExploited: number;
  keptSynvoya: number;
  note?: CoverageNote;
}

export function applyDependencyScope(
  findings: Finding[],
  options: { scopes: ReadonlyMap<string, DependencyScope>; exploited?: ReadonlySet<string> },
): DependencyScopeResult {
  const result: DependencyScopeResult = { findings: [], lowered: 0, keptMalware: 0, keptExploited: 0, keptSynvoya: 0 };
  let keptForMissingList = 0;
  for (const finding of findings) {
    const scope = finding.finding_kind === "vulnerability" && finding.package?.name
      ? mergedScope(finding, options.scopes)
      : undefined;
    if (!scope) {
      result.findings.push(finding);
      continue;
    }
    if (scope === "prod") {
      result.findings.push({ ...finding, dependency_scope: "prod" });
      continue;
    }
    const lines = [DEV_SCOPE_NOTE];
    let severity = finding.severity;
    if (lowerOneLevel(severity) !== severity) {
      if (isMalware(finding)) {
        result.keptMalware += 1;
        lines.push("Severity not lowered: malicious package.");
      } else if (options.exploited && identities(finding).some((identity) => options.exploited!.has(identity))) {
        result.keptExploited += 1;
        lines.push("Severity not lowered: known to be exploited.");
      } else if (isSynvoyaCurated(finding)) {
        result.keptSynvoya += 1;
        lines.push("Severity not lowered: Synvoya advisory.");
      } else if (!options.exploited) {
        keptForMissingList += 1;
      } else {
        severity = lowerOneLevel(finding.severity);
        result.lowered += 1;
        lines.push(`Severity lowered from ${finding.severity} to ${severity}: development-only dependency.`);
      }
    }
    result.findings.push({
      ...finding,
      severity,
      dependency_scope: "dev",
      title: devTitle(finding),
      message: `${finding.message}\n${lines.join("\n")}`,
    });
  }
  if (keptForMissingList > 0) {
    result.note = {
      component: SCOPE_NOTE_COMPONENT,
      detail: "Development-only dependency findings kept their severity: the Synvoya dataset, which holds the known-exploited list, could not be loaded.",
    };
  } else if (result.lowered > 0) {
    result.note = {
      component: SCOPE_NOTE_COMPONENT,
      detail: `${result.lowered} development-only dependency finding(s) were lowered one severity level (never below low; malware, known-exploited and Synvoya findings keep theirs).`,
    };
  }
  return result;
}
