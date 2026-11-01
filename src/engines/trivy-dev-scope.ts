/**
 * Development-dependency scope for Trivy findings (pre-release field validation, item 1).
 *
 * Trivy 0.76.1 drops devDependencies (npm, Yarn, pnpm, Bun) and Composer `packages-dev` unless
 * `--include-dev-deps` is passed; with it, every one of those ecosystems is analysed (verified per
 * ecosystem on the real binary). Its SARIF carries no scope, but its JSON report lists each package
 * with `Dev: true` (`--list-all-pkgs`), so the wrapper writes JSON, converts it to SARIF with
 * `trivy convert`, and marks the SARIF results of development-only packages here. Export schema 3.0.0
 * has no free field on a finding, so the scope reaches the finding as text (see normalize.ts).
 */

import type { SarifLog, SarifResult } from "../sarif/types.js";

/** SARIF result property the normalizer reads. */
export const DEPENDENCY_SCOPE_PROPERTY = "codeinspectus/dependency-scope";

export interface DevScope {
  /** `target\0name\0version` where every package entry with that name and version is dev-only. */
  versions: Set<string>;
  /** `target\0name` where every package entry with that name is dev-only (license results). */
  names: Set<string>;
}

function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => item !== null && typeof item === "object") : [];
}

/** Dev-only packages per lockfile from Trivy's JSON report; anything unreadable is treated as production. */
export function devScopeFromReport(report: unknown): DevScope {
  const versionDev = new Map<string, boolean>();
  const nameDev = new Map<string, boolean>();
  const root = report !== null && typeof report === "object" ? report as Record<string, unknown> : {};
  for (const result of records(root.Results)) {
    if (typeof result.Target !== "string") continue;
    for (const pkg of records(result.Packages)) {
      if (typeof pkg.Name !== "string" || typeof pkg.Version !== "string") continue;
      const dev = pkg.Dev === true;
      const versionKey = `${result.Target}\0${pkg.Name}\0${pkg.Version}`;
      const nameKey = `${result.Target}\0${pkg.Name}`;
      versionDev.set(versionKey, (versionDev.get(versionKey) ?? true) && dev);
      nameDev.set(nameKey, (nameDev.get(nameKey) ?? true) && dev);
    }
  }
  const onlyDev = (map: Map<string, boolean>) => new Set([...map].filter(([, dev]) => dev).map(([key]) => key));
  return { versions: onlyDev(versionDev), names: onlyDev(nameDev) };
}

/**
 * Marks vulnerability results (`Package:` / `Installed Version:` lines) and license results
 * (`PkgName:` line) whose package is development-only in the lockfile they cite.
 */
export function markDevScope(sarif: SarifLog, scope: DevScope): number {
  if (!scope.versions.size && !scope.names.size) return 0;
  let marked = 0;
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const uri = result.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
      const text = result.message?.text ?? "";
      if (typeof uri !== "string") continue;
      const name = /^Package: (\S+)$/m.exec(text)?.[1];
      const version = /^Installed Version: (\S+)$/m.exec(text)?.[1];
      const licensePackage = /^PkgName: (\S+)$/m.exec(text)?.[1];
      const dev = name && version
        ? scope.versions.has(`${uri}\0${name}\0${version}`)
        : licensePackage !== undefined && scope.names.has(`${uri}\0${licensePackage}`);
      if (!dev) continue;
      result.properties = { ...(result.properties ?? {}), [DEPENDENCY_SCOPE_PROPERTY]: "dev" };
      marked++;
    }
  }
  return marked;
}

/**
 * Drops a dev-marked result when a production result in the same run has the same rule and lockfile.
 * Dedup keys Trivy findings on (lockfile, rule id) and would merge the two anyway, but its tiebreak
 * could keep the dev copy and change the production finding's fingerprint (field re-scan: ghostfolio's
 * production undici@7.30.0 lost to a dev undici@7.29.0). The CVE stays reported by the production one.
 */
export function foldDevDuplicates(sarif: SarifLog): number {
  let folded = 0;
  const isDev = (result: SarifResult) => result.properties?.[DEPENDENCY_SCOPE_PROPERTY] === "dev";
  const key = (result: SarifResult) => `${result.locations?.[0]?.physicalLocation?.artifactLocation?.uri}\0${result.ruleId}`;
  for (const run of sarif.runs ?? []) {
    if (!run.results) continue;
    const production = new Set(run.results.filter((result) => !isDev(result)).map(key));
    const kept = run.results.filter((result) =>
      !isDev(result) || typeof result.ruleId !== "string" || !production.has(key(result)));
    folded += run.results.length - kept.length;
    run.results = kept;
  }
  return folded;
}
