/**
 * RubyGems CVE/GHSA aliases for Trivy findings (4.1 M5, Ruling 8).
 *
 * For a Gemfile.lock gem, Trivy reports a ruby-advisory-db advisory under its CVE id while osv-scanner reports
 * the same advisory under its GHSA id, and Trivy's findings carry no aliases, so the package-aware alias graph
 * in dedup could not join them (recheck case C-38: crass 1.0.7, shopify_app 23.0.2). The CVE's `References`
 * name the GHSA. When they name exactly one distinct GHSA (in any URL form), that GHSA becomes the finding's
 * alias; two or more are related advisories, not aliases (rexml CVE-2024-41123), and add nothing. A GHSA that
 * two or more different CVEs of the same lockfile, gem and version would each claim is given to none of them
 * (it would merge two different advisories through the alias graph). Only
 * `Gemfile.lock` / `gems.locked` results from `ruby-advisory-db` with a `CVE-` id are considered. The alias
 * travels as a SARIF result property the normalizer reads; the fingerprint and rule id never change.
 *
 * GHSA ids are written in GitHub's and OSV's canonical form (`GHSA-` then a lower-case body), the form
 * osv-scanner reports, so a merged finding never lists one advisory twice in two cases.
 */

import type { SarifLog } from "../sarif/types.js";

/** SARIF result property the normalizer reads into `vulnerability_aliases`. */
export const TRIVY_ALIASES_PROPERTY = "codeinspectus/aliases";

const GHSA = /GHSA(?:-[0-9a-z]{4}){3}/gi;

/** `GHSA-` + lower-case body: GitHub's and OSV's canonical spelling. */
export function canonicalGhsa(id: string): string {
  return `GHSA${id.slice(4).toLowerCase()}`;
}
const RUBY_LOCKFILE = /^(?:Gemfile\.lock|gems\.locked)$/;

function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => item !== null && typeof item === "object") : [];
}

/** `Target \0 PkgName \0 InstalledVersion \0 VulnerabilityID` → the one GHSA its references name (canonical form). */
export function rubyAdvisoryAliases(report: unknown): Map<string, string[]> {
  const aliases = new Map<string, string[]>();
  const root = report !== null && typeof report === "object" ? report as Record<string, unknown> : {};
  for (const result of records(root.Results)) {
    if (typeof result.Target !== "string") continue;
    if (!RUBY_LOCKFILE.test(result.Target.slice(Math.max(result.Target.lastIndexOf("/"), result.Target.lastIndexOf("\\")) + 1))) continue;
    for (const vulnerability of records(result.Vulnerabilities)) {
      const { VulnerabilityID: id, PkgName: name, InstalledVersion: version } = vulnerability;
      if (typeof id !== "string" || !id.startsWith("CVE-") || typeof name !== "string" || typeof version !== "string") continue;
      const source = vulnerability.DataSource !== null && typeof vulnerability.DataSource === "object"
        ? (vulnerability.DataSource as Record<string, unknown>).ID
        : undefined;
      if (source !== "ruby-advisory-db") continue;
      const references = Array.isArray(vulnerability.References) ? vulnerability.References.filter((ref): ref is string => typeof ref === "string") : [];
      const ghsas = new Set(references.flatMap((ref) => [...ref.matchAll(GHSA)].map((match) => canonicalGhsa(match[0]))));
      if (ghsas.size !== 1) continue;
      aliases.set(`${result.Target}\0${name}\0${version}\0${id}`, [...ghsas]);
    }
  }
  // Claims per (lockfile, gem, version, GHSA): more than one CVE means the GHSA is no alias of either.
  const claims = new Map<string, Set<string>>();
  const claimKey = (key: string, ghsa: string) => `${key.slice(0, key.lastIndexOf("\0"))}\0${ghsa}`;
  for (const [key, [ghsa]] of aliases) {
    const cves = claims.get(claimKey(key, ghsa!)) ?? new Set<string>();
    claims.set(claimKey(key, ghsa!), cves.add(key.slice(key.lastIndexOf("\0") + 1)));
  }
  for (const [key, [ghsa]] of aliases) if (claims.get(claimKey(key, ghsa!))!.size > 1) aliases.delete(key);
  return aliases;
}

/** Writes each vulnerability result's alias property (`Package:` / `Installed Version:` lines, rule id, lockfile). */
export function markAliases(sarif: SarifLog, aliases: Map<string, string[]>): number {
  if (!aliases.size) return 0;
  let marked = 0;
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const uri = result.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
      const text = result.message?.text ?? "";
      const name = /^Package: (\S+)$/m.exec(text)?.[1];
      const version = /^Installed Version: (\S+)$/m.exec(text)?.[1];
      if (typeof uri !== "string" || !name || !version || typeof result.ruleId !== "string") continue;
      const found = aliases.get(`${uri}\0${name}\0${version}\0${result.ruleId}`);
      if (!found) continue;
      result.properties = { ...(result.properties ?? {}), [TRIVY_ALIASES_PROPERTY]: [...found] };
      marked++;
    }
  }
  return marked;
}
