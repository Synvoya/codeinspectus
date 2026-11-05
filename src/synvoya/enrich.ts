/**
 * Enrich, never merge (PRD §9.1 rule 3, design §8 item 1).
 *
 * When an upstream engine (osv-scanner, Trivy, native Pub) already reports the advisory a Synvoya package
 * finding reports, the Synvoya finding is dropped and its fix is appended to the upstream finding's
 * remediation steps. Nothing else of the upstream finding changes: its id, fingerprint, engine(s),
 * producer components, severity, title and message stay exactly as the engine produced them, so triage
 * and rescan matching never detach from it (the kept finding's producers decide its rescan). A Synvoya
 * package finding stands alone unless an upstream finding in the same file names the same ecosystem, package
 * and version with an intersecting advisory id. A Synvoya finding without a package (a product or runtime
 * advisory, e.g. CosmicSting on a Magento lock, a Go release on go.mod) stands alone unless an upstream or SBOM
 * finding in the same file shares one of its advisory aliases (CVE, GHSA, GO id). Another file never absorbs
 * either: dropping it there would lose its location and, on rescan, read as resolved.
 */

import { dedupFindings } from "../dedup.js";
import type { Finding } from "../types.js";
import { packageKey } from "./evaluate.js";

export interface EnrichmentResult {
  /** The upstream findings in input order; an unmatched one is the same object it was. */
  upstream: Finding[];
  /** Synvoya findings no upstream finding reports. */
  standalone: Finding[];
  /**
   * Upstream vulnerabilities that gained a Synvoya fix, counted as the scan reports them: copies that dedup
   * later merges into one finding (Trivy's and osv-scanner's of the same advisory) count once.
   */
  enriched: number;
}

function isUpstreamVulnerability(finding: Finding): boolean {
  return finding.engine !== "synvoya" && finding.package !== undefined && (finding.finding_kind ?? "vulnerability") === "vulnerability";
}

function packageIdentity(finding: Finding): string | undefined {
  const pkg = finding.package;
  if (!pkg || !pkg.ecosystem || !pkg.name || !pkg.version) return undefined;
  return `${packageKey(pkg.ecosystem, pkg.name)}\0${pkg.version.trim()}`;
}

const ids = (values: Iterable<string>): Set<string> => new Set([...values].map((value) => value.trim().toUpperCase()));

/**
 * The same-file rule for osv-scanner findings from the vendored-library SBOM: one that an upstream finding in
 * the same file already reports (same package and version, an intersecting advisory id) is dropped, so the
 * upstream finding stands unchanged; any other stands alone. Another file never absorbs it.
 */
export function foldSbomDuplicates(upstream: readonly Finding[], sbom: readonly Finding[]): { kept: Finding[]; folded: number } {
  // Indexed by file, so the cost is the matches in each file, not every upstream finding per SBOM finding.
  const byFile = new Map<string, Array<{ identity: string; advisories: Set<string> }>>();
  for (const finding of upstream) {
    const identity = isUpstreamVulnerability(finding) ? packageIdentity(finding) : undefined;
    if (identity === undefined) continue;
    const entry = { identity, advisories: ids([finding.rule_id, ...(finding.vulnerability_aliases ?? [])]) };
    const list = byFile.get(finding.location.file);
    if (list) list.push(entry);
    else byFile.set(finding.location.file, [entry]);
  }
  const kept = sbom.filter((finding) => {
    const identity = packageIdentity(finding);
    const advisories = [...ids([finding.rule_id, ...(finding.vulnerability_aliases ?? [])])];
    return !(byFile.get(finding.location.file) ?? []).some((candidate) =>
      candidate.identity === identity && advisories.some((id) => candidate.advisories.has(id)));
  });
  return { kept, folded: sbom.length - kept.length };
}

export function enrichUpstream(upstream: Finding[], synvoya: Finding[]): EnrichmentResult {
  // Steps to append per upstream index, in Synvoya order.
  const additions = new Map<number, string[]>();
  const standalone: Finding[] = [];
  const candidates = upstream.flatMap((finding, index) => {
    const identity = isUpstreamVulnerability(finding) ? packageIdentity(finding) : undefined;
    return identity === undefined ? [] : [{ finding, index, identity, advisories: ids([finding.rule_id, ...(finding.vulnerability_aliases ?? [])]) }];
  });

  for (const finding of synvoya) {
    const identity = finding.engine === "synvoya" ? packageIdentity(finding) : undefined;
    const aliases = ids(finding.vulnerability_aliases ?? []);
    // A package finding must name the same package; one without a package (product, runtime) matches on the
    // shared advisory alone. Either way only in the same file, and only on an alias (never the SYN- rule id).
    const packageless = finding.engine === "synvoya" && finding.package === undefined;
    const matches = aliases.size === 0 || (identity === undefined && !packageless)
      ? []
      : candidates.filter((candidate) =>
          candidate.finding.location.file === finding.location.file &&
          (packageless || candidate.identity === identity) &&
          [...aliases].some((alias) => candidate.advisories.has(alias)));
    if (matches.length === 0) {
      standalone.push(finding);
      continue;
    }
    const steps = [`Synvoya ${finding.rule_id}: ${finding.remediation.summary}`, ...finding.remediation.steps];
    for (const { index } of matches) {
      additions.set(index, [...(additions.get(index) ?? []), ...steps]);
    }
  }

  const enrichedUpstream = upstream.map((finding, index) => {
    const extra = additions.get(index);
    if (!extra) return finding;
    return { ...finding, remediation: { ...finding.remediation, steps: [...new Set([...finding.remediation.steps, ...extra])] } };
  });
  const gained = [...additions.keys()].map((index) => enrichedUpstream[index]!);
  return { upstream: enrichedUpstream, standalone, enriched: dedupFindings(gained).findings.length };
}
