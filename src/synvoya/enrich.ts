/**
 * Enrich, never merge (PRD §9.1 rule 3, design §8 item 1).
 *
 * When an upstream engine (osv-scanner, Trivy, native Pub) already reports the advisory a Synvoya package
 * finding reports, the Synvoya finding is dropped and its fix is appended to the upstream finding's
 * remediation steps. Nothing else of the upstream finding changes: its id, fingerprint, engine(s),
 * producer components, severity, title and message stay exactly as the engine produced them, so triage
 * and rescan matching never detach from it. A Synvoya finding stands alone unless an upstream finding in the
 * same file names the same ecosystem, package and version with an intersecting advisory id. Another file
 * never absorbs it: dropping it there would lose its location and, on rescan, read as resolved.
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
    const matches = identity === undefined || aliases.size === 0
      ? []
      : candidates.filter((candidate) =>
          candidate.finding.location.file === finding.location.file &&
          candidate.identity === identity &&
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
