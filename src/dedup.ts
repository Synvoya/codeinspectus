/**
 * Dedup layer (PRD §4.4, §5).
 *
 * Secret overlap (Trivy ⨯ Gitleaks): both engines flag hard-coded secrets and
 * WILL overlap. Dedup secrets on (normalized path + line range + SHA256 of the
 * matched secret value). Prefer the Gitleaks finding (richer secret-type
 * metadata); keep whichever has higher confidence/severity otherwise.
 *
 * Global dedup: merge non-secret findings on (normalized path + line range +
 * CWE set). The merged finding always carries every engine that reported it.
 *
 * Trivy SCA/IaC/license findings are the exception (CG-05): Trivy reports many
 * DISTINCT dependency CVEs at the SAME lockfile location (e.g. pnpm-lock.yaml:1)
 * with the same fallback CWE, so the location+CWE key would collapse ~180 real
 * CVEs into a handful — a dangerous under-report for a security tool. Those dedup
 * on the vulnerability IDENTITY (rule_id = CVE/GHSA/advisory/check id) + path.
 */

import type { Finding, Engine } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

const CONFIDENCE_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };
const SECRET_ENGINE_PREFERENCE: Record<string, number> = {
  gitleaks: 3,
  "codeinspectus-ai": 2,
  trivy: 1,
  opengrep: 0,
};

export function dedupKey(f: Finding): string {
  const range = `${f.location.file}:${f.location.start_line}-${f.location.end_line}`;
  if (f.is_secret) {
    // Secret overlap (PRD §4.4): dedup on (normalized path + line range + secret
    // value hash). Trivy REDACTS the value, so its findings carry no hash; to
    // still merge the Trivy⨯Gitleaks overlap, key on location and treat a
    // hash-less finding at the same path+line as the same secret. (Two distinct
    // secrets on one identical line is a rare, accepted collision.)
    return `secret|${range}`;
  }
  if (f.finding_kind === "vulnerability" || f.engine === "trivy" || f.engine === "codeinspectus-pub") {
    // Vulnerability findings (external or first-party SCA). Key on the
    // finding's IDENTITY (rule_id) + path, NOT the shared lockfile location, so
    // distinct CVEs never collapse into one. A truly-identical CVE reported twice
    // (same rule_id, same path) still merges to one. Secret Trivy findings took
    // the branch above, so the cross-engine Trivy⨯Gitleaks dedup is untouched.
    const identities = [f.rule_id, ...(f.vulnerability_aliases ?? [])]
      .map((identity) => identity.toUpperCase())
      .filter((identity, index, all) => all.indexOf(identity) === index)
      .sort((left, right) => {
        const rank = (identity: string) => identity.startsWith("CVE-") ? 0
          : identity.startsWith("GHSA-") ? 1
            : 2;
        return rank(left) - rank(right) || left.localeCompare(right);
      });
    return `vuln|${f.location.file}|${identities[0] ?? f.rule_id}`;
  }
  const cweKey = [...f.cwe].sort().join(",");
  return `general|${range}|${cweKey}`;
}

function vulnerabilityIdentities(f: Finding): string[] {
  return [f.rule_id, ...(f.vulnerability_aliases ?? [])]
    .map((identity) => identity.toUpperCase())
    .filter((identity, index, all) => all.indexOf(identity) === index);
}

/** All stable cross-scan identities for one finding, including every vulnerability alias. */
export function dedupIdentityKeys(f: Finding): string[] {
  if (
    !f.is_secret &&
    (f.finding_kind === "vulnerability" || f.engine === "trivy" || f.engine === "codeinspectus-pub")
  ) {
    return vulnerabilityIdentities(f).map(
      (identity) => `vuln|${f.location.file}|${identity}`,
    );
  }
  return [dedupKey(f)];
}

function identityRank(identity: string): number {
  return identity.startsWith("CVE-") ? 0 : identity.startsWith("GHSA-") ? 1 : 2;
}

/**
 * Build alias-connected keys before merging. A Pub finding can carry both a
 * GHSA and CVE while Trivy may report either identity. Picking only one ID per
 * finding would miss the other representation; unioning the identity graph
 * makes both bridge cases deterministic.
 */
function vulnerabilityGroupKeys(findings: readonly Finding[]): Map<number, string> {
  const parent = new Map<string, string>();
  const find = (value: string): string => {
    const current = parent.get(value);
    if (!current) {
      parent.set(value, value);
      return value;
    }
    if (current === value) return value;
    const root = find(current);
    parent.set(value, root);
    return root;
  };
  const union = (left: string, right: string): void => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot === rightRoot) return;
    // Stable root selection prevents input order from affecting group keys.
    if (leftRoot < rightRoot) parent.set(rightRoot, leftRoot);
    else parent.set(leftRoot, rightRoot);
  };

  const tokensByFinding = new Map<number, string[]>();
  findings.forEach((finding, index) => {
    if (finding.finding_kind !== "vulnerability") return;
    const tokens = vulnerabilityIdentities(finding).map(
      (identity) => `${finding.location.file}\0${identity}`,
    );
    if (!tokens.length) return;
    tokensByFinding.set(index, tokens);
    for (const token of tokens) find(token);
    for (const token of tokens.slice(1)) union(tokens[0]!, token);
  });

  const identitiesByRoot = new Map<string, Set<string>>();
  for (const tokens of tokensByFinding.values()) {
    for (const token of tokens) {
      const root = find(token);
      const identities = identitiesByRoot.get(root) ?? new Set<string>();
      identities.add(token.slice(token.indexOf("\0") + 1));
      identitiesByRoot.set(root, identities);
    }
  }

  const keys = new Map<number, string>();
  for (const [index, tokens] of tokensByFinding) {
    const root = find(tokens[0]!);
    const identities = [...(identitiesByRoot.get(root) ?? [])].sort(
      (left, right) => identityRank(left) - identityRank(right) || left.localeCompare(right),
    );
    keys.set(index, `vuln|${findings[index]!.location.file}|${identities[0]}`);
  }
  return keys;
}

/** Decide which of two findings for the same key is the keeper. */
function preferred(a: Finding, b: Finding): Finding {
  // Severity wins FIRST — a merge must never lower severity (CG-23 A3-3). Otherwise a
  // Gitleaks `high` secret (un-classifiable as live once --redact hides the value) would
  // mask the AI client-secret check's `critical` at the same location.
  const sevDelta = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (sevDelta !== 0) return sevDelta > 0 ? a : b;
  // At equal severity, prefer the engine with richer secret-type metadata (Gitleaks).
  if (a.is_secret && b.is_secret) {
    const ap = SECRET_ENGINE_PREFERENCE[a.engine] ?? 0;
    const bp = SECRET_ENGINE_PREFERENCE[b.engine] ?? 0;
    if (ap !== bp) return ap > bp ? a : b;
  }
  // Then higher confidence.
  const confDelta = (CONFIDENCE_RANK[a.confidence] ?? 0) - (CONFIDENCE_RANK[b.confidence] ?? 0);
  if (confDelta !== 0) return confDelta > 0 ? a : b;
  // Final DETERMINISTIC tiebreak (CG-75 / Claim 1): when severity, secret-engine preference and
  // confidence all tie — e.g. two Gitleaks rules matching one secret at the same location — pick
  // by fingerprint so the SAME representative is kept regardless of engine output order. Without
  // this the surviving fingerprint (which includes rule_id) flips run-to-run and a like-for-like
  // rescan falsely reports the finding resolved+introduced. Severity still wins first (above), so
  // this never lowers severity.
  if (a.fingerprint !== b.fingerprint) return a.fingerprint < b.fingerprint ? a : b;
  return a;
}

function mergeEngines(a: Finding, b: Finding): Engine[] {
  return [...new Set<Engine>([...a.engines, ...b.engines])];
}

function unionCwes(a: Finding, b: Finding): string[] {
  return [...new Set<string>([...a.cwe, ...b.cwe])].filter((c) => c !== "CWE-noinfo");
}

function unionProducerComponents(a: Finding, b: Finding): string[] | undefined {
  const components = [...new Set([...(a.producer_components ?? []), ...(b.producer_components ?? [])])].sort();
  return components.length ? components : undefined;
}

function unionVulnerabilityAliases(a: Finding, b: Finding): string[] | undefined {
  const aliases = [...new Set([
    ...(a.vulnerability_aliases ?? []),
    ...(b.vulnerability_aliases ?? []),
    ...(a.finding_kind === "vulnerability" ? [a.rule_id] : []),
    ...(b.finding_kind === "vulnerability" ? [b.rule_id] : []),
  ])].sort();
  return aliases.length ? aliases : undefined;
}

export interface DedupStats {
  before: number;
  after: number;
  merged: number;
}

export function dedupFindings(findings: Finding[]): { findings: Finding[]; stats: DedupStats } {
  const map = new Map<string, Finding>();
  const vulnerabilityKeys = vulnerabilityGroupKeys(findings);
  for (const [index, f] of findings.entries()) {
    const key = vulnerabilityKeys.get(index) ?? dedupKey(f);
    const existing = map.get(key);
    if (!existing) {
      map.set(key, { ...f, engines: [...f.engines] });
      continue;
    }
    const keep = preferred(existing, f);
    const other = keep === existing ? f : existing;
    const mergedCwe = unionCwes(keep, other);
    const producerComponents = unionProducerComponents(existing, f);
    const vulnerabilityAliases = unionVulnerabilityAliases(existing, f);
    const merged: Finding = {
      ...keep,
      engines: mergeEngines(existing, f),
      cwe: mergedCwe.length ? mergedCwe : keep.cwe,
      ...(producerComponents ? { producer_components: producerComponents } : {}),
      ...(vulnerabilityAliases ? { vulnerability_aliases: vulnerabilityAliases } : {}),
    };
    map.set(key, merged);
  }
  const result = [...map.values()];
  return {
    findings: result,
    stats: { before: findings.length, after: result.length, merged: findings.length - result.length },
  };
}
