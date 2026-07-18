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
  if (f.engine === "trivy") {
    // Non-secret Trivy findings (SCA CVEs, IaC misconfig, license). Key on the
    // finding's IDENTITY (rule_id) + path, NOT the shared lockfile location, so
    // distinct CVEs never collapse into one. A truly-identical CVE reported twice
    // (same rule_id, same path) still merges to one. Secret Trivy findings took
    // the branch above, so the cross-engine Trivy⨯Gitleaks dedup is untouched.
    return `vuln|${f.location.file}|${f.rule_id}`;
  }
  const cweKey = [...f.cwe].sort().join(",");
  return `general|${range}|${cweKey}`;
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

export interface DedupStats {
  before: number;
  after: number;
  merged: number;
}

export function dedupFindings(findings: Finding[]): { findings: Finding[]; stats: DedupStats } {
  const map = new Map<string, Finding>();
  for (const f of findings) {
    const key = dedupKey(f);
    const existing = map.get(key);
    if (!existing) {
      map.set(key, { ...f, engines: [...f.engines] });
      continue;
    }
    const keep = preferred(existing, f);
    const other = keep === existing ? f : existing;
    const mergedCwe = unionCwes(keep, other);
    const producerComponents = unionProducerComponents(existing, f);
    const merged: Finding = {
      ...keep,
      engines: mergeEngines(existing, f),
      cwe: mergedCwe.length ? mergedCwe : keep.cwe,
      ...(producerComponents ? { producer_components: producerComponents } : {}),
    };
    map.set(key, merged);
  }
  const result = [...map.values()];
  return {
    findings: result,
    stats: { before: findings.length, after: result.length, merged: findings.length - result.length },
  };
}
