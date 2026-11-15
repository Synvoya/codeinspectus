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
 *
 * Package-aware: when a vulnerability finding names its package (osv-scanner, Trivy, native Pub),
 * the normalized package name is part of the key. One advisory can affect two packages locked in the
 * same file (Brotli and brotlicffi share CVE-2026-111497 in one requirements.txt); those are two
 * findings. The ecosystem is never part of the key, so Trivy's best-effort ecosystem cannot keep it
 * from merging with osv-scanner's.
 *
 * Version-aware (4.1): when the package's version is known, it is part of the key too, so one advisory on
 * two locked versions of one package (semver 5.7.1 nested under a dev tool, 7.5.1 at the top level) is two
 * findings with their own location, remediation and dependency scope. A finding without a version joins the
 * package's one known version in that file (several known versions: it stays apart). A leading `v` before a
 * digit is ignored. Cross-scan identity keys stay version-free, so an upgraded package that still has the
 * advisory reads remaining, as before.
 *
 * One finding per secret (4.1): after the key pass, a secret candidate whose line range lies inside a
 * private-key block's range in the same file is the same secret as that block (Gitleaks 1-30 and Trivy 2-29
 * on one PEM key; a native check on a line of a Gitleaks key block), unless both carry a known value hash and
 * they differ. Clusters are formed by union-find; the survivor is the `preferred()` maximum.
 */

import { mergeFixedVersions } from "./upgrade-actions.js";
import type { Finding, Engine, FindingPackage } from "./types.js";
import { SEVERITY_RANK } from "./types.js";
import { normalizePackageName } from "./osv/ecosystems.js";
import { DEDUP_COMPONENT } from "./provenance.js";

const CONFIDENCE_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };
const SECRET_ENGINE_PREFERENCE: Record<string, number> = {
  gitleaks: 3,
  "codeinspectus-ai": 2,
  trivy: 1,
  opengrep: 0,
};

/**
 * The file, plus the normalized package name when the finding names one (and `packageAware`). NUL-separated,
 * because a file path may itself contain `|`.
 */
function vulnerabilityScope(f: Finding, packageAware = true): string {
  // A Synvoya runtime, image or product finding names no package, and the evaluator already emits one finding
  // per (advisory, file, subject), which its fingerprint encodes. Advisories share aliases across subjects
  // (Node.js and .NET both list the Brotli CVE), so the file alone would merge two different exposures.
  if (f.engine === "synvoya" && !f.package?.name) return `${f.location.file}\0${f.rule_id}\0${f.fingerprint}`;
  const name = packageAware && f.package?.name ? normalizePackageName(f.package.name) : undefined;
  return name === undefined ? f.location.file : `${f.location.file}\0${name}`;
}

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
    return `vuln|${vulnerabilityScope(f)}|${identities[0] ?? f.rule_id}`;
  }
  const cweKey = [...f.cwe].sort().join(",");
  return `general|${range}|${cweKey}`;
}

const normalizeVersion = (version: string): string => version.replace(/^v(?=\d)/, "");

/**
 * Per finding index, the version part of its vulnerability scope: its own normalized version, or for a finding
 * without one the single version other findings know for that package in that file ("" when none or several).
 * Only findings that name a package get one.
 */
function versionTags(findings: readonly Finding[]): Map<number, string> {
  const known = new Map<string, Set<string>>();
  findings.forEach((finding) => {
    if (finding.finding_kind !== "vulnerability" || !finding.package?.name || !finding.package.version) return;
    const scope = vulnerabilityScope(finding);
    known.set(scope, (known.get(scope) ?? new Set()).add(normalizeVersion(finding.package.version)));
  });
  const tags = new Map<number, string>();
  findings.forEach((finding, index) => {
    if (finding.finding_kind !== "vulnerability" || !finding.package?.name) return;
    if (finding.package.version) {
      tags.set(index, normalizeVersion(finding.package.version));
      return;
    }
    const versions = known.get(vulnerabilityScope(finding));
    tags.set(index, versions?.size === 1 ? [...versions][0]! : "");
  });
  return tags;
}

/**
 * Packages (other than the survivor's own) a merged finding absorbed, kept for the dependency-scope pass: a
 * merged finding is development-only only if every package version it absorbed is. An enumerable symbol, so
 * object spreads keep it while JSON (storage, MCP and CLI output) never carries it. Set only when an absorbed
 * package differs from the survivor's (name or version after normalization).
 */
const ABSORBED_PACKAGES = Symbol("codeinspectus.dedup.absorbedPackages");
type WithAbsorbed = Finding & { [ABSORBED_PACKAGES]?: FindingPackage[] };

export function absorbedPackages(finding: Finding): readonly FindingPackage[] {
  return (finding as WithAbsorbed)[ABSORBED_PACKAGES] ?? [];
}

function packageIdentity(pkg: FindingPackage): string {
  return `${normalizePackageName(pkg.name)}\0${normalizeVersion(pkg.version)}`;
}

function vulnerabilityIdentities(f: Finding): string[] {
  return [f.rule_id, ...(f.vulnerability_aliases ?? [])]
    .map((identity) => identity.toUpperCase())
    .filter((identity, index, all) => all.indexOf(identity) === index);
}

/**
 * Line-independent content anchors for cross-scan matching. A finding whose code is unchanged but
 * moved (lines inserted above it) keeps the same file, rule, CWE, secret-value hash and normalized
 * snippet, so it must not read as resolved + introduced. The occurrence index (in line order)
 * preserves multiplicity: a duplicated vulnerable line still counts as a new occurrence.
 * Findings with neither a snippet nor a secret-value hash get no anchor.
 */
export function contentAnchors(findings: readonly Finding[]): Map<Finding, string> {
  const anchors = new Map<Finding, string>();
  const occurrences = new Map<string, number>();
  const ordered = [...findings].sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    left.location.start_line - right.location.start_line ||
    left.location.end_line - right.location.end_line);
  for (const finding of ordered) {
    // A secret's value hash is itself line-independent; its context window is not.
    const snippet = finding.secret_value_hash ? "" : finding.location.snippet?.replace(/\s+/g, " ").trim() ?? "";
    if (!snippet && !finding.secret_value_hash) continue;
    const base = [finding.location.file, finding.rule_id, [...finding.cwe].sort().join(","), finding.secret_value_hash ?? "", snippet].join("\u0000");
    const index = occurrences.get(base) ?? 0;
    occurrences.set(base, index + 1);
    anchors.set(finding, `${base}\u0000${index}`);
  }
  return anchors;
}

/**
 * Pair findings that only moved lines. Anchors are computed over the findings each side left
 * unmatched by the exact (fingerprint / dedup-identity) pass, so within this pass an unchanged
 * identical occurrence cannot absorb a genuinely new or fixed one. The exact pass itself is
 * location-keyed and has its own known limits (see the audit backlog). Returns fresh → prior (1:1).
 */
export function pairMovedFindings(priorUnmatched: readonly Finding[], freshUnmatched: readonly Finding[]): Map<Finding, Finding> {
  const priorByAnchor = new Map<string, Finding>();
  for (const [finding, anchor] of contentAnchors(priorUnmatched)) priorByAnchor.set(anchor, finding);
  const pairs = new Map<Finding, Finding>();
  for (const [finding, anchor] of contentAnchors(freshUnmatched)) {
    const prior = priorByAnchor.get(anchor);
    if (prior) pairs.set(finding, prior);
  }
  return pairs;
}

/**
 * All stable cross-scan identities for one finding, including every vulnerability alias. A
 * vulnerability's keys include its normalized package name unless `packageAware` is false.
 */
export function dedupIdentityKeys(f: Finding, packageAware = true): string[] {
  if (
    !f.is_secret &&
    (f.finding_kind === "vulnerability" || f.engine === "trivy" || f.engine === "codeinspectus-pub")
  ) {
    return vulnerabilityIdentities(f).map(
      (identity) => `vuln|${vulnerabilityScope(f, packageAware)}|${identity}`,
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
  const tags = versionTags(findings);
  const scopeOf = (index: number): string => {
    const tag = tags.get(index);
    return tag === undefined ? vulnerabilityScope(findings[index]!) : `${vulnerabilityScope(findings[index]!)}\0v=${tag}`;
  };
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
    // `<vulnerabilityScope> [\0 v=<version>] \0 identity`: package-aware and version-aware.
    const scope = scopeOf(index);
    const tokens = vulnerabilityIdentities(finding).map((identity) => `${scope}\0${identity}`);
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
      identities.add(token.slice(token.lastIndexOf("\0") + 1));
      identitiesByRoot.set(root, identities);
    }
  }

  const keys = new Map<number, string>();
  for (const [index, tokens] of tokensByFinding) {
    const root = find(tokens[0]!);
    const identities = [...(identitiesByRoot.get(root) ?? [])].sort(
      (left, right) => identityRank(left) - identityRank(right) || left.localeCompare(right),
    );
    keys.set(index, `vuln|${scopeOf(index)}|${identities[0]}`);
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

/** Merge `other` into `keep` (the `preferred()` of `existing` and `incoming`): the one merge body both passes use. */
function mergeFindings(keep: Finding, other: Finding, existing: Finding, incoming: Finding): Finding {
  const mergedCwe = unionCwes(keep, other);
  const producerComponents = unionProducerComponents(existing, incoming);
  const vulnerabilityAliases = unionVulnerabilityAliases(existing, incoming);
  const pkg = keep.package ?? other.package;
  // Fix round 2: per release line, the highest of each engine's minimum fix.
  const fixedVersions = mergeFixedVersions(pkg?.ecosystem ?? "", keep.fixed_versions ?? [], other.fixed_versions ?? []);
  const merged: Finding = {
    ...keep,
    engines: mergeEngines(existing, incoming),
    cwe: mergedCwe.length ? mergedCwe : keep.cwe,
    ...(producerComponents ? { producer_components: producerComponents } : {}),
    ...(vulnerabilityAliases ? { vulnerability_aliases: vulnerabilityAliases } : {}),
    ...(pkg ? { package: pkg } : {}),
    ...(fixedVersions.length ? { fixed_versions: fixedVersions } : {}),
  };
  const own = pkg ? packageIdentity(pkg) : undefined;
  const absorbed = new Map<string, FindingPackage>();
  for (const candidate of [existing.package, incoming.package, ...absorbedPackages(existing), ...absorbedPackages(incoming)]) {
    if (!candidate) continue;
    const identity = packageIdentity(candidate);
    if (identity !== own && !absorbed.has(identity)) absorbed.set(identity, candidate);
  }
  if (absorbed.size) (merged as WithAbsorbed)[ABSORBED_PACKAGES] = [...absorbed.values()];
  else delete (merged as WithAbsorbed)[ABSORBED_PACKAGES];
  return merged;
}

/** A finding about a hard-coded secret: `is_secret`, or CWE-798 outside dependency and licence findings. */
export function isSecretCandidate(f: Finding): boolean {
  return f.is_secret === true ||
    (f.cwe.includes("CWE-798") && f.finding_kind !== "vulnerability" && f.finding_kind !== "license");
}

/** A secret candidate that spans a private key's lines (Gitleaks/Trivy `private-key`, ...). */
export function isPrivateKeyBlock(f: Finding): boolean {
  return isSecretCandidate(f) && /private[-_]?key/i.test(f.rule_id) && f.location.end_line > f.location.start_line;
}

function within(inner: Finding, block: Finding): boolean {
  return inner.location.start_line >= block.location.start_line && inner.location.end_line <= block.location.end_line;
}

/**
 * Whether two secret candidates in one file are the same secret: one is a private-key block whose line range
 * contains the other's, and their value hashes, when both are known, are equal.
 */
export function sameSecretByContainment(a: Finding, b: Finding): boolean {
  if (a === b || a.location.file !== b.location.file) return false;
  if (!isSecretCandidate(a) || !isSecretCandidate(b)) return false;
  if (a.secret_value_hash && b.secret_value_hash && a.secret_value_hash !== b.secret_value_hash) return false;
  return (isPrivateKeyBlock(a) && within(b, a)) || (isPrivateKeyBlock(b) && within(a, b));
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** A canonical order of findings, so the cluster pass never depends on input order. */
function canonicalOrder(left: Finding, right: Finding): number {
  return compareText(left.fingerprint, right.fingerprint) ||
    left.location.start_line - right.location.start_line ||
    left.location.end_line - right.location.end_line ||
    compareText(left.rule_id, right.rule_id) ||
    compareText(left.engine, right.engine) ||
    compareText(left.secret_value_hash ?? "", right.secret_value_hash ?? "") ||
    compareText(left.title, right.title) ||
    compareText(left.message, right.message);
}

/**
 * The containment pass. Per file, candidates are unioned with each private-key block that contains them, in a
 * canonical order; a union that would join two different known values (through a hash-less block) is skipped,
 * so one block never ties two different secrets together. Each cluster folds into its `preferred()` maximum.
 */
function mergeContainedSecrets(findings: Finding[]): Finding[] {
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (!isSecretCandidate(finding)) continue;
    const list = byFile.get(finding.location.file);
    if (list) list.push(finding);
    else byFile.set(finding.location.file, [finding]);
  }
  const parent = new Map<Finding, Finding>();
  const hashes = new Map<Finding, Set<string>>();
  const find = (finding: Finding): Finding => {
    let root = finding;
    while (parent.get(root) !== root) root = parent.get(root)!;
    parent.set(finding, root);
    return root;
  };
  let joined = false;
  for (const candidates of byFile.values()) {
    if (candidates.length < 2 || !candidates.some(isPrivateKeyBlock)) continue;
    candidates.sort(canonicalOrder);
    for (const finding of candidates) {
      parent.set(finding, finding);
      hashes.set(finding, new Set(finding.secret_value_hash ? [finding.secret_value_hash] : []));
    }
    for (const block of candidates.filter(isPrivateKeyBlock)) {
      for (const other of candidates) {
        if (!sameSecretByContainment(block, other)) continue;
        const left = find(block);
        const right = find(other);
        if (left === right) continue;
        const merged = new Set([...hashes.get(left)!, ...hashes.get(right)!]);
        if (merged.size > 1) continue;
        // The root is the earlier finding in canonical order, so roots never depend on input order.
        const [root, child] = canonicalOrder(left, right) <= 0 ? [left, right] : [right, left];
        parent.set(child, root);
        hashes.set(root, merged);
        joined = true;
      }
    }
  }
  if (!joined) return findings;

  const clusters = new Map<Finding, Finding[]>();
  for (const finding of findings) {
    if (!parent.has(finding)) continue;
    const root = find(finding);
    const members = clusters.get(root);
    if (members) members.push(finding);
    else clusters.set(root, [finding]);
  }
  const result: Finding[] = [];
  for (const finding of findings) {
    if (!parent.has(finding)) {
      result.push(finding);
      continue;
    }
    const members = clusters.get(find(finding))!;
    if (members[0] !== finding) continue; // emitted once, where its first member stood
    if (members.length === 1) {
      result.push(finding);
      continue;
    }
    const ordered = [...members].sort(canonicalOrder);
    const survivor = ordered.reduce((best, candidate) => preferred(best, candidate));
    let merged: Finding = { ...survivor, engines: [...survivor.engines] };
    for (const other of ordered) {
      if (other === survivor) continue;
      merged = mergeFindings(merged, other, merged, other);
    }
    result.push(merged);
  }
  return result;
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
    map.set(key, mergeFindings(keep, other, existing, f));
  }
  const result = mergeContainedSecrets([...map.values()]);
  return {
    findings: result,
    stats: { before: findings.length, after: result.length, merged: findings.length - result.length },
  };
}

export interface FindingsMatchOptions {
  /**
   * Allow the private-key containment match (a pre-4.1 older scan held separately what 4.1 merged). Off by
   * default; callers derive it from both scans with `secretContainmentAgainst(older, newer)`.
   */
  secretContainment?: boolean;
}

type SignedScan = { component_signatures?: Readonly<Record<string, string>> };

/**
 * The match options for comparing `newer` against `older`: containment only when the older scan predates the
 * 4.1 dedup marker and the newer one carries it (only a 4.1 scan holds the merged survivors it bridges).
 */
export function secretContainmentAgainst(older: SignedScan, newer: SignedScan): FindingsMatchOptions {
  return { secretContainment: !older.component_signatures?.[DEDUP_COMPONENT] && Boolean(newer.component_signatures?.[DEDUP_COMPONENT]) };
}

/**
 * A pre-4.1 scan stored a private key twice (Gitleaks 1-30, Trivy 2-29) where 4.1 keeps one merged survivor.
 * The older finding matches only when it is a single-engine private-key finding, the newer one is a merged
 * survivor carrying its engine, both are secret candidates in one file with compatible value hashes, and one
 * range contains the other: the survivor's lines contain the older finding's (Trivy 2-29 absorbed by Gitleaks
 * 1-30), or the older key block's lines contain the survivor's (a Gitleaks block 645-648 absorbed by a native
 * finding at 645). The reverse direction also needs the survivor's own value hash (a native secret finding), so
 * an engine-only token that merely sits inside an old key block never matches it.
 */
function absorbedKeyBlock(older: Finding, newer: Finding): boolean {
  if (older.location.file !== newer.location.file) return false;
  if (!isSecretCandidate(older) || !isSecretCandidate(newer)) return false;
  if (older.engines.length !== 1 || !/private[-_]?key/i.test(older.rule_id)) return false;
  if (newer.engines.length < 2 || !newer.engines.includes(older.engines[0]!)) return false;
  const contains = (outer: Finding, inner: Finding) =>
    outer.location.start_line <= inner.location.start_line && outer.location.end_line >= inner.location.end_line;
  return contains(newer, older) || (contains(older, newer) && Boolean(newer.secret_value_hash));
}

/**
 * Whether two findings from different scans are the same issue. Beyond an exact fingerprint, a
 * shared dedup-identity key (location/CWE, secret location, or vulnerability identity) matches only
 * when it cannot hide a different issue: two known secret values must be equal, and a location key
 * also needs a producing engine in common (the dedup-survivor flip keeps its merged engines).
 */
export function findingsMatch(left: Finding, right: Finding, options: FindingsMatchOptions = {}): boolean {
  if (left.fingerprint === right.fingerprint) return true;
  if (left.secret_value_hash && right.secret_value_hash && left.secret_value_hash !== right.secret_value_hash) return false;
  // `left` is the older finding. A pre-4.1 scan that held a key-block duplicate separately reads it as still
  // present in the 4.1 survivor (M5 fix round 2: only then, and only in that direction).
  if (options.secretContainment && absorbedKeyBlock(left, right)) return true;
  // A scan stored before vulnerability findings named their package keys on path + identity only;
  // comparing that with a package-aware key would read every such finding as resolved + introduced.
  const packageAware = Boolean(left.package?.name) === Boolean(right.package?.name);
  const keys = new Set(dedupIdentityKeys(left, packageAware));
  const shared = dedupIdentityKeys(right, packageAware).filter((key) => keys.has(key));
  if (!shared.length) return false;
  if (shared.some((key) => key.startsWith("vuln|"))) return true;
  return left.engines.some((engine) => right.engines.includes(engine));
}
