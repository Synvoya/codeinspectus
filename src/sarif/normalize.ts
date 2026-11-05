/**
 * SARIF 2.1.0 → CWE-keyed internal Finding[] (PRD §5).
 *
 * Per engine: resolve each result's rule, extract CWE(s) (assigning CWE-798 for
 * Gitleaks which has no CWE field, §4.2), normalize severity, redact secret
 * values, and compute a stable fingerprint for rescan diffing. Framework tags
 * and OWASP crosswalks are added later by the compliance mapper.
 */

import type { Engine, Finding, Confidence, FindingKind, FindingPackage } from "../types.js";
import type { EngineOutput } from "../engines/types.js";
import type { SarifLog, SarifRule, SarifResult, SarifProps } from "./types.js";
import { normalizeSeverity } from "../severity.js";
import { findSecret, hashSecret, redactSecretText } from "../redact.js";
import { recordGitleaksMatchEnd } from "../secret-match-key.js";
import { dependencyRemediation, remediationForCwe } from "../remediation.js";
import { fingerprint as fp } from "../util/hash.js";
import { externalFindingComponents } from "../provenance.js";
import { osvEcosystemForFile } from "../osv/ecosystems.js";
import { DEPENDENCY_SCOPE_PROPERTY, DEV_SCOPE_NOTE } from "../engines/trivy-dev-scope.js";
import { compareVersions } from "../synvoya/versions.js";

const CWE_RE = /CWE[-_ ]?(\d{1,5})/gi;
const OWASP_WEB_RE = /OWASP[-_ ]?(A\d{2}:\d{4})/gi;

const OWASP_API_BY_RULE: Record<string, string[]> = {
  "ci-baseline-cors-wildcard-credentials": ["API8:2023"],
  "ci-baseline-cors-arbitrary-origin-credentials": ["API8:2023"],
};

function extractCwes(...sources: Array<string | string[] | undefined>): string[] {
  const out = new Set<string>();
  for (const src of sources) {
    if (!src) continue;
    const text = Array.isArray(src) ? src.join(" ") : src;
    for (const m of text.matchAll(CWE_RE)) {
      out.add(`CWE-${m[1]}`);
    }
  }
  return [...out];
}

function extractOwaspWeb(...sources: Array<string | string[] | undefined>): string[] {
  const out = new Set<string>();
  for (const source of sources) {
    if (!source) continue;
    const text = Array.isArray(source) ? source.join(" ") : source;
    for (const match of text.matchAll(OWASP_WEB_RE)) {
      if (match[1]) out.add(match[1]);
    }
  }
  return [...out];
}

function normalizePath(uri: string | undefined, target: string): string {
  if (!uri) return "(unknown)";
  let p = uri;
  if (p.startsWith("file://")) {
    try {
      p = decodeURIComponent(new URL(p).pathname);
    } catch {
      p = p.slice("file://".length);
    }
  }
  p = p.replace(/\\/g, "/");
  // URL.pathname represents a Windows file URI as /C:/path. Strip only that
  // synthetic leading slash; a real POSIX absolute path must keep its root.
  if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1);

  const normalizedTarget = target.replace(/\\/g, "/");
  const windowsStyle = /^(?:[A-Za-z]:\/|\/\/)/;
  const caseInsensitive = windowsStyle.test(p) && windowsStyle.test(normalizedTarget);
  const comparablePath = caseInsensitive ? p.toLowerCase() : p;
  const comparableTarget = caseInsensitive ? normalizedTarget.toLowerCase() : normalizedTarget;
  if (comparablePath === comparableTarget) {
    // A direct file scan must converge with first-party analyzers, which report the target's
    // basename. SARIF engines vary between absolute-target and basename URIs for the same file.
    return p.slice(p.lastIndexOf("/") + 1) || ".";
  }

  const targetPrefix = comparableTarget.endsWith("/") ? comparableTarget : comparableTarget + "/";
  if (comparablePath.startsWith(targetPrefix)) {
    return p.slice(targetPrefix.length);
  }
  return p;
}

function ruleFor(result: SarifResult, rules: SarifRule[]): SarifRule | undefined {
  if (result.ruleId) {
    const byId = rules.find((r) => r.id === result.ruleId);
    if (byId) return byId;
  }
  if (typeof result.ruleIndex === "number" && rules[result.ruleIndex]) {
    return rules[result.ruleIndex];
  }
  return undefined;
}

function precisionToConfidence(props: SarifProps | undefined, isSecret: boolean): Confidence {
  if (isSecret) return "high";
  // Authored rule confidence is the primary signal. Some SARIF producers emit a generic
  // `precision: high`; that must not silently upgrade an explicitly MEDIUM/LOW rule.
  const explicit = typeof props?.confidence === "string" ? props.confidence.toLowerCase() : "";
  if (/^(?:very-high|high)$/.test(explicit)) return "high";
  if (explicit === "medium") return "medium";
  if (explicit === "low") return "low";
  const tagConfidence = (props?.tags ?? []).find((tag) => /\b(?:high|medium|low)\s+confidence\b/i.test(tag)) ?? "";
  const normalizedTag = tagConfidence.toLowerCase();
  if (/\b(?:very-high|high)\s+confidence\b/.test(normalizedTag)) return "high";
  if (/\bmedium\s+confidence\b/.test(normalizedTag)) return "medium";
  if (/\blow\s+confidence\b/.test(normalizedTag)) return "low";
  const prec = `${props?.precision ?? ""}`.toLowerCase();
  if (prec === "very-high" || prec === "high") return "high";
  if (/\b(?:very-high|high)(?:\s+confidence)?\b/.test(prec)) return "high";
  if (/\blow(?:\s+confidence)?\b/.test(prec)) return "low";
  return "medium";
}

function firstSentence(s: string, max = 100): string {
  const t = s.trim().replace(/\s+/g, " ");
  const dot = t.indexOf(". ");
  const sentence = dot > 0 ? t.slice(0, dot + 1) : t;
  return sentence.length > max ? sentence.slice(0, max).trimEnd() + "…" : sentence;
}

function deriveTitle(
  shortDesc: string | undefined,
  name: string | undefined,
  message: string,
  rawRuleId: string,
  ruleId: string,
  isSecret: boolean,
): string {
  // Opengrep emits a generic "Opengrep Finding: <id>" shortDescription — skip it.
  if (shortDesc && !shortDesc.startsWith("Opengrep Finding:")) return shortDesc;
  if (name && name !== rawRuleId) return name;
  if (isSecret) return "Hard-coded secret";
  if (message && message !== rawRuleId && message !== ruleId) return firstSentence(message);
  return ruleId;
}

function isSecretFinding(engine: Engine, rule: SarifRule | undefined, ruleId: string, snippet: string): boolean {
  if (engine === "gitleaks") return true;
  // This bundled Opengrep surface is SAST-only. A rule can discuss credentialed
  // requests (for example CORS `credentials: true`) without detecting a credential
  // value. Treating that word as a secret signal misclassifies the finding.
  if (engine === "opengrep") return Boolean(findSecret(snippet));
  // A Trivy license result's rule id is `<package>:<license>`, so a package named like
  // `passport-headerapikey` matched the keywords below (field validation: MIT reported as a secret).
  const tags = (rule?.properties?.tags ?? []).map((tag) => tag.toLowerCase());
  if (engine === "trivy" && (rule?.name === "License" || tags.includes("license"))) return false;
  const hay = `${ruleId} ${rule?.name ?? ""} ${(rule?.properties?.tags ?? []).join(" ")}`.toLowerCase();
  if (hay.includes("secret") || hay.includes("credential") || hay.includes("api-key") || hay.includes("apikey")) {
    return true;
  }
  return Boolean(findSecret(snippet));
}

/** Trivy provenance classification is structural: rule name/tags only, never CVE/message parsing. */
export function findingKindForSarif(
  engine: Engine,
  rule: SarifRule | undefined,
  isSecret: boolean,
): FindingKind {
  if (isSecret) return "secret";
  if (engine === "opengrep") return "sast";
  if (engine !== "trivy") return "other";
  const name = (rule?.name ?? "").toLowerCase();
  const tags = (rule?.properties?.tags ?? []).map((tag) => tag.toLowerCase());
  if (name === "languagespecificpackagevulnerability" || tags.includes("vulnerability")) return "vulnerability";
  if (name === "license" || tags.includes("license")) return "license";
  if (name === "misconfiguration" || tags.includes("misconfiguration")) return "misconfiguration";
  return "other";
}

/**
 * Trivy's vulnerability message starts with `Package: <name>` and `Installed Version: <version>` lines
 * (the Pub name-collision exclusion has always read the first). The ecosystem is derived from the
 * lockfile name where that is unambiguous; dedup keys on the normalized name only, never on it.
 */
function trivyPackage(message: string, file: string): FindingPackage | undefined {
  const name = /^Package: (\S+)/.exec(message)?.[1];
  if (!name) return undefined;
  return {
    ecosystem: osvEcosystemForFile(file) ?? "unknown",
    name,
    version: /^Installed Version: (\S+)/m.exec(message)?.[1] ?? "",
  };
}

/** Trivy's SARIF vulnerability message: `Package: …`, `Installed Version: …`, `Fixed Version: a, b`. */
function trivyDependency(message: string): { name: string; installed: string; fixed: string[] } | undefined {
  const name = /^Package: (\S{1,256})$/m.exec(message)?.[1];
  const installed = /^Installed Version: (\S{1,128})$/m.exec(message)?.[1];
  const fixedLine = /^Fixed Version:(.*)$/m.exec(message)?.[1];
  if (!name || !installed || fixedLine === undefined) return undefined;
  const fixed = fixedLine.split(",").map((version) => version.trim()).filter(Boolean);
  // A fix may be a constraint with spaces (Ruby: `>= 2.9.0`); the line itself has no newline.
  return fixed.every((version) => version.length <= 128) ? { name, installed, fixed } : undefined;
}

/**
 * Magento 2 core packages GitHub advisories (and so Trivy) key Magento advisories on, or that a Composer install
 * locks; all are versioned as the product (`2.4.7`, then patch releases `2.4.7-p1`, `-p2`, ...).
 */
const MAGENTO_CORE_PACKAGES: ReadonlySet<string> = new Set([
  "magento/community-edition",
  "magento/product-community-edition",
  "magento/project-community-edition",
  "magento/magento2-base",
  "magento/product-enterprise-edition",
]);

/** A Trivy finding on a Magento core package that is provably fixed at its installed `-pN` release. */
export interface MagentoPatchSuppression {
  file: string;
  name: string;
  version: string;
  rule_id: string;
}

/**
 * Trivy orders a Magento `-pN` patch release before its base release (as a semver pre-release) and compares N
 * as text, so it reports `2.4.7-p3` as affected by an advisory fixed in `2.4.7`, and `2.4.6-p11` by one fixed
 * in `2.4.6-p6` (field N2: 91 such findings on one 2.4.6-p11 store). Such a finding is split out when, under
 * Magento ordering (base release, then `-pN` by number), the installed `-pN` release is at or above every fixed
 * release Trivy lists on the same release line, and at least one is listed there. Anything Magento ordering
 * cannot read, a release with no `-pN` suffix, no fix on that line, or any other package is kept unchanged (the
 * same object, so ids and fingerprints never move). The caller must disclose what was split out.
 */
export function splitMagentoPatchFixed(findings: readonly Finding[]): { kept: Finding[]; suppressed: MagentoPatchSuppression[] } {
  const kept: Finding[] = [];
  const suppressed: MagentoPatchSuppression[] = [];
  const base = (version: string): string => version.split("-")[0]!;
  for (const finding of findings) {
    const dependency = finding.engine === "trivy" && finding.finding_kind === "vulnerability" ? trivyDependency(finding.message) : undefined;
    const fixed = dependency !== undefined && MAGENTO_CORE_PACKAGES.has(dependency.name.toLowerCase()) && /-p\d+$/i.test(dependency.installed)
      ? provablyFixed(dependency.installed, dependency.fixed, base)
      : false;
    if (!fixed) {
      kept.push(finding);
      continue;
    }
    suppressed.push({ file: finding.location.file, name: dependency!.name, version: dependency!.installed, rule_id: finding.rule_id });
  }
  return { kept, suppressed };
}

function provablyFixed(installed: string, fixed: readonly string[], base: (version: string) => string): boolean {
  if (compareVersions("magento", installed, installed) === undefined || fixed.length === 0) return false;
  let sameLine = 0;
  for (const version of fixed) {
    const line = compareVersions("magento", base(version), base(installed));
    // A fix Magento ordering cannot read could be on any line: nothing is proven.
    if (line === undefined || compareVersions("magento", version, version) === undefined) return false;
    if (line !== 0) continue;
    sameLine++;
    const order = compareVersions("magento", installed, version);
    if (order === undefined || order < 0) return false;
  }
  return sameLine > 0;
}

export function normalizeEngineOutput(output: EngineOutput, target: string): Finding[] {
  if (!output.sarif) return [];
  return normalizeSarif(output.sarif, output.engine, target);
}

export function normalizeSarif(sarif: SarifLog, engine: Engine, target: string): Finding[] {
  const findings: Finding[] = [];
  for (const run of sarif.runs ?? []) {
    const rules = run.tool?.driver?.rules ?? [];
    for (const result of run.results ?? []) {
      const f = normalizeResult(result, rules, engine, target);
      if (f) findings.push(f);
    }
  }
  return findings;
}

function normalizeResult(
  result: SarifResult,
  rules: SarifRule[],
  engine: Engine,
  target: string,
): Finding | undefined {
  const rule = ruleFor(result, rules);
  const rawRuleId = result.ruleId ?? rule?.id ?? "unknown";
  // Opengrep namespaces rule ids by the config path (path.segments.ruleid);
  // the real id is the last dot-segment.
  const ruleId = engine === "opengrep" ? rawRuleId.split(".").pop() || rawRuleId : rawRuleId;

  const loc = result.locations?.[0]?.physicalLocation;
  const file = normalizePath(loc?.artifactLocation?.uri, target);
  const startLine = loc?.region?.startLine ?? 0;
  const endLine = loc?.region?.endLine ?? startLine;
  const rawSnippet = loc?.region?.snippet?.text ?? "";

  const messageText =
    result.message?.text ?? rule?.shortDescription?.text ?? rule?.fullDescription?.text ?? ruleId;

  const isSecret = isSecretFinding(engine, rule, ruleId, `${rawSnippet} ${messageText}`);
  const findingKind = findingKindForSarif(engine, rule, isSecret);

  // CWE extraction. Gitleaks (and bare secrets) have no CWE → assign CWE-798.
  let cwes = extractCwes(
    typeof result.properties?.cwe === "string" ? result.properties?.cwe : undefined,
    Array.isArray(result.properties?.cwe) ? result.properties?.cwe : undefined,
    typeof rule?.properties?.cwe === "string" ? rule?.properties?.cwe : undefined,
    Array.isArray(rule?.properties?.cwe) ? rule?.properties?.cwe : undefined,
    rule?.properties?.tags,
    result.properties?.tags,
    rule?.name,
    rule?.shortDescription?.text,
    rule?.fullDescription?.text,
    (rule?.relationships ?? []).map((r) => r.target?.id ?? "").join(" "),
  );
  if (cwes.length === 0 && isSecret) cwes = ["CWE-798"];
  // Trivy SARIF does not reliably carry per-CVE CWEs (only its JSON CweIDs does).
  // An SCA finding's precise canonical weakness is CWE-1395 (dependency on a
  // vulnerable third-party component) → OWASP A06. Use it as the fallback so the
  // canonical-key invariant holds and the A06/Essential-Eight crosswalk fires.
  if (cwes.length === 0 && engine === "trivy" && /^(cve-|ghsa-)/i.test(ruleId)) {
    cwes = ["CWE-1395"];
  }
  if (cwes.length === 0) cwes = ["CWE-noinfo"];

  // Secret handling: detect the value for the dedup hash, then scrub EVERY surfaced field
  // value-agnostically (CG-24 A3-1/A6-2). Redaction must never depend on the value matching
  // a known pattern — a Gitleaks default-rule / entropy hit must be redacted in BOTH the
  // snippet and the message, or its raw value leaks via structuredContent / explain_finding.
  let secretValueHash: string | undefined;
  let liveSecret = false;
  let snippet = rawSnippet;
  let message = messageText;
  if (isSecret) {
    const found = findSecret(`${rawSnippet}\n${messageText}`);
    if (found) {
      secretValueHash = hashSecret(found.value);
      liveSecret = found.live;
    }
    snippet = redactSecretText(rawSnippet, ruleId);
    message = redactSecretText(messageText, ruleId);
  }

  const severity = normalizeSeverity({
    engine,
    level: result.level ?? rule?.defaultConfiguration?.level,
    securitySeverity: rule?.properties?.["security-severity"] ?? result.properties?.["security-severity"],
    ruleSeverity:
      (rule?.properties?.severity as string | undefined) ??
      (result.properties?.severity as string | undefined),
    isSecret,
    liveSecret,
  });

  const baseTitle = deriveTitle(rule?.shortDescription?.text, rule?.name, message, rawRuleId, ruleId, isSecret);
  // Trivy's vulnerability message carries the package, installed and fixed versions. They feed the
  // title and remediation only; the fingerprint inputs and the location are unchanged.
  const dependency = engine === "trivy" && findingKind === "vulnerability" ? trivyDependency(messageText) : undefined;
  // Development-only packages (marked by the Trivy wrapper) are named as such in the text: export 3.0.0
  // has no field for it, and title and message are not fingerprint inputs.
  const devScope = engine === "trivy" && result.properties?.[DEPENDENCY_SCOPE_PROPERTY] === "dev";
  const title = dependency
    ? `${baseTitle} (${dependency.name}@${dependency.installed}${devScope ? ", dev dependency" : ""})`
    : devScope ? `${baseTitle} (dev dependency)` : baseTitle;
  if (devScope) {
    message = `${message}\n${DEV_SCOPE_NOTE}`;
  }

  const fingerprint = fp([engine, file, startLine, endLine, cwes[0], ruleId, secretValueHash]);
  // A CWE taken from the advisory text (e.g. CWE-400) describes the library bug, not the fix.
  const remediation = dependency
    ? dependencyRemediation(dependency.name, dependency.installed, dependency.fixed, remediationForCwe(["CWE-1395"]))
    : remediationForCwe(cwes);
  const owaspWeb = extractOwaspWeb(rule?.properties?.tags, result.properties?.tags);
  const owaspApi = OWASP_API_BY_RULE[ruleId] ?? [];

  const finding: Finding = {
    id: fingerprint, // reassigned to CI-#### after dedup
    fingerprint,
    title,
    severity,
    engine,
    engines: [engine],
    rule_id: ruleId,
    cwe: cwes,
    location: { file, start_line: startLine, end_line: endLine, snippet: snippet || undefined },
    message,
    remediation,
    frameworks: [],
    confidence: precisionToConfidence(rule?.properties, isSecret),
    producer_components: externalFindingComponents(engine, findingKind, ruleId),
    finding_kind: findingKind,
  };
  if (owaspWeb.length) finding.owasp_web = owaspWeb;
  if (owaspApi.length) finding.owasp_api = owaspApi;
  if (isSecret) {
    finding.is_secret = true;
    if (secretValueHash) finding.secret_value_hash = secretValueHash;
    // Gitleaks redacts its value (--redact=100): keep only where the match ends, so routing can read the
    // value back for its reuse check. Nothing is added to the finding.
    else if (engine === "gitleaks") recordGitleaksMatchEnd(finding, loc?.region?.endColumn);
  }
  if (engine === "trivy" && findingKind === "vulnerability") {
    const pkg = trivyPackage(message, file);
    if (pkg) finding.package = pkg;
  }
  return finding;
}
