/**
 * SARIF 2.1.0 → CWE-keyed internal Finding[] (PRD §5).
 *
 * Per engine: resolve each result's rule, extract CWE(s) (assigning CWE-798 for
 * Gitleaks which has no CWE field, §4.2), normalize severity, redact secret
 * values, and compute a stable fingerprint for rescan diffing. Framework tags
 * and OWASP crosswalks are added later by the compliance mapper.
 */

import type { Engine, Finding, Confidence } from "../types.js";
import type { EngineOutput } from "../engines/types.js";
import type { SarifLog, SarifRule, SarifResult, SarifProps } from "./types.js";
import { normalizeSeverity } from "../severity.js";
import { findSecret, hashSecret, redactSecretText } from "../redact.js";
import { remediationForCwe } from "../remediation.js";
import { fingerprint as fp } from "../util/hash.js";

const CWE_RE = /CWE[-_ ]?(\d{1,5})/gi;

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
  if (comparablePath === comparableTarget) return ".";

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
  const prec = (props?.precision ?? "").toLowerCase();
  if (prec === "very-high" || prec === "high") return "high";
  if (prec === "low") return "low";
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
  const hay = `${ruleId} ${rule?.name ?? ""} ${(rule?.properties?.tags ?? []).join(" ")}`.toLowerCase();
  if (hay.includes("secret") || hay.includes("credential") || hay.includes("api-key") || hay.includes("apikey")) {
    return true;
  }
  return Boolean(findSecret(snippet));
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

  const title = deriveTitle(rule?.shortDescription?.text, rule?.name, message, rawRuleId, ruleId, isSecret);

  const fingerprint = fp([engine, file, startLine, endLine, cwes[0], ruleId, secretValueHash]);
  const remediation = remediationForCwe(cwes);

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
  };
  if (isSecret) {
    finding.is_secret = true;
    if (secretValueHash) finding.secret_value_hash = secretValueHash;
  }
  return finding;
}
