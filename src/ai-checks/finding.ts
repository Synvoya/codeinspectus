/**
 * Helper to build a CodeInspectus AI-code finding (engine: "codeinspectus-ai")
 * in the §5 schema. Framework tags are added later by the compliance mapper.
 */

import type { Finding, Severity, Confidence, Remediation } from "../types.js";
import { fingerprint as fp } from "../util/hash.js";
import { redactSnippet } from "../redact.js";

export interface AiFindingSpec {
  ruleId: string;
  title: string;
  severity: Severity;
  cwe: string[];
  owasp_web?: string[];
  owasp_llm?: string[];
  attack_techniques?: string[];
  file: string;
  startLine: number;
  endLine?: number;
  snippet: string;
  message: string;
  remediation: Remediation;
  confidence: Confidence;
  isSecret?: boolean;
  secretValueHash?: string;
}

export function makeAiFinding(spec: AiFindingSpec): Finding {
  const endLine = spec.endLine ?? spec.startLine;
  const fingerprint = fp([
    "codeinspectus-ai",
    spec.file,
    spec.startLine,
    endLine,
    spec.cwe[0],
    spec.ruleId,
    spec.secretValueHash,
  ]);
  const finding: Finding = {
    id: fingerprint,
    fingerprint,
    title: spec.title,
    severity: spec.severity,
    engine: "codeinspectus-ai",
    engines: ["codeinspectus-ai"],
    rule_id: spec.ruleId,
    cwe: spec.cwe,
    location: {
      file: spec.file,
      start_line: spec.startLine,
      end_line: endLine,
      // Always redact: an AI-code snippet may contain a secret.
      snippet: redactSnippet(spec.snippet),
    },
    message: spec.message,
    remediation: spec.remediation,
    frameworks: [],
    confidence: spec.confidence,
  };
  if (spec.owasp_web) finding.owasp_web = spec.owasp_web;
  if (spec.owasp_llm) finding.owasp_llm = spec.owasp_llm;
  if (spec.attack_techniques) finding.attack_techniques = spec.attack_techniques;
  if (spec.isSecret) {
    finding.is_secret = true;
    if (spec.secretValueHash) finding.secret_value_hash = spec.secretValueHash;
  }
  return finding;
}
