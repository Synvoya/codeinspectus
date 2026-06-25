/**
 * Core internal types — the CWE-keyed normalized schema (PRD §5).
 * Zod schemas in schemas.ts are the runtime source of truth for tool IO; these
 * TS types describe the internal model the orchestrator passes around.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export type Confidence = "high" | "medium" | "low";

export type Engine =
  | "opengrep"
  | "gitleaks"
  | "trivy"
  | "codeinspectus-ai";

export type ScannerKind = "sast" | "secret" | "vuln" | "misconfig" | "license" | "ai";

export interface FindingLocation {
  file: string;
  start_line: number;
  end_line: number;
  /** Source excerpt. Secret values MUST be redacted before this is populated. */
  snippet?: string;
}

export interface Remediation {
  summary: string;
  steps: string[];
  code_suggestion?: string;
  references: string[];
}

export interface FrameworkTag {
  framework: string;
  controls: string[];
}

export interface Finding {
  id: string;
  /** Stable across scans for the same issue+location — drives rescan diffing. */
  fingerprint: string;
  title: string;
  severity: Severity;
  engine: Engine;
  /** Every engine that reported this finding (after dedup merge). */
  engines: Engine[];
  rule_id: string;
  /** Canonical key. Always at least one CWE. */
  cwe: string[];
  owasp_web?: string[];
  owasp_llm?: string[];
  /** MITRE ATT&CK is context only, never a coverage score (PRD §10.1). */
  attack_techniques?: string[];
  location: FindingLocation;
  message: string;
  remediation: Remediation;
  frameworks: FrameworkTag[];
  confidence: Confidence;
  /** True when the matched artifact was a secret value (drives redaction/dedup). */
  is_secret?: boolean;
  /** SHA256 of the matched secret value — dedup key for the Trivy⨯Gitleaks overlap. */
  secret_value_hash?: string;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface EngineRunInfo {
  engine: Engine;
  version: string;
  available: boolean;
  ran: boolean;
  finding_count: number;
  duration_ms: number;
  /** Actionable note when an engine could not run (binary missing, etc.). */
  note?: string;
}

export interface ComplianceControlCoverage {
  id: string;
  name: string;
  findings: number;
  status: "gap" | "clear";
}

export interface FrameworkCoverage {
  framework: string;
  scope: string;
  code_visible_controls: number;
  controls_with_findings: number;
  controls: ComplianceControlCoverage[];
  disclaimer: string;
}

export interface ComplianceOverview {
  /** Severity-weighted 0–100 posture score — its OWN view, never "% compliant". */
  posture_score: number;
  frameworks: Array<{
    framework: string;
    code_visible_controls: number;
    controls_with_findings: number;
  }>;
  disclaimer: string;
}

export interface ScanResult {
  scan_id: string;
  target: string;
  started_at: string;
  duration_ms: number;
  engines_run: string[];
  engine_details: EngineRunInfo[];
  offline: boolean;
  trivy_db_date?: string;
  summary: SeveritySummary;
  findings: Finding[];
  /** True when findings were truncated by max_findings/severity_threshold. */
  truncated: boolean;
  total_findings_before_limit: number;
  compliance_overview?: ComplianceOverview;
  disclaimer: string;
  warnings: string[];
}

export interface RescanResult {
  scan_id: string;
  prior_scan_id: string;
  target: string;
  resolved: Finding[];
  remaining: Finding[];
  introduced: Finding[];
  summary: {
    resolved: number;
    remaining: number;
    introduced: number;
  };
  disclaimer: string;
}
