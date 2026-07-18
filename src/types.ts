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

/** Structural detector category. Trivy vulnerability attribution never relies on CVE/message regexes. */
export type FindingKind = "vulnerability" | "license" | "misconfiguration" | "secret" | "sast" | "ai" | "other";

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
  /** Detector components required to reproduce this finding; unioned across dedup producers. */
  producer_components?: string[];
  /** Structural finding category used for component-scoped provenance (not display severity). */
  finding_kind?: FindingKind;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

/** CG-41 git-safety states for the scan target's working tree. */
export type GitSafetyState = "no_git" | "dirty" | "clean" | "unknown";

/**
 * CG-41 read-only workspace advisory: the git state of the scan target plus a plain-language
 * checkpoint recommendation. Advisory METADATA — never a security finding, never severity-bearing.
 */
export interface GitSafety {
  state: GitSafetyState;
  /** Checkpoint recommendation — present ONLY when state is no_git or dirty. */
  recommendation?: string;
}

/** Gitleaks suppression surfaces detected in the target without retaining config or secret content. */
export interface SecretSuppressionChannel {
  channel: "target_config" | "gitleaks_ignore" | "inline_allow";
  count: number;
  paths: string[];
  handling: "ignored_by_codeinspectus" | "coverage_unverified";
}

export interface SecretSuppressionMetadata {
  channels: SecretSuppressionChannel[];
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
  /** Secret-scanner coverage status. Unverified when Gitleaks did not run or .gitleaksignore exists. */
  secret_coverage?: "verified" | "unverified";
  /** Redacted metadata only: channel names, counts, and relative file paths. */
  secret_suppression?: SecretSuppressionMetadata;
  /** Component id -> content/semantic signature. Optional only for legacy stored scans. */
  component_signatures?: Record<string, string>;
  /** CG-41 read-only git-safety advisory for the scan target (never a finding). */
  git_safety: GitSafety;
  /**
   * CG-75: the effective scan configuration, captured so a bare rescan can reproduce the
   * original scope like-for-like AND so rescan can prove whether a prior finding was even
   * re-checkable. Absent on pre-CG-75 scans — rescan then degrades those prior findings to
   * `not_rechecked` (never `resolved`), because like-for-like scope cannot be proven.
   */
  scan_config?: ScanConfig;
}

/** CG-75 captured scan config (per-engine ran/failed status lives in engine_details). */
export interface ScanConfig {
  /** Scanner classes requested; undefined = all classes. */
  scanners?: ScannerKind[];
  /** Severity floor applied; undefined = info (all severities). */
  severity_threshold?: Severity;
  /** The effective max_findings cap actually applied. */
  max_findings: number;
}

export interface RescanResult {
  scan_id: string;
  prior_scan_id: string;
  target: string;
  resolved: Finding[];
  remaining: Finding[];
  introduced: Finding[];
  /**
   * CG-75: prior findings whose resolution could NOT be proven — the producing engine did
   * not run in the rescan, the finding fell outside the rescan's scanner/threshold scope,
   * a scan was truncated, or the prior scan predates captured config. Indeterminate:
   * NOT confirmed resolved and NOT silently dropped.
   */
  not_rechecked: Finding[];
  summary: {
    resolved: number;
    remaining: number;
    introduced: number;
    not_rechecked: number;
  };
  /** True when not_rechecked is non-empty — the comparison is partial, not like-for-like. */
  partial: boolean;
  /** Human-readable reason(s) the not_rechecked findings could not be confirmed; present iff partial. */
  not_rechecked_note?: string;
  disclaimer: string;
}
