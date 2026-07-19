/**
 * Zod schemas for every tool's input and output (PRD §11).
 *
 * registerTool() takes ZodRawShape for inputSchema/outputSchema. We define full
 * z.object schemas here and pass `.shape` at registration. The SDK validates
 * structuredContent against outputSchema, so the orchestrator MUST return
 * objects that satisfy these schemas exactly.
 */

import { z } from "zod";

// ── Enumerations ────────────────────────────────────────────────────────────
export const severityEnum = z.enum(["critical", "high", "medium", "low", "info"]);
export const confidenceEnum = z.enum(["high", "medium", "low"]);
export const engineEnum = z.enum(["opengrep", "gitleaks", "trivy", "codeinspectus-ai"]);
export const scannerEnum = z.enum(["sast", "secret", "vuln", "misconfig", "license", "ai"]);

// ── scan_id hardening (CG-75 / Claim 2) ─────────────────────────────────────
// scan_ids are generated as `scan-${randomUUID()}` (UUIDv4, lowercase hex) — see
// src/scan.ts. Constrain EVERY tool input that accepts one to that exact shape so
// traversal ("../"), absolute paths, and arbitrary strings are rejected at the Zod
// boundary. Defense-in-depth with the store's path-containment check (src/store.ts).
const SCAN_ID_RE = /^scan-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const scanIdSchema = z
  .string()
  .regex(
    SCAN_ID_RE,
    "scan_id must be a CodeInspectus-generated id of the form 'scan-<uuid>' (e.g. scan-7a264fd8-0d50-43e4-bcf1-75f401a90f88).",
  );

export const FRAMEWORKS = [
  "NIST_CSF_2.0",
  "ISO27001:2022",
  "SOC2",
  "CIS_v8.1",
  "EssentialEight",
  "OWASP_Web_2021",
  "OWASP_LLM_2025",
] as const;
export const frameworkEnum = z.enum(FRAMEWORKS);

// ── Finding ─────────────────────────────────────────────────────────────────
export const locationSchema = z.object({
  file: z.string(),
  start_line: z.number().int(),
  end_line: z.number().int(),
  snippet: z.string().optional(),
});

export const remediationSchema = z.object({
  summary: z.string(),
  steps: z.array(z.string()),
  code_suggestion: z.string().optional(),
  references: z.array(z.string()),
});

export const frameworkTagSchema = z.object({
  framework: z.string(),
  controls: z.array(z.string()),
});

export const findingSchema = z.object({
  id: z.string(),
  fingerprint: z.string(),
  title: z.string(),
  severity: severityEnum,
  engine: engineEnum,
  engines: z.array(engineEnum),
  rule_id: z.string(),
  cwe: z.array(z.string()),
  owasp_web: z.array(z.string()).optional(),
  owasp_llm: z.array(z.string()).optional(),
  attack_techniques: z.array(z.string()).optional(),
  location: locationSchema,
  message: z.string(),
  remediation: remediationSchema,
  frameworks: z.array(frameworkTagSchema),
  confidence: confidenceEnum,
  is_secret: z.boolean().optional(),
  secret_value_hash: z.string().optional(),
  producer_components: z.array(z.string()).optional(),
  finding_kind: z.enum(["vulnerability", "license", "misconfiguration", "secret", "sast", "ai", "other"]).optional(),
});

export const summarySchema = z.object({
  critical: z.number().int(),
  high: z.number().int(),
  medium: z.number().int(),
  low: z.number().int(),
  info: z.number().int(),
  total: z.number().int(),
});

export const engineRunInfoSchema = z.object({
  engine: engineEnum,
  version: z.string(),
  available: z.boolean(),
  ran: z.boolean(),
  finding_count: z.number().int(),
  duration_ms: z.number().int(),
  note: z.string().optional(),
});

export const complianceOverviewSchema = z.object({
  posture_score: z.number(),
  frameworks: z.array(
    z.object({
      framework: z.string(),
      code_visible_controls: z.number().int(),
      controls_with_findings: z.number().int(),
    }),
  ),
  disclaimer: z.string(),
});

// ── CG-41 git-safety advisory (read-only workspace metadata, never a finding) ─
export const gitSafetySchema = z.object({
  state: z.enum(["no_git", "dirty", "clean", "unknown"]),
  recommendation: z.string().optional(),
});

const secretSuppressionSchema = z.object({
  channels: z.array(
    z.object({
      channel: z.enum(["target_config", "gitleaks_ignore", "inline_allow"]),
      count: z.number().int().nonnegative(),
      paths: z.array(z.string()),
      handling: z.enum(["ignored_by_codeinspectus", "coverage_unverified"]),
    }),
  ),
});

// ── scan / rescan output envelope (PRD §5) ──────────────────────────────────
export const scanResultSchema = z.object({
  scan_id: z.string(),
  target: z.string(),
  started_at: z.string(),
  duration_ms: z.number().int(),
  engines_run: z.array(z.string()),
  engine_details: z.array(engineRunInfoSchema),
  offline: z.boolean(),
  trivy_db_date: z.string().optional(),
  summary: summarySchema,
  findings: z.array(findingSchema),
  truncated: z.boolean(),
  total_findings_before_limit: z.number().int(),
  compliance_overview: complianceOverviewSchema.optional(),
  disclaimer: z.string(),
  warnings: z.array(z.string()),
  secret_coverage: z.enum(["verified", "unverified"]).optional(),
  secret_suppression: secretSuppressionSchema.optional(),
  component_signatures: z.record(z.string()).optional(),
  trivy_db_provenance: z
    .object({
      state: z.literal("unrecorded"),
      instruction: z.string(),
    })
    .optional(),
  git_safety: gitSafetySchema,
  // CG-75: effective scan config, captured so a bare rescan is like-for-like and rescan can
  // prove re-checkability. Optional so pre-CG-75 stored scans still validate on load.
  scan_config: z
    .object({
      scanners: z.array(scannerEnum).optional(),
      severity_threshold: severityEnum.optional(),
      max_findings: z.number().int(),
    })
    .optional(),
});

// Store-tolerant LOAD schema (CG-75 / Claim 2c). Persisted scans on disk may predate
// fields added in later versions — `git_safety` (CG-41). Fresh scan OUTPUT is still
// strictly validated by scanResultSchema (the honesty surface is unchanged); this schema
// governs ONLY what the store accepts when reading previously-persisted JSON, so a rescan
// of an older scan validates instead of crashing. (Any field that is optional on
// scanResultSchema — including the CG-75 scan-config fields once they are added — is
// inherited leniently here.)
export const storedScanResultSchema = scanResultSchema.extend({
  git_safety: gitSafetySchema.optional(),
});

// ── Tool INPUT schemas ──────────────────────────────────────────────────────
export const scanInput = z.object({
  path: z.string().describe("Absolute path to the repository or directory to scan."),
  severity_threshold: severityEnum
    .optional()
    .describe("Only return findings at or above this severity (default: info — all)."),
  scanners: z
    .array(scannerEnum)
    .optional()
    .describe(
      "Limit which scanner classes run: sast, secret, vuln, misconfig, license, ai. Default: all.",
    ),
  max_findings: z
    .number()
    .int()
    .positive()
    .optional()
    .describe("Cap the number of findings returned to protect agent context (default: 200)."),
  include_compliance: z
    .boolean()
    .optional()
    .describe("Include the per-framework compliance overview in the result (default: true)."),
});

export const rescanInput = z.object({
  path: z.string().describe("Absolute path to the repository or directory to rescan."),
  prior_scan_id: scanIdSchema
    .optional()
    .describe("scan_id of a previous scan to diff against. Defaults to the most recent scan of this path."),
  severity_threshold: severityEnum.optional(),
  scanners: z.array(scannerEnum).optional(),
  max_findings: z.number().int().positive().optional(),
});

export const complianceReportInput = z.object({
  scan_id: scanIdSchema.describe("scan_id returned by a prior codeinspectus_scan call."),
  framework: frameworkEnum
    .optional()
    .describe("Restrict the report to one framework. Default: all frameworks."),
});

export const explainFindingInput = z.object({
  scan_id: scanIdSchema.describe("scan_id the finding belongs to."),
  finding_id: z.string().describe("The finding id (e.g. CI-0007) to explain in depth."),
});

export const generateSbomInput = z.object({
  path: z.string().describe("Absolute path to the project to generate an SBOM for."),
  format: z
    .enum(["cyclonedx", "spdx"])
    .optional()
    .describe("SBOM format (default: cyclonedx)."),
  output_path: z
    .string()
    .optional()
    .describe("Where to write the SBOM file. Default: <path>/codeinspectus-sbom.<fmt>.json."),
});

export const listRulesInput = z.object({
  engine: engineEnum.optional().describe("Filter to one engine's rules/detectors."),
});

// ── Tool OUTPUT schemas ─────────────────────────────────────────────────────
export const rescanResultSchema = z.object({
  scan_id: z.string(),
  prior_scan_id: z.string(),
  target: z.string(),
  resolved: z.array(findingSchema),
  remaining: z.array(findingSchema),
  introduced: z.array(findingSchema),
  // CG-75: prior findings whose resolution could NOT be proven — indeterminate, never
  // reported as resolved. Surfaced as its own category alongside resolved/remaining/introduced.
  not_rechecked: z.array(findingSchema),
  summary: z.object({
    resolved: z.number().int(),
    remaining: z.number().int(),
    introduced: z.number().int(),
    not_rechecked: z.number().int(),
  }),
  /** True when the comparison is partial (not_rechecked non-empty). */
  partial: z.boolean(),
  /** Reason(s) findings could not be confirmed resolved; present iff partial. */
  not_rechecked_note: z.string().optional(),
  disclaimer: z.string(),
});

export const complianceControlSchema = z.object({
  id: z.string(),
  name: z.string(),
  findings: z.number().int(),
  status: z.enum(["gap", "clear"]),
});

export const frameworkCoverageSchema = z.object({
  framework: z.string(),
  scope: z.string(),
  code_visible_controls: z.number().int(),
  controls_with_findings: z.number().int(),
  controls: z.array(complianceControlSchema),
  disclaimer: z.string(),
});

export const complianceReportOutput = z.object({
  scan_id: z.string(),
  posture_score: z.number(),
  posture_note: z.string(),
  frameworks: z.array(frameworkCoverageSchema),
  disclaimer: z.string(),
});

export const explainFindingOutput = z.object({
  finding: findingSchema,
  explanation: z.string(),
  why_it_matters: z.string(),
  remediation: remediationSchema,
  references: z.array(z.string()),
});

export const sbomOutput = z.object({
  format: z.string(),
  output_path: z.string(),
  component_count: z.number().int(),
  generated: z.boolean(),
  note: z.string().optional(),
});

export const ruleInfoSchema = z.object({
  id: z.string(),
  engine: engineEnum,
  name: z.string(),
  kind: scannerEnum,
  cwe: z.array(z.string()),
  source: z.enum(["builtin-engine", "codeinspectus-custom"]),
});

export const listRulesOutput = z.object({
  detection_db_version: z.string(),
  detection_db_date: z.string(),
  engines: z.array(
    z.object({
      engine: engineEnum,
      version: z.string(),
      available: z.boolean(),
      ruleset: z.string(),
    }),
  ),
  trivy_db_date: z.string().optional(),
  custom_rules: z.array(ruleInfoSchema),
  custom_rule_count: z.number().int(),
  note: z.string(),
});

// Inferred TS types for convenience.
export type ScanInput = z.infer<typeof scanInput>;
export type RescanInput = z.infer<typeof rescanInput>;
export type ComplianceReportInput = z.infer<typeof complianceReportInput>;
export type ExplainFindingInput = z.infer<typeof explainFindingInput>;
export type GenerateSbomInput = z.infer<typeof generateSbomInput>;
export type ListRulesInput = z.infer<typeof listRulesInput>;
