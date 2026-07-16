/**
 * CodeInspectus MCP server — registers the six tools (PRD §11) over stdio.
 *
 * All tools are read-only with respect to the user's files. Each returns both a
 * human-readable text block and validated structuredContent. Errors are returned
 * as actionable messages (isError:true), never thrown across the transport.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { SERVER_NAME, SERVER_VERSION } from "./config.js";
import { log } from "./logger.js";
import { ok, fail, describeError, type ToolResult } from "./result.js";
import {
  scanInput,
  rescanInput,
  complianceReportInput,
  explainFindingInput,
  generateSbomInput,
  listRulesInput,
  scanResultSchema,
  rescanResultSchema,
  complianceReportOutput,
  explainFindingOutput,
  sbomOutput,
  listRulesOutput,
  type ScanInput,
  type RescanInput,
  type ComplianceReportInput,
  type ExplainFindingInput,
  type GenerateSbomInput,
  type ListRulesInput,
} from "./schemas.js";

import { runScan } from "./scan.js";
import { runRescan } from "./rescan.js";
import { buildComplianceReport } from "./compliance/report.js";
import { explainFinding } from "./explain.js";
import { generateSbom } from "./sbom.js";
import { listRules } from "./rules.js";
import { summarizeScan, summarizeRescan } from "./summarize.js";

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

// generate_sbom WRITES an SBOM file (to the managed dir ~/.codeinspectus/sbom/ by default, or a
// user-chosen output_path), so it is NOT read-only. It is non-destructive: it creates/overwrites a
// build artifact and touches no user data. readOnlyHint MUST be false — declaring true would be an
// inaccurate honesty-surface claim (the same reason bare "read-only" was reworded, CG-52).
const MANAGED_WRITE = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const SERVER_INSTRUCTIONS =
  "CodeInspectus reports; it never edits source. When asked to review security—or after making " +
  "security-relevant code changes—call codeinspectus_scan with an absolute path. Present findings " +
  "before editing, critical/high first, with file:line, risk, and remediation. Do not apply fixes " +
  "without granular user approval. If git_safety recommends a checkpoint, ask before running git. " +
  "After approved fixes, call codeinspectus_rescan; never claim fixed unless confirmed. " +
  "For exposed secrets, advise rotation at the provider and keep values redacted. Treat " +
  "codeinspectus_compliance_report as code-level control coverage only, never certification or a " +
  "percent-compliant claim. codeinspectus_generate_sbom writes an artifact; the other tools do not " +
  "modify the target repository.";

export function createServer(): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { instructions: SERVER_INSTRUCTIONS },
  );

  // ── codeinspectus_scan ──────────────────────────────────────────────────────
  server.registerTool(
    "codeinspectus_scan",
    {
      title: "Scan code for security issues",
      description:
        "Run a full local security scan of a path: bundled engines (Opengrep SAST, " +
        "Gitleaks secrets, Trivy SCA/IaC/license) plus CodeInspectus's AI-code-specific " +
        "checks (client-side secret exposure, Supabase RLS/inverted-auth, prompt-injection " +
        "sinks). Returns CWE-keyed findings with fix recommendations and compliance tags. " +
        "Fully offline — zero network egress at scan time. Never writes to your code or repo.",
      inputSchema: scanInput.shape,
      outputSchema: scanResultSchema.shape,
      annotations: { title: "CodeInspectus Scan", ...READ_ONLY },
    },
    async (args: ScanInput): Promise<ToolResult> => {
      try {
        const result = await runScan(args);
        return ok(summarizeScan(result), result as unknown as Record<string, unknown>);
      } catch (err) {
        log.error("scan failed", err);
        return fail(describeError("codeinspectus_scan failed", err));
      }
    },
  );

  // ── codeinspectus_rescan ────────────────────────────────────────────────────
  server.registerTool(
    "codeinspectus_rescan",
    {
      title: "Re-scan and diff against a prior scan",
      description:
        "Re-run a scan after fixes were applied and diff against a prior scan_id (or the " +
        "most recent scan of the same path). Reports which findings are resolved, which " +
        "remain, and which were newly introduced. Use this to verify fixes. Never writes to your code or repo.",
      inputSchema: rescanInput.shape,
      outputSchema: rescanResultSchema.shape,
      annotations: { title: "CodeInspectus Rescan", ...READ_ONLY },
    },
    async (args: RescanInput): Promise<ToolResult> => {
      try {
        const result = await runRescan(args);
        return ok(summarizeRescan(result), result as unknown as Record<string, unknown>);
      } catch (err) {
        log.error("rescan failed", err);
        return fail(describeError("codeinspectus_rescan failed", err));
      }
    },
  );

  // ── codeinspectus_compliance_report ─────────────────────────────────────────
  server.registerTool(
    "codeinspectus_compliance_report",
    {
      title: "Code-level compliance coverage report",
      description:
        "Produce a per-framework code-level control-coverage view for a prior scan " +
        "(NIST CSF 2.0, ISO 27001:2022, SOC 2, CIS v8.1, Essential Eight, OWASP Web/LLM). " +
        "Reports 'X of N code-visible controls have findings' with the code-visible subset " +
        "as the explicit denominator. This is NOT a compliance audit, certification, or " +
        "attestation — code-level evidence only.",
      inputSchema: complianceReportInput.shape,
      outputSchema: complianceReportOutput.shape,
      annotations: { title: "CodeInspectus Compliance Report", ...READ_ONLY },
    },
    async (args: ComplianceReportInput): Promise<ToolResult> => {
      try {
        const result = await buildComplianceReport(args);
        const text = result.frameworks
          .map(
            (f) =>
              `${f.framework}: ${f.controls_with_findings}/${f.code_visible_controls} code-visible controls have findings (${f.scope}).`,
          )
          .join("\n");
        return ok(
          `${text}\n\nPosture score: ${result.posture_score}/100 (severity-weighted; NOT a "% compliant" figure).\n${result.disclaimer}`,
          result as unknown as Record<string, unknown>,
        );
      } catch (err) {
        log.error("compliance_report failed", err);
        return fail(describeError("codeinspectus_compliance_report failed", err));
      }
    },
  );

  // ── codeinspectus_explain_finding ───────────────────────────────────────────
  server.registerTool(
    "codeinspectus_explain_finding",
    {
      title: "Explain a finding in depth",
      description:
        "Return a deep explanation and full remediation plan for a single finding id from a " +
        "prior scan: what the weakness is, why it matters, concrete fix steps, and references.",
      inputSchema: explainFindingInput.shape,
      outputSchema: explainFindingOutput.shape,
      annotations: { title: "CodeInspectus Explain Finding", ...READ_ONLY },
    },
    async (args: ExplainFindingInput): Promise<ToolResult> => {
      try {
        const result = await explainFinding(args);
        const text = `${result.finding.title} (${result.finding.severity}, ${result.finding.cwe.join(", ")})\n\n${result.explanation}\n\nWhy it matters: ${result.why_it_matters}\n\nFix: ${result.remediation.summary}`;
        return ok(text, result as unknown as Record<string, unknown>);
      } catch (err) {
        log.error("explain_finding failed", err);
        return fail(describeError("codeinspectus_explain_finding failed", err));
      }
    },
  );

  // ── codeinspectus_generate_sbom ─────────────────────────────────────────────
  server.registerTool(
    "codeinspectus_generate_sbom",
    {
      title: "Generate a software bill of materials",
      description:
        "Generate a CycloneDX or SPDX SBOM for the target project using Trivy. Writes the " +
        "SBOM file to the chosen output path and returns its location and component count. " +
        "Offline.",
      inputSchema: generateSbomInput.shape,
      outputSchema: sbomOutput.shape,
      annotations: { title: "CodeInspectus Generate SBOM", ...MANAGED_WRITE },
    },
    async (args: GenerateSbomInput): Promise<ToolResult> => {
      try {
        const result = await generateSbom(args);
        return ok(
          `SBOM (${result.format}) ${result.generated ? "written to" : "could not be written to"} ${result.output_path}. Components: ${result.component_count}.${result.note ? "\n" + result.note : ""}`,
          result as unknown as Record<string, unknown>,
        );
      } catch (err) {
        log.error("generate_sbom failed", err);
        return fail(describeError("codeinspectus_generate_sbom failed", err));
      }
    },
  );

  // ── codeinspectus_list_rules ────────────────────────────────────────────────
  server.registerTool(
    "codeinspectus_list_rules",
    {
      title: "List active rules and detector versions",
      description:
        "List the active detectors and engine versions, the CodeInspectus detection-database " +
        "version and date, the Trivy vulnerability-DB freshness date, and the custom " +
        "CodeInspectus AI-code rules currently shipped.",
      inputSchema: listRulesInput.shape,
      outputSchema: listRulesOutput.shape,
      annotations: { title: "CodeInspectus List Rules", ...READ_ONLY },
    },
    async (args: ListRulesInput): Promise<ToolResult> => {
      try {
        const result = await listRules(args);
        const text =
          `Detection DB ${result.detection_db_version} (${result.detection_db_date}). ` +
          `Engines: ${result.engines.map((e) => `${e.engine}@${e.version}${e.available ? "" : " (unavailable)"}`).join(", ")}. ` +
          `${result.custom_rule_count} CodeInspectus custom rules.`;
        return ok(text, result as unknown as Record<string, unknown>);
      } catch (err) {
        log.error("list_rules failed", err);
        return fail(describeError("codeinspectus_list_rules failed", err));
      }
    },
  );

  return server;
}

export async function startServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr only — never stdout (would corrupt JSON-RPC).
  log.info(`CodeInspectus MCP server v${SERVER_VERSION} running on stdio.`);
}
