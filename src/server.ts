/**
 * CodeInspectus MCP server — registers local security/reporting tools over stdio.
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
import { engineSetupMessage, inspectEngineSetup } from "./engine-health.js";
import {
  scanInput,
  rescanInput,
  complianceReportInput,
  explainFindingInput,
  generateSbomInput,
  listRulesInput,
  setupInput,
  scanResultSchema,
  rescanResultSchema,
  complianceReportOutput,
  explainFindingOutput,
  sbomOutput,
  listRulesOutput,
  setupOutput,
  type ScanInput,
  type RescanInput,
  type ComplianceReportInput,
  type ExplainFindingInput,
  type GenerateSbomInput,
  type ListRulesInput,
  type SetupInput,
} from "./schemas.js";

import { runScan } from "./scan.js";
import { runRescan } from "./rescan.js";
import { buildComplianceReport } from "./compliance/report.js";
import { explainFinding } from "./explain.js";
import { generateSbom } from "./sbom.js";
import { listRules } from "./rules.js";
import { summarizeScan, summarizeRescan } from "./summarize.js";
import { buildSetupPlan, declineSetupComponents, formatSetupPlan, installSetupComponents, SETUP_COMPONENTS } from "./setup.js";

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

const NETWORKED_MANAGED_WRITE = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const SERVER_INSTRUCTIONS =
  "CodeInspectus reports; it never edits source. When asked to review security—or after making " +
  "security-relevant code changes—call codeinspectus_scan with an absolute path. Present findings " +
  "before editing, critical/high first, with file:line, risk, and remediation. Do not apply fixes " +
  "without granular user approval. If git_safety recommends a checkpoint, ask before running git. " +
  "After approved fixes, call codeinspectus_rescan; never claim fixed unless confirmed. " +
  "Inspect pack_coverage and disclose partial, unavailable, not_run, or not_applicable native packs; " +
  "a ran pack means its listed rules executed, not complete security coverage for that language. " +
  "Inspect repository_trust coverage separately from vulnerability findings. V3.1 deterministically audits source integrity. " +
  "V3.2 audits explicit AI attribution, media metadata, git co-author trailers, and supported C2PA Content Credentials. " +
  "Treat declarative attribution as an observed claim, not proof of authorship. Never label hidden Unicode as AI-generated or a vendor watermark. " +
  "Do not remove or alter C2PA, legal, licensing, or attribution records. Statistical watermark detection remains unavailable. " +
  "For cleanup-eligible source-integrity artifacts, show the escaped code point, exact file/location and proposed action, then " +
  "ask for explicit approval for the named file and marker before editing. CodeInspectus itself never removes characters. " +
  "Inspect engine_setup in scan/list-rules output. For repair_required, explain that engine coverage may be partial; " +
  "for db_refresh_recommended, explain the DB freshness/rescan-continuity limitation without calling current findings incomplete. " +
  "When engine readiness is not yet known, call codeinspectus_setup with action=plan before the first scan. " +
  "Explain each affected component, coverage, license and size, " +
  "then ask for approval. Only after approval call action=install with confirm_downloads=true. Never download " +
  "engines silently or during a scan. A terminal is not required for MCP setup. " +
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
        "Run a full local security scan of a path: managed engines (Opengrep SAST, " +
        "Gitleaks secrets, Trivy SCA/IaC/license), CodeInspectus's offline native Pub SCA, " +
        "plus AI-code-specific " +
        "checks (client-side secret exposure, Supabase RLS/inverted-auth, prompt-injection " +
        "sinks, API-boundary failures, and explicit runtime-control misconfiguration). " +
        "Returns CWE-keyed findings with fix recommendations, detected repository technologies, " +
        "explicit native-pack execution counts, compliance tags, and three-state repository " +
        "evidence for supported runtime controls. Also returns the V3 repository-trust contract with " +
        "deterministic V3.1 source-integrity evidence for bidi controls, hidden/default-ignorable characters, " +
        "Unicode tag and variation-selector payloads, and bounded mixed-script confusables. " +
        "V3.2 additionally audits explicit AI attribution in source/git/media metadata and validates supported local C2PA assets " +
        "with the official optional Content Authenticity Initiative library. Remote manifests and revocation endpoints are never fetched. " +
        "Statistical-watermark detection remains explicitly unavailable. " +
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

  // ── codeinspectus_setup ────────────────────────────────────────────────────
  server.registerTool(
    "codeinspectus_setup",
    {
      title: "Plan or install external security engines",
      description:
        "Inspect external-engine health and exact platform download sizes, save declined choices, or install selected " +
        "Opengrep/Gitleaks/Trivy components after explicit confirmation. Plan is offline. Install writes only to " +
        "~/.codeinspectus, verifies immutable pins/publisher provenance, and never modifies the target repository.",
      inputSchema: setupInput.shape,
      outputSchema: setupOutput.shape,
      annotations: { title: "CodeInspectus Setup", ...NETWORKED_MANAGED_WRITE },
    },
    async (args: SetupInput): Promise<ToolResult> => {
      try {
        const selection = args.components?.length ? args.components : [...SETUP_COMPONENTS];
        const result = args.action === "install"
          ? await installSetupComponents(selection, args.confirm_downloads === true, {
              io: { stdout: (text) => log.info(text), stderr: (text) => log.warn(text) },
            })
          : args.action === "decline"
            ? await declineSetupComponents(selection)
            : { outcome: "planned" as const, message: "Review the plan and ask for approval before installing.", plan: await buildSetupPlan({ selection }) };
        return ok(`${result.message}\n\n${formatSetupPlan(result.plan)}`, result as unknown as Record<string, unknown>);
      } catch (err) {
        log.error("setup failed", err);
        return fail(describeError("codeinspectus_setup failed", err));
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
        "remain, and which were newly introduced, plus fresh technology and native-pack " +
        "execution coverage. Repository-trust artifacts are diffed separately with fail-closed " +
        "resolved, remaining, introduced and not-rechecked states. Use this to verify approved fixes. " +
        "Never writes to your code or repo.",
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
        "Generate a CycloneDX or SPDX SBOM for the target project using Trivy plus the " +
        "first-party offline Pub lockfile inventory, with native Pub fallback when Trivy is unavailable. Writes the " +
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
          `SBOM (${result.format}) ${result.generated ? "written to" : "could not be written to"} ${result.output_path}. ` +
          `Components: ${result.component_count}. Providers: ${result.providers.join(", ") || "none"}. ` +
          `Coverage: ${result.coverage_state}.${result.note ? "\n" + result.note : ""}`,
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
        "version and date, Trivy vulnerability-DB freshness, bundled Pub advisory-database " +
        "provenance/freshness, and the custom " +
        "CodeInspectus AI-code rules and native detector packs currently shipped.",
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
          `${result.custom_rule_count} CodeInspectus custom rules. ` +
          engineSetupMessage(result.engine_setup);
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
  const preflight = await inspectEngineSetup();
  if (preflight.state !== "ready") log.warn(engineSetupMessage(preflight));
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr only — never stdout (would corrupt JSON-RPC).
  log.info(`CodeInspectus MCP server v${SERVER_VERSION} running on stdio.`);
}
