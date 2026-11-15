/**
 * CodeInspectus MCP server — registers local security/reporting tools over stdio.
 *
 * Scan/report tools are read-only with respect to the user's files. The V3.3 apply and rollback
 * tools are the explicit, approval-gated mutation surface. Every tool returns both a human-readable
 * text block and validated structuredContent. Errors are actionable (isError:true), never thrown
 * across the transport.
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
  cleanupPlanInput,
  cleanupApplyInput,
  cleanupRollbackInput,
  scanResultSchema,
  rescanResultSchema,
  complianceReportOutput,
  explainFindingOutput,
  sbomOutput,
  listRulesOutput,
  setupOutput,
  cleanupPlanOutput,
  cleanupApplyOutput,
  cleanupRollbackOutput,
  type ScanInput,
  type RescanInput,
  type ComplianceReportInput,
  type ExplainFindingInput,
  type GenerateSbomInput,
  type ListRulesInput,
  type SetupInput,
  type CleanupPlanInput,
  type CleanupApplyInput,
  type CleanupRollbackInput,
} from "./schemas.js";

import { runScan } from "./scan.js";
import { runRescan } from "./rescan.js";
import { buildComplianceReport } from "./compliance/report.js";
import { explainFinding } from "./explain.js";
import { generateSbom } from "./sbom.js";
import { listRules, sastRuleLanguagesLine, synvoyaDatasetLine } from "./rules.js";
import { summarizeScan, summarizeRescan } from "./summarize.js";
import { buildSetupPlan, declineSetupComponents, formatSetupPlan, installSetupComponents, SETUP_COMPONENTS } from "./setup.js";
import { applyRepositoryCleanup, planRepositoryCleanup, rollbackRepositoryCleanup } from "./repository-trust/cleanup.js";
import type { repairEngines } from "./install.js";
import type { EngineSetupStatus } from "./types.js";
import {
  databaseUpdatePrompt,
  formatDatabaseUpdatePrompt,
  largeDownloadNames,
  snoozeUpdatePrompt,
  type DatabaseUpdatePrompt,
} from "./update-prompt.js";
import { formatDatabaseUpdatePlan, formatDatabaseUpdateResult, planDatabaseUpdate, runDatabaseUpdate } from "./update.js";

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

const TARGET_MUTATION = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: false,
} as const;

const SERVER_INSTRUCTIONS =
  "CodeInspectus scans and reports without editing source. V3.3 cleanup is the only target-repository mutation surface. When asked to review security—or after making " +
  "security-relevant code changes—call codeinspectus_scan with an absolute path. Present findings " +
  "before editing, critical/high first, with file:line, risk, and remediation. After approved fixes, " +
  "call codeinspectus_rescan; never claim fixed unless confirmed. Do not apply fixes " +
  "without granular user approval. If git_safety recommends a checkpoint, ask before running git. " +
  "Inspect pack_coverage and disclose partial, unavailable, not_run, or not_applicable native packs; " +
  "a ran pack means its listed rules executed, not complete security coverage for that language. " +
  "Disclose coverage_gaps: inputs no bundled engine analyzes (stable ids such as php-sast, vue-sast, deno-lock, " +
  "sast-parse-errors) make coverage partial; also mention coverage_notes. Pass accept_gaps only with ids the user " +
  "explicitly chose; accepted gaps stay listed and those inputs remain unanalyzed. " +
  "Inspect repository_trust coverage separately from vulnerability findings. V3.1 deterministically audits source integrity. " +
  "V3.2 audits explicit AI attribution, media metadata, git co-author trailers, and supported C2PA Content Credentials. " +
  "Treat declarative attribution as an observed claim, not proof of authorship. Never label hidden Unicode as AI-generated or a vendor watermark. " +
  "Never alter Git history or protected legal, licensing, or compliance records. Statistical watermark detection remains unavailable. " +
  "For cleanup-eligible artifacts, call codeinspectus_plan_cleanup and show the exact files, transformations, limitations, and artifact IDs. " +
  "Only after granular user approval call codeinspectus_apply_cleanup with the exact approved IDs and confirmations. Media cleanup creates a copy; it never overwrites the original asset. " +
  "Run relevant repository tests, formatters, and builds after apply; cleanup is incomplete until those checks and the same-validator rescan pass. Use codeinspectus_rollback_cleanup if an approved change must be restored. " +
  "Inspect engine_setup in scan/list-rules output. For repair_required, explain that engine coverage may be partial; " +
  "for db_refresh_recommended, explain the DB freshness/rescan-continuity limitation without calling current findings incomplete. " +
  "When engine readiness is not yet known, call codeinspectus_setup with action=plan before the first scan. " +
  "Explain each affected component, coverage, license and size, " +
  "then ask for approval. Only after approval call action=install with confirm_downloads=true. Never download " +
  "engines silently or during a scan. A terminal is not required for MCP setup. " +
  "When a scan, rescan or list-rules result carries database_update, ask the user its question with the three answers " +
  "(yes, not now, not for a week) before continuing, and never call codeinspectus_setup with action=update without a yes. " +
  "If an update plan lists large downloads, get a separate yes for them before passing confirm_large_downloads=true. " +
  "For exposed secrets, advise rotation at the provider and keep values redacted. Treat " +
  "codeinspectus_compliance_report as code-level control coverage only, never certification or a " +
  "percent-compliant claim. codeinspectus_generate_sbom writes only an SBOM (managed directory, or an absolute .json path the user chooses; it never replaces a non-SBOM file); only the explicitly approved V3.3 apply/rollback tools edit repository files.";

/** Test seams for the database update prompt and update; production uses the defaults. */
export interface ServerOptions {
  update?: {
    statePath?: string;
    now?: () => number;
    fetch?: typeof fetch;
    repair?: typeof repairEngines;
    /** Engine status for the prompt and the update (default: the offline inspectEngineSetup). */
    inspect?: () => Promise<EngineSetupStatus>;
  };
}

export function createServer(options: ServerOptions = {}): McpServer {
  const updateOptions = options.update ?? {};
  const now = (): number => (updateOptions.now ?? Date.now)();
  const inspectForUpdate = (): Promise<EngineSetupStatus> => (updateOptions.inspect ?? inspectEngineSetup)();
  // Offline (file reads only). A failure here never fails the tool call it decorates.
  async function withDatabaseUpdate<T extends object>(
    result: T,
    status: EngineSetupStatus | undefined,
  ): Promise<{ result: T & { database_update?: DatabaseUpdatePrompt }; text: string }> {
    try {
      const current = updateOptions.inspect ? await updateOptions.inspect() : status ?? await inspectEngineSetup();
      const prompt = await databaseUpdatePrompt(current, now(), updateOptions.statePath);
      if (prompt) return { result: { ...result, database_update: prompt }, text: `\n\n${formatDatabaseUpdatePrompt(prompt)}` };
    } catch (err) {
      log.warn("database update prompt unavailable", err);
    }
    return { result, text: "" };
  }

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
        "Gitleaks secrets, Trivy SCA/IaC), CodeInspectus's offline native Pub SCA, " +
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
        "Licence findings are off by default (informational, not fixable); pass include_licenses: true to add them. " +
        "Lists declared coverage gaps (coverage_gaps, stable ids) that make coverage partial and informational " +
        "coverage_notes; accept_gaps accepts named gap ids for CI while they stay listed. " +
        "Fully offline — zero network egress at scan time. Never writes to your code or repo.",
      inputSchema: scanInput,
      outputSchema: scanResultSchema,
      annotations: { title: "CodeInspectus Scan", ...READ_ONLY },
    },
    async (args: ScanInput): Promise<ToolResult> => {
      try {
        const scanned = await runScan(args);
        const { result, text } = await withDatabaseUpdate(scanned, scanned.engine_setup);
        return ok(summarizeScan(scanned) + text, result as unknown as Record<string, unknown>);
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
        "Opengrep/Gitleaks/Trivy/OSV-Scanner components after explicit confirmation. Pass path (the repository to scan) to " +
        "plan or install only the OSV vulnerability databases for the ecosystems its lockfiles use (and GitHub Actions advisories " +
        "when it has workflows); each is listed with an " +
        "estimated size (integrity: TLS + recorded SHA-256, OSV publishes no signature), and osv_ecosystems pins the exact " +
        "list the user approved. Plan is offline. Install writes only to ~/.codeinspectus, verifies immutable " +
        "pins/publisher provenance for engines, and never modifies the target repository.",
      inputSchema: setupInput,
      outputSchema: setupOutput,
      annotations: { title: "CodeInspectus Setup", ...NETWORKED_MANAGED_WRITE },
    },
    async (args: SetupInput): Promise<ToolResult> => {
      try {
        const selection = args.components?.length ? args.components : [...SETUP_COMPONENTS];
        const osv = {
          ...(args.path ? { target: args.path } : {}),
          ...(args.osv_ecosystems ? { osvEcosystems: args.osv_ecosystems } : {}),
        };
        const io = { stdout: (text: string) => log.info(text), stderr: (text: string) => log.warn(text) };
        if (args.action === "snooze") {
          if (!args.snooze) throw new Error('action="snooze" needs snooze="not_now" or snooze="not_for_a_week".');
          const state = await snoozeUpdatePrompt(args.snooze, now(), updateOptions.statePath);
          const message = `No database update now. CodeInspectus will ask again after ${state.next_prompt_at}. Nothing was downloaded.`;
          const snoozed = { outcome: "snoozed" as const, message, plan: await buildSetupPlan({ selection, ...osv, status: await inspectForUpdate() }) };
          return ok(message, snoozed as unknown as Record<string, unknown>);
        }
        if (args.action === "update") {
          const status = await inspectForUpdate();
          const updatePlan = planDatabaseUpdate(status);
          // Without approval, or with nothing an update can refresh, the answer is the offline plan.
          if (args.confirm_downloads !== true || !updatePlan.databases.length) {
            const planned = { outcome: "planned" as const, message: updatePlan.message, plan: await buildSetupPlan({ selection, ...osv, status }), update_plan: updatePlan };
            return ok(formatDatabaseUpdatePlan(updatePlan), planned as unknown as Record<string, unknown>);
          }
          // skip_large_downloads (the user declined the large ones) wins over confirm_large_downloads.
          const skipLarge = args.skip_large_downloads === true && updatePlan.large_downloads.length > 0;
          const hasSmall = updatePlan.databases.some((database) => !database.large);
          if (skipLarge && !hasSmall) {
            const message = "Every database in this update is over 100 MB, so skipping them leaves nothing to refresh. Nothing was downloaded.";
            const planned = { outcome: "planned" as const, message, plan: await buildSetupPlan({ selection, ...osv, status }), update_plan: updatePlan };
            return ok(`${message}\n\n${formatDatabaseUpdatePlan(updatePlan)}`, planned as unknown as Record<string, unknown>);
          }
          // A download over 100 MB needs its own yes: the prompt's yes never covers it, so the plan comes back first.
          if (updatePlan.large_downloads.length && args.confirm_large_downloads !== true && !skipLarge) {
            const several = updatePlan.large_downloads.length > 1;
            const next_step =
              `Nothing was downloaded. Ask the user separately: ${largeDownloadNames(updatePlan.large_downloads)} ` +
              `${several ? "are" : "is"} over 100 MB. Download ${several ? "them" : "it"} too? Only after a yes, call ` +
              'codeinspectus_setup with action="update", confirm_downloads=true and confirm_large_downloads=true. ' +
              (hasSmall
                ? 'If the user declines the large downloads, call codeinspectus_setup with action="update", confirm_downloads=true ' +
                  'and skip_large_downloads=true to refresh only the smaller databases, or action="snooze".'
                : 'If the user declines, nothing is downloaded; call codeinspectus_setup with action="snooze".');
            const planned = { outcome: "planned" as const, message: updatePlan.message, plan: await buildSetupPlan({ selection, ...osv, status }), update_plan: updatePlan, next_step };
            return ok(`${formatDatabaseUpdatePlan(updatePlan)}\n\n${next_step}`, planned as unknown as Record<string, unknown>);
          }
          const update = await runDatabaseUpdate({
            confirmDownloads: true,
            confirmLargeDownloads: !skipLarge && args.confirm_large_downloads === true,
            ...(skipLarge ? { skipLargeDownloads: true } : {}),
            io,
            nowMs: now(),
            ...(updateOptions.fetch ? { fetch: updateOptions.fetch } : {}),
            ...(updateOptions.repair ? { repair: updateOptions.repair } : {}),
            ...(updateOptions.statePath ? { statePath: updateOptions.statePath } : {}),
            ...(updateOptions.inspect ? { inspect: updateOptions.inspect } : {}),
          });
          const outcome = update.outcome === "updated" ? "updated" as const : update.outcome === "partial" ? "update_partial" as const : "update_failed" as const;
          const updated = { outcome, message: update.message, plan: await buildSetupPlan({ selection, ...osv, status: await inspectForUpdate() }), update };
          const response = ok(formatDatabaseUpdateResult(update), updated as unknown as Record<string, unknown>);
          return update.outcome === "failed" ? { ...response, isError: true } : response;
        }
        const result = args.action === "install"
          ? await installSetupComponents(selection, args.confirm_downloads === true, {
              io,
              ...osv,
            })
          : args.action === "decline"
            ? await declineSetupComponents(selection)
            : { outcome: "planned" as const, message: "Review the plan and ask for approval before installing.", plan: await buildSetupPlan({ selection, ...osv }) };
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
      inputSchema: rescanInput,
      outputSchema: rescanResultSchema,
      annotations: { title: "CodeInspectus Rescan", ...READ_ONLY },
    },
    async (args: RescanInput): Promise<ToolResult> => {
      try {
        const rescanned = await runRescan(args);
        const { result, text } = await withDatabaseUpdate(rescanned, undefined);
        return ok(summarizeRescan(rescanned) + text, result as unknown as Record<string, unknown>);
      } catch (err) {
        log.error("rescan failed", err);
        return fail(describeError("codeinspectus_rescan failed", err));
      }
    },
  );

  // ── codeinspectus_plan_cleanup ──────────────────────────────────────────────
  server.registerTool(
    "codeinspectus_plan_cleanup",
    {
      title: "Plan verified repository cleanup",
      description:
        "Create a fresh, read-only V3.3 cleanup plan for exact verified repository-trust artifact IDs. " +
        "The plan reproduces current evidence, rejects protected, ambiguous, or unsupported records, hashes every preimage, " +
        "and discloses exact text edits or copy-only media metadata transformations. It never changes the repository.",
      inputSchema: cleanupPlanInput,
      outputSchema: cleanupPlanOutput,
      annotations: { title: "CodeInspectus Cleanup Plan", ...READ_ONLY },
    },
    async (args: CleanupPlanInput): Promise<ToolResult> => {
      try {
        const result = await planRepositoryCleanup(args);
        const text = result.outcome === "ready"
          ? `Cleanup plan ${result.plan_id} is ready for ${result.artifact_ids.length} exact artifact(s) across ${result.operations.length} operation(s). Show the plan and obtain granular approval before apply.`
          : `Cleanup plan ${result.plan_id} is blocked: ${result.blockers.map((item) => `${item.artifact_id} (${item.reason})`).join("; ")}`;
        return ok(text, result as unknown as Record<string, unknown>);
      } catch (err) {
        log.error("plan_cleanup failed", err);
        return fail(describeError("codeinspectus_plan_cleanup failed", err));
      }
    },
  );

  // ── codeinspectus_apply_cleanup ─────────────────────────────────────────────
  server.registerTool(
    "codeinspectus_apply_cleanup",
    {
      title: "Apply approved repository cleanup",
      description:
        "Apply one exact ready V3.3 cleanup plan after explicit approval. Requires an exact artifact-ID match and confirmation, " +
        "creates managed content backups, uses atomic bounded edits, creates new media copies, reruns the same repository-trust validators, " +
        "and writes a content-free audit log. This modifies selected source files and/or creates named cleaned copies.",
      inputSchema: cleanupApplyInput,
      outputSchema: cleanupApplyOutput,
      annotations: { title: "CodeInspectus Apply Cleanup", ...TARGET_MUTATION },
    },
    async (args: CleanupApplyInput): Promise<ToolResult> => {
      try {
        const result = await applyRepositoryCleanup(args);
        return ok(
          `Cleanup ${result.cleanup_id}: ${result.outcome}. Targeted artifacts resolved=${result.verification.targeted_artifacts_resolved}; same validators ran=${result.verification.same_validators_ran}. Repository tests, formatters, and build remain required.`,
          result as unknown as Record<string, unknown>,
        );
      } catch (err) {
        log.error("apply_cleanup failed", err);
        return fail(describeError("codeinspectus_apply_cleanup failed", err));
      }
    },
  );

  // ── codeinspectus_rollback_cleanup ──────────────────────────────────────────
  server.registerTool(
    "codeinspectus_rollback_cleanup",
    {
      title: "Roll back repository cleanup",
      description:
        "Restore an applied V3.3 cleanup from its managed checkpoint after explicit confirmation. " +
        "Rollback refuses to overwrite files or cleaned copies that changed after cleanup.",
      inputSchema: cleanupRollbackInput,
      outputSchema: cleanupRollbackOutput,
      annotations: { title: "CodeInspectus Rollback Cleanup", ...TARGET_MUTATION },
    },
    async (args: CleanupRollbackInput): Promise<ToolResult> => {
      try {
        const result = await rollbackRepositoryCleanup(args);
        return ok(`Cleanup ${result.cleanup_id}: ${result.outcome}.`, result as unknown as Record<string, unknown>);
      } catch (err) {
        log.error("rollback_cleanup failed", err);
        return fail(describeError("codeinspectus_rollback_cleanup failed", err));
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
      inputSchema: complianceReportInput,
      outputSchema: complianceReportOutput,
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
          `${text}\n\n${(result.coverage_notes ?? []).map((note) => `${note.detail}\n`).join("")}` +
            `Posture score: ${result.posture_score}/100 (severity-weighted; NOT a "% compliant" figure).\n${result.disclaimer}`,
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
      inputSchema: explainFindingInput,
      outputSchema: explainFindingOutput,
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
      inputSchema: generateSbomInput,
      outputSchema: sbomOutput,
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
      inputSchema: listRulesInput,
      outputSchema: listRulesOutput,
      annotations: { title: "CodeInspectus List Rules", ...READ_ONLY },
    },
    async (args: ListRulesInput): Promise<ToolResult> => {
      try {
        const rules = await listRules(args);
        const { result, text: updateText } = await withDatabaseUpdate(rules, rules.engine_setup);
        const text =
          `Detection DB ${result.detection_db_version} (${result.detection_db_date}). ` +
          `Engines: ${result.engines.map((e) => `${e.display_name ? `${e.display_name} [${e.engine}]` : e.engine}@${e.version}${e.available ? "" : " (unavailable)"}`).join(", ")}. ` +
          `${result.custom_rule_count} CodeInspectus custom rules. ` +
          `${result.rule_groups.map((g) => `${g.group}: ${g.rule_count}`).join("; ")}. ` +
          `${synvoyaDatasetLine(result.synvoya_dataset)}. ` +
          `${sastRuleLanguagesLine(result.sast_rule_languages)}. ` +
          engineSetupMessage(result.engine_setup) +
          updateText;
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
