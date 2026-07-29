/**
 * Human-readable text summaries for tool results (the `content` block).
 * Kept compact to protect the agent's context window (PRD §5 output discipline).
 */

import type { ScanResult, RescanResult, Finding, DependencyCoverage } from "./types.js";
import { TRIVY_DB_PROVENANCE_MESSAGE } from "./trivy-db-provenance.js";
import { engineSetupMessage } from "./engine-health.js";

function technologyAndPackSummary(
  technologies: ScanResult["detected_technologies"],
  coverage: ScanResult["pack_coverage"],
): string {
  const detected = technologies.length
    ? technologies.map((technology) => technology.id).join(", ")
    : "none from supported repository signals";
  const packs = coverage.length
    ? coverage
        .map(
          (pack) =>
            `${pack.pack_id}=${pack.state} ` +
            `(${pack.analyzers.ran}/${pack.analyzers.registered} analyzers, ` +
            `${pack.rules.ran}/${pack.rules.registered} rules)` +
            (pack.note ? ` — ${pack.note}` : ""),
        )
        .join("\n  ")
    : "none registered";
  return (
    `\n\nDetected technologies: ${detected}\n` +
    `Native pack execution (registered rules only; not complete language coverage):\n  ${packs}`
  );
}

function dependencyCoverageSummary(coverage: DependencyCoverage[] | undefined): string {
  if (!coverage?.length) return "";
  const lines = coverage.map((entry) => {
    const snapshot = entry.database_version ? `, snapshot ${entry.database_version}` : "";
    const limitation = entry.note ? ` — ${entry.note}` : "";
    return (
      `${entry.ecosystem}/${entry.engine}=${entry.state} ` +
      `(${entry.lockfiles.analyzed}/${entry.lockfiles.discovered} lockfiles, ` +
      `${entry.packages.eligible}/${entry.packages.resolved} eligible packages, ` +
      `${entry.packages.skipped} skipped${snapshot})${limitation}`
    );
  });
  return `\n\nNative dependency coverage (exact locked-version matching only):\n  ${lines.join("\n  ")}`;
}

function topLines(findings: Finding[], n: number): string {
  return findings
    .slice(0, n)
    .map(
      (f) =>
        `  • [${f.severity}]${f.scope_role ? ` [${f.scope_role === "primary" ? "changed" : "supporting context"}]` : ""} ${f.title} — ${f.location.file}:${f.location.start_line} (${f.cwe.join(", ")}, ${f.engine})`,
    )
    .join("\n");
}

export function summarizeScan(r: ScanResult): string {
  const s = r.summary;
  const head =
    `CodeInspectus scan of ${r.target}\n` +
    `${s.total} findings — ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low, ${s.info} info.\n` +
    `Engines: ${r.engines_run.join(", ")} | offline: ${r.offline}` +
    (r.trivy_db_date ? ` | trivy DB: ${r.trivy_db_date}` : "") +
    (r.secret_coverage === "unverified" ? " | secret coverage: UNVERIFIED" : "");

  const engineNotes = r.engine_details
    .filter((e) => !e.ran && e.note)
    .map((e) => `  ! ${e.engine}: ${e.note}`)
    .join("\n");

  const orderedFindings = r.git_scope
    ? [...r.findings.filter((finding) => finding.scope_role === "primary"), ...r.findings.filter((finding) => finding.scope_role !== "primary")]
    : r.findings;
  const body = r.findings.length
    ? `\n\nTop findings:\n${topLines(orderedFindings, 10)}`
    : "\n\nNo findings.";

  const trunc = r.truncated
    ? `\n\n(${r.total_findings_before_limit} total before limit; ${r.findings.length} shown.)`
    : "";

  const warn = r.warnings.length ? `\n\nWarnings:\n  - ${r.warnings.join("\n  - ")}` : "";
  const eng = engineNotes ? `\n\nEngine status:\n${engineNotes}` : "";

  // CG-42: the read-only git-safety advisory gets its OWN "Before you fix:" line — deliberately
  // NOT under "Warnings:" (a non-expert reads Warnings as "problems in my code"; this is a pre-fix
  // safety nudge, not a finding). Present only for no_git / dirty (recommendation is set); silent otherwise.
  const beforeFix = r.git_safety?.recommendation
    ? `\n\nBefore you fix:\n  ${r.git_safety.recommendation}`
    : "";

  const dbProvenance = r.trivy_db_provenance?.state === "unrecorded"
    ? `\n\nCVE rescan tracking:\n  ${TRIVY_DB_PROVENANCE_MESSAGE}`
    : "";

  const engineSetup = r.engine_setup && r.engine_setup.state !== "ready"
    ? `\n\nMachine setup:\n  ${engineSetupMessage(r.engine_setup)}`
    : "";

  const controlEvidence = r.security_control_evidence?.length
    ? (() => {
        const counts = {
          verified_in_repository: 0,
          insecure_configuration_found: 0,
          not_verifiable_from_repository: 0,
        };
        for (const record of r.security_control_evidence!) counts[record.state]++;
        return (
          "\n\nRuntime-control evidence (metadata; no absence penalty):\n" +
          `  ${counts.verified_in_repository} verified in repository | ` +
          `${counts.insecure_configuration_found} explicit insecure configuration | ` +
          `${counts.not_verifiable_from_repository} not verifiable from repository`
        );
      })()
    : "";

  const nativeCoverage = technologyAndPackSummary(r.detected_technologies, r.pack_coverage);
  const dependencyCoverage = dependencyCoverageSummary(r.dependency_coverage);
  const gitScope = r.git_scope
    ? `\n\nGit scope: ${r.git_scope.mode} | base=${r.git_scope.base.commit}` +
      (r.git_scope.head ? ` | head=${r.git_scope.head.commit}` : " | head=working-tree") +
      ` | ${r.git_scope.entries.length} change record(s) | ${r.git_scope.primary_finding_count} changed-path finding(s) | ${r.git_scope.supporting_context_finding_count} supporting-context finding(s) | ${r.git_scope.completeness}`
    : "";

  return `${head}${gitScope}${nativeCoverage}${dependencyCoverage}${body}${trunc}${controlEvidence}${dbProvenance}${engineSetup}${beforeFix}${eng}${warn}\n\n${r.disclaimer}`;
}

export function summarizeRescan(r: RescanResult): string {
  // CG-75: findings the rescan could not re-check get their OWN section and are explicitly
  // NOT presented as resolved — a false "you fixed it" on a live security finding is the exact
  // failure this guards against. Surfaced in both this text and structuredContent.
  const notRechecked = r.not_rechecked.length
    ? `\n\nCould not re-check — NOT confirmed resolved:\n${topLines(r.not_rechecked, 10)}` +
      (r.not_rechecked_note ? `\n  ⚠ ${r.not_rechecked_note}` : "")
    : "";

  return (
    `CodeInspectus rescan of ${r.target} (vs ${r.prior_scan_id})\n` +
    `Resolved: ${r.summary.resolved} | Remaining: ${r.summary.remaining} | ` +
    `Newly introduced: ${r.summary.introduced} | Not re-checked: ${r.summary.not_rechecked}` +
    technologyAndPackSummary(r.detected_technologies, r.pack_coverage) +
    dependencyCoverageSummary(r.dependency_coverage) +
    (r.introduced.length ? `\n\nNewly introduced:\n${topLines(r.introduced, 10)}` : "") +
    (r.remaining.length ? `\n\nStill present:\n${topLines(r.remaining, 10)}` : "") +
    notRechecked +
    `\n\n${r.disclaimer}`
  );
}
