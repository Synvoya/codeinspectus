/**
 * Human-readable text summaries for tool results (the `content` block).
 * Kept compact to protect the agent's context window (PRD §5 output discipline).
 */

import type { ScanResult, RescanResult, Finding } from "./types.js";

function topLines(findings: Finding[], n: number): string {
  return findings
    .slice(0, n)
    .map(
      (f) =>
        `  • [${f.severity}] ${f.title} — ${f.location.file}:${f.location.start_line} (${f.cwe.join(", ")}, ${f.engine})`,
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

  const body = r.findings.length
    ? `\n\nTop findings:\n${topLines(r.findings, 10)}`
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

  return `${head}${body}${trunc}${beforeFix}${eng}${warn}\n\n${r.disclaimer}`;
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
    (r.introduced.length ? `\n\nNewly introduced:\n${topLines(r.introduced, 10)}` : "") +
    (r.remaining.length ? `\n\nStill present:\n${topLines(r.remaining, 10)}` : "") +
    notRechecked +
    `\n\n${r.disclaimer}`
  );
}
