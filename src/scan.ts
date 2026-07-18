/**
 * Scan orchestrator (PRD §3 data flow):
 *   run engines (Opengrep/Gitleaks/Trivy) + AI-code checks as subprocesses/analyzers
 *   → normalize each SARIF into the CWE-keyed schema
 *   → dedup (global + Trivy⨯Gitleaks secret overlap)
 *   → compliance-tag each finding
 *   → sort, threshold, paginate → §5 envelope.
 *
 * Read-only: never writes to or deletes the user's files (PRD §11). Scratch SARIF
 * goes to an OS temp dir that is removed afterwards.
 */

import { randomUUID } from "node:crypto";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve as resolvePath } from "node:path";

import { DEFAULT_MAX_FINDINGS, STANDING_DISCLAIMER } from "./config.js";
import { SEVERITY_RANK } from "./types.js";
import type {
  Finding,
  ScanResult,
  EngineRunInfo,
  Severity,
  SeveritySummary,
  SecretSuppressionMetadata,
} from "./types.js";
import type { ScanInput } from "./schemas.js";
import { log } from "./logger.js";
import { saveScan } from "./store.js";

import { runOpengrep } from "./engines/opengrep.js";
import { runGitleaks } from "./engines/gitleaks.js";
import { runTrivy, type TrivyScanner } from "./engines/trivy.js";
import type { EngineOutput } from "./engines/types.js";
import { runAiChecks } from "./ai-checks/index.js";
import { normalizeEngineOutput } from "./sarif/normalize.js";
import { routeScanFindings } from "./file-routing.js";
import { detectGitSafety } from "./git-safety.js";
import { dedupFindings } from "./dedup.js";
import { tagFindings } from "./compliance/mapper.js";
import { buildComplianceOverview } from "./compliance/report.js";
import { hasUnverifiedSecretCoverage, secretSuppressionWarnings } from "./gitleaks-suppression.js";
import { PIPELINE_COMPONENT, staticComponentSignatures } from "./provenance.js";

function wants(input: ScanInput, scanner: string): boolean {
  return !input.scanners || input.scanners.length === 0 || input.scanners.includes(scanner as never);
}

function emptySummary(): SeveritySummary {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
}

function summarize(findings: Finding[]): SeveritySummary {
  const s = emptySummary();
  for (const f of findings) {
    s[f.severity]++;
    s.total++;
  }
  return s;
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;
    if (a.location.file !== b.location.file) return a.location.file < b.location.file ? -1 : 1;
    return a.location.start_line - b.location.start_line;
  });
}

export async function runScan(input: ScanInput): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const target = resolvePath(input.path);

  // Validate target exists and is a directory/file (read-only check).
  try {
    await stat(target);
  } catch {
    throw new Error(`Path not found: ${target}. Provide an absolute path to an existing directory or file.`);
  }

  const warnings: string[] = [];
  // CG-41 git-safety rail (READ-ONLY): detect the target's git state concurrently with the
  // engines. Never mutates git or the repo — only reads (rev-parse / status --porcelain).
  const gitSafetyProbe = detectGitSafety(target);
  const tmpDir = await mkdtemp(join(tmpdir(), "ci-scan-"));

  try {
    // Decide which engines/scanners to run from the scanner filter.
    const runSast = wants(input, "sast");
    const runSecret = wants(input, "secret");
    const trivyScanners: TrivyScanner[] = (["vuln", "misconfig", "secret", "license"] as TrivyScanner[]).filter(
      (s) => wants(input, s),
    );
    const runAi = wants(input, "ai");

    // Run everything concurrently.
    const tasks: Array<Promise<EngineOutput | (EngineOutput & { trivyDbDate?: string })>> = [];
    if (runSast) tasks.push(runOpengrep(target, tmpDir));
    if (runSecret) tasks.push(runGitleaks(target, tmpDir));
    let trivyTask: Promise<EngineOutput & { trivyDbDate?: string }> | undefined;
    if (trivyScanners.length) {
      trivyTask = runTrivy(target, tmpDir, trivyScanners);
      tasks.push(trivyTask);
    }
    const aiTask = runAi ? runAiChecks(target) : undefined;

    const [engineOutputs, aiResult] = await Promise.all([
      Promise.all(tasks),
      aiTask ?? Promise.resolve(undefined),
    ]);

    // Normalize engine SARIF → findings; track per-engine raw counts.
    let allFindings: Finding[] = [];
    const engineDetails: EngineRunInfo[] = [];
    let trivyDbDate: string | undefined;
    let secretCoverage: "verified" | "unverified" | undefined;
    let secretSuppression: SecretSuppressionMetadata | undefined;
    const componentSignatures: Record<string, string> = staticComponentSignatures([PIPELINE_COMPONENT]);

    for (const out of engineOutputs) {
      const normalized = out.ran ? normalizeEngineOutput(out, target) : [];
      allFindings.push(...normalized);
      if ("trivyDbDate" in out && out.trivyDbDate) trivyDbDate = out.trivyDbDate;
      if (out.engine === "gitleaks" && out.secretSuppression) {
        secretCoverage = out.ran && !hasUnverifiedSecretCoverage(out.secretSuppression)
          ? "verified"
          : "unverified";
        if (out.secretSuppression.channels.length) {
          secretSuppression = out.secretSuppression;
          warnings.push(...secretSuppressionWarnings(out.secretSuppression));
        }
      }
      Object.assign(componentSignatures, out.componentSignatures ?? {});
      engineDetails.push({
        engine: out.engine,
        version: out.version,
        available: out.available,
        ran: out.ran,
        finding_count: normalized.length,
        duration_ms: out.durationMs,
        ...(out.note ? { note: out.note } : {}),
      });
      if (!out.ran && out.note) warnings.push(`${out.engine} did not run: ${out.note}`);
    }

    if (aiResult) {
      allFindings.push(...aiResult.findings);
      Object.assign(componentSignatures, aiResult.componentSignatures);
      engineDetails.push(aiResult.info);
    }

    // CG-30 git-aware file routing: classify each finding by WHERE it lives (node_modules /
    // build output / git-ignored / tracked) and set severity+framing accordingly. Runs
    // BEFORE dedup so severity-first dedup (CG-24) operates on the corrected severities.
    const { findings: routed, stats: routeStats } = await routeScanFindings(allFindings, target);
    if (routeStats.dropped_node_modules || routeStats.dropped_build_noise || routeStats.reframed) {
      warnings.push(
        `File routing: reframed ${routeStats.reframed} git-ignored finding(s) as local-hygiene ` +
          `(lower urgency — present on local disk but not committed); dropped ` +
          `${routeStats.dropped_node_modules} in node_modules and ${routeStats.dropped_build_noise} ` +
          `non-bundle finding(s) in build output. The §6.1 client-bundle secret check still fires in build output.`,
      );
    }

    // Dedup (global + secret overlap), then compliance-tag.
    const { findings: deduped, stats } = dedupFindings(routed);
    if (stats.merged > 0) log.debug(`dedup merged ${stats.merged} overlapping findings`);
    await tagFindings(deduped);

    // Sort, threshold, assign ids, paginate.
    let sorted = sortFindings(deduped);
    if (input.severity_threshold) {
      const min = SEVERITY_RANK[input.severity_threshold];
      sorted = sorted.filter((f) => SEVERITY_RANK[f.severity] >= min);
    }
    sorted.forEach((f, i) => {
      f.id = `CI-${String(i + 1).padStart(4, "0")}`;
    });

    const summary = summarize(sorted);
    const totalBeforeLimit = sorted.length;
    const max = input.max_findings ?? DEFAULT_MAX_FINDINGS;
    const limited = sorted.slice(0, max);
    const truncated = limited.length < totalBeforeLimit;

    const enginesRun = engineDetails
      .filter((e) => e.ran)
      .map((e) => `${e.engine}@${e.version}`);

    // CG-41/CG-42: resolve the read-only git-safety probe. The structured `git_safety` field is
    // attached below; the human-readable half renders its recommendation under its own
    // "Before you fix:" line (summarize.ts), deliberately NOT under "Warnings:". Advisory only —
    // never added to `findings`, so it does not perturb severity counts/totals.
    const git_safety = await gitSafetyProbe;

    const result: ScanResult = {
      scan_id: `scan-${randomUUID()}`,
      target,
      started_at: startedAt,
      duration_ms: Date.now() - t0,
      engines_run: enginesRun,
      engine_details: engineDetails,
      offline: true,
      ...(trivyDbDate ? { trivy_db_date: trivyDbDate } : {}),
      summary,
      findings: limited,
      truncated,
      total_findings_before_limit: totalBeforeLimit,
      disclaimer: STANDING_DISCLAIMER,
      warnings,
      ...(secretCoverage ? { secret_coverage: secretCoverage } : {}),
      ...(secretSuppression ? { secret_suppression: secretSuppression } : {}),
      component_signatures: componentSignatures,
      git_safety,
      // CG-75: capture the effective config so a bare rescan is like-for-like and rescan can
      // prove re-checkability. An empty/absent scanners request means "all" — store it as
      // undefined (not []) to keep that meaning unambiguous for reuse.
      scan_config: {
        ...(input.scanners && input.scanners.length ? { scanners: input.scanners } : {}),
        ...(input.severity_threshold ? { severity_threshold: input.severity_threshold } : {}),
        max_findings: max,
      },
    };

    if (input.include_compliance !== false) {
      result.compliance_overview = await buildComplianceOverview(sorted);
    }

    await saveScan(result);
    return result;
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
