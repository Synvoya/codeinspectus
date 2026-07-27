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
  DetectorPackCoverage,
  DependencyCoverage,
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
import { nativePackNotRunCoverage } from "./packs/registry.js";
import { detectTechnologies } from "./technology-detection.js";
import { normalizeEngineOutput } from "./sarif/normalize.js";
import { routeScanFindings } from "./file-routing.js";
import { detectGitSafety } from "./git-safety.js";
import { dedupFindings } from "./dedup.js";
import { tagFindings } from "./compliance/mapper.js";
import { buildComplianceOverview } from "./compliance/report.js";
import { hasUnverifiedSecretCoverage, secretSuppressionWarnings } from "./gitleaks-suppression.js";
import { PIPELINE_COMPONENT, staticComponentSignatures } from "./provenance.js";
import { trivyDbProvenanceSignal } from "./trivy-db-provenance.js";
import { inspectEngineSetup } from "./engine-health.js";
import { runPubScan } from "./pub/scanner.js";
import { PROMOTED_OPENGREP_RULE_IDS, reconcileNativeSast } from "./native-sast-reconciliation.js";

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

function inactivePubCoverage(
  state: "not_run" | "not_applicable",
  note: string,
): DependencyCoverage {
  return {
    ecosystem: "Pub",
    engine: "codeinspectus-pub",
    state,
    lockfiles: { discovered: 0, analyzed: 0 },
    packages: { resolved: 0, eligible: 0, skipped: 0 },
    matching: "exact-enumerated-versions",
    limitations: [],
    note,
  };
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
  const technologyProbe = detectTechnologies(target);
  const tmpDir = await mkdtemp(join(tmpdir(), "ci-scan-"));

  try {
    // Decide which engines/scanners to run from the scanner filter.
    const runSast = wants(input, "sast");
    const runSecret = wants(input, "secret");
    const trivyScanners: TrivyScanner[] = (["vuln", "misconfig", "secret", "license"] as TrivyScanner[]).filter(
      (s) => wants(input, s),
    );
    const runAi = wants(input, "ai");
    const runVuln = wants(input, "vuln");

    // Run everything concurrently.
    const tasks: Array<Promise<EngineOutput | (EngineOutput & { trivyDbDate?: string })>> = [];
    if (runSast) tasks.push(runOpengrep(target, tmpDir));
    if (runSecret) tasks.push(runGitleaks(target, tmpDir));
    let trivyTask: Promise<EngineOutput & { trivyDbDate?: string }> | undefined;
    if (trivyScanners.length) {
      trivyTask = runTrivy(target, tmpDir, trivyScanners);
      tasks.push(trivyTask);
    }
    const nativeScannerKinds: ("ai" | "sast")[] = [
      ...(runAi ? ["ai" as const] : []),
      ...(runSast ? ["sast" as const] : []),
    ];
    const nativeTask = nativeScannerKinds.length
      ? technologyProbe.then((technologyDetection) => runAiChecks(target, {
          detectedTechnologies: technologyDetection.detected_technologies,
          scannerKinds: nativeScannerKinds,
        }))
      : undefined;
    // Always perform the bounded Pub discovery probe for vuln scans. Technology detection cannot
    // infer a language hidden behind an unreadable/symlinked subtree; the Pub loader must get a
    // chance to report that omission as partial rather than the envelope saying not_applicable.
    const pubTask = runVuln ? runPubScan(target) : undefined;

    const [engineOutputs, nativeResult, technologyDetection, pubResult] = await Promise.all([
      Promise.all(tasks),
      nativeTask ?? Promise.resolve(undefined),
      technologyProbe,
      pubTask ?? Promise.resolve(undefined),
    ]);

    if (technologyDetection.limitations.length) {
      warnings.push(
        "Technology detection was partial: " +
          technologyDetection.limitations
            .map((limitation) => `${limitation.path} (${limitation.reason})`)
            .join(", "),
      );
    }

    const packCoverage: DetectorPackCoverage[] = nativeResult?.packCoverage ?? nativePackNotRunCoverage(
      "The ai and sast scanner classes were excluded by this scan's scanner filter.",
    );
    const baselineCoverage = packCoverage.find((pack) => pack.pack_id === "javascript-baseline");
    if (baselineCoverage?.state === "ran" && baselineCoverage.note) baselineCoverage.state = "partial";
    for (const pack of packCoverage) {
      if ((pack.state === "partial" || pack.state === "unavailable") && pack.note) {
        warnings.push(`Native pack ${pack.pack_id} ${pack.state}: ${pack.note}`);
      }
    }
    const dartDetected = technologyDetection.detected_technologies.some(
      (technology) => technology.id === "dart",
    );
    const activePubResult = pubResult && (
      dartDetected || pubResult.applicability !== "not_applicable"
    ) ? pubResult : undefined;
    const dependencyCoverage: DependencyCoverage[] = [
      activePubResult?.coverage ?? (runVuln
        ? inactivePubCoverage(
            "not_applicable",
            "No Dart project signal was detected, so native Pub dependency analysis was not applicable.",
          )
        : inactivePubCoverage(
            "not_run",
            dartDetected
              ? "The vuln scanner class was excluded by this scan's scanner filter."
              : "The vuln scanner class was excluded; no Dart project signal was detected.",
          )),
    ];
    if (activePubResult && (activePubResult.coverage.state === "partial" || activePubResult.coverage.state === "unavailable")) {
      warnings.push(
        `Native Pub dependency coverage ${activePubResult.coverage.state}: ${activePubResult.coverage.note ?? "see dependency_coverage limitations"}`,
      );
    }

    // Normalize engine SARIF → findings; track per-engine raw counts.
    let allFindings: Finding[] = [];
    const engineDetails: EngineRunInfo[] = [];
    let trivyDbDate: string | undefined;
    let secretCoverage: "verified" | "unverified" | undefined;
    let secretSuppression: SecretSuppressionMetadata | undefined;
    let trivyVulnerabilityScanRan = false;
    const componentSignatures: Record<string, string> = staticComponentSignatures([PIPELINE_COMPONENT]);

    let opengrepFindings: Finding[] = [];
    let opengrepRan = false;
    for (const out of engineOutputs) {
      const normalized = out.ran ? normalizeEngineOutput(out, target) : [];
      if (out.engine === "opengrep") {
        opengrepFindings = normalized;
        opengrepRan = out.ran;
      } else {
        allFindings.push(...normalized);
      }
      if ("trivyDbDate" in out && out.trivyDbDate) trivyDbDate = out.trivyDbDate;
      if (out.engine === "trivy" && out.ran && trivyScanners.includes("vuln")) {
        trivyVulnerabilityScanRan = true;
      }
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

    if (nativeResult) {
      const sastCandidates = nativeResult.findings.filter((finding) =>
        PROMOTED_OPENGREP_RULE_IDS.has(finding.rule_id)
      );
      const otherNativeFindings = nativeResult.findings.filter((finding) =>
        !PROMOTED_OPENGREP_RULE_IDS.has(finding.rule_id)
      );
      const reconciliation = runSast
        ? reconcileNativeSast(opengrepRan, opengrepFindings, sastCandidates)
        : undefined;
      allFindings.push(
        ...otherNativeFindings,
        ...(reconciliation?.findings ?? opengrepFindings),
      );
      if (reconciliation?.note) {
        const coverage = packCoverage.find((pack) => pack.pack_id === "javascript-baseline");
        if (coverage) {
          coverage.note = [coverage.note, reconciliation.note].filter(Boolean).join(" ");
          if (!reconciliation.usedFallback) coverage.state = "partial";
        }
        if (!reconciliation.usedFallback) warnings.push(`Native pack javascript-baseline partial: ${reconciliation.note}`);
      }
      Object.assign(componentSignatures, nativeResult.componentSignatures);
      engineDetails.push({
        ...nativeResult.info,
        finding_count: otherNativeFindings.length + (reconciliation?.nativeFindings.length ?? 0),
      });
    } else {
      allFindings.push(...opengrepFindings);
    }
    if (activePubResult) {
      allFindings.push(...activePubResult.findings);
      Object.assign(componentSignatures, activePubResult.componentSignatures);
      engineDetails.push(activePubResult.info);
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
    const trivyDbProvenance = trivyDbProvenanceSignal(
      trivyVulnerabilityScanRan,
      componentSignatures,
    );

    const engineSetup = await inspectEngineSetup();
    const result: ScanResult = {
      scan_id: `scan-${randomUUID()}`,
      target,
      started_at: startedAt,
      duration_ms: Date.now() - t0,
      engines_run: enginesRun,
      engine_details: engineDetails,
      offline: true,
      detected_technologies: technologyDetection.detected_technologies,
      pack_coverage: packCoverage,
      dependency_coverage: dependencyCoverage,
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
      ...(nativeResult?.securityControlEvidence.length
        ? { security_control_evidence: nativeResult.securityControlEvidence }
        : {}),
      ...(trivyDbProvenance ? { trivy_db_provenance: trivyDbProvenance } : {}),
      engine_setup: engineSetup,
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
