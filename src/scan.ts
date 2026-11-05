/**
 * Scan orchestrator (PRD §3 data flow):
 *   run engines (Opengrep/Gitleaks/Trivy/osv-scanner) + AI-code checks as subprocesses/analyzers
 *   → normalize each SARIF into the CWE-keyed schema (osv-scanner and native Pub emit findings directly)
 *   → dedup (global + Trivy⨯Gitleaks secret overlap + package-aware vulnerability merge)
 *   → compliance-tag each finding
 *   → sort, threshold, paginate → §5 envelope.
 *
 * Read-only: never writes to or deletes the user's files (PRD §11). Scratch SARIF
 * goes to an OS temp dir that is removed afterwards.
 */

import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
import { createUnavailableRepositoryTrust } from "./repository-trust/schemas.js";
import { scanRepositoryTrust } from "./repository-trust/index.js";
import type { ScanInput } from "./schemas.js";
import { log } from "./logger.js";
import { saveScan } from "./store.js";

import { runOpengrep } from "./engines/opengrep.js";
import { runGitleaks } from "./engines/gitleaks.js";
import { runTrivy, type TrivyScanner } from "./engines/trivy.js";
import { runOsvScanner } from "./engines/osv-scanner.js";
import { osvContribution } from "./osv/contribution.js";
import { detectOsvLockfiles } from "./osv/ecosystems.js";
import type { EngineOutput } from "./engines/types.js";
import { runAiChecks } from "./ai-checks/index.js";
import { nativePackNotRunCoverage } from "./packs/registry.js";
import { detectionVisitsLinkTarget, detectTechnologies } from "./technology-detection.js";
import { normalizeEngineOutput, splitMagentoPatchFixed, type MagentoPatchSuppression } from "./sarif/normalize.js";
import { routeScanFindings, type RouteStats } from "./file-routing.js";
import { detectGitSafety } from "./git-safety.js";
import { dedupFindings } from "./dedup.js";
import { withEngineFamily } from "./synvoya/family.js";
import { isConfigurationFile, scrubCredentialContext } from "./redact.js";
import { tagFindings } from "./compliance/mapper.js";
import { buildComplianceOverview } from "./compliance/report.js";
import { hasUnverifiedSecretCoverage, secretSuppressionWarnings } from "./gitleaks-suppression.js";
import { detectTrivyInlineIgnores, trivyInlineIgnoreWarning } from "./trivy-suppression.js";
import { escapeScanDisplayText } from "./display-path.js";
import { nativeGaps } from "./native-gaps.js";
import { PIPELINE_COMPONENT, staticComponentSignatures } from "./provenance.js";
import { trivyDbProvenanceSignal } from "./trivy-db-provenance.js";
import { inspectEngineSetup } from "./engine-health.js";
import { runPubScan } from "./pub/scanner.js";
import { runSynvoyaScan, synvoyaUpstreamInputs } from "./synvoya/scanner.js";
import { enrichUpstream, foldSbomDuplicates } from "./synvoya/enrich.js";
import { PROMOTED_OPENGREP_RULE_IDS, reconcileNativeSast } from "./native-sast-reconciliation.js";
import { requireSafeScanTarget } from "./path-safety.js";
import { actionsUncheckedGap, COVERAGE_GAP_IDS, defaultScopeNotes, discoverCoverageGaps, type CoverageGap, type CoverageNote } from "./coverage-gaps.js";

function wants(input: ScanInput, scanner: string): boolean {
  return !input.scanners || input.scanners.length === 0 || input.scanners.includes(scanner as never);
}

/** The coverage note a scan carries when licence findings were left out because nobody asked for them. */
export const LICENSES_NOT_REQUESTED_NOTE: CoverageNote = {
  component: "scanner:license",
  detail: "Licence findings were not requested (use include_licenses / --licenses).",
};

/**
 * Licences are opt-in (4.0): `include_licenses`, or `license` named in `scanners`. A scanner filter that leaves
 * `license` out still wins, as it always did.
 */
function wantsLicenses(input: ScanInput): boolean {
  return input.scanners?.includes("license") === true || (input.include_licenses === true && wants(input, "license"));
}

/**
 * Whether a stored scan ran licence checks, which a rescan repeats. Scans stored before 4.0 have no recorded
 * choice: they ran licences unless their scanner filter left them out.
 */
export function scanIncludedLicenses(scan: Pick<ScanResult, "scan_config">): boolean {
  const config = scan.scan_config;
  if (config?.include_licenses !== undefined) return config.include_licenses;
  return !config?.scanners?.length || config.scanners.includes("license");
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

/** The coverage note for Trivy Magento findings provably fixed at the installed `-pN` release: count, package, file, advisories. */
function magentoPatchNote(suppressed: readonly MagentoPatchSuppression[]): string {
  const groups = new Map<string, string[]>();
  for (const entry of suppressed) {
    const key = `${entry.name} ${entry.version} in ${entry.file}`;
    groups.set(key, [...(groups.get(key) ?? []), entry.rule_id]);
  }
  const shown = [...groups].slice(0, 5).map(([key, ids]) => `${key} (${ids.length > 3 ? `${ids.slice(0, 3).join(", ")} and ${ids.length - 3} more` : ids.join(", ")})`);
  const more = groups.size > 5 ? `; and ${groups.size - 5} more package(s)` : "";
  const count = suppressed.length;
  return `Trivy orders Magento -pN patch releases before their base release, so it matched ${count} ${count === 1 ? "advisory" : "advisories"} ` +
    `that Magento ordering shows fixed at the installed release; ${count === 1 ? "it is" : "they are"} not reported: ${shown.join("; ")}${more}.`;
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

export interface ScanExecution {
  /** Complete redacted finding set persisted for export/history/baseline use. */
  canonical: ScanResult;
  /** Backward-compatible MCP/CLI view after severity and max-findings display filters. */
  display: ScanResult;
}

/**
 * Design §10.6: the file router's third-party routing, disclosed as scope notes. Code findings in the
 * path scope Opengrep's default ignore list already skips (a case-sensitive vendor/ folder, *.min.js)
 * are not reported; code findings in scripts that only look like copied libraries (by content or
 * folder name) are reported at low. Secret, credential-class and dependency findings are never routed.
 */
export function routingNotes(
  stats: Pick<RouteStats, "third_party_code" | "third_party_files" | "third_party_lowered" | "third_party_lowered_files"> &
    Partial<Pick<RouteStats, "context_lowered" | "context_lowered_rules" | "context_kept_reused">>,
): CoverageNote[] {
  const notes: CoverageNote[] = [];
  const list = (files: string[]) => {
    const shown = files.slice(0, 20);
    return shown.join(", ") + (files.length > shown.length ? ` and ${files.length - shown.length} more` : "");
  };
  if (stats.third_party_code) {
    notes.push({
      component: "routing:third-party-code",
      detail: `${stats.third_party_code} code finding(s) in ${stats.third_party_files.length} vendor/ or *.min.js script(s) are not ` +
        `reported (${list(stats.third_party_files)}): the same scope Opengrep's default ignore list skips. Secret and dependency ` +
        "findings in those files are still reported.",
    });
  }
  if (stats.third_party_lowered) {
    notes.push({
      component: "routing:third-party-lowered",
      detail: `${stats.third_party_lowered} code finding(s) in ${stats.third_party_lowered_files.length} script(s) that look like ` +
        `copied libraries (a licence banner, a UMD wrapper, a minified body or a vendors-style folder) are reported at low severity with a ` +
        `"Third-party code" label (${list(stats.third_party_lowered_files)}).`,
    });
  }
  const reused = stats.context_kept_reused ?? 0;
  if (stats.context_lowered || reused) {
    const byRule = Object.entries(stats.context_lowered_rules ?? {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([rule, count]) => `${rule} ${count}`).join(", ");
    notes.push({
      component: "routing:test-example-context",
      detail: (stats.context_lowered
        ? `${stats.context_lowered} finding(s) in test, fixture, example or documentation files are reported at low severity ` +
          `with a "Test/example context" label, never dropped (${byRule}). Only Gitleaks' generic rules (generic-api-key, ` +
          "curl-auth-header, curl-auth-user) and generic code findings are lowered; every named-provider secret, private key, " +
          "malware and vulnerability finding keeps its severity everywhere."
        : "No finding was lowered for test or example context.") +
        (reused
          ? ` ${reused} test or example secret(s) kept their severity because the same value also appears in a non-test file.`
          : ""),
    });
  }
  return notes;
}

export async function projectScanForDisplay(
  canonical: ScanResult,
  input: Pick<ScanInput, "severity_threshold" | "max_findings" | "include_compliance">,
): Promise<ScanResult> {
  let visible = canonical.findings;
  if (input.severity_threshold) {
    const min = SEVERITY_RANK[input.severity_threshold];
    visible = visible.filter((finding) => SEVERITY_RANK[finding.severity] >= min);
  }
  const totalBeforeLimit = visible.length;
  const limited = visible.slice(0, input.max_findings ?? DEFAULT_MAX_FINDINGS);
  // Rescan proof data only; kept out of the agent-facing view to protect its context window.
  const { synvoya_checked: _checked, ...shown } = canonical;
  const display: ScanResult = {
    ...shown,
    summary: summarize(visible),
    findings: limited,
    truncated: limited.length < totalBeforeLimit,
    total_findings_before_limit: totalBeforeLimit,
  };
  if (input.include_compliance === false) delete display.compliance_overview;
  else display.compliance_overview = await buildComplianceOverview(visible);
  return display;
}

export async function executeScan(
  input: ScanInput,
  options: { persist?: boolean } = {},
): Promise<ScanExecution> {
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  // One target boundary for CLI and MCP: a stable canonical regular file/directory. A symlink
  // leaf is rejected; platform ancestor aliases are collapsed before any engine receives it.
  const targetInspection = await requireSafeScanTarget(input.path);
  const target = targetInspection.canonical_path;

  const warnings: string[] = [];
  // CG-41 git-safety rail (READ-ONLY): detect the target's git state concurrently with the
  // engines. Never mutates git or the repo — only reads (rev-parse / status --porcelain).
  const gitSafetyProbe = detectGitSafety(target);
  const technologyProbe = detectTechnologies(target);
  const repositoryTrustProbe = scanRepositoryTrust(target).catch((error: unknown) => {
    warnings.push(`Repository-trust detectors unavailable: ${error instanceof Error ? error.message : "unknown detector failure"}`);
    return createUnavailableRepositoryTrust();
  });
  const gapProbe = discoverCoverageGaps(target);
  const tmpDir = await mkdtemp(join(tmpdir(), "ci-scan-"));

  try {
    // Decide which engines/scanners to run from the scanner filter.
    const runSast = wants(input, "sast");
    const runSecret = wants(input, "secret");
    const runLicenses = wantsLicenses(input);
    const trivyScanners: TrivyScanner[] = (["vuln", "misconfig", "secret", "license"] as TrivyScanner[]).filter(
      (s) => (s === "license" ? runLicenses : wants(input, s)),
    );
    const runAi = wants(input, "ai");
    const runVuln = wants(input, "vuln");

    // Run everything concurrently.
    const tasks: Array<Promise<EngineOutput | (EngineOutput & { trivyDbDate?: string })>> = [];
    if (runSast) tasks.push(runOpengrep(target, tmpDir));
    if (runSecret) tasks.push(runGitleaks(target, tmpDir));
    let trivyTask: ReturnType<typeof runTrivy> | undefined;
    const trivyIgnoreProbe = trivyScanners.includes("misconfig") ? detectTrivyInlineIgnores(target) : undefined;
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
    // Offline against the per-ecosystem OSV databases setup installed; additive to Trivy and native Pub.
    const osvTask = runVuln ? runOsvScanner(target, tmpDir) : undefined;
    // Bounded, name-only walk, run alongside the engines; used only to reconcile an osv-scanner run that happened.
    const osvLockfilesTask = runVuln ? detectOsvLockfiles(target) : undefined;
    // Synvoya gap layer (same gate as Pub): its readers start now, alongside the engines; evaluation
    // waits for the package inventory osv-scanner and Trivy produce in this scan (design §8 item 2).
    const synvoyaUpstream = runVuln
      ? Promise.all([trivyTask, osvTask]).then(([trivy, osv]) =>
          synvoyaUpstreamInputs({ trivy, trivyVulnerabilityScan: trivyScanners.includes("vuln"), osv }))
      : undefined;
    const synvoyaTask = synvoyaUpstream
      ? runSynvoyaScan(target, synvoyaUpstream.then((inputs) => inputs.inventory), synvoyaUpstream.then((inputs) => inputs.dates), { tmpDir })
      : undefined;

    const [engineOutputs, nativeResult, technologyDetection, pubResult, repositoryTrust, osvResult, osvLockfiles, synvoyaResult] = await Promise.all([
      Promise.all(tasks),
      nativeTask ?? Promise.resolve(undefined),
      technologyProbe,
      pubTask ?? Promise.resolve(undefined),
      repositoryTrustProbe,
      osvTask ?? Promise.resolve(undefined),
      osvLockfilesTask ?? Promise.resolve([]),
      synvoyaTask ?? Promise.resolve(undefined),
    ]);

    // A skipped symbolic link whose real target detection visits inside the root is the declared gap
    // symlinked-paths (Ruling 30); any other link, and every other detection limit, stays partial.
    const visitedLinks = new Set<string>();
    for (const limitation of technologyDetection.limitations) {
      if (limitation.reason === "symlink_skipped" && await detectionVisitsLinkTarget(target, limitation.path)) {
        visitedLinks.add(limitation.path);
      }
    }
    const isVisitedLink = (limitation: { reason: string; path: string }) =>
      limitation.reason === "symlink_skipped" && visitedLinks.has(limitation.path);
    const detectionLimits = technologyDetection.limitations.filter((limitation) => !isVisitedLink(limitation));
    const nativeGapEntries = [
      ...technologyDetection.limitations
        .filter(isVisitedLink)
        .map((limitation) => ({ id: "symlinked-paths" as const, path: limitation.path })),
      ...(nativeResult?.gapRecords ?? []),
    ];
    if (detectionLimits.length) {
      warnings.push(
        "Technology detection was partial: " +
          detectionLimits
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
    const osv = osvResult
      ? osvContribution(
          osvResult,
          // Lockfile detection is only for reconciling a run that happened; it never invents osv coverage.
          osvResult.info.available ? osvLockfiles : [],
          activePubResult?.coverage.state === "ran" || activePubResult?.coverage.state === "partial",
        )
      : undefined;
    if (osv) {
      dependencyCoverage.push(...osv.coverage);
      warnings.push(...osv.warnings);
    }

    // Normalize engine SARIF → findings; track per-engine raw counts.
    let allFindings: Finding[] = [];
    const engineDetails: EngineRunInfo[] = [];
    const engineGaps: CoverageGap[] = nativeGaps(nativeGapEntries);
    const engineNotes: CoverageNote[] = [];
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
        secretCoverage = out.ran && !hasUnverifiedSecretCoverage(out.secretSuppression) && !out.coverageWarnings?.length
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
      if (out.ran) {
        warnings.push(...(out.coverageWarnings ?? []));
        engineGaps.push(...(out.coverageGaps ?? []));
        for (const detail of out.coverageNotes ?? []) engineNotes.push({ component: `engine:${out.engine}`, detail });
      }
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
    if (osvResult && osv?.include) {
      allFindings.push(...osvResult.findings);
      Object.assign(componentSignatures, osvResult.componentSignatures);
      engineDetails.push(osv.info);
    }

    // Trivy orders Magento `-pN` patch releases as pre-releases (field N2): an advisory Magento ordering shows
    // fixed at the installed release is not reported, and the coverage notes name it (never a silent drop).
    const magentoPatch = splitMagentoPatchFixed(allFindings);
    allFindings = magentoPatch.kept;

    // Trivy and osv-scanner match Pub advisories by package name only. A git-sourced, custom-hosted,
    // path or SDK package with a pub.dev name is a different package, so those matches are name collisions.
    if (activePubResult?.nonOfficialPackages.length) {
      const excluded = new Set(activePubResult.nonOfficialPackages.map((pkg) => `${pkg.lockfile}\u0000${pkg.name}`));
      const before = allFindings.length;
      allFindings = allFindings.filter((finding) => {
        if ((finding.engine !== "trivy" && finding.engine !== "osv-scanner") || !finding.location.file.endsWith("pubspec.lock")) return true;
        const name = finding.package?.name;
        return !(name && excluded.has(`${finding.location.file}\u0000${name}`));
      });
      if (allFindings.length < before) {
        warnings.push(`${before - allFindings.length} Trivy or osv-scanner Pub advisory match(es) were package-name collisions with git-sourced, custom-hosted, path or SDK packages and are not reported.`);
      }
    }

    // Synvoya: enrich, never merge (PRD §9.1 rule 3). A Synvoya package finding an upstream engine
    // already reports only adds its fix to that finding's remediation; the rest stand alone.
    let synvoyaRow: EngineRunInfo | undefined;
    if (synvoyaResult) {
      // osv-scanner's findings for vendored libraries join the upstream findings (a duplicate of one an
      // upstream engine reports in the same file is folded), so a Synvoya package finding enriches them too.
      const sbom = foldSbomDuplicates(allFindings, synvoyaResult.sbomFindings);
      allFindings = allFindings.concat(sbom.kept);
      for (const gap of synvoyaResult.coverageGaps) engineGaps.push(gap);
      const enrichment = enrichUpstream(allFindings, synvoyaResult.findings);
      allFindings = [...enrichment.upstream, ...enrichment.standalone];
      Object.assign(componentSignatures, synvoyaResult.componentSignatures);
      const folded = synvoyaResult.findings.length - enrichment.standalone.length;
      const foldedNote = folded > 0
        ? ` ${folded} Synvoya finding(s) duplicated an upstream finding; ${enrichment.enriched} matching upstream finding(s) gained its fix instead.`
        : "";
      synvoyaRow = {
        ...synvoyaResult.info,
        // Recounted after routing and dedup below, so the row matches the findings shown.
        finding_count: enrichment.standalone.length,
        ...(synvoyaResult.info.note || foldedNote ? { note: `${synvoyaResult.info.note ?? ""}${foldedNote}`.trim() } : {}),
      };
      engineDetails.push(synvoyaRow);
      warnings.push(...synvoyaResult.warnings);
    }

    // CG-30 git-aware file routing: classify each finding by WHERE it lives (node_modules /
    // build output / git-ignored / tracked) and set severity+framing accordingly. Runs
    // BEFORE dedup so severity-first dedup (CG-24) operates on the corrected severities.
    const { findings: routed, stats: routeStats } = await routeScanFindings(allFindings, target);
    // Reframing git-ignored findings is context. Dropping findings is a coverage gap (the router
    // drops by path segment, so a committed build/ file can be affected), and the aggregate-coverage
    // classifier keys on the word "dropped", so only a real drop is worded that way.
    if (routeStats.reframed) {
      warnings.push(
        `File routing: ${routeStats.reframed} git-ignored finding(s) reframed as local hygiene ` +
          "(lower urgency — present on local disk but not committed).",
      );
    }
    if (routeStats.dropped_node_modules || routeStats.dropped_build_noise) {
      warnings.push(
        `File routing dropped ${routeStats.dropped_node_modules} finding(s) in node_modules and ` +
          `${routeStats.dropped_build_noise} non-bundle finding(s) in build output; they are not reported. ` +
          "The §6.1 client-bundle secret check still covers build output.",
      );
    }

    // Dedup (global + secret overlap), then compliance-tag.
    const { findings: dedupedRaw, stats } = dedupFindings(routed);
    // Display family only: runs once, after dedup, so no key, fingerprint or id ever sees it.
    const deduped = dedupedRaw.map(withEngineFamily);
    if (synvoyaRow) synvoyaRow.finding_count = deduped.filter((finding) => finding.engines.includes("synvoya")).length;
    if (stats.merged > 0) log.debug(`dedup merged ${stats.merged} overlapping findings`);
    // Single chokepoint before persistence and every presentation surface: context windows can
    // carry neighbouring or truncated credentials that per-engine redaction cannot localize.
    for (const finding of deduped) {
      const scrub = { literalValues: isConfigurationFile(finding.location.file) };
      if (finding.location.snippet) finding.location.snippet = scrubCredentialContext(finding.location.snippet, scrub);
      finding.message = scrubCredentialContext(finding.message, scrub);
      // Synvoya titles quote the declared version as written in the repository.
      if (finding.engine === "synvoya") finding.title = scrubCredentialContext(finding.title, scrub);
    }
    await tagFindings(deduped);

    // The canonical set is sorted and assigned stable display ids before ANY presentation
    // filtering. Severity/max are views only; persistence/export/history retain every finding.
    const sorted = sortFindings(deduped);
    sorted.forEach((f, i) => {
      f.id = `CI-${String(i + 1).padStart(4, "0")}`;
    });

    const summary = summarize(sorted);
    const max = input.max_findings ?? DEFAULT_MAX_FINDINGS;

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

    // Review I-6: Trivy honours in-source ignore comments it cannot be told to disregard.
    const trivyIgnores = await trivyIgnoreProbe;
    const trivyIgnoreWarning = trivyIgnores && engineDetails.some((engine) => engine.engine === "trivy" && engine.ran)
      ? trivyInlineIgnoreWarning(trivyIgnores)
      : undefined;
    if (trivyIgnoreWarning) warnings.push(trivyIgnoreWarning);

    // A gap only matters for a scanner class this scan runs: SAST gaps with sast, lockfile gaps with vuln.
    const gapDiscovery = await gapProbe;
    if (gapDiscovery.limitation) warnings.push(gapDiscovery.limitation);
    // Once the Synvoya Actions matcher ran, actions-unchecked keeps only the references it could not evaluate.
    const actionsCoverage = synvoyaResult?.actionsCoverage;
    const actionsGap = actionsCoverage
      ? actionsUncheckedGap([...(gapDiscovery.actionReferences ?? []), ...actionsCoverage.references], actionsCoverage.evaluated)
      : undefined;
    const coverageGaps = [
      ...gapDiscovery.gaps
        .filter((gap) => !(actionsCoverage && gap.id === "actions-unchecked"))
        .filter((gap) => wants(input, gap.id.endsWith("-sast") ? "sast" : "vuln")),
      ...(actionsGap ? [actionsGap] : []),
      ...engineGaps,
    ].sort((left, right) => COVERAGE_GAP_IDS.indexOf(left.id) - COVERAGE_GAP_IDS.indexOf(right.id));
    const coverageNotes: CoverageNote[] = [...defaultScopeNotes({ engine_details: engineDetails, pack_coverage: packCoverage }), ...engineNotes];
    // A user choice, like the scanner filter: a note, never a coverage gap.
    if (wants(input, "license") && !runLicenses) coverageNotes.push(LICENSES_NOT_REQUESTED_NOTE);
    if (runSast && gapDiscovery.scriptNote) coverageNotes.push({ component: "scope:scripts", detail: gapDiscovery.scriptNote });
    // Synvoya notes quote repository text (image references, declared versions): the same scrub as snippets.
    for (const detail of synvoyaResult?.notes ?? []) coverageNotes.push({ component: "engine:synvoya", detail: scrubCredentialContext(detail) });
    if (magentoPatch.suppressed.length) coverageNotes.push({ component: "engine:trivy", detail: magentoPatchNote(magentoPatch.suppressed) });
    coverageNotes.push(...routingNotes(routeStats));
    const engineSetup = await inspectEngineSetup();
    // Fix round 3: notes and warnings that can embed repository paths are escaped once, here.
    const canonical: ScanResult = escapeScanDisplayText({
      scan_id: `scan-${randomUUID()}`,
      target,
      ...(targetInspection.repository_root ? { repository_root: targetInspection.repository_root } : {}),
      started_at: startedAt,
      duration_ms: Date.now() - t0,
      engines_run: enginesRun,
      engine_details: engineDetails,
      offline: true,
      detected_technologies: technologyDetection.detected_technologies,
      pack_coverage: packCoverage,
      repository_trust: repositoryTrust,
      dependency_coverage: dependencyCoverage,
      ...(trivyDbDate ? { trivy_db_date: trivyDbDate } : {}),
      summary,
      findings: sorted,
      truncated: false,
      total_findings_before_limit: sorted.length,
      disclaimer: STANDING_DISCLAIMER,
      warnings,
      ...(secretCoverage ? { secret_coverage: secretCoverage } : {}),
      ...(secretSuppression ? { secret_suppression: secretSuppression } : {}),
      ...(coverageGaps.length ? { coverage_gaps: coverageGaps } : {}),
      ...(input.accept_gaps?.length ? { accepted_gaps: [...new Set(input.accept_gaps)] } : {}),
      ...(coverageNotes.length ? { coverage_notes: coverageNotes } : {}),
      component_signatures: componentSignatures,
      ...(synvoyaResult?.info.ran ? { synvoya_checked: synvoyaResult.evidence.checked } : {}),
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
        include_licenses: runLicenses,
      },
    });

    canonical.compliance_overview = await buildComplianceOverview(sorted);
    if (options.persist !== false) await saveScan(canonical, { canonicalFindings: true });
    return { canonical, display: await projectScanForDisplay(canonical, input) };
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

export async function runScan(input: ScanInput): Promise<ScanResult> {
  return (await executeScan(input)).display;
}
