import { SERVER_VERSION } from "../config.js";
import { redactSecretText, redactSnippet } from "../redact.js";
import type { StoredScanResult } from "../store.js";
import type { Finding, ScannerKind } from "../types.js";
import type { Severity } from "../types.js";
import type { BaselineComparison } from "../baseline.js";
import type { TriageSnapshot } from "../triage.js";
import { matchingTriageAnnotations } from "../triage.js";
import { listNativePacks } from "../packs/registry.js";
import {
  EXPORT_SCHEMA_URI,
  EXPORT_SCHEMA_VERSION,
  jsonExportSchema,
  type AggregateCoverage,
  type CoverageEvidence,
  type JsonExport,
} from "./schemas.js";

const ALL_SCANNERS: readonly ScannerKind[] = ["sast", "secret", "vuln", "misconfig", "license", "ai"];

function categoryForDetail(detail: string): CoverageEvidence["category"] {
  if (/defer|not re-?checked/i.test(detail)) return /defer/i.test(detail) ? "deferred_surface" : "not_rechecked";
  if (/incompat|unsupported|malformed|encoding|syntax/i.test(detail)) return "incompatible_surface";
  if (/bound|limit|oversiz|unreadable|symlink|excluded|skipp|drop/i.test(detail)) return "bounded_input";
  return "declared_scope";
}

function pushUnique(evidence: CoverageEvidence[], item: CoverageEvidence): void {
  if (!evidence.some((existing) =>
    existing.category === item.category && existing.component === item.component && existing.state === item.state && existing.detail === item.detail
  )) evidence.push(item);
}

function redactRecognizedSecretsDeep<T>(value: T): T {
  if (typeof value === "string") return redactSnippet(value) as T;
  if (Array.isArray(value)) return value.map(redactRecognizedSecretsDeep) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, redactRecognizedSecretsDeep(entry)])) as T;
  }
  return value;
}

export function assessAggregateCoverage(scan: StoredScanResult): {
  aggregate: AggregateCoverage;
  evidence: CoverageEvidence[];
} {
  const evidence: CoverageEvidence[] = [];
  if (scan.git_scope) {
    evidence.push({
      category: "declared_scope",
      component: `git-scope:${scan.git_scope.mode}`,
      state: scan.git_scope.completeness === "complete" ? "covered" : "partial",
      detail: scan.git_scope.completeness === "complete"
        ? `Exact Git scope enumerated ${scan.git_scope.entries.length} change record(s) with supporting repository context.`
        : `Git scope is partial: ${scan.git_scope.limitations.join(" ") || "required context was not fully inspected."}`,
    });
  }
  if (scan.history_revision) {
    evidence.push({
      category: "declared_scope",
      component: "repository-history",
      state: scan.history_revision.snapshot_completeness === "complete" ? "covered" : "partial",
      detail: scan.history_revision.snapshot_completeness === "complete"
        ? `Exact ${scan.history_revision.temporal_scope} commit snapshot ${scan.history_revision.commit} was inspected.`
        : `Repository-history snapshot is partial: ${scan.history_revision.limitations.join(" ") || "some commit content was not materialized."}`,
    });
  }
  const requested = scan.scan_config?.scanners?.length ? scan.scan_config.scanners : [...ALL_SCANNERS];
  if (!scan.canonical_findings) {
    evidence.push({
      category: "legacy_store",
      component: "scan-store",
      state: "unknown",
      detail: "This stored scan predates the V2 canonical-finding marker; severity or max-finding filtering before persistence cannot be excluded.",
    });
  }
  if (scan.truncated) {
    evidence.push({
      category: "truncation",
      component: "scan-results",
      state: "partial",
      detail: `The stored finding set was truncated (${scan.findings.length} retained of ${scan.total_findings_before_limit}).`,
    });
  }
  for (const scanner of ALL_SCANNERS) {
    if (!requested.includes(scanner)) {
      evidence.push({
        category: "excluded_input",
        component: `scanner:${scanner}`,
        state: "excluded",
        detail: `The ${scanner} scanner class was explicitly excluded by scan configuration.`,
      });
    }
  }
  const expectedEngines = new Set<string>();
  if (requested.includes("sast")) expectedEngines.add("opengrep");
  if (requested.includes("secret")) expectedEngines.add("gitleaks");
  if (requested.some((scanner) => ["secret", "vuln", "misconfig", "license"].includes(scanner))) {
    expectedEngines.add("trivy");
  }
  for (const engine of expectedEngines) {
    if (!scan.engine_details.some((detail) => detail.engine === engine)) {
      evidence.push({
        category: "component_execution",
        component: `engine:${engine}`,
        state: "unknown",
        detail: `The selected scanner scope has no persisted execution record for ${engine}.`,
      });
    }
  }
  const expectedPacks = listNativePacks()
    .filter((pack) => requested.includes(pack.scannerKind))
    .map((pack) => pack.id);
  for (const packId of expectedPacks) {
    if (!(scan.pack_coverage ?? []).some((coverage) => coverage.pack_id === packId)) {
      evidence.push({
        category: "component_execution",
        component: `pack:${packId}`,
        state: "unknown",
        detail: `The selected scanner scope has no persisted execution/applicability record for native pack ${packId}.`,
      });
    }
  }
  for (const engine of scan.engine_details) {
    evidence.push({
      category: "component_execution",
      component: `engine:${engine.engine}`,
      state: engine.ran ? "covered" : engine.available ? "partial" : "unknown",
      detail: engine.ran
        ? `${engine.engine}@${engine.version} ran and produced ${engine.finding_count} normalized finding(s).`
        : engine.note ?? `${engine.engine}@${engine.version} did not run.`,
    });
  }
  for (const pack of scan.pack_coverage ?? []) {
    const state: CoverageEvidence["state"] = pack.state === "ran"
      ? "covered"
      : pack.state === "not_applicable"
        ? "not_applicable"
        : pack.state === "not_run"
          ? "excluded"
          : pack.state === "unavailable"
            ? "unknown"
            : "partial";
    pushUnique(evidence, {
      category: "component_execution",
      component: `pack:${pack.pack_id}`,
      state,
      detail: pack.note ?? `${pack.analyzers.ran}/${pack.analyzers.registered} analyzers and ${pack.rules.ran}/${pack.rules.registered} rules ran.`,
    });
    if (pack.state === "ran" && (
      pack.analyzers.ran < pack.analyzers.registered || pack.rules.ran < pack.rules.registered
    )) {
      pushUnique(evidence, {
        category: "bounded_input",
        component: `pack:${pack.pack_id}`,
        state: "partial",
        detail: `Observed execution skipped registered coverage: ${pack.analyzers.ran}/${pack.analyzers.registered} analyzers and ${pack.rules.ran}/${pack.rules.registered} rules ran.`,
      });
    }
    for (const limitation of pack.limitations) {
      pushUnique(evidence, {
        category: categoryForDetail(limitation),
        component: `pack:${pack.pack_id}`,
        state: "informational",
        detail: limitation,
      });
    }
  }
  for (const dependency of scan.dependency_coverage ?? []) {
    const state: CoverageEvidence["state"] = dependency.state === "ran"
      ? "covered"
      : dependency.state === "not_applicable"
        ? "not_applicable"
        : dependency.state === "not_run"
          ? "excluded"
          : dependency.state === "unavailable"
            ? "unknown"
            : "partial";
    pushUnique(evidence, {
      category: "component_execution",
      component: `dependency:${dependency.engine}:${dependency.ecosystem}`,
      state,
      detail: dependency.note ?? `${dependency.lockfiles.analyzed}/${dependency.lockfiles.discovered} lockfiles analyzed.`,
    });
    if (dependency.state === "ran" && (
      dependency.lockfiles.analyzed < dependency.lockfiles.discovered || dependency.packages.skipped > 0
    )) {
      pushUnique(evidence, {
        category: "bounded_input",
        component: `dependency:${dependency.engine}:${dependency.ecosystem}`,
        state: "partial",
        detail: `Observed dependency coverage skipped ${dependency.lockfiles.discovered - dependency.lockfiles.analyzed} lockfile(s) and ${dependency.packages.skipped} package(s).`,
      });
    }
    for (const limitation of dependency.limitations) {
      pushUnique(evidence, {
        category: "dependency_limitation",
        component: `dependency:${dependency.engine}:${dependency.ecosystem}`,
        state: "partial",
        detail: limitation,
      });
    }
  }
  if (requested.includes("secret") && scan.secret_coverage !== "verified") {
    evidence.push({
      category: "secret_uncertainty",
      component: "secret-coverage",
      state: scan.secret_coverage === "unverified" ? "partial" : "unknown",
      detail: scan.secret_coverage === "unverified"
        ? "Secret coverage is explicitly unverified because a suppression or unavailable component can hide results."
        : "The scan did not record verified secret coverage.",
    });
  }
  for (const warning of scan.warnings) {
    if (!/partial|unavailable|did not run|excluded|bounded|truncat|dropped|unverified|incompat|not.re.?check/i.test(warning)) continue;
    pushUnique(evidence, {
      category: categoryForDetail(warning),
      component: "scan-pipeline",
      state: "partial",
      detail: warning,
    });
  }

  const unknown = evidence.some((item) => item.state === "unknown");
  const partial = evidence.some((item) => item.state === "partial" || item.state === "excluded");
  const covered = evidence.some((item) => item.state === "covered");
  return {
    aggregate: !scan.canonical_findings || (unknown && !covered) ? "unknown" : unknown || partial ? "partial" : "complete",
    evidence,
  };
}

/** Shared public-output projection for commands that expose stored findings. */
export function redactFindingForOutput(finding: Finding, aggregate: AggregateCoverage): JsonExport["findings"][number] {
  const producerComponents = finding.producer_components?.length
    ? [...finding.producer_components]
    : (finding.engines.length ? finding.engines : [finding.engine]).map((engine) => `engine:${engine}`);
  const secret = finding.is_secret === true;
  const scrub = (value: string): string => redactSnippet(value);
  return redactRecognizedSecretsDeep({
    ...finding,
    title: redactSnippet(finding.title),
    message: secret ? redactSecretText(finding.message, finding.rule_id) : scrub(finding.message),
    location: {
      ...finding.location,
      file: redactSnippet(finding.location.file),
      ...(finding.location.snippet !== undefined
        ? { snippet: secret ? redactSecretText(finding.location.snippet, finding.rule_id) : scrub(finding.location.snippet) }
        : {}),
    },
    remediation: {
      summary: scrub(finding.remediation.summary),
      steps: finding.remediation.steps.map(scrub),
      ...(finding.remediation.code_suggestion !== undefined ? { code_suggestion: scrub(finding.remediation.code_suggestion) } : {}),
      references: finding.remediation.references.map((reference) => redactSnippet(reference)),
    },
    producer_components: producerComponents,
    coverage_context: { aggregate, producer_components: producerComponents },
  });
}

export function createJsonExport(scan: StoredScanResult, options: {
  failOnSeverity?: Severity;
  failOnNewSeverity?: Severity;
  baseline?: BaselineComparison;
  triage?: TriageSnapshot;
} = {}): JsonExport {
  const coverage = assessAggregateCoverage(scan);
  const triageMatches = options.triage ? matchingTriageAnnotations(scan, options.triage) : [];
  const document: JsonExport = {
    $schema: EXPORT_SCHEMA_URI,
    schema_version: EXPORT_SCHEMA_VERSION,
    generated_by: { name: "codeinspectus", version: SERVER_VERSION },
    scan: {
      id: scan.scan_id,
      target: scan.target,
      started_at: scan.started_at,
      duration_ms: scan.duration_ms,
      offline: true,
      canonical_findings: scan.canonical_findings === true,
      configuration: {
        policy_mode: options.failOnNewSeverity ? "new_findings_enforcement" : options.failOnSeverity ? "enforcement" : "report_only",
        ...(options.failOnSeverity ? { fail_on_severity: options.failOnSeverity } : {}),
        ...(options.baseline ? { baseline_scan_id: options.baseline.baseline_scan_id } : {}),
        ...(options.failOnNewSeverity ? { fail_on_new_severity: options.failOnNewSeverity } : {}),
        ...(scan.scan_config?.scanners ? { scanners: scan.scan_config.scanners } : {}),
        ...(scan.scan_config?.severity_threshold ? { severity_threshold: scan.scan_config.severity_threshold } : {}),
        ...(scan.scan_config?.max_findings ? { max_findings: scan.scan_config.max_findings } : {}),
      },
      summary: scan.summary,
      ...(scan.git_scope ? { git_scope: scan.git_scope } : {}),
      ...(scan.history_revision ? { history_revision: scan.history_revision } : {}),
    },
    coverage,
    ...(options.baseline ? { baseline: {
      ...options.baseline,
      items: options.baseline.items.map((item) => ({ state: item.state, finding_id: item.finding.id, fingerprint: item.finding.fingerprint, evidence: item.evidence })),
    } } : {}),
    ...(options.triage ? { triage_store: { partial: !options.triage.available || options.triage.truncated || options.triage.corrupt_record_count > 0, matched_annotations: triageMatches.length } } : {}),
    findings: scan.findings.map((finding) => {
      const projected = redactFindingForOutput(finding, coverage.aggregate);
      const contexts = triageMatches.filter((match) => match.finding_id === finding.id).map(({ annotation }) => ({
        annotation_id: annotation.annotation_id, state: annotation.state, reason: redactSnippet(annotation.reason),
        recorded_at: annotation.recorded_at, ...(annotation.actor ? { actor: redactSnippet(annotation.actor) } : {}),
      }));
      return contexts.length ? { ...projected, triage_context: contexts } : projected;
    }),
  };
  return jsonExportSchema.parse(document);
}
