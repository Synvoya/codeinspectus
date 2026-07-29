import {
  DEFAULT_MAX_FINDINGS,
  ENGINE_TIMEOUT_MS,
  MAX_BUFFER_BYTES,
  SERVER_VERSION,
} from "./config.js";
import { inspectEngineSetup } from "./engine-health.js";
import { listNativePacks } from "./packs/registry.js";
import {
  inspectOutputDirectory,
  inspectOutputFile,
  inspectTargetPath,
  outputContainmentRoot,
  type OutputPathInspection,
  type TargetPathInspection,
} from "./path-safety.js";
import { detectTechnologies, type TechnologyInspectionLimitation } from "./technology-detection.js";
import type { DetectedTechnology, EngineSetupStatus, ScannerKind, Severity } from "./types.js";

export const ALL_SCANNERS: readonly ScannerKind[] = [
  "sast",
  "secret",
  "vuln",
  "misconfig",
  "license",
  "ai",
];

export type CliOutputFormat = "text" | "json" | "sarif" | "csv";

export interface CliScanConfiguration {
  scanners?: ScannerKind[];
  severity_threshold?: Severity;
  max_findings?: number;
  output_directory?: string;
  output_file?: string;
  output_format?: CliOutputFormat;
  allow_output_in_target?: boolean;
  include_compliance?: boolean;
  fail_on_severity?: Severity;
  baseline_scan_id?: string;
  fail_on_new_severity?: Severity;
  git_scope?: { mode: "commit_diff" | "working_tree"; base: string; head?: string };
}

export interface PreflightPackApplicability {
  pack_id: string;
  version: string;
  scanner: "ai" | "sast";
  selected: boolean;
  state: "applicable" | "not_applicable" | "unknown";
  reason: string;
}

export interface PreflightScannerApplicability {
  scanner: ScannerKind;
  selected: boolean;
  components: string[];
  state: "applicable" | "not_applicable" | "unknown";
  reason: string;
}

export interface PreflightResult {
  schema_version: "1.0.0";
  codeinspectus_version: string;
  offline: true;
  writes_repository: false;
  ready: boolean;
  target: TargetPathInspection;
  output: OutputPathInspection;
  configuration: {
    scanners: ScannerKind[];
    severity_threshold: Severity;
    max_findings: number;
    output_format: CliOutputFormat;
    output_directory?: string;
    output_file?: string;
    include_compliance: boolean;
  };
  effective_limits: {
    max_findings: number;
    engine_timeout_ms: number;
    engine_output_max_bytes: number;
  };
  detected_technologies: DetectedTechnology[];
  technology_detection_limitations: TechnologyInspectionLimitation[];
  scanner_applicability: PreflightScannerApplicability[];
  native_pack_applicability: PreflightPackApplicability[];
  engine_setup: EngineSetupStatus;
  engine_integrity: Array<{
    engine: "opengrep" | "gitleaks" | "trivy";
    version: string;
    selected: boolean;
    state: string;
    hash_provenance: "verified" | "unverified";
    detail?: string;
  }>;
  trivy_database: {
    selected: boolean;
    state: EngineSetupStatus["trivy_db"]["state"];
    provenance: "recorded" | "unrecorded";
    downloaded_at?: string;
  };
  repair: {
    required_for_selected_scope: boolean;
    network_required: boolean;
    command?: string;
  };
  errors: string[];
  warnings: string[];
}

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

function selectedExternalEngines(scanners: readonly ScannerKind[]): Array<"opengrep" | "gitleaks" | "trivy"> {
  return unique([
    ...(scanners.includes("sast") ? ["opengrep" as const] : []),
    ...(scanners.includes("secret") ? ["gitleaks" as const] : []),
    ...(scanners.some((scanner) => ["secret", "vuln", "misconfig", "license"].includes(scanner))
      ? ["trivy" as const]
      : []),
  ]);
}

function scannerComponents(scanner: ScannerKind): string[] {
  switch (scanner) {
    case "sast": return ["opengrep", "native javascript-baseline pack"];
    case "secret": return ["gitleaks", "trivy secret scanner", "applicable native secret checks"];
    case "vuln": return ["trivy vulnerability scanner", "native Pub advisory matcher when applicable"];
    case "misconfig": return ["trivy misconfiguration scanner"];
    case "license": return ["trivy license scanner"];
    case "ai": return ["applicable first-party native packs"];
  }
}

function nativePackApplicability(
  selectedScanners: readonly ScannerKind[],
  technologies: readonly DetectedTechnology[],
  limitations: readonly TechnologyInspectionLimitation[],
): PreflightPackApplicability[] {
  return listNativePacks().map((pack) => {
    const selected = selectedScanners.includes(pack.scannerKind);
    const applicable = pack.isApplicable?.(technologies) ?? true;
    const unknown = !applicable && limitations.length > 0;
    return {
      pack_id: pack.id,
      version: pack.version,
      scanner: pack.scannerKind,
      selected,
      state: applicable ? "applicable" : unknown ? "unknown" : "not_applicable",
      reason: !selected
        ? `The ${pack.scannerKind} scanner class is not selected.`
        : applicable
          ? "Detected repository technology matches this pack's bounded applicability predicate."
          : unknown
            ? "No matching technology was detected, but technology inspection had limitations."
            : "No detected repository technology matches this pack.",
    };
  });
}

function scannerApplicability(
  selectedScanners: readonly ScannerKind[],
  packs: readonly PreflightPackApplicability[],
): PreflightScannerApplicability[] {
  return ALL_SCANNERS.map((scanner) => {
    const selected = selectedScanners.includes(scanner);
    if (scanner !== "ai") {
      return {
        scanner,
        selected,
        components: scannerComponents(scanner),
        state: "applicable",
        reason: selected
          ? "The selected commodity scanner accepts regular file and directory targets; bounded native additions run only when applicable."
          : "Scanner not selected.",
      };
    }
    const relevant = packs.filter((pack) => pack.scanner === "ai" && pack.selected);
    const state = relevant.some((pack) => pack.state === "applicable")
      ? "applicable"
      : relevant.some((pack) => pack.state === "unknown")
        ? "unknown"
        : "not_applicable";
    return {
      scanner,
      selected,
      components: scannerComponents(scanner),
      state,
      reason: !selected
        ? "Scanner not selected."
        : state === "applicable"
          ? "At least one bounded first-party native pack is applicable."
          : state === "unknown"
            ? "Applicability is unknown because technology inspection was limited."
            : "No first-party native pack applies to the detected repository technologies.",
    };
  });
}

export async function runPreflight(
  targetInput: string,
  requested: CliScanConfiguration = {},
): Promise<PreflightResult> {
  const scanners = unique(requested.scanners?.length ? requested.scanners : ALL_SCANNERS);
  const severity = requested.severity_threshold ?? "info";
  const maxFindings = requested.max_findings ?? DEFAULT_MAX_FINDINGS;
  const outputFormat = requested.output_format ?? "text";
  const includeCompliance = requested.include_compliance ?? true;
  const target = await inspectTargetPath(targetInput);
  const output = requested.output_file
    ? await inspectOutputFile(
        requested.output_file,
        target.supported ? outputContainmentRoot(target) : undefined,
        true,
      )
    : await inspectOutputDirectory(
        requested.output_directory,
        target.supported ? outputContainmentRoot(target) : undefined,
        requested.allow_output_in_target ?? false,
      );
  const [technology, engineSetup] = await Promise.all([
    target.supported && target.canonical_path
      ? detectTechnologies(target.canonical_path)
      : Promise.resolve({ detected_technologies: [], limitations: [] }),
    inspectEngineSetup(),
  ]);
  const packs = nativePackApplicability(scanners, technology.detected_technologies, technology.limitations);
  const applicability = scannerApplicability(scanners, packs);
  const selectedEngines = selectedExternalEngines(scanners);
  const selectedTrivyDatabase = scanners.includes("vuln");
  const selectedEngineBroken = engineSetup.engines.some(
    (engine) => selectedEngines.includes(engine.engine) && engine.state !== "ready",
  );
  const selectedDbMissing = selectedTrivyDatabase && engineSetup.trivy_db.state === "missing";
  const repairRequired = selectedEngineBroken || selectedDbMissing;
  const errors = [
    ...(!target.exists || !target.supported || !target.symlink_safe
      ? [target.error ?? "Target is not safe to scan."]
      : []),
    ...(!output.safe ? [output.error ?? "Output directory is unsafe."] : []),
  ];
  const warnings = [
    ...(technology.limitations.length
      ? [`Technology detection reported ${technology.limitations.length} bounded or unreadable input(s).`]
      : []),
    ...(selectedTrivyDatabase && ["provenance_missing", "stale"].includes(engineSetup.trivy_db.state)
      ? [`Trivy vulnerability database state is ${engineSetup.trivy_db.state}; current findings may run, but provenance/freshness continuity is limited.`]
      : []),
    ...(repairRequired ? ["Selected scanner scope requires engine or vulnerability-database repair before complete execution."] : []),
  ];

  return {
    schema_version: "1.0.0",
    codeinspectus_version: SERVER_VERSION,
    offline: true,
    writes_repository: false,
    ready: errors.length === 0 && !repairRequired,
    target,
    output,
    configuration: {
      scanners,
      severity_threshold: severity,
      max_findings: maxFindings,
      output_format: outputFormat,
      ...(requested.output_directory ? { output_directory: requested.output_directory } : {}),
      ...(requested.output_file ? { output_file: requested.output_file } : {}),
      include_compliance: includeCompliance,
    },
    effective_limits: {
      max_findings: maxFindings,
      engine_timeout_ms: ENGINE_TIMEOUT_MS,
      engine_output_max_bytes: MAX_BUFFER_BYTES,
    },
    detected_technologies: technology.detected_technologies,
    technology_detection_limitations: technology.limitations,
    scanner_applicability: applicability,
    native_pack_applicability: packs,
    engine_setup: engineSetup,
    engine_integrity: engineSetup.engines.map((engine) => ({
      engine: engine.engine,
      version: engine.version,
      selected: selectedEngines.includes(engine.engine),
      state: engine.state,
      hash_provenance: engine.state === "ready" ? "verified" : "unverified",
      ...(engine.detail ? { detail: engine.detail } : {}),
    })),
    trivy_database: {
      selected: selectedTrivyDatabase,
      state: engineSetup.trivy_db.state,
      provenance: engineSetup.trivy_db.state === "provenance_missing" || engineSetup.trivy_db.state === "missing"
        ? "unrecorded"
        : "recorded",
      ...(engineSetup.trivy_db.downloaded_at ? { downloaded_at: engineSetup.trivy_db.downloaded_at } : {}),
    },
    repair: {
      required_for_selected_scope: repairRequired,
      network_required: repairRequired && engineSetup.network_required,
      ...(repairRequired && engineSetup.repair_command ? { command: engineSetup.repair_command } : {}),
    },
    errors,
    warnings,
  };
}

export function summarizePreflight(result: PreflightResult): string {
  const target = result.target.canonical_path ?? result.target.resolved_path;
  const lines = [
    `CodeInspectus v${result.codeinspectus_version} preflight`,
    `Target: ${target} (${result.target.type ?? "unavailable"})`,
    `Status: ${result.ready ? "ready" : "not ready"} | offline: yes | repository writes: none`,
    `Scanners: ${result.configuration.scanners.join(", ")}`,
    `Limits: max ${result.effective_limits.max_findings} findings; engine timeout ${result.effective_limits.engine_timeout_ms}ms`,
    `Engine setup: ${result.engine_setup.state}; Trivy DB: ${result.trivy_database.state}; repair network required: ${result.repair.network_required}`,
    `Output: ${result.output.mode === "stdout" ? "stdout" : `${result.output.resolved_path} (${result.output.safe ? "safe" : "unsafe"})`}`,
  ];
  if (result.errors.length) lines.push(`Errors:\n  - ${result.errors.join("\n  - ")}`);
  if (result.warnings.length) lines.push(`Warnings:\n  - ${result.warnings.join("\n  - ")}`);
  return `${lines.join("\n")}\n`;
}
