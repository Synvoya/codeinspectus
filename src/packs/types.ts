import type {
  DetectedTechnology,
  DetectorPackCoverage,
  Finding,
  SecurityControlEvidence,
  ScannerKind,
} from "../types.js";

/** Result returned by one first-party analyzer inside a native detector pack. */
export interface NativeAnalyzerResult {
  findings: Finding[];
  evidence?: SecurityControlEvidence[];
  /** Bounded, non-secret execution limitations surfaced in this pack's coverage note. */
  notes?: readonly string[];
}

/**
 * One independently-failable analyzer. Keeping this boundary preserves the existing
 * Promise.allSettled behavior: a broken detector cannot suppress sibling results.
 */
export interface NativeAnalyzer {
  id: string;
  components: readonly string[];
  ruleIds: readonly string[];
  run: () => Promise<NativeAnalyzerResult>;
}

/** Analyzer plus the immutable ownership metadata supplied by its registered pack. */
export interface RegisteredNativeAnalyzer extends NativeAnalyzer {
  packId: string;
  packVersion: string;
  packLanguages: readonly string[];
  packFrameworks: readonly string[];
  packPlatforms: readonly string[];
  packLimitations: readonly string[];
  packScannerKind: Extract<ScannerKind, "ai" | "sast">;
}

/**
 * A statically shipped CodeInspectus detector pack. Packs are compiled into the npm
 * package; this contract never loads target-provided or remotely downloaded code.
 */
export interface NativeDetectorPack {
  id: string;
  version: string;
  /** Scanner filter that selects this pack. */
  scannerKind: Extract<ScannerKind, "ai" | "sast">;
  /** Rule-specific source languages; never a claim of complete language coverage. */
  languages: readonly string[];
  /** Frameworks with at least one explicitly registered detector; never blanket coverage. */
  frameworks: readonly string[];
  /** Platforms with explicit repository-configuration coverage. */
  platforms: readonly string[];
  /** User-visible boundaries that qualify the language/framework metadata above. */
  limitations: readonly string[];
  /** Optional pure predicate used to skip packs that do not match detected project technology. */
  isApplicable?: (detectedTechnologies: readonly DetectedTechnology[]) => boolean;
  createAnalyzers: (target: string) => readonly NativeAnalyzer[];
}

/** Installed pack metadata and static counts, without claiming that anything ran. */
export interface NativePackInventory {
  pack_id: string;
  version: string;
  scanner_kind: Extract<ScannerKind, "ai" | "sast">;
  languages: string[];
  frameworks: string[];
  platforms: string[];
  analyzers: { registered: number };
  rules: { registered: number };
  limitations: string[];
}

/** Results retained by the AI runner so findings and execution accounting share one run. */
export interface NativePackExecution {
  analyzers: readonly RegisteredNativeAnalyzer[];
  results: readonly PromiseSettledResult<NativeAnalyzerResult>[];
  packCoverage: DetectorPackCoverage[];
}
