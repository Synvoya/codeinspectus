import type { CoverageGap } from "../coverage-gaps.js";
import type { Engine, SecretSuppressionMetadata } from "../types.js";
import type { SarifLog } from "../sarif/types.js";

export interface EngineOutput {
  engine: Engine;
  version: string;
  available: boolean;
  ran: boolean;
  sarif?: SarifLog;
  durationMs: number;
  /** Actionable note when the engine could not run. */
  note?: string;
  /** Gitleaks-only redacted metadata about target-controlled suppression surfaces. */
  secretSuppression?: SecretSuppressionMetadata;
  /** Coverage limits the engine reported while it ran; each one makes scan coverage partial. */
  coverageWarnings?: string[];
  /** Declared coverage gaps the engine reported while it ran (acceptable by id with accept_gaps). */
  coverageGaps?: CoverageGap[];
  /** Detector-component signatures captured before execution for rescan equivalence proof. */
  componentSignatures?: Record<string, string>;
}
