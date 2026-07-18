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
  /** Detector-component signatures captured before execution for rescan equivalence proof. */
  componentSignatures?: Record<string, string>;
}
