import type { Engine } from "../types.js";
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
}
