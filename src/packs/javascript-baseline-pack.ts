import {
  JAVASCRIPT_BASELINE_RULE_IDS,
  runJavaScriptBaselineCandidates,
} from "./javascript-baseline/index.js";
import type { NativeDetectorPack } from "./types.js";

export const JAVASCRIPT_BASELINE_PACK_ID = "javascript-baseline";

export const javascriptBaselinePack: NativeDetectorPack = {
  id: JAVASCRIPT_BASELINE_PACK_ID,
  version: "1.0.0",
  scannerKind: "sast",
  languages: ["javascript", "typescript"],
  frameworks: [],
  platforms: [],
  limitations: [
    "Two selected JavaScript/TypeScript crypto rules only; this is not complete SAST or language coverage.",
    "Findings are reconciled against the bundled Opengrep rules before they surface; Opengrep remains the fallback on mismatches or native parser limitations.",
    "Bounded structural parsing has no type checker, module graph, or interprocedural data flow and never executes target code.",
    "Native JavaScript/TypeScript analysis uses a lightweight lexer, not a full parser: these are pattern checks for ordinary code and can be evaded by deliberately crafted code while a file reads as parsed. When the SAST scanner runs, Opengrep's full parser still scans the same files for generic sinks; a full parser replacement is planned for 4.0.",
  ],
  isApplicable: (detectedTechnologies) => detectedTechnologies.some(
    (technology) => technology.id === "javascript" || technology.id === "typescript",
  ),
  createAnalyzers: (target) => [{
    id: "javascript-baseline-crypto",
    components: [
      "pack:javascript-baseline:dispatch",
      "javascript:bounded-structural-parser",
      "native-sast:opengrep-reconciliation",
      "sast:javascript-weak-hash",
      "sast:javascript-weak-cipher",
    ],
    ruleIds: [...JAVASCRIPT_BASELINE_RULE_IDS],
    run: async () => {
      const result = await runJavaScriptBaselineCandidates(target);
      return { findings: result.findings, notes: result.limitations, ...(result.gaps.length ? { gaps: result.gaps } : {}) };
    },
  }],
};
