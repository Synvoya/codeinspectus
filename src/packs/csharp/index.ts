import type { NativeAnalyzer } from "../types.js";
import { createCachedCsharpProjectLoader } from "./project.js";
import {
  CSHARP_UNSAFE_TOOL_EXECUTION_RULE_ID,
  runCsharpUnsafeToolExecution,
} from "./unsafe-tool-execution.js";

/** One independently-failable C# AI analyzer sharing a bounded project load. */
export function createCsharpAiAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedCsharpProjectLoader(target);
  return [{
    id: "csharp-unsafe-tool-execution",
    components: [
      "pack:csharp-ai:dispatch",
      "csharp:bounded-structural-parser",
      "ai:csharp-unsafe-tool-execution",
    ],
    ruleIds: [CSHARP_UNSAFE_TOOL_EXECUTION_RULE_ID],
    run: async () => {
      const project = await loadProject();
      return {
        findings: await runCsharpUnsafeToolExecution(project),
        ...(project.limitations?.length ? { notes: project.limitations } : {}),
      };
    },
  }];
}

export * from "./project.js";
export * from "./unsafe-tool-execution.js";
