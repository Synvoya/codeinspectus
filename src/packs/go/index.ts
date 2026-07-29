import type { NativeAnalyzer } from "../types.js";
import { createCachedGoProjectLoader } from "./project.js";
import {
  GO_UNSAFE_TOOL_EXECUTION_RULE_ID,
  runGoUnsafeToolExecution,
} from "./unsafe-tool-execution.js";

/** One independently-failable Go AI analyzer sharing a bounded project load. */
export function createGoAiAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedGoProjectLoader(target);
  return [{
    id: "go-unsafe-tool-execution",
    components: [
      "pack:go-ai:dispatch",
      "go:bounded-structural-parser",
      "ai:go-unsafe-tool-execution",
    ],
    ruleIds: [GO_UNSAFE_TOOL_EXECUTION_RULE_ID],
    run: async () => {
      const project = await loadProject();
      return {
        findings: await runGoUnsafeToolExecution(project),
        ...(project.limitations?.length ? { notes: project.limitations } : {}),
      };
    },
  }];
}

export * from "./project.js";
export * from "./unsafe-tool-execution.js";
