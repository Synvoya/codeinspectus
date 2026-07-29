import type { NativeAnalyzer } from "../types.js";
import { createCachedPhpProjectLoader } from "./project.js";
import { PHP_UNSAFE_TOOL_EXECUTION_RULE_ID, runPhpUnsafeToolExecution } from "./unsafe-tool-execution.js";

export function createPhpAiAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedPhpProjectLoader(target);
  return [{
    id: "php-unsafe-tool-execution",
    components: [
      "pack:php-ai:dispatch",
      "php:bounded-structural-parser",
      "ai:php-unsafe-tool-execution",
    ],
    ruleIds: [PHP_UNSAFE_TOOL_EXECUTION_RULE_ID],
    run: async () => {
      const project = await loadProject();
      return {
        findings: await runPhpUnsafeToolExecution(project),
        ...(project.limitations?.length ? { notes: project.limitations } : {}),
      };
    },
  }];
}

export * from "./project.js";
export * from "./unsafe-tool-execution.js";
