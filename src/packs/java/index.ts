import type { NativeAnalyzer } from "../types.js";
import { createCachedJavaProjectLoader } from "./project.js";
import {
  JAVA_UNSAFE_TOOL_EXECUTION_RULE_ID,
  runJavaUnsafeToolExecution,
} from "./unsafe-tool-execution.js";

/** One independently-failable Java AI analyzer sharing a bounded project load. */
export function createJavaAiAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedJavaProjectLoader(target);
  return [{
    id: "java-unsafe-tool-execution",
    components: [
      "pack:java-ai:dispatch",
      "java:bounded-structural-parser",
      "ai:java-unsafe-tool-execution",
    ],
    ruleIds: [JAVA_UNSAFE_TOOL_EXECUTION_RULE_ID],
    run: async () => {
      const project = await loadProject();
      return {
        findings: await runJavaUnsafeToolExecution(project),
        ...(project.limitations?.length ? { notes: project.limitations } : {}),
      };
    },
  }];
}

export * from "./project.js";
export * from "./unsafe-tool-execution.js";
