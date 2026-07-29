import type { NativeAnalyzer } from "../types.js";
import { createCachedRubyProjectLoader } from "./project.js";
import {
  RUBY_UNSAFE_TOOL_EXECUTION_RULE_ID,
  runRubyUnsafeToolExecution,
} from "./unsafe-tool-execution.js";

/** One independently-failable Ruby AI analyzer sharing a bounded project load. */
export function createRubyAiAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedRubyProjectLoader(target);
  return [{
    id: "ruby-unsafe-tool-execution",
    components: [
      "pack:ruby-ai:dispatch",
      "ruby:bounded-structural-parser",
      "ai:ruby-unsafe-tool-execution",
    ],
    ruleIds: [RUBY_UNSAFE_TOOL_EXECUTION_RULE_ID],
    run: async () => {
      const project = await loadProject();
      return {
        findings: await runRubyUnsafeToolExecution(project),
        ...(project.limitations?.length ? { notes: project.limitations } : {}),
      };
    },
  }];
}

export * from "./project.js";
export * from "./unsafe-tool-execution.js";
