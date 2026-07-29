import type { NativeAnalyzer } from "../types.js";
import { createCachedRustProjectLoader } from "./project.js";
import {
  RUST_UNSAFE_TOOL_EXECUTION_RULE_ID,
  runRustUnsafeToolExecution,
} from "./unsafe-tool-execution.js";

/** One independently-failable Rust AI analyzer sharing a bounded project load. */
export function createRustAiAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedRustProjectLoader(target);
  return [{
    id: "rust-unsafe-tool-execution",
    components: [
      "pack:rust-ai:dispatch",
      "rust:bounded-structural-parser",
      "ai:rust-unsafe-tool-execution",
    ],
    ruleIds: [RUST_UNSAFE_TOOL_EXECUTION_RULE_ID],
    run: async () => {
      const project = await loadProject();
      return {
        findings: await runRustUnsafeToolExecution(project),
        ...(project.limitations?.length ? { notes: project.limitations } : {}),
      };
    },
  }];
}

export * from "./project.js";
export * from "./unsafe-tool-execution.js";
