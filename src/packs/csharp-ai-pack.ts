import type { NativeDetectorPack } from "./types.js";
import { createCsharpAiAnalyzers } from "./csharp/index.js";

export const CSHARP_AI_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile C# analysis without a compiler, semantic model, project graph, path-sensitive branch merge, or claim of complete .NET security coverage.",
  "The rule covers exact official OpenAI .NET ChatToolCall FunctionArguments reaching an actually-started recognized System.Diagnostics.Process shell; Azure OpenAI, Semantic Kernel, Microsoft.Extensions.AI, other model types, generic dispatch, and cross-project flow fail closed.",
  "Dataflow is bounded to direct aliases, System.Text.Json dictionary/property extraction, one local parsing helper, and one local command wrapper; checked approval/allowlist rejection and validated replacement values suppress findings.",
  "Generated, dependency, build, publish, test, fixture, demo, sample, and example trees and conventional C# test/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; raw string contents are treated as opaque and individual structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never restores, builds, or executes target .NET code, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

/** First-party C# AI source-security pack; target code never executes. */
export const csharpAiPack: NativeDetectorPack = {
  id: "csharp-ai",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["csharp"],
  frameworks: ["openai"],
  platforms: [],
  limitations: CSHARP_AI_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) => {
    const ids = new Set(detectedTechnologies.map((technology) => technology.id));
    return ids.has("csharp") && ids.has("openai");
  },
  createAnalyzers: createCsharpAiAnalyzers,
};
