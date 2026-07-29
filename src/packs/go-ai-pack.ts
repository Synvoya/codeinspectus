import type { NativeDetectorPack } from "./types.js";
import { createGoAiAnalyzers } from "./go/index.js";

export const GO_AI_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Go analysis without a type checker, module graph, path-sensitive branch merge, or claim of complete Go security coverage.",
  "The rule covers exact official OpenAI Go Chat Completions tool-call arguments reaching import-proven os/exec shell interpreters; Anthropic, Gemini, custom model types, generic dispatch, renamed external wrappers, and cross-module flow fail closed.",
  "Dataflow is bounded to direct aliases, encoding/json unmarshal, one local JSON parsing helper, and one local command wrapper; checked approval/allowlist rejection and validated replacement values suppress findings.",
  "Generated, dependency, build, test, fixture, demo, sample, and example trees and conventional _test.go/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; individual structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never builds or executes target Go, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

/** First-party Go AI source-security pack; target code never executes. */
export const goAiPack: NativeDetectorPack = {
  id: "go-ai",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["go"],
  frameworks: ["openai"],
  platforms: [],
  limitations: GO_AI_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) => {
    const ids = new Set(detectedTechnologies.map((technology) => technology.id));
    return ids.has("go") && ids.has("openai");
  },
  createAnalyzers: createGoAiAnalyzers,
};
