import type { NativeDetectorPack } from "./types.js";
import { createJavaAiAnalyzers } from "./java/index.js";

export const JAVA_AI_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Java analysis without a type checker, module graph, path-sensitive branch merge, or claim of complete Java security coverage.",
  "The rule covers exact official OpenAI Java tool-call argument types reaching an actually-started recognized ProcessBuilder or Runtime shell interpreter; Spring AI, LangChain4j, Azure OpenAI, other model types, generic dispatch, and cross-module flow fail closed.",
  "Dataflow is bounded to direct aliases, one local parsing helper, and one local command wrapper; checked approval/allowlist rejection and validated replacement values suppress findings.",
  "Generated, dependency, build, test, fixture, demo, sample, and top-level example trees and conventional Java test/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, malformed strings/comments, Java text blocks, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; individual structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never builds or executes target Java, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

/** First-party Java AI source-security pack; target code never executes. */
export const javaAiPack: NativeDetectorPack = {
  id: "java-ai",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["java"],
  frameworks: ["openai"],
  platforms: [],
  limitations: JAVA_AI_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) => {
    const ids = new Set(detectedTechnologies.map((technology) => technology.id));
    return ids.has("java") && ids.has("openai");
  },
  createAnalyzers: createJavaAiAnalyzers,
};
