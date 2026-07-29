import type { NativeDetectorPack } from "./types.js";
import { createRubyAiAnalyzers } from "./ruby/index.js";

export const RUBY_AI_PACK_LIMITATIONS = [
  "Source-ordered intrafile Ruby analysis without a Ruby parser, type resolver, Bundler graph, path-sensitive branch merge, or claim of complete Ruby security coverage.",
  "The rule requires exact official openai production Gemfile or runtime gemspec evidence and covers Chat tool-call function arguments or explicitly typed Responses function-tool arguments reaching system, exec, IO.popen, or import-proven Open3 shell execution; lockfile-only and development-only dependencies, other clients, generic argument objects, backticks, percent-x literals, spawn APIs, and cross-file flow fail closed.",
  "Dataflow is bounded to direct aliases, JSON.parse command extraction, one local parsing helper, and one local command wrapper; checked approval/full-command allowlists and validated replacement values suppress findings.",
  "Generated, dependency, cache, build, test, spec, fixture, demo, sample, and example trees and conventional Ruby test/spec/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, heredocs, malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never installs gems or executes target Ruby, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

/** First-party official OpenAI Ruby source-security pack; target code never executes. */
export const rubyAiPack: NativeDetectorPack = {
  id: "ruby-ai",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["ruby"],
  frameworks: ["openai"],
  platforms: [],
  limitations: RUBY_AI_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) => {
    const ids = new Set(detectedTechnologies.map((technology) => technology.id));
    return ids.has("ruby") && ids.has("openai");
  },
  createAnalyzers: createRubyAiAnalyzers,
};
