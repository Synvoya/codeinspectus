import type { NativeDetectorPack } from "./types.js";
import { createPhpAiAnalyzers } from "./php/index.js";

export const PHP_AI_PACK_LIMITATIONS = [
  "Bounded intrafile PHP analysis without a PHP parser, type resolver, Composer graph, path-sensitive branch merge, or claim of complete PHP security coverage.",
  "The rule covers exact openai-php/client or openai-php/laravel package evidence and tool-call function arguments reaching exec, system, shell_exec, or passthru; other clients, generic callables, and cross-file flow fail closed.",
  "Dataflow is bounded to direct aliases, associative json_decode extraction, one local parsing helper, one local command wrapper, and one exact mapped variadic method dispatch; checked approval/full-command allowlists and validated replacement values suppress findings.",
  "Custom validation helpers are not assumed safe; first-token executable checks do not neutralize shell metacharacters in the remaining command string.",
  "Generated, dependency, cache, build, test, fixture, demo, sample, and example trees and conventional PHP test/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, heredoc/nowdoc or malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never installs dependencies or executes target PHP, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

export const phpAiPack: NativeDetectorPack = {
  id: "php-ai",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["php"],
  frameworks: ["openai"],
  platforms: [],
  limitations: PHP_AI_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) => {
    const ids = new Set(detectedTechnologies.map((technology) => technology.id));
    return ids.has("php") && ids.has("openai");
  },
  createAnalyzers: createPhpAiAnalyzers,
};
