import { createPythonAiApiAnalyzers } from "./python-ai-api/index.js";
import type { NativeDetectorPack } from "./types.js";

export const PYTHON_AI_API_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Python analysis with a bounded Lezer syntax gate; it has no type checker, module graph, interprocedural flow, path-sensitive branch merge, or claim of complete Python security coverage.",
  "The six rules cover exact Django, Flask, FastAPI, Starlette, Jinja, OpenAI, and Anthropic source shapes only; unsupported aliases, computed values, dynamic imports, spreads, and flows beyond the documented bounded aliases fail closed.",
  "Format strings and leading tab indentation are currently unsupported: Python 3.12 nested same-delimiter replacement strings and mixed tab-stop indentation are skipped and reported rather than risking literal text or conditional bindings being analyzed as executable direct scope.",
  "Generated, migration, dependency, build, test, fixture, demo, sample, and example trees and conventional test files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, generated headers, unreadable or malformed files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/1,000,000-token/1,000,000-node/32-level project bounds are skipped and reported in pack coverage.",
  "The pack parses repository evidence only, never imports or executes target Python, and does not replace dependency, runtime, or penetration testing.",
] as const;

const APPLICABLE_TECHNOLOGIES = new Set([
  "python", "fastapi", "starlette", "flask", "django", "jinja2", "openai", "anthropic",
]);

/** First-party Python API/AI source-security pack; target code never executes. */
export const pythonAiApiPack: NativeDetectorPack = {
  id: "python-ai-api",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["python"],
  frameworks: ["fastapi", "starlette", "flask", "django", "jinja2", "openai", "anthropic"],
  platforms: [],
  limitations: PYTHON_AI_API_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => APPLICABLE_TECHNOLOGIES.has(technology.id)),
  createAnalyzers: createPythonAiApiAnalyzers,
};
