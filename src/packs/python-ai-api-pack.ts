import { createPythonAiApiAnalyzers } from "./python-ai-api/index.js";
import type { NativeDetectorPack } from "./types.js";

export const PYTHON_AI_API_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Python analysis with a bounded Lezer syntax gate; it has no type checker, module graph, interprocedural flow, path-sensitive branch merge, or claim of complete Python security coverage.",
  "The ten rules cover exact Django, Flask, FastAPI, Starlette, Jinja, OpenAI, Anthropic, LangChain, and Python OS-command source/sink shapes only; unsupported aliases, computed values, dynamic imports, spreads, generic dispatch, and flows beyond the documented bounded aliases fail closed.",
  "Lezer-validated format strings are tokenized as opaque dynamic strings, so replacement expressions are not inspected; leading tab indentation remains unsupported and mixed tab-stop indentation is skipped and reported rather than risking conditional bindings being analyzed as executable direct scope.",
  "Generated, migration, dependency, build, test, fixture, demo, sample, and example trees and conventional test files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, generated headers, unreadable or malformed files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/1,000,000-token/1,000,000-node/32-level project bounds are skipped and reported in pack coverage.",
  "The pack parses repository evidence only, never imports or executes target Python, and does not replace dependency, runtime, or penetration testing.",
] as const;

/** First-party Python API/AI source-security pack; target code never executes. */
export const pythonAiApiPack: NativeDetectorPack = {
  id: "python-ai-api",
  version: "1.4.0",
  scannerKind: "ai",
  languages: ["python"],
  frameworks: ["fastapi", "starlette", "flask", "django", "jinja2", "openai", "anthropic", "langchain"],
  platforms: [],
  limitations: PYTHON_AI_API_PACK_LIMITATIONS,
  // Framework tags such as `openai` are ecosystem-neutral. Requiring the
  // language prevents an official OpenAI Go module from activating Python.
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => technology.id === "python"),
  createAnalyzers: createPythonAiApiAnalyzers,
};
