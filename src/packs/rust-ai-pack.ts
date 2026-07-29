import type { NativeDetectorPack } from "./types.js";
import { createRustAiAnalyzers } from "./rust/index.js";

export const RUST_AI_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Rust analysis without rustc, a Rust parser, type resolution, a Cargo graph, path-sensitive branch merge, or claim of complete Rust security coverage.",
  "The rule covers exact community async-openai package evidence and recognized tool-call arguments reaching an import-proven standard/tokio process shell or a literal bollard Docker exec shell vector; other clients, generic dispatch, renamed external wrappers, and cross-crate flow fail closed.",
  "Dataflow is bounded to direct aliases, serde_json extraction, one recognized generate_function_call result, and one local command wrapper; checked approval/allowlist rejection and validated replacement values suppress findings.",
  "Generated, dependency, build, benchmark, test, fixture, demo, sample, and example trees and conventional Rust test/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; individual structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never fetches crates, builds, or executes target Rust, and does not replace dependency, runtime, sandbox, container-isolation, or penetration testing.",
] as const;

/** First-party Rust AI source-security pack; target code never executes. */
export const rustAiPack: NativeDetectorPack = {
  id: "rust-ai",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["rust"],
  frameworks: ["openai"],
  platforms: [],
  limitations: RUST_AI_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) => {
    const ids = new Set(detectedTechnologies.map((technology) => technology.id));
    return ids.has("rust") && ids.has("openai");
  },
  createAnalyzers: createRustAiAnalyzers,
};
