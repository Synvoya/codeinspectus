import { createReactNativeAnalyzers } from "./react-native/index.js";
import type { NativeDetectorPack } from "./types.js";

export const REACT_NATIVE_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile JavaScript/TypeScript/JSX analysis; it has no type checker, module graph, interprocedural state flow, or path-sensitive branch merge and does not claim complete React Native security coverage.",
  "Only receivers and components proven by static imports/requires and bounded source-ordered aliases are analyzed; computed properties, dynamic imports, JSX spread props, and unresolved dynamic security values fail closed.",
  "Generated, dependency, build, test, fixture, demo, sample, and example trees are excluded from project-root scans unless a supported source file is scanned directly.",
  "Unreadable, malformed, symbolic-link, over-2 MiB, over-200,000-token, or over-64-level structurally nested files and source beyond the 50,000-entry/10,000-file/64 MiB/1,000,000-token/32-level project bounds are skipped and reported in pack coverage.",
  "The pack analyzes repository evidence only, never executes target code, and does not replace runtime mobile security testing.",
] as const;

/** First-party React Native source-security pack; no target code or external scanner executes. */
export const reactNativePack: NativeDetectorPack = {
  id: "react-native",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["javascript", "typescript"],
  frameworks: ["react-native"],
  platforms: [],
  limitations: REACT_NATIVE_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => technology.id === "react-native"),
  createAnalyzers: createReactNativeAnalyzers,
};
