import { createFlutterAnalyzers } from "./flutter/index.js";
import type { NativeDetectorPack } from "./types.js";

/** First-party Flutter/Dart source-security pack; no target code or external scanner executes. */
export const flutterPack: NativeDetectorPack = {
  id: "flutter",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["dart"],
  frameworks: ["flutter"],
  platforms: [],
  limitations: [
    "Token-aware, source-ordered intrafile Dart analysis; it has no type resolution or path-sensitive branch merge and does not claim complete Flutter security coverage.",
    "Generated files and test/example corpora are excluded from project-root scans unless scanned directly.",
    "Unreadable Dart files, files over 2 MiB, and source beyond the 10,000-file/64 MiB project bounds are skipped and reported in pack coverage.",
    "The pack analyzes repository evidence only and does not replace runtime mobile security testing.",
  ],
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => technology.id === "flutter"),
  createAnalyzers: createFlutterAnalyzers,
};
