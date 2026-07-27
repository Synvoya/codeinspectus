import { createExpoAnalyzers } from "./expo/index.js";
import type { NativeDetectorPack } from "./types.js";

export const EXPO_PACK_LIMITATIONS = [
  "Parses app.json/app.config.json and direct static app.config JavaScript/TypeScript object exports at the scan root and bounded nested package roots; it never imports, evaluates, transpiles, or executes target configuration.",
  "Comments and trailing commas are supported, but spreads, functions, computed keys, branches, unresolved aliases, duplicate keys, ambiguous config files, and unsupported or malformed syntax encountered in the exported static-object subset suppress findings and are reported as coverage notes; unrelated module statements are not fully syntax-validated.",
  "The secret rule covers sensitive non-EXPO_PUBLIC process.env references and one-hop const aliases in public Expo config paths; Expo's hooks, ios.config, android.config, and update code-signing fields are excluded.",
  "The update rule covers explicit enabled/default-enabled non-local production HTTP URLs without a literal signing certificate; dynamic fields, HTTPS, local/private/reserved/example URLs, disabled updates, and signed updates are excluded.",
  "Symbolic links and generated/corpus trees are skipped; discovery is bounded to 20,000 entries, 500 package roots, and 24 levels. Individual configs are limited to 1 MiB/100,000 tokens; aggregate package/config reads are limited to 4,096 files/4 MiB and static parsing to 250,000 tokens/25,000 properties.",
] as const;

/** First-party Expo repository-configuration pack; target config never executes. */
export const expoPack: NativeDetectorPack = {
  id: "expo",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["javascript", "typescript", "json"],
  frameworks: ["expo"],
  platforms: [],
  limitations: EXPO_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => technology.id === "expo"),
  createAnalyzers: createExpoAnalyzers,
};
