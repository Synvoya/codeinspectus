import {
  ANDROID_CONFIG_RULE_IDS,
  runAndroidConfig,
} from "./android/android-config.js";
import type { NativeDetectorPack } from "./types.js";

export const ANDROID_PACK_LIMITATIONS = [
  "Parses explicit repository AndroidManifest.xml and referenced Network Security Config XML, with bounded main-to-release overlay handling for the supported attributes and resources; it does not run Gradle or model arbitrary product flavors, build-type DSL, placeholders, the full manifest merger, runtime behavior, or complete Android security coverage.",
  "Directory scans inspect only root, main, and release manifests; non-production demo, sample, example, debug, profile, test, dependency, generated, build, vendor, and cache trees are excluded.",
  "Only literal @xml/... networkSecurityConfig references are resolved; unreferenced configurations are not claimed.",
  "XML files over 1 MiB, discovery beyond 20,000 entries, 500 manifests, or 24 levels, and malformed or unreadable files are skipped and reported in pack coverage.",
  "Symbolic links are skipped and never followed; the structured parser never resolves external or DTD-defined XML entities and never executes target content.",
] as const;

/** First-party Android repository-configuration pack; no Gradle or target code executes. */
export const androidPack: NativeDetectorPack = {
  id: "android",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["xml"],
  frameworks: [],
  platforms: ["android"],
  limitations: ANDROID_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => technology.id === "android"),
  createAnalyzers: (target) => [{
    id: "android-configuration",
    components: [
      "pack:android:dispatch",
      "android:xml-config-parser",
      "ai:android-debuggable",
      "ai:android-cleartext-traffic",
      "ai:android-user-ca-trust",
      "ai:android-exported-file-provider",
    ],
    ruleIds: ANDROID_CONFIG_RULE_IDS,
    run: () => runAndroidConfig(target),
  }],
};
