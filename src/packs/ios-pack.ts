import { createIosAnalyzers } from "./ios/index.js";
import type { NativeDetectorPack } from "./types.js";

export const IOS_PACK_LIMITATIONS = [
  "Parses explicit repository XML property lists and entitlements and resolves only literal Release/AppStore INFOPLIST_FILE and CODE_SIGN_ENTITLEMENTS project settings; it does not run Xcode, expand xcconfig/preprocessing/dynamic variables, inspect provisioning profiles, or claim complete iOS security coverage.",
  "Non-production demo, sample, example, debug, profile, test, macOS/OS X, dependency, generated, build, Pods, and DerivedData trees are excluded from directory scans.",
  "Binary, malformed, unreadable, or oversized configuration is skipped and reported; discovery is bounded to 50,000 entries, Xcode projects to 4 MiB each and 16 MiB total, and selected property lists to 256 files, 512 KiB each, and 8 MiB total.",
  "Symbolic links are skipped and never followed; the structured parser never resolves external or DTD-defined XML entities and never executes target content.",
] as const;

/** First-party iOS repository-configuration pack; no Xcode or target code executes. */
export const iosPack: NativeDetectorPack = {
  id: "ios",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["xml"],
  frameworks: [],
  platforms: ["ios"],
  limitations: IOS_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => technology.id === "ios"),
  createAnalyzers: createIosAnalyzers,
};
