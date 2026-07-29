import {
  FIREBASE_CONFIG_RULE_IDS,
  runFirebaseConfig,
} from "./firebase/firebase-config.js";
import type { NativeDetectorPack } from "./types.js";

export const FIREBASE_PACK_LIMITATIONS = [
  "Detects only literal unconditional public write grants in checked-in Cloud Firestore, Cloud Storage, and Realtime Database Security Rules; public reads, semantic helper functions, runtime policy state, IAM, App Check, and complete Firebase security coverage are outside this pack.",
  "Cloud Firestore and Cloud Storage analysis requires exact service declarations and literal allow write/create/update/delete statements with no condition or a condition that is exactly true; other expressions fail closed.",
  "Realtime Database analysis requires strict JSON and recognizes only .write values that are boolean true or the exact string true; dynamic expressions are not evaluated.",
  "Directory scans inspect .rules files and database.rules.json while excluding test, example, sample, dependency, generated, build, vendor, and cache trees; custom non-.rules filenames are not discovered.",
  "Files over 1 MiB and discovery beyond 1,000 rule files, 32 MiB total, 50,000 entries, or 32 levels are skipped and reported in pack coverage.",
  "Symbolic links and symbolic-link ancestors are skipped and never followed; target code and Firebase tooling are never executed.",
] as const;

/** First-party Firebase checked-in Security Rules pack; no target code executes. */
export const firebasePack: NativeDetectorPack = {
  id: "firebase",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["firebase-rules", "json"],
  frameworks: [],
  platforms: ["firebase"],
  limitations: FIREBASE_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => technology.id === "firebase"),
  createAnalyzers: (target) => [{
    id: "firebase-security-rules",
    components: [
      "pack:firebase:dispatch",
      "firebase:bounded-rules-parser",
      "ai:firebase-firestore-public-write",
      "ai:firebase-storage-public-write",
      "ai:firebase-realtime-database-public-write",
    ],
    ruleIds: FIREBASE_CONFIG_RULE_IDS,
    run: () => runFirebaseConfig(target),
  }],
};
