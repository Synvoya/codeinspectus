import { javascriptPack } from "./javascript.js";
import { flutterPack } from "./flutter-pack.js";
import { androidPack } from "./android-pack.js";
import { iosPack } from "./ios-pack.js";
import { reactNativePack } from "./react-native-pack.js";
import { expoPack } from "./expo-pack.js";
import { pythonAiApiPack } from "./python-ai-api-pack.js";
import { javascriptBaselinePack } from "./javascript-baseline-pack.js";
import { goAiPack } from "./go-ai-pack.js";
import { javaAiPack } from "./java-ai-pack.js";
import { csharpAiPack } from "./csharp-ai-pack.js";
import { phpAiPack } from "./php-ai-pack.js";
import { rustAiPack } from "./rust-ai-pack.js";
import { rubyAiPack } from "./ruby-ai-pack.js";
import { firebasePack } from "./firebase-pack.js";
import { githubActionsPack } from "./github-actions-pack.js";
import type { DetectedTechnology, DetectorPackCoverage } from "../types.js";
import type {
  NativeDetectorPack,
  NativePackExecution,
  NativePackInventory,
  RegisteredNativeAnalyzer,
} from "./types.js";

/** Static registry only: no remote or target-provided code is ever loaded. */
const NATIVE_PACKS: readonly NativeDetectorPack[] = [
  javascriptPack,
  flutterPack,
  androidPack,
  iosPack,
  reactNativePack,
  expoPack,
  pythonAiApiPack,
  javascriptBaselinePack,
  goAiPack,
  javaAiPack,
  csharpAiPack,
  phpAiPack,
  rustAiPack,
  rubyAiPack,
  firebasePack,
  githubActionsPack,
];

export function listNativePacks(): readonly NativeDetectorPack[] {
  return NATIVE_PACKS;
}

export function registeredNativeAnalyzers(
  target: string,
  packs: readonly NativeDetectorPack[] = NATIVE_PACKS,
): readonly RegisteredNativeAnalyzer[] {
  return packs.flatMap((pack) =>
    pack.createAnalyzers(target).map((analyzer) => ({
      ...analyzer,
      packId: pack.id,
      packVersion: pack.version,
      packLanguages: pack.languages,
      packFrameworks: pack.frameworks,
      packPlatforms: pack.platforms,
      packLimitations: pack.limitations,
      packScannerKind: pack.scannerKind,
    })),
  );
}

function inventoryForPack(pack: NativeDetectorPack): NativePackInventory {
  // Creating analyzer closures is side-effect free; no analyzer executes and no target is read.
  const analyzers = pack.createAnalyzers("");
  return {
    pack_id: pack.id,
    version: pack.version,
    scanner_kind: pack.scannerKind,
    languages: [...pack.languages],
    frameworks: [...pack.frameworks],
    platforms: [...pack.platforms],
    analyzers: { registered: analyzers.length },
    rules: {
      registered: analyzers.reduce((count, analyzer) => count + analyzer.ruleIds.length, 0),
    },
    limitations: [...pack.limitations],
  };
}

/** Installed native-pack inventory. This does not execute analyzers or claim scan coverage. */
export function nativePackInventory(
  packs: readonly NativeDetectorPack[] = NATIVE_PACKS,
): NativePackInventory[] {
  return packs.map(inventoryForPack);
}

/** Coverage envelope for an installed pack when the native AI scanner was not selected. */
export function nativePackNotRunCoverage(
  note = "The native AI scanner was not selected for this scan.",
  packs: readonly NativeDetectorPack[] = NATIVE_PACKS,
): DetectorPackCoverage[] {
  return nativePackInventory(packs).map((pack) => ({
    ...pack,
    state: "not_run",
    analyzers: { ...pack.analyzers, ran: 0 },
    rules: { ...pack.rules, ran: 0 },
    note,
  }));
}

function coverageForExecution(
  packs: readonly NativeDetectorPack[],
  applicablePackIds: ReadonlySet<string>,
  analyzers: readonly RegisteredNativeAnalyzer[],
  results: NativePackExecution["results"],
): DetectorPackCoverage[] {
  return packs.map((pack) => {
    const inventory = inventoryForPack(pack);
    if (!applicablePackIds.has(pack.id)) {
      return {
        ...inventory,
        state: "not_applicable",
        analyzers: { ...inventory.analyzers, ran: 0 },
        rules: { ...inventory.rules, ran: 0 },
        note: "No detected project technology matched this native pack; its analyzers did not run.",
      };
    }

    const owned = analyzers
      .map((analyzer, index) => ({ analyzer, result: results[index] }))
      .filter(({ analyzer }) => analyzer.packId === pack.id);
    const successful = owned.filter(({ result }) => result?.status === "fulfilled");
    const analyzersRegistered = inventory.analyzers.registered;
    const analyzersRan = successful.length;
    const rulesRegistered = inventory.rules.registered;
    const rulesRan = successful.reduce(
      (count, { analyzer }) => count + analyzer.ruleIds.length,
      0,
    );
    const failedAnalyzers = analyzersRegistered - analyzersRan;
    const failedRules = rulesRegistered - rulesRan;
    const executionNotes = [...new Set(successful.flatMap(({ result }) =>
      result?.status === "fulfilled" ? [...(result.value.notes ?? [])] : []
    ))].sort();
    const state: DetectorPackCoverage["state"] =
      analyzersRan === analyzersRegistered && analyzersRegistered > 0
        ? executionNotes.length ? "partial" : "ran"
        : analyzersRan > 0
          ? "partial"
          : "unavailable";
    const failureNote = failedAnalyzers > 0
      ? `${failedAnalyzers} of ${analyzersRegistered} native analyzers failed; ` +
        `${failedRules} of ${rulesRegistered} registered rules did not run.`
      : analyzersRegistered === 0
        ? "No native analyzers were registered for this installed pack."
        : undefined;
    const note = [failureNote, ...executionNotes].filter((value): value is string => Boolean(value)).join(" ") ||
      undefined;

    return {
      ...inventory,
      state,
      analyzers: { registered: analyzersRegistered, ran: analyzersRan },
      rules: { registered: rulesRegistered, ran: rulesRan },
      ...(note ? { note } : {}),
    };
  });
}

export interface ExecuteNativePacksOptions {
  detectedTechnologies: readonly DetectedTechnology[];
  scannerKinds?: readonly ("ai" | "sast")[];
  packs?: readonly NativeDetectorPack[];
}

/** Execute each applicable analyzer once while inventorying every installed native pack. */
export async function executeNativePacks(
  target: string,
  options: ExecuteNativePacksOptions,
): Promise<NativePackExecution> {
  const packs = options.packs ?? NATIVE_PACKS;
  const selectedKinds = new Set(options.scannerKinds ?? ["ai"]);
  const selectedPacks = packs.filter((pack) => selectedKinds.has(pack.scannerKind));
  const applicablePacks = selectedPacks.filter(
    (pack) => pack.isApplicable?.(options.detectedTechnologies) ?? true,
  );
  const applicablePackIds = new Set(applicablePacks.map((pack) => pack.id));
  const analyzers = registeredNativeAnalyzers(target, applicablePacks);
  const results = await Promise.allSettled(analyzers.map((analyzer) => analyzer.run()));
  return {
    analyzers,
    results,
    packCoverage: [
      ...coverageForExecution(selectedPacks, applicablePackIds, analyzers, results),
      ...nativePackNotRunCoverage("This pack's scanner class was excluded by this scan's scanner filter.", packs.filter((pack) => !selectedKinds.has(pack.scannerKind))),
    ].sort((left, right) => packs.findIndex((pack) => pack.id === left.pack_id) - packs.findIndex((pack) => pack.id === right.pack_id)),
  };
}
