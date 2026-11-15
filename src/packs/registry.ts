import type { NativeGapRecord } from "../native-gaps.js";
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
import { withJavaScriptParseCache } from "./react-native/javascript-parse.js";
import type {
  NativeDetectorPack,
  NativePackExecution,
  NativePackInventory,
  RegisteredNativeAnalyzer,
} from "./types.js";

/**
 * 4.1 M9 Ruling 4: native rules that failed the fresh-set precision gate (fresh-set precision: true over triaged hits).
 * An experimental rule is not reported, not counted and disclosed: the registry drops it from its analyzer's
 * `ruleIds` (so from every inventory and rule count), drops its findings, and adds one line to the owning pack's
 * `limitations` (`pack_coverage`, `list_rules`). The analyzer code and its unit tests stay. No opt-in in 4.1.
 */
// `ci-ai-client-hardcoded-secret` failed the gate too (0/7) but ships as in 4.0 by owner override (Hibi,
// 2026-11-15) for detection coverage; its false-positive classes are fixed and re-measured in 4.2.
const EXPERIMENTAL_NATIVE_RULES: Readonly<Record<string, string>> = {
  "ci-ai-sensitive-api-response": "0/5",
  "ci-ai-sensitive-log": "6/17",
};
export const EXPERIMENTAL_NATIVE_RULE_IDS: ReadonlySet<string> = new Set(Object.keys(EXPERIMENTAL_NATIVE_RULES));

/** The pack with its experimental rules held back (unchanged when it owns none). */
function withExperimentalRulesHeldBack(pack: NativeDetectorPack): NativeDetectorPack {
  const held = [...new Set(pack.createAnalyzers("").flatMap((analyzer) => analyzer.ruleIds))]
    .filter((ruleId) => EXPERIMENTAL_NATIVE_RULE_IDS.has(ruleId))
    .sort();
  if (!held.length) return pack;
  return {
    ...pack,
    limitations: [
      ...pack.limitations,
      ...held.map((ruleId) =>
        `${ruleId} is experimental in 4.1 and not reported (fresh-set precision ${EXPERIMENTAL_NATIVE_RULES[ruleId]} triaged hits).`),
    ],
    createAnalyzers: (target) => pack.createAnalyzers(target).map((analyzer) => {
      if (!analyzer.ruleIds.some((ruleId) => EXPERIMENTAL_NATIVE_RULE_IDS.has(ruleId))) return analyzer;
      return {
        ...analyzer,
        ruleIds: analyzer.ruleIds.filter((ruleId) => !EXPERIMENTAL_NATIVE_RULE_IDS.has(ruleId)),
        run: async () => {
          const result = await analyzer.run();
          return { ...result, findings: result.findings.filter((finding) => !EXPERIMENTAL_NATIVE_RULE_IDS.has(finding.rule_id)) };
        },
      };
    }),
  };
}

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
].map(withExperimentalRulesHeldBack);

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
  gapRecords: NativeGapRecord[],
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
    // Structured gap records (never free-text notes) are declared gaps and do not make the pack partial.
    for (const { result } of successful) {
      if (result?.status === "fulfilled") for (const record of result.value.gaps ?? []) gapRecords.push(record);
    }
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
  // One JavaScript/TypeScript parse cache per execution, shared by its analyzers and cleared at the end.
  const results = await withJavaScriptParseCache(() => Promise.allSettled(analyzers.map((analyzer) => analyzer.run())));
  const gapRecords: NativeGapRecord[] = [];
  return {
    analyzers,
    results,
    gapRecords,
    packCoverage: [
      ...coverageForExecution(selectedPacks, applicablePackIds, analyzers, results, gapRecords),
      ...nativePackNotRunCoverage("This pack's scanner class was excluded by this scan's scanner filter.", packs.filter((pack) => !selectedKinds.has(pack.scannerKind))),
    ].sort((left, right) => packs.findIndex((pack) => pack.id === left.pack_id) - packs.findIndex((pack) => pack.id === right.pack_id)),
  };
}
