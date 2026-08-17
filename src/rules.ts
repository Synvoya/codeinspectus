/**
 * codeinspectus_list_rules — active detectors, engine versions, DB freshness
 * (PRD §11). Reads the detection-db manifest and probes engine availability.
 */

import { z } from "zod";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  DETECTION_DB_DIR,
  CODEINSPECTUS_AI_VERSION,
  CODEINSPECTUS_PUB_VERSION,
  type EngineName,
} from "./config.js";
import { readTrivyDbDate } from "./engines/trivy.js";
import { inspectEngineSetup } from "./engine-health.js";
import { nativePackInventory, registeredNativeAnalyzers } from "./packs/registry.js";
import type { listRulesOutput, ruleInfoSchema } from "./schemas.js";
import type { ListRulesInput } from "./schemas.js";
import { inspectPubDatabase } from "./pub/database.js";

type ListRulesResult = z.infer<typeof listRulesOutput>;
type RuleInfo = z.infer<typeof ruleInfoSchema>;

interface Manifest {
  version: string;
  date: string;
  custom_rules: RuleInfo[];
}

async function loadManifest(): Promise<Manifest> {
  const raw = await readFile(join(DETECTION_DB_DIR, "manifest.json"), "utf8");
  return JSON.parse(raw) as Manifest;
}

function assertUnique(values: readonly string[], label: string): void {
  if (new Set(values).size !== values.length) {
    throw new Error(`Invalid native pack registry: duplicate ${label}.`);
  }
}

/**
 * The manifest is the public rule catalogue while the registry is executable
 * ownership. Refuse to publish contradictory native metadata when both load.
 */
function validateNativeRuleOwnership(rules: readonly RuleInfo[]): void {
  const packs = nativePackInventory();
  const analyzers = registeredNativeAnalyzers(DETECTION_DB_DIR);
  const packIds = packs.map((pack) => pack.pack_id);
  const analyzerIds = analyzers.map((analyzer) => analyzer.id);
  const nativeManifestRules = rules.filter((rule) => rule.engine === "codeinspectus-ai");
  const nativeManifestIds = nativeManifestRules.map((rule) => rule.id);

  assertUnique(packIds, "pack id");
  assertUnique(analyzerIds, "analyzer id");
  assertUnique(nativeManifestIds, "manifest rule id");
  assertUnique(rules.map((rule) => rule.id), "manifest rule id across all engines");

  const knownPacks = new Set(packIds);
  const ruleOwners = new Map<string, string>();
  for (const analyzer of analyzers) {
    if (!knownPacks.has(analyzer.packId)) {
      throw new Error(`Invalid native pack registry: analyzer ${analyzer.id} has unknown pack ${analyzer.packId}.`);
    }
    for (const ruleId of analyzer.ruleIds) {
      if (ruleOwners.has(ruleId)) {
        throw new Error(`Invalid native pack registry: duplicate rule id ${ruleId}.`);
      }
      ruleOwners.set(ruleId, analyzer.packId);
    }
  }

  for (const rule of nativeManifestRules) {
    if (!rule.pack_id) {
      throw new Error(`Invalid detection manifest: native rule ${rule.id} has no pack_id.`);
    }
    const owner = ruleOwners.get(rule.id);
    if (!owner) {
      throw new Error(`Invalid detection manifest: native rule ${rule.id} has no registered analyzer.`);
    }
    if (owner !== rule.pack_id) {
      throw new Error(`Invalid detection manifest: native rule ${rule.id} belongs to ${owner}, not ${rule.pack_id}.`);
    }
    const ownerPack = packs.find((pack) => pack.pack_id === owner);
    if (ownerPack?.scanner_kind !== rule.kind) {
      throw new Error(`Invalid detection manifest: native rule ${rule.id} kind ${rule.kind} does not match pack scanner ${ownerPack?.scanner_kind}.`);
    }
    if (rule.fallback_engine && ownerPack?.scanner_kind !== "sast") {
      throw new Error(`Invalid detection manifest: native rule ${rule.id} declares an external fallback outside a SAST pack.`);
    }
  }

  for (const rule of rules) {
    if (rule.engine !== "codeinspectus-ai" && rule.pack_id) {
      throw new Error(`Invalid detection manifest: external rule ${rule.id} must not declare pack_id.`);
    }
  }

  const manifestIds = new Set(nativeManifestIds);
  for (const [ruleId] of ruleOwners) {
    if (!manifestIds.has(ruleId)) {
      throw new Error(`Invalid native pack registry: registered rule ${ruleId} is absent from the manifest.`);
    }
  }

  for (const pack of packs) {
    const packAnalyzers = analyzers.filter((analyzer) => analyzer.packId === pack.pack_id);
    const packRules = new Set(packAnalyzers.flatMap((analyzer) => analyzer.ruleIds));
    if (
      packAnalyzers.length !== pack.analyzers.registered ||
      packRules.size !== pack.rules.registered
    ) {
      throw new Error(`Invalid native pack registry: inventory counts disagree for ${pack.pack_id}.`);
    }
  }
}

export async function listRules(input: ListRulesInput): Promise<ListRulesResult> {
  const loadedManifest = await loadManifest().catch(() => undefined);
  const manifest = loadedManifest ?? ({
    version: "unknown",
    date: "unknown",
    custom_rules: [] as RuleInfo[],
  } satisfies Manifest);

  if (loadedManifest) validateNativeRuleOwnership(manifest.custom_rules);

  const nativePacks = nativePackInventory().map((pack) => ({
    id: pack.pack_id,
    version: pack.version,
    scanner_kind: pack.scanner_kind,
    languages: [...pack.languages],
    frameworks: [...pack.frameworks],
    platforms: [...pack.platforms],
    limitations: [...pack.limitations],
    analyzer_count: pack.analyzers.registered,
    rule_count: pack.rules.registered,
  }));

  const engineNames: EngineName[] = ["opengrep", "gitleaks", "trivy"];
  const [engineSetup, trivyDbDate, pubDatabase] = await Promise.all([
    inspectEngineSetup(),
    readTrivyDbDate(),
    inspectPubDatabase(),
  ]);

  const engines = [
    ...engineNames.map((engine) => ({
      engine,
      version: engineSetup.engines.find((item) => item.engine === engine)?.version ?? "unknown",
      available: engineSetup.engines.find((item) => item.engine === engine)?.state === "ready",
      ruleset: engine === "opengrep" ? "security-baseline" : engine === "gitleaks" ? "codeinspectus.toml + defaults" : "embedded + vuln DB",
    })),
    {
      engine: "codeinspectus-ai" as const,
      version: CODEINSPECTUS_AI_VERSION,
      available: true,
      ruleset: "AI-code analyzers (§6)",
    },
    {
      engine: "codeinspectus-pub" as const,
      version: CODEINSPECTUS_PUB_VERSION,
      available: pubDatabase.info.state === "current" || pubDatabase.info.state === "stale",
      ruleset: "bundled OSV Pub snapshot (exact enumerated versions)",
    },
  ];

  let custom = manifest.custom_rules;
  if (input.engine) custom = custom.filter((r) => r.engine === input.engine);

  return {
    detection_db_version: manifest.version,
    detection_db_date: manifest.date,
    engines,
    ...(trivyDbDate ? { trivy_db_date: trivyDbDate } : {}),
    engine_setup: engineSetup,
    native_packs: nativePacks,
    advisory_databases: [pubDatabase.info],
    custom_rules: custom,
    custom_rule_count: custom.length,
    note: "Generic SAST remains available through managed engines. Selected JavaScript rules are first-party native with an explicit Opengrep fallback; other native packs target bounded AI-code and framework-specific issues.",
  };
}
