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
import type { advisoryDatabaseInfoSchema, listRulesOutput, ruleInfoSchema } from "./schemas.js";
import { loadSynvoyaDataset } from "./synvoya/dataset.js";
import { SYNVOYA_FAMILY, SYNVOYA_FAMILY_DISPLAY, isSynvoyaFinding } from "./synvoya/family.js";
import type { ListRulesInput } from "./schemas.js";
import { inspectPubDatabase } from "./pub/database.js";
import { inspectOsvDatabases, osvDbSourceUrl, readOsvDbRecord } from "./osv/database.js";

type ListRulesResult = z.infer<typeof listRulesOutput>;
type RuleInfo = z.infer<typeof ruleInfoSchema>;
type AdvisoryDatabaseInfo = z.infer<typeof advisoryDatabaseInfoSchema>;
type SynvoyaDatasetInfo = ListRulesResult["synvoya_dataset"];

/** One human line for the dataset state; shown wherever list_rules is summarised, including when it failed to load. */
export function synvoyaDatasetLine(info: SynvoyaDatasetInfo): string {
  return info.state === "available"
    ? `Synvoya gap advisories: ${info.version} (${info.date}), ${info.advisory_count} advisories`
    : `Synvoya gap advisories: unavailable (${info.reason})`;
}

async function synvoyaDatasetInfo(): Promise<SynvoyaDatasetInfo> {
  try {
    const loaded = await loadSynvoyaDataset();
    return loaded.ok
      ? { state: "available", version: loaded.dataset.version, date: loaded.dataset.date, advisory_count: loaded.dataset.advisories.length }
      : { state: "unavailable", reason: loaded.reason };
  } catch (error) {
    return { state: "unavailable", reason: error instanceof Error ? error.message : String(error) };
  }
}

/** Custom rules grouped for humans: the Synvoya family first, then each remaining engine under its raw id. */
function groupRules(rules: readonly RuleInfo[]): ListRulesResult["rule_groups"] {
  const synvoya = rules.filter((rule) => rule.engine_family === SYNVOYA_FAMILY);
  const groups: ListRulesResult["rule_groups"] = [];
  if (synvoya.length) {
    groups.push({
      group: SYNVOYA_FAMILY_DISPLAY,
      engine_family: SYNVOYA_FAMILY,
      rule_count: synvoya.length,
      engines: [...new Set(synvoya.map((rule) => rule.engine))],
    });
  }
  const others = new Map<RuleInfo["engine"], number>();
  for (const rule of rules) if (rule.engine_family !== SYNVOYA_FAMILY) others.set(rule.engine, (others.get(rule.engine) ?? 0) + 1);
  for (const [engine, count] of others) groups.push({ group: engine, rule_count: count, engines: [engine] });
  return groups;
}

/** OSV aggregates sources under their own licenses (attribution only; not a legal review). */
const OSV_DATA_LICENSE =
  "Per source: CC-BY-4.0 (GitHub Advisory Database GHSA-, PyPA PYSEC-, OSS-Fuzz OSV-, Go GO-), " +
  "Apache-2.0 (OpenSSF Malicious Packages MAL-), MIT (Drupal), CC0-1.0 (RustSec RUSTSEC-)";
const OSV_DATA_ATTRIBUTION =
  "OSV.dev and its sources: GitHub Advisory Database, PyPA Advisory Database, OSS-Fuzz, Go Vulnerability Database, " +
  "OpenSSF Malicious Packages, Drupal and RustSec contributors";

/** One entry per OSV database installed for osv-scanner; offline (a stat and a small record read each). */
async function osvAdvisoryDatabases(): Promise<AdvisoryDatabaseInfo[]> {
  const installed = await inspectOsvDatabases();
  return Promise.all(installed.map(async ({ ecosystem, state, downloaded_at }): Promise<AdvisoryDatabaseInfo> => {
    // A record that does not describe the archive on disk proves nothing about it: report no digest.
    const record = state === "provenance_missing" ? undefined : await readOsvDbRecord(ecosystem);
    return {
      engine: "osv-scanner",
      ecosystem,
      state: state === "ready" ? "current" : state,
      version: record?.last_modified ?? downloaded_at ?? "unknown",
      ...(downloaded_at ? { checked_at: downloaded_at } : {}),
      ...(record ? { content_digest: record.signature } : {}),
      matching: "osv-scanner-offline",
      source_url: osvDbSourceUrl(ecosystem),
      source_database: "OSV.dev",
      license: OSV_DATA_LICENSE,
      attribution: OSV_DATA_ATTRIBUTION,
      ...(state === "provenance_missing"
        ? { note: "No install record matches this database archive, so results from it cannot be proven reproducible on rescan. Run `codeinspectus setup` to reinstall it." }
        : state === "stale"
          ? { note: "This database is older than the refresh window; run `codeinspectus setup` to refresh it." }
          : {}),
    };
  }));
}

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

/** Engines that belong wholly to the Synvoya family are labelled for humans; `engine` keeps the raw id. */
const FAMILY_ROW = { display_name: SYNVOYA_FAMILY_DISPLAY, engine_family: SYNVOYA_FAMILY } as const;

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

  const engineNames: EngineName[] = ["opengrep", "gitleaks", "trivy", "osv-scanner"];
  const [engineSetup, trivyDbDate, pubDatabase, osvDatabases, synvoyaDataset] = await Promise.all([
    inspectEngineSetup(),
    readTrivyDbDate(),
    inspectPubDatabase(),
    osvAdvisoryDatabases(),
    synvoyaDatasetInfo(),
  ]);
  const rulesets: Record<EngineName, string> = {
    opengrep: "security-baseline",
    gitleaks: "codeinspectus.toml + defaults",
    trivy: "embedded + vuln DB",
    "osv-scanner": "offline OSV databases (installed ecosystems only)",
  };

  const engines = [
    ...engineNames.map((engine) => ({
      engine,
      version: engineSetup.engines.find((item) => item.engine === engine)?.version ?? "unknown",
      available: engineSetup.engines.find((item) => item.engine === engine)?.state === "ready",
      ruleset: rulesets[engine],
    })),
    {
      engine: "codeinspectus-ai" as const,
      ...FAMILY_ROW,
      version: CODEINSPECTUS_AI_VERSION,
      available: true,
      ruleset: "AI-code analyzers (§6)",
    },
    {
      engine: "codeinspectus-pub" as const,
      ...FAMILY_ROW,
      version: CODEINSPECTUS_PUB_VERSION,
      available: pubDatabase.info.state === "current" || pubDatabase.info.state === "stale",
      ruleset: "bundled OSV Pub snapshot (exact enumerated versions)",
    },
    {
      engine: "synvoya" as const,
      ...FAMILY_ROW,
      version: synvoyaDataset.state === "available" ? synvoyaDataset.version : "unknown",
      available: synvoyaDataset.state === "available",
      ruleset: "bundled gap-advisory dataset (declared versions)",
    },
  ];

  // Display grouping only: the raw engine and id of every rule stay as the manifest has them.
  let custom: RuleInfo[] = manifest.custom_rules.map((rule) =>
    isSynvoyaFinding({ engine: rule.engine, rule_id: rule.id }) ? { ...rule, engine_family: SYNVOYA_FAMILY } : rule);
  if (input.engine) custom = custom.filter((r) => r.engine === input.engine);

  return {
    detection_db_version: manifest.version,
    detection_db_date: manifest.date,
    engines,
    synvoya_dataset: synvoyaDataset,
    rule_groups: groupRules(custom),
    ...(trivyDbDate ? { trivy_db_date: trivyDbDate } : {}),
    engine_setup: engineSetup,
    native_packs: nativePacks,
    advisory_databases: [pubDatabase.info, ...osvDatabases],
    custom_rules: custom,
    custom_rule_count: custom.length,
    note: "Generic SAST remains available through managed engines. Selected JavaScript rules are first-party native with an explicit Opengrep fallback; other native packs target bounded AI-code and framework-specific issues.",
  };
}
