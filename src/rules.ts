/**
 * codeinspectus_list_rules — active detectors, engine versions, DB freshness
 * (PRD §11). Reads the detection-db manifest and probes engine availability.
 */

import { z } from "zod";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DETECTION_DB_DIR, CODEINSPECTUS_AI_VERSION, type EngineName } from "./config.js";
import { probeEngine } from "./engines/resolve.js";
import { readTrivyDbDate } from "./engines/trivy.js";
import type { listRulesOutput, ruleInfoSchema } from "./schemas.js";
import type { ListRulesInput } from "./schemas.js";

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

export async function listRules(input: ListRulesInput): Promise<ListRulesResult> {
  const manifest = await loadManifest().catch(() => ({
    version: "unknown",
    date: "unknown",
    custom_rules: [] as RuleInfo[],
  }));

  const engineNames: EngineName[] = ["opengrep", "gitleaks", "trivy"];
  const probes = await Promise.all(engineNames.map((e) => probeEngine(e)));
  const trivyDbDate = await readTrivyDbDate();

  const engines = [
    ...engineNames.map((engine, i) => ({
      engine,
      version: probes[i]!.version,
      available: probes[i]!.available,
      ruleset: engine === "opengrep" ? "security-baseline" : engine === "gitleaks" ? "codeinspectus.toml + defaults" : "embedded + vuln DB",
    })),
    {
      engine: "codeinspectus-ai" as const,
      version: CODEINSPECTUS_AI_VERSION,
      available: true,
      ruleset: "AI-code analyzers (§6)",
    },
  ];

  let custom = manifest.custom_rules;
  if (input.engine) custom = custom.filter((r) => r.engine === input.engine);

  return {
    detection_db_version: manifest.version,
    detection_db_date: manifest.date,
    engines,
    ...(trivyDbDate ? { trivy_db_date: trivyDbDate } : {}),
    custom_rules: custom,
    custom_rule_count: custom.length,
    note: "Generic SAST is provided by the bundled engines; CodeInspectus's custom rules target AI-code / vibe-coding / framework-specific issues the engines miss (PRD §9).",
  };
}
