/**
 * The "Synvoya (CodeInspectus)" display family.
 *
 * Synvoya is a presentation grouping of detection CodeInspectus owns, not an engine rename: every
 * member keeps its raw `engine`, `rule_id`, id and fingerprint. `engine_family` is therefore never an
 * input to fingerprints, dedup keys, baselines or rescan matching, and `withEngineFamily` runs once,
 * after dedup, so nothing upstream of it can see the field.
 */

import { readFileSync } from "node:fs";

import { GITLEAKS_CONFIG } from "../config.js";
import { log } from "../logger.js";
import type { Finding } from "../types.js";

export const SYNVOYA_FAMILY = "synvoya" as const;
export const SYNVOYA_FAMILY_DISPLAY = "Synvoya (CodeInspectus)";

/** Engines whose every finding is CodeInspectus-owned detection. */
const OWNED_ENGINES: ReadonlySet<string> = new Set(["synvoya", "codeinspectus-ai", "codeinspectus-pub"]);

/** Opengrep rule ids (already reduced to their last path segment) that CodeInspectus authored. */
const OPENGREP_PREFIXES = ["ci-baseline-", "syn-"] as const;

/** `id = "..."` lines of the bundled Gitleaks config: its [[rules]] are the CodeInspectus-added ones. */
export function parseGitleaksRuleIds(toml: string): Set<string> {
  const ids = new Set<string>();
  for (const match of toml.matchAll(/^[ \t]*id[ \t]*=[ \t]*(?:"([^"\n]+)"|'([^'\n]+)')/gm)) {
    ids.add(match[1] ?? match[2]!);
  }
  return ids;
}

function loadGitleaksRuleIds(): ReadonlySet<string> {
  try {
    return parseGitleaksRuleIds(readFileSync(GITLEAKS_CONFIG, "utf8"));
  } catch (error) {
    // Display only: without the list the Gitleaks rules simply keep their raw engine label.
    log.warn("Synvoya family: could not read the bundled Gitleaks rule ids", error);
    return new Set();
  }
}

const GITLEAKS_RULE_IDS = loadGitleaksRuleIds();

/**
 * `engines_run` entries ("name@version") with the wholly-owned engines folded into one family entry that
 * still names its members, so the human line reads the family while the raw engine ids stay visible.
 */
export function displayEnginesRun(enginesRun: readonly string[]): string[] {
  const members: string[] = [];
  const others: string[] = [];
  for (const entry of enginesRun) (OWNED_ENGINES.has(entry.split("@")[0]!) ? members : others).push(entry);
  return members.length ? [...others, `${SYNVOYA_FAMILY_DISPLAY} [${members.join(", ")}]`] : others;
}

export function isSynvoyaFinding(f: Pick<Finding, "engine" | "rule_id">): boolean {
  if (OWNED_ENGINES.has(f.engine)) return true;
  if (f.engine === "opengrep") return OPENGREP_PREFIXES.some((prefix) => f.rule_id.startsWith(prefix));
  if (f.engine === "gitleaks") return GITLEAKS_RULE_IDS.has(f.rule_id);
  return false;
}

/** Adds `engine_family: "synvoya"` to a member; any other finding is returned as the same object. */
export function withEngineFamily(f: Finding): Finding {
  return isSynvoyaFinding(f) ? { ...f, engine_family: SYNVOYA_FAMILY } : f;
}
