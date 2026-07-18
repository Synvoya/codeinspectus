/**
 * Opengrep wrapper — SAST / OWASP Top 10 (PRD §4.1). Fully offline: self-
 * contained binary + local rule files. Emits SARIF 2.1.0.
 *
 * We point Opengrep at the bundled rules directory (CodeInspectus custom AI-code
 * rules + any vendored security-registry rules). We do NOT use `--config auto`
 * or registry packs, which would require network and break zero-egress.
 */

import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { OPENGREP_RULES_DIR } from "../config.js";
import { resolveEngine, EngineUnavailableError } from "./resolve.js";
import { execBinary } from "./exec.js";
import { log } from "../logger.js";
import type { EngineOutput } from "./types.js";
import type { SarifLog } from "../sarif/types.js";
import { invocationSignature, rulesetSignature } from "../provenance.js";

export async function runOpengrep(target: string, tmpDir: string): Promise<EngineOutput> {
  const t0 = Date.now();
  let version = "unknown";
  try {
    const bin = await resolveEngine("opengrep");
    version = bin.version;
    const sarifPath = join(tmpDir, "opengrep.sarif");
    const args = buildOpengrepArgs(target, sarifPath);
    const componentSignatures = {
      "opengrep:binary": `sha256:${bin.sha256}`,
      "opengrep:ruleset": await rulesetSignature(OPENGREP_RULES_DIR),
      "opengrep:invocation": invocationSignature("opengrep", args.map((arg) =>
        arg === `--sarif-output=${sarifPath}` ? "--sarif-output=<managed-temp>"
          : arg === OPENGREP_RULES_DIR ? "<bundled-ruleset>"
            : arg === target ? "<target>"
              : arg)),
    };

    // VERIFY: confirm flag spelling against opengrep v1.23.0 (`--sarif-output=`
    // per PRD §4.1; some builds use `--sarif --output`). Isolated here for easy fix.
    const res = await execBinary(bin.path, args, { cwd: target, offline: true });
    // Opengrep exit code is non-zero when findings exist; we read the SARIF
    // regardless and interpret results, not the exit code.
    let sarif: SarifLog | undefined;
    try {
      await access(sarifPath);
      sarif = JSON.parse(await readFile(sarifPath, "utf8")) as SarifLog;
    } catch {
      if (res.timedOut) {
        return engineNote("opengrep", version, t0, "Opengrep timed out before producing SARIF.");
      }
      return engineNote(
        "opengrep",
        version,
        t0,
        `Opengrep produced no SARIF (exit ${res.code}). stderr: ${truncate(res.stderr)}`,
      );
    }

    return {
      engine: "opengrep",
      version,
      available: true,
      ran: true,
      sarif,
      durationMs: Date.now() - t0,
      componentSignatures,
    };
  } catch (err) {
    if (err instanceof EngineUnavailableError) {
      return engineNote("opengrep", version, t0, err.message);
    }
    log.warn("opengrep wrapper error", err);
    return engineNote(
      "opengrep",
      version,
      t0,
      err instanceof Error ? err.message : String(err),
    );
  }
}

export function buildOpengrepArgs(target: string, sarifPath: string): string[] {
  return [
    "scan",
    `--sarif-output=${sarifPath}`,
    "-f",
    OPENGREP_RULES_DIR,
    "--quiet",
    "--taint-intrafile", // intrafile cross-function taint (PRD §1.4 in-scope)
    target,
  ];
}

function engineNote(
  engine: "opengrep",
  version: string,
  t0: number,
  note: string,
  componentSignatures?: Record<string, string>,
): EngineOutput {
  return { engine, version, available: false, ran: false, durationMs: Date.now() - t0, note, componentSignatures };
}

function truncate(s: string, n = 300): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
