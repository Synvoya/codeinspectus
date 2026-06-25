/**
 * Gitleaks wrapper — secrets (PRD §4.2). Fully offline (regex + entropy).
 * Emits SARIF 2.1.0. Uses our default .gitleaks.toml; a user config in the
 * target extends it.
 *
 *   gitleaks dir <target> --report-format sarif --report-path <file>
 *     --no-banner --exit-code 0 [--config <our toml>]
 *
 * --exit-code 0 so that findings (which normally exit non-zero) don't look like
 * a crash; the server interprets the SARIF, not the exit code.
 */

import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { GITLEAKS_CONFIG } from "../config.js";
import { resolveEngine, EngineUnavailableError } from "./resolve.js";
import { execBinary } from "./exec.js";
import { log } from "../logger.js";
import type { EngineOutput } from "./types.js";
import type { SarifLog } from "../sarif/types.js";

export async function runGitleaks(target: string, tmpDir: string): Promise<EngineOutput> {
  const t0 = Date.now();
  let version = "unknown";
  try {
    const bin = await resolveEngine("gitleaks");
    version = bin.version;

    const sarifPath = join(tmpDir, "gitleaks.sarif");
    const args = [
      "dir",
      target,
      "--report-format",
      "sarif",
      "--report-path",
      sarifPath,
      "--no-banner",
      "--exit-code",
      "0",
    ];
    // Prefer a user .gitleaks.toml in the target; else our bundled default.
    const userConfig = join(target, ".gitleaks.toml");
    if (existsSync(userConfig)) {
      args.push("--config", userConfig);
    } else if (existsSync(GITLEAKS_CONFIG)) {
      args.push("--config", GITLEAKS_CONFIG);
    }

    const res = await execBinary(bin.path, args, { cwd: target, offline: true });
    let sarif: SarifLog | undefined;
    try {
      await access(sarifPath);
      sarif = JSON.parse(await readFile(sarifPath, "utf8")) as SarifLog;
    } catch {
      if (res.timedOut) return note(version, t0, "Gitleaks timed out before producing SARIF.");
      return note(version, t0, `Gitleaks produced no SARIF (exit ${res.code}). stderr: ${trunc(res.stderr)}`);
    }

    return { engine: "gitleaks", version, available: true, ran: true, sarif, durationMs: Date.now() - t0 };
  } catch (err) {
    if (err instanceof EngineUnavailableError) return note(version, t0, err.message);
    log.warn("gitleaks wrapper error", err);
    return note(version, t0, err instanceof Error ? err.message : String(err));
  }
}

function note(version: string, t0: number, msg: string): EngineOutput {
  return { engine: "gitleaks", version, available: false, ran: false, durationMs: Date.now() - t0, note: msg };
}
function trunc(s: string, n = 300): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
