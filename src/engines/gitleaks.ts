/**
 * Gitleaks wrapper — secrets (PRD §4.2). Fully offline (regex + entropy).
 * Emits SARIF 2.1.0. Always uses the bundled CodeInspectus config. Target
 * Gitleaks config and inline allow comments are deliberately ignored so they
 * cannot silently replace or suppress the bundled checks. A target
 * .gitleaksignore cannot be neutralized by Gitleaks 8.30.1; it is detected and
 * disclosed as unverified secret coverage by the scan envelope.
 *
 *   gitleaks dir <target> --report-format sarif --report-path <file>
 *     --no-banner --exit-code 0 [--config <our toml>]
 *
 * --exit-code 0 so that findings (which normally exit non-zero) don't look like
 * a crash; the server interprets the SARIF, not the exit code.
 */

import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { GITLEAKS_CONFIG } from "../config.js";
import { detectGitleaksSuppression } from "../gitleaks-suppression.js";
import { resolveEngine, EngineUnavailableError } from "./resolve.js";
import { execBinary } from "./exec.js";
import { log } from "../logger.js";
import type { EngineOutput } from "./types.js";
import type { SarifLog } from "../sarif/types.js";
import { fileSignature, invocationSignature, signature } from "../provenance.js";

export async function runGitleaks(target: string, tmpDir: string): Promise<EngineOutput> {
  const t0 = Date.now();
  let version = "unknown";
  const secretSuppression = await detectGitleaksSuppression(target);
  try {
    const bin = await resolveEngine("gitleaks");
    version = bin.version;
    const sarifPath = join(tmpDir, "gitleaks.sarif");
    const args = buildGitleaksArgs(target, sarifPath);
    const ignorePresent = secretSuppression.channels.some((surface) => surface.channel === "gitleaks_ignore");
    const componentSignatures = {
      "gitleaks:binary": `sha256:${bin.sha256}`,
      "gitleaks:config": await fileSignature(GITLEAKS_CONFIG),
      "gitleaks:invocation": invocationSignature("gitleaks", args.map((arg) =>
        arg === target ? "<target>"
          : arg === sarifPath ? "<managed-temp>"
            : arg === GITLEAKS_CONFIG ? "<bundled-config>"
              : arg)),
      "gitleaks:effective-ignore": ignorePresent
        ? await fileSignature(join(target, ".gitleaksignore"))
        : signature("gitleaks:effective-ignore\0absent"),
    };

    const res = await execBinary(bin.path, args, { cwd: target, offline: true });
    let sarif: SarifLog | undefined;
    try {
      await access(sarifPath);
      sarif = JSON.parse(await readFile(sarifPath, "utf8")) as SarifLog;
    } catch {
      if (res.timedOut) return note(version, t0, "Gitleaks timed out before producing SARIF.", secretSuppression);
      return note(version, t0, `Gitleaks produced no SARIF (exit ${res.code}). stderr: ${trunc(res.stderr)}`, secretSuppression);
    }

    return {
      engine: "gitleaks",
      version,
      available: true,
      ran: true,
      sarif,
      durationMs: Date.now() - t0,
      secretSuppression,
      componentSignatures,
    };
  } catch (err) {
    if (err instanceof EngineUnavailableError) return note(version, t0, err.message, secretSuppression);
    log.warn("gitleaks wrapper error", err);
    return note(version, t0, err instanceof Error ? err.message : String(err), secretSuppression);
  }
}

/** Exported for a no-engine unit contract: target config never enters argv. */
export function buildGitleaksArgs(target: string, sarifPath: string): string[] {
  return [
      "dir",
      target,
      "--report-format",
      "sarif",
      "--report-path",
      sarifPath,
      "--no-banner",
      "--exit-code",
      "0",
      // Layer 1 of the redaction guarantee (CG-24 A3-1): Gitleaks replaces the matched
      // secret with REDACTED in its SARIF report, so the raw value never reaches our
      // process. The normalizer's value-agnostic scrub is the second, independent layer.
      "--redact=100",
      "--ignore-gitleaks-allow",
      "--config",
      GITLEAKS_CONFIG,
  ];
}

function note(
  version: string,
  t0: number,
  msg: string,
  secretSuppression: EngineOutput["secretSuppression"],
): EngineOutput {
  return {
    engine: "gitleaks",
    version,
    available: false,
    ran: false,
    durationMs: Date.now() - t0,
    note: msg,
    secretSuppression,
  };
}
function trunc(s: string, n = 300): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
