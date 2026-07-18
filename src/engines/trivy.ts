/**
 * Trivy wrapper — SCA + IaC misconfig + secrets + license + SBOM (PRD §4.3, §7, §8).
 *
 * ZERO-EGRESS GUARDRAIL (PRD §7): every scan-time invocation includes
 * --skip-db-update --skip-java-db-update --offline-scan --skip-check-update and a
 * managed --cache-dir. No network call ever happens during a scan. The vuln DB
 * is populated out of band by `install-engines` (the only network step).
 */

import { readFile, access, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { MANAGED_TRIVY_CACHE, MANAGED_TRIVY_DB_META } from "../config.js";
import { resolveEngine, EngineUnavailableError } from "./resolve.js";
import { execBinary } from "./exec.js";
import { log } from "../logger.js";
import type { EngineOutput } from "./types.js";
import type { SarifLog } from "../sarif/types.js";
import { invocationSignature, readTrivyDbContentDigest, signature } from "../provenance.js";

const OFFLINE_FLAGS = [
  "--skip-db-update",
  "--skip-java-db-update",
  "--offline-scan",
  "--skip-check-update",
];

export type TrivyScanner = "vuln" | "misconfig" | "secret" | "license";

export async function runTrivy(
  target: string,
  tmpDir: string,
  scanners: TrivyScanner[] = ["vuln", "misconfig", "secret", "license"],
): Promise<EngineOutput & { trivyDbDate?: string }> {
  const t0 = Date.now();
  let version = "unknown";
  try {
    const bin = await resolveEngine("trivy");
    version = bin.version;
    const sarifPath = join(tmpDir, "trivy.sarif");
    const args = buildTrivyArgs(target, sarifPath, scanners);
    const dbSignature = await readTrivyDbContentDigest();
    const componentSignatures: Record<string, string> = {
      "trivy:binary": `sha256:${bin.sha256}`,
      // Trivy's built-in secret/license/misconfiguration checks ship with the verified binary.
      "trivy:checks": signature(`trivy:checks\0${bin.sha256}`),
      "trivy:invocation": invocationSignature("trivy", args.map((arg) =>
        arg === sarifPath ? "<managed-temp>"
          : arg === MANAGED_TRIVY_CACHE ? "<managed-cache>"
            : arg === target ? "<target>"
              : arg)),
      ...(dbSignature ? { "trivy:vulnerability-db": dbSignature } : {}),
    };
    await mkdir(MANAGED_TRIVY_CACHE, { recursive: true });

    const res = await execBinary(bin.path, args, { cwd: target, offline: true });
    const trivyDbDate = await readTrivyDbDate();

    let sarif: SarifLog | undefined;
    try {
      await access(sarifPath);
      sarif = JSON.parse(await readFile(sarifPath, "utf8")) as SarifLog;
    } catch {
      if (res.timedOut) return note(version, t0, "Trivy timed out before producing SARIF.", trivyDbDate);
      // A common offline failure is a missing DB — give an actionable hint.
      const dbHint = trivyDbDate
        ? ""
        : " The Trivy vuln DB may be missing; run `codeinspectus install-engines` to populate the offline DB snapshot.";
      return note(version, t0, `Trivy produced no SARIF (exit ${res.code}).${dbHint} stderr: ${trunc(res.stderr)}`, trivyDbDate);
    }

    return {
      engine: "trivy",
      version,
      available: true,
      ran: true,
      sarif,
      durationMs: Date.now() - t0,
      trivyDbDate,
      componentSignatures,
    };
  } catch (err) {
    if (err instanceof EngineUnavailableError) return note(version, t0, err.message);
    log.warn("trivy wrapper error", err);
    return note(version, t0, err instanceof Error ? err.message : String(err));
  }
}

export function buildTrivyArgs(target: string, sarifPath: string, scanners: TrivyScanner[]): string[] {
  return [
    "fs",
    "--scanners",
    scanners.join(","),
    "--format",
    "sarif",
    "--output",
    sarifPath,
    ...OFFLINE_FLAGS,
    "--cache-dir",
    MANAGED_TRIVY_CACHE,
    target,
  ];
}

/** SBOM generation (PRD §8). Separate invocation; writes the SBOM to outputPath. */
export async function runTrivySbom(
  target: string,
  format: "cyclonedx" | "spdx",
  outputPath: string,
): Promise<{ ran: boolean; note?: string; version: string }> {
  let version = "unknown";
  try {
    const bin = await resolveEngine("trivy");
    version = bin.version;
    await mkdir(MANAGED_TRIVY_CACHE, { recursive: true });
    const fmt = format === "spdx" ? "spdx-json" : "cyclonedx";
    const args = [
      "fs",
      "--format",
      fmt,
      "--output",
      outputPath,
      ...OFFLINE_FLAGS,
      "--cache-dir",
      MANAGED_TRIVY_CACHE,
      target,
    ];
    const res = await execBinary(bin.path, args, { cwd: target, offline: true });
    try {
      await access(outputPath);
      return { ran: true, version };
    } catch {
      return { ran: false, version, note: `Trivy SBOM produced no output (exit ${res.code}). stderr: ${trunc(res.stderr)}` };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ran: false, version, note: msg };
  }
}

/** Trivy DB freshness date from cache metadata (PRD §7.2 — surface in output). */
export async function readTrivyDbDate(): Promise<string | undefined> {
  try {
    const raw = JSON.parse(await readFile(MANAGED_TRIVY_DB_META, "utf8")) as {
      DownloadedAt?: string;
      UpdatedAt?: string;
    };
    return raw.DownloadedAt ?? raw.UpdatedAt;
  } catch {
    return undefined;
  }
}

function note(
  version: string,
  t0: number,
  msg: string,
  trivyDbDate?: string,
): EngineOutput & { trivyDbDate?: string } {
  return {
    engine: "trivy",
    version,
    available: false,
    ran: false,
    durationMs: Date.now() - t0,
    note: msg,
    trivyDbDate,
  };
}
function trunc(s: string, n = 300): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
