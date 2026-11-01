/**
 * Trivy wrapper — SCA + IaC misconfig + secrets + license + SBOM (PRD §4.3, §7, §8).
 *
 * ZERO-EGRESS GUARDRAIL (PRD §7): every scan-time invocation includes
 * --skip-db-update --skip-java-db-update --offline-scan --skip-check-update and a
 * managed --cache-dir. No network call ever happens during a scan. The vuln DB
 * is populated out of band by explicit `repair-engines` maintenance.
 */

import { randomUUID } from "node:crypto";
import { readFile, access, lstat, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MANAGED_TRIVY_CACHE, MANAGED_TRIVY_DB_META } from "../config.js";
import { resolveEngine, EngineUnavailableError } from "./resolve.js";
import { execBinary } from "./exec.js";
import { log } from "../logger.js";
import type { EngineOutput } from "./types.js";
import type { SarifLog } from "../sarif/types.js";
import { invocationSignature, readTrivyDbContentDigest, signature } from "../provenance.js";
import { devScopeFromReport, foldDevDuplicates, markDevScope } from "./trivy-dev-scope.js";

const OFFLINE_FLAGS = [
  "--skip-db-update",
  "--skip-java-db-update",
  "--offline-scan",
  "--skip-check-update",
];

export type TrivyScanner = "vuln" | "misconfig" | "secret" | "license";
const MAX_TRIVY_SBOM_BYTES = 128 * 1024 * 1024;

export interface TrivySbomRun {
  ran: boolean;
  note?: string;
  version: string;
  /** Exact fresh staged bytes; the caller validates before promoting them to outputPath. */
  content?: string;
}

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
    const reportPath = join(tmpDir, "trivy.json");
    const args = buildTrivyArgs(target, reportPath, scanners);
    const convertArgs = buildTrivyConvertArgs(reportPath, sarifPath);
    const dbSignature = await readTrivyDbContentDigest();
    const componentSignatures: Record<string, string> = {
      "trivy:binary": `sha256:${bin.sha256}`,
      // Trivy's built-in secret/license/misconfiguration checks ship with the verified binary.
      "trivy:checks": signature(`trivy:checks\0${bin.sha256}`),
      "trivy:invocation": invocationSignature("trivy", [...args, "&&", ...convertArgs].map((arg) =>
        arg === sarifPath || arg === reportPath ? "<managed-temp>"
          : arg === MANAGED_TRIVY_CACHE ? "<managed-cache>"
            : arg === target ? "<target>"
              : arg)),
      ...(dbSignature ? { "trivy:vulnerability-db": dbSignature } : {}),
    };
    await mkdir(MANAGED_TRIVY_CACHE, { recursive: true });
    const workingDirectory = join(tmpDir, "trivy-cwd");
    await mkdir(workingDirectory);

    let res = await execBinary(bin.path, args, {
      cwd: workingDirectory,
      offline: true,
    });
    // The JSON report is converted to the same SARIF a direct run writes (verified: identical results
    // and rules on a field repository), and keeps each package's Dev flag for the scope marking.
    if (!res.timedOut && await access(reportPath).then(() => true, () => false)) {
      res = await execBinary(bin.path, convertArgs, { cwd: workingDirectory, offline: true });
    }
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
        : " The Trivy vuln DB may be missing; run `codeinspectus setup` to populate the offline DB snapshot.";
      return note(version, t0, `Trivy produced no SARIF (exit ${res.code}).${dbHint} stderr: ${trunc(res.stderr)}`, trivyDbDate);
    }

    // Findings are reported either way; an unreadable report only leaves their scope unmarked.
    const report = await readFile(reportPath, "utf8").then((text) => JSON.parse(text) as unknown, () => undefined);
    markDevScope(sarif, devScopeFromReport(report));
    foldDevDuplicates(sarif);

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

/**
 * Trivy 0.76.1 reads `trivy.yaml`, `.trivyignore` and `trivy-secret.yaml` from its working directory,
 * so a scanned repository could lower severities, ignore CVEs or disable secret rules (verified on the
 * real binary). Callers run it from an empty managed directory, and an empty value for each of the
 * three flags disables loading (Trivy's documented behaviour; it also beats TRIVY_CONFIG).
 */
const NO_REPOSITORY_CONFIG = ["--config", "", "--secret-config", "", "--ignorefile", ""];

/**
 * Pre-release field validation: without `--include-dev-deps` Trivy drops devDependencies (npm, Yarn,
 * pnpm, Bun) and Composer `packages-dev` with no trace. The JSON report (`--list-all-pkgs`) records
 * each package's Dev flag; `buildTrivyConvertArgs` turns it into SARIF.
 */
export function buildTrivyArgs(target: string, reportPath: string, scanners: TrivyScanner[]): string[] {
  return [
    "fs",
    "--scanners",
    scanners.join(","),
    "--format",
    "json",
    "--list-all-pkgs",
    "--include-dev-deps",
    "--output",
    reportPath,
    ...OFFLINE_FLAGS,
    ...NO_REPOSITORY_CONFIG,
    "--cache-dir",
    MANAGED_TRIVY_CACHE,
    target,
  ];
}

/** `trivy convert` has no `--secret-config`; it does read a config file and an ignore file. */
export function buildTrivyConvertArgs(reportPath: string, sarifPath: string): string[] {
  return ["convert", "--format", "sarif", "--output", sarifPath, "--config", "", "--ignorefile", "", "--cache-dir", MANAGED_TRIVY_CACHE, reportPath];
}

/** SBOM generation (PRD §8). The caller validates and promotes the staged content. */
export async function runTrivySbom(
  target: string,
  format: "cyclonedx" | "spdx",
  outputPath: string,
): Promise<TrivySbomRun> {
  let version = "unknown";
  const stagedOutput = `${outputPath}.${process.pid}.${randomUUID()}.trivy.tmp`;
  let workingDirectory: string | undefined;
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
      stagedOutput,
      ...OFFLINE_FLAGS,
      "--config",
      "",
      "--cache-dir",
      MANAGED_TRIVY_CACHE,
      target,
    ];
    // Same reason as buildTrivyArgs: never let the target's trivy.yaml shape the SBOM.
    workingDirectory = await mkdtemp(join(tmpdir(), "ci-trivy-sbom-cwd-"));
    const res = await execBinary(bin.path, args, {
      cwd: workingDirectory,
      offline: true,
    });
    if (res.timedOut || res.code !== 0) {
      return {
        ran: false,
        version,
        note: `Trivy SBOM failed (exit ${res.code ?? "unknown"}${res.timedOut ? ", timed out" : ""}). stderr: ${trunc(res.stderr)}`,
      };
    }
    try {
      const metadata = await lstat(stagedOutput);
      if (!metadata.isFile() || metadata.size === 0) throw new Error("staged output is not a non-empty regular file");
      if (metadata.size > MAX_TRIVY_SBOM_BYTES) {
        throw new Error(`staged output exceeds the ${MAX_TRIVY_SBOM_BYTES / (1024 * 1024)} MiB bound`);
      }
      const content = await readFile(stagedOutput, "utf8");
      return { ran: true, version, content };
    } catch (error) {
      return {
        ran: false,
        version,
        note:
          `Trivy SBOM produced no fresh output (exit ${res.code}). ` +
          `${error instanceof Error ? error.message : String(error)} stderr: ${trunc(res.stderr)}`,
      };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ran: false, version, note: msg };
  } finally {
    await rm(stagedOutput, { force: true }).catch(() => undefined);
    if (workingDirectory) await rm(workingDirectory, { recursive: true, force: true }).catch(() => undefined);
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
