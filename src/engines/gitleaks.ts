/**
 * Gitleaks wrapper — secrets (PRD §4.2). Fully offline (regex + entropy).
 * Emits SARIF 2.1.0. Always uses the bundled CodeInspectus config. Target
 * Gitleaks config and inline allow comments are deliberately ignored so they
 * cannot silently replace or suppress the bundled checks. A target
 * .gitleaksignore cannot be neutralized by Gitleaks 8.30.1. Only an entry naming
 * an absolute path can match this directory scan; one that can is disclosed as
 * unverified secret coverage by the scan envelope. (A target scanned through the
 * managed link, see gitleaksSource, matches neither; it is still disclosed.)
 *
 *   gitleaks dir <target> --report-format sarif --report-path <file>
 *     --no-banner --exit-code 0 [--config <our toml>]
 *
 * --exit-code 0 so that findings (which normally exit non-zero) don't look like
 * a crash; the server interprets the SARIF, not the exit code.
 */

import { readFile, access, mkdir, stat, symlink } from "node:fs/promises";
import { join, sep } from "node:path";
import { GITLEAKS_CONFIG } from "../config.js";
import { detectGitleaksSuppression } from "../gitleaks-suppression.js";
import { resolveEngine, EngineUnavailableError } from "./resolve.js";
import { execBinary } from "./exec.js";
import { log } from "../logger.js";
import type { EngineOutput } from "./types.js";
import type { SarifLog } from "../sarif/types.js";
import { fileSignature, invocationSignature, signature } from "../provenance.js";
import { directoryPrefixAllowlisted, filePrefixAllowlisted } from "./gitleaks-allowlist.js";

const ALLOWLISTED_TARGET =
  "Secret coverage unverified: Gitleaks' default allowlist matches a folder above the scan target (such as " +
  "node_modules/, vendor/bundle/ or lib/python3.x/site-packages/), so Gitleaks reports no secrets in it.";

interface GitleaksSource {
  /** The `gitleaks dir` source argument. */
  path: string;
  /** Set when scanning through the managed link: the URI prefix to map back to the target. */
  linkPrefix?: string;
  limitation?: string;
}

/**
 * Review I-7: Gitleaks applies its default allowlist to absolute paths, so a target whose own folders
 * match it (node_modules/pkg, site-packages/pkg) is scanned through a managed link instead. Gitleaks
 * walks a linked folder given with a trailing separator (verified on 8.30.1) and still follows no
 * symlink inside it. Every other target is scanned at its real path, unchanged. A single file cannot be
 * linked (Gitleaks skips a symlinked file), so an allowlisted one is reported as unverified.
 */
async function gitleaksSource(target: string, tmpDir: string): Promise<GitleaksSource> {
  const metadata = await stat(target).catch(() => undefined);
  if (metadata?.isFile()) return filePrefixAllowlisted(target) ? { path: target, limitation: ALLOWLISTED_TARGET } : { path: target };
  if (!metadata?.isDirectory() || !directoryPrefixAllowlisted(target)) return { path: target };
  // Final review Minor 5: a junction with a trailing separator is unverified on Windows; fail closed.
  if (process.platform === "win32") return { path: target, limitation: ALLOWLISTED_TARGET };
  const parent = join(tmpDir, "gitleaks-source");
  const link = join(parent, "target");
  try {
    await mkdir(parent);
    await symlink(target, link, "dir");
  } catch {
    return { path: target, limitation: ALLOWLISTED_TARGET };
  }
  if (directoryPrefixAllowlisted(link)) return { path: target, limitation: ALLOWLISTED_TARGET };
  return { path: `${link}${sep}`, linkPrefix: `${link}${sep}` };
}

function mapLinkedUris(sarif: SarifLog, linkPrefix: string, target: string): void {
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      for (const location of result.locations ?? []) {
        const artifact = location.physicalLocation?.artifactLocation;
        if (artifact?.uri?.startsWith(linkPrefix)) artifact.uri = join(target, artifact.uri.slice(linkPrefix.length));
      }
    }
  }
}

export async function runGitleaks(target: string, tmpDir: string): Promise<EngineOutput> {
  const t0 = Date.now();
  let version = "unknown";
  const secretSuppression = await detectGitleaksSuppression(target);
  try {
    const bin = await resolveEngine("gitleaks");
    version = bin.version;
    const sarifPath = join(tmpDir, "gitleaks.sarif");
    const source = await gitleaksSource(target, tmpDir);
    const args = buildGitleaksArgs(source.path, sarifPath);
    const ignorePresent = secretSuppression.channels.some((surface) => surface.channel === "gitleaks_ignore");
    const componentSignatures = {
      "gitleaks:binary": `sha256:${bin.sha256}`,
      "gitleaks:config": await fileSignature(GITLEAKS_CONFIG),
      "gitleaks:invocation": invocationSignature("gitleaks", args.map((arg) =>
        arg === target ? "<target>"
          : source.linkPrefix && arg === source.path ? "<target-via-managed-link>"
          : arg === sarifPath ? "<managed-temp>"
            : arg === GITLEAKS_CONFIG ? "<bundled-config>"
              : arg)),
      "gitleaks:effective-ignore": ignorePresent
        ? await fileSignature(join(target, ".gitleaksignore"))
        : signature("gitleaks:effective-ignore\0absent"),
    };

    // Gitleaks also loads `.gitleaksignore` from its working directory (`--gitleaks-ignore-path .`).
    // For a single-file target that was the file's directory, whose ignore file hid findings without
    // disclosure; an empty managed directory leaves only the target's own, disclosed `.gitleaksignore`.
    const workingDirectory = join(tmpDir, "gitleaks-cwd");
    await mkdir(workingDirectory);
    const res = await execBinary(bin.path, args, {
      cwd: workingDirectory,
      offline: true,
    });
    let sarif: SarifLog | undefined;
    try {
      await access(sarifPath);
      sarif = JSON.parse(await readFile(sarifPath, "utf8")) as SarifLog;
      if (source.linkPrefix) mapLinkedUris(sarif, source.linkPrefix, target);
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
      ...(source.limitation ? { coverageWarnings: [source.limitation] } : {}),
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
