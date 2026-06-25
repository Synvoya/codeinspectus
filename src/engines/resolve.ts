/**
 * Engine binary resolution + SHA verification (PRD §4, §0.2, §12).
 *
 * Resolution order: bundled package data → managed dir (~/.codeinspectus/bin) →
 * actionable install error.
 *
 * GUARDRAIL: before returning a path, the binary's SHA256 is verified against
 * the committed lockfile pin. If the pin is null (not yet installed) or the hash
 * mismatches (possible tampering), resolution FAILS with an actionable error and
 * the engine is never executed. This is non-negotiable given the 2026 Trivy
 * supply-chain compromises.
 */

import { readFile, access } from "node:fs/promises";
import { constants as FS } from "node:fs";
import { join } from "node:path";
import { MANAGED_BIN, PKG_ROOT, type EngineName } from "../config.js";
import { sha256Hex } from "../util/hash.js";
import { loadLockfile, getPlatformEntry, platformKey, type Lockfile } from "./lockfile.js";
import { log } from "../logger.js";

export class EngineUnavailableError extends Error {
  constructor(
    public engine: EngineName,
    message: string,
  ) {
    super(message);
    this.name = "EngineUnavailableError";
  }
}

interface Resolved {
  path: string;
  version: string;
  sha256: string;
}

const cache = new Map<EngineName, Resolved>();

function binaryFilename(base: string): string {
  return process.platform === "win32" ? `${base}.exe` : base;
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await access(p, FS.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Candidate locations in resolution order. */
function candidatePaths(engine: EngineName): string[] {
  const fname = binaryFilename(engine);
  return [
    // 1. bundled in the package (platform-specific vendor dir)
    join(PKG_ROOT, "vendor", platformKey(), fname),
    // 2. managed install dir
    join(MANAGED_BIN, fname),
  ];
}

function installHint(engine: EngineName): string {
  return (
    `Engine '${engine}' is not available. Run \`codeinspectus install-engines\` once per machine ` +
    `to fetch and SHA-pin the engine binaries (this is the only network step; install-time only). ` +
    `Expected at: ${join(MANAGED_BIN, binaryFilename(engine))}.`
  );
}

export async function resolveEngine(
  engine: EngineName,
  lock?: Lockfile,
): Promise<Resolved> {
  const cached = cache.get(engine);
  if (cached) return cached;

  const lockfile = lock ?? (await loadLockfile().catch(() => undefined));
  if (!lockfile) {
    throw new EngineUnavailableError(
      engine,
      `engines.lock.json could not be read. Reinstall CodeInspectus or run \`codeinspectus install-engines\`.`,
    );
  }

  const entry = getPlatformEntry(lockfile, engine);
  const engineMeta = lockfile.engines[engine];
  if (!entry || !engineMeta) {
    throw new EngineUnavailableError(
      engine,
      `No lockfile entry for ${engine} on platform '${platformKey()}'. This platform may be unsupported; see README.`,
    );
  }

  // Find the binary on disk.
  let found: string | undefined;
  for (const p of candidatePaths(engine)) {
    if (await fileExists(p)) {
      found = p;
      break;
    }
  }
  if (!found) {
    throw new EngineUnavailableError(engine, installHint(engine));
  }

  // GUARDRAIL: pin must exist and must match before we ever exec.
  if (!entry.sha256) {
    throw new EngineUnavailableError(
      engine,
      `${engine} is present at ${found} but has no SHA256 pin in engines.lock.json. ` +
        `Refusing to execute an unpinned binary (supply-chain safety, PRD §0.2). ` +
        `Run \`codeinspectus install-engines\` to fetch + verify + pin it.`,
    );
  }

  const actual = sha256Hex(await readFile(found));
  if (actual.toLowerCase() !== entry.sha256.toLowerCase()) {
    throw new EngineUnavailableError(
      engine,
      `SHA256 MISMATCH for ${engine} at ${found}.\n` +
        `  expected (lockfile): ${entry.sha256}\n` +
        `  actual (on disk):    ${actual}\n` +
        `Refusing to execute a binary that does not match its pin (possible tampering). ` +
        `Re-run \`codeinspectus install-engines\` from a trusted network, or restore the verified binary.`,
    );
  }

  log.debug(`${engine} verified (sha256 ${actual.slice(0, 12)}…) at ${found}`);
  const resolved: Resolved = { path: found, version: engineMeta.version, sha256: actual };
  cache.set(engine, resolved);
  return resolved;
}

/** Non-throwing availability probe for list_rules / scan engine_details. */
export async function probeEngine(
  engine: EngineName,
): Promise<{ available: boolean; version: string; note?: string }> {
  try {
    const r = await resolveEngine(engine);
    return { available: true, version: r.version };
  } catch (err) {
    const version = await loadLockfile()
      .then((l) => l.engines[engine]?.version ?? "unknown")
      .catch(() => "unknown");
    return {
      available: false,
      version,
      note: err instanceof Error ? err.message : String(err),
    };
  }
}
