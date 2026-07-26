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

import { readFile, access, stat } from "node:fs/promises";
import { constants as FS } from "node:fs";
import { join } from "node:path";
import { MANAGED_BIN, PKG_ROOT, type EngineName } from "../config.js";
import { sha256Hex } from "../util/hash.js";
import { loadLockfile, getPlatformEntry, platformKey, type Lockfile } from "./lockfile.js";
import { log } from "../logger.js";

export class EngineUnavailableError extends Error {
  constructor(
    public engine: EngineName,
    public reason: EngineAvailabilityIssue,
    message: string,
  ) {
    super(message);
    this.name = "EngineUnavailableError";
  }
}

export type EngineAvailabilityIssue =
  | "missing"
  | "hash_mismatch"
  | "unpinned"
  | "lockfile_error"
  | "unsupported_platform";

interface Resolved {
  path: string;
  version: string;
  sha256: string;
  file_identity: {
    size: number;
    mtime_ms: number;
    ctime_ms: number;
    ino: number;
  };
}

const cache = new Map<EngineName, Resolved>();

async function cachedFileUnchanged(cached: Resolved): Promise<boolean> {
  try {
    const current = await stat(cached.path);
    return (
      current.isFile() &&
      current.size === cached.file_identity.size &&
      current.mtimeMs === cached.file_identity.mtime_ms &&
      current.ctimeMs === cached.file_identity.ctime_ms &&
      current.ino === cached.file_identity.ino
    );
  } catch {
    return false;
  }
}

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
    `Engine '${engine}' is not available. Run \`codeinspectus repair-engines\` once per machine ` +
    `to fetch and SHA-pin the engine binaries (this is the only network step; install-time only). ` +
    `Expected at: ${join(MANAGED_BIN, binaryFilename(engine))}.`
  );
}

export async function resolveEngine(
  engine: EngineName,
  lock?: Lockfile,
): Promise<Resolved> {
  const cached = cache.get(engine);
  if (cached && await cachedFileUnchanged(cached)) return cached;
  if (cached) cache.delete(engine);

  const lockfile = lock ?? (await loadLockfile().catch(() => undefined));
  if (!lockfile) {
    throw new EngineUnavailableError(
      engine,
      "lockfile_error",
      `engines.lock.json could not be read. Reinstall CodeInspectus; repair cannot replace a missing packaged lockfile.`,
    );
  }

  const entry = getPlatformEntry(lockfile, engine);
  const engineMeta = lockfile.engines[engine];
  if (!entry || !engineMeta) {
    throw new EngineUnavailableError(
      engine,
      "unsupported_platform",
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
    throw new EngineUnavailableError(engine, "missing", installHint(engine));
  }

  // GUARDRAIL: pin must exist and must match before we ever exec.
  if (!entry.sha256) {
    throw new EngineUnavailableError(
      engine,
      "unpinned",
      `${engine} is present at ${found} but has no SHA256 pin in engines.lock.json. ` +
        `Refusing to execute an unpinned binary (supply-chain safety, PRD §0.2). ` +
        `Reinstall CodeInspectus; user repair cannot modify an unpinned packaged lockfile.`,
    );
  }

  const actual = sha256Hex(await readFile(found));
  if (actual.toLowerCase() !== entry.sha256.toLowerCase()) {
    throw new EngineUnavailableError(
      engine,
      "hash_mismatch",
      `SHA256 MISMATCH for ${engine} at ${found}.\n` +
        `  expected (lockfile): ${entry.sha256}\n` +
        `  actual (on disk):    ${actual}\n` +
        `Refusing to execute a binary that does not match its pin (possible tampering). ` +
        `Run \`codeinspectus repair-engines\` from a trusted network, or restore the verified binary.`,
    );
  }

  log.debug(`${engine} verified (sha256 ${actual.slice(0, 12)}…) at ${found}`);
  const identity = await stat(found);
  const resolved: Resolved = {
    path: found,
    version: engineMeta.version,
    sha256: actual,
    file_identity: {
      size: identity.size,
      mtime_ms: identity.mtimeMs,
      ctime_ms: identity.ctimeMs,
      ino: identity.ino,
    },
  };
  cache.set(engine, resolved);
  return resolved;
}

/** Non-throwing availability probe for list_rules / scan engine_details. */
export async function probeEngine(
  engine: EngineName,
): Promise<{ available: boolean; version: string; issue?: EngineAvailabilityIssue; note?: string }> {
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
      ...(err instanceof EngineUnavailableError ? { issue: err.reason } : { issue: "lockfile_error" as const }),
      note: err instanceof Error ? err.message : String(err),
    };
  }
}
