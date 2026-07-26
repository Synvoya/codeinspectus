/**
 * Explicit engine maintenance commands — the only normal user network path (PRD §7, §12).
 *
 * User modes:
 *   repair-engines                   Offline-plan, then repair only unhealthy engines/DB state.
 *   install-engines                  Backward-compatible alias; also refreshes the Trivy DB.
 *
 * Maintainer mode:
 *   pin-engines [--platform <k>|--all-platforms|--pin-only]
 *                                    Verify release artifacts and update the shipped lockfile.
 *
 * Pinning a platform = download asset -> verify authenticity (MANDATORY, fail-closed:
 * cosign for opengrep; cosign sigstore bundle over checksums for trivy; checksum
 * match for gitleaks) -> extract the binary -> record the EXTRACTED binary's
 * SHA256 + provenance in engines.lock.json. cosign verification is platform-agnostic
 * (it verifies the artifact, not a running process), so foreign-platform binaries
 * can be pinned from any machine; only the CURRENT platform's binary is placed in
 * ~/.codeinspectus/bin and made runnable.
 *
 * Output goes to stdout/stderr (CLI mode; not the MCP transport).
 */

import { mkdir, writeFile, readFile, rm, chmod, copyFile, rename, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { spawn } from "node:child_process";
import {
  MANAGED_BIN,
  MANAGED_TRIVY_CACHE,
  MANAGED_TRIVY_DB_PROVENANCE,
  MANAGED_PROVENANCE,
  MANAGED_ROOT,
  type EngineName,
} from "./config.js";
import { sha256Hex } from "./util/hash.js";
import {
  loadLockfile,
  saveLockfile,
  platformKey,
  type Lockfile,
  type EngineLockEntry,
  type PlatformEntry,
  type Provenance,
} from "./engines/lockfile.js";
import { hasCosign, verifyCertSig, verifyBundle } from "./engines/signature.js";
import { sha256FileStreaming, writeTrivyDbContentDigest } from "./provenance.js";
import { inspectEngineSetup } from "./engine-health.js";
import type { EngineSetupStatus } from "./types.js";

const ENGINE_ORDER: EngineName[] = ["opengrep", "gitleaks", "trivy"];

function out(s: string): void {
  process.stdout.write(s + "\n");
}
function err(s: string): void {
  process.stderr.write(s + "\n");
}

async function run(cmd: string, args: string[], cwd?: string): Promise<{ code: number | null; stderr: string }> {
  return await new Promise((resolve) => {
    const c = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    c.stderr.on("data", (d) => (stderr += d.toString()));
    c.stdout.on("data", () => {});
    c.on("error", (e) => resolve({ code: null, stderr: e.message }));
    c.on("close", (code) => resolve({ code, stderr }));
  });
}

async function download(url: string, dest: string): Promise<void> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download failed (${res.status} ${res.statusText}): ${url}`);
  await writeFile(dest, Buffer.from(await res.arrayBuffer()));
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`fetch failed (${res.status}): ${url}`);
  return await res.text();
}

function parseChecksums(text: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const m = line.trim().match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (m && m[1] && m[2]) map.set(m[2].trim().replace(/^\.\//, ""), m[1].toLowerCase());
  }
  return map;
}

function isWinPlatform(plat: string): boolean {
  return plat.startsWith("win32") || plat.startsWith("win-");
}

/** In-archive binary member name for a target platform. */
function memberName(entry: PlatformEntry, plat: string): string {
  return isWinPlatform(plat) ? `${entry.binary}.exe` : entry.binary;
}

/** Extract the binary member to outDir; return its path. For raw, the asset IS the binary. */
async function extractMember(
  archivePath: string,
  entry: PlatformEntry,
  plat: string,
  outDir: string,
): Promise<string> {
  if (entry.archive === "raw") return archivePath;
  const member = memberName(entry, plat);
  if (entry.archive === "tar.gz") {
    const r = await run("tar", ["-xzf", archivePath, "-C", outDir, member]);
    if (r.code !== 0) {
      const r2 = await run("tar", ["-xzf", archivePath, "-C", outDir]);
      if (r2.code !== 0) throw new Error(`tar extraction failed: ${r.stderr || r2.stderr}`);
    }
    return join(outDir, member);
  }
  // zip — prefer bsdtar (present on macOS + Windows 10+, handles zip), fallback to unzip.
  let r = await run("tar", ["-xf", archivePath, "-C", outDir, member]);
  if (r.code !== 0) {
    r = await run("unzip", ["-o", archivePath, member, "-d", outDir]);
    if (r.code !== 0) throw new Error(`zip extraction failed: ${r.stderr}`);
  }
  return join(outDir, member);
}

/** Per-engine verified checksums (download once, verify signature where applicable). */
async function getVerifiedChecksums(
  engine: EngineName,
  meta: EngineLockEntry,
  identities: Record<string, string>,
  cosignBin: boolean,
  staging: string,
  cache: Map<EngineName, Map<string, string>>,
): Promise<Map<string, string>> {
  const cached = cache.get(engine);
  if (cached) return cached;
  if (!meta.checksums_asset) throw new Error(`${engine}: no checksums asset configured (fail-closed).`);
  const checksumsPath = join(staging, `${engine}-${meta.checksums_asset}`);
  await download(`${meta.release_base}/${meta.checksums_asset}`, checksumsPath);

  if (meta.signature === "checksums+sigstore") {
    if (!cosignBin) {
      throw new Error(`${engine} requires cosign signature verification but cosign is not installed (fail-closed).`);
    }
    const identity = identities[engine];
    const issuer = identities.issuer;
    if (!identity || !issuer) throw new Error(`${engine}: no pinned cosign identity/issuer (fail-closed).`);
    const bundlePath = join(staging, `${engine}-${meta.checksums_asset}.sigstore.json`);
    await download(`${meta.release_base}/${meta.checksums_asset}.sigstore.json`, bundlePath);
    const r = await verifyBundle({ blob: checksumsPath, bundlePath, identity, issuer });
    if (!r.ok) throw new Error(`${engine}: sigstore verification of checksums FAILED — ${r.detail} (fail-closed).`);
    out(`  ✓ ${engine}: cosign sigstore bundle verified over ${meta.checksums_asset} (identity: ${identity}).`);
    await cacheArtifacts(engine, [checksumsPath, bundlePath]);
  } else {
    out(`  i ${engine}: checksums fetched (gitleaks publishes no cosign signature; checksum-only).`);
    await cacheArtifacts(engine, [checksumsPath]);
  }
  const parsed = parseChecksums(await readFile(checksumsPath, "utf8"));
  cache.set(engine, parsed);
  return parsed;
}

async function cacheArtifacts(engine: EngineName, files: string[]): Promise<void> {
  const dir = join(MANAGED_PROVENANCE, engine);
  await mkdir(dir, { recursive: true });
  for (const f of files) {
    const base = basename(f).replace(new RegExp(`^${engine}-`), "");
    await copyFile(f, join(dir, base)).catch(() => {});
  }
}

interface PinResult {
  engine: EngineName;
  platform: string;
  sha256: string;
  provenance: Provenance;
  installed: boolean;
}

async function atomicInstallBinary(source: string, dest: string): Promise<void> {
  await mkdir(MANAGED_BIN, { recursive: true });
  const tmp = join(MANAGED_BIN, `.${basename(dest)}.${process.pid}.${Date.now()}.tmp`);
  const backup = `${dest}.${process.pid}.${Date.now()}.backup`;
  await copyFile(source, tmp);
  await chmod(tmp, 0o755).catch(() => {});
  try {
    try {
      // POSIX rename replaces atomically. This is the normal path.
      await rename(tmp, dest);
    } catch (first) {
      // Windows may reject replacement of an existing executable. Preserve the
      // prior verified binary until the replacement has been moved into place.
      await rename(dest, backup);
      try {
        await rename(tmp, dest);
      } catch (second) {
        await rename(backup, dest).catch(() => {});
        throw second;
      }
      await rm(backup, { force: true }).catch(() => {});
    }
  } finally {
    await rm(tmp, { force: true }).catch(() => {});
    await rm(backup, { force: true }).catch(() => {});
  }
}

async function pinEnginePlatform(
  engine: EngineName,
  plat: string,
  lock: Lockfile,
  identities: Record<string, string>,
  cosignBin: boolean,
  staging: string,
  checksumsCache: Map<EngineName, Map<string, string>>,
  install: boolean,
  updateLockfile: boolean,
): Promise<PinResult> {
  const meta = lock.engines[engine];
  const entry = meta?.platforms[plat];
  if (!meta || !entry) throw new Error(`no asset for platform '${plat}'`);

  const platDir = join(staging, `${engine}-${plat}`);
  await mkdir(platDir, { recursive: true });
  const url = `${meta.release_base}/${entry.asset}`;
  out(`• ${engine} v${meta.version} [${plat}] — ${entry.asset}`);
  const archivePath = join(platDir, entry.asset);
  await download(url, archivePath);

  const at = new Date().toISOString();
  let provenance: Provenance;

  if (meta.signature === "cosign") {
    // opengrep: per-asset cosign cert+sig over the binary. MANDATORY.
    if (!cosignBin) throw new Error(`${engine} requires cosign but it is not installed (fail-closed).`);
    const identity = identities[engine];
    const issuer = identities.issuer;
    if (!identity || !issuer) throw new Error(`${engine}: no pinned cosign identity/issuer (fail-closed).`);
    const sigPath = join(platDir, `${entry.asset}.sig`);
    const certPath = join(platDir, `${entry.asset}.cert`);
    await download(`${url}.sig`, sigPath);
    await download(`${url}.cert`, certPath);
    const r = await verifyCertSig({ blob: archivePath, certPath, sigPath, identity, issuer });
    if (!r.ok) throw new Error(`${engine} [${plat}]: signature verification FAILED — ${r.detail} (fail-closed; not pinned).`);
    out(`  ✓ cosign signature verified.`);
    if (install) await cacheArtifacts(engine, [sigPath, certPath]);
    provenance = { method: "cosign", verified: true, at, identity, issuer };
  } else {
    // gitleaks (checksums) / trivy (checksums+sigstore): verify checksum match.
    const checksums = await getVerifiedChecksums(engine, meta, identities, cosignBin, staging, checksumsCache);
    const expected = checksums.get(entry.asset);
    if (!expected) throw new Error(`${engine} [${plat}]: '${entry.asset}' not in checksums; cannot verify (fail-closed).`);
    const actualArchive = sha256Hex(await readFile(archivePath));
    if (actualArchive.toLowerCase() !== expected) {
      throw new Error(`${engine} [${plat}]: archive checksum MISMATCH (expected ${expected}, got ${actualArchive}). Fail-closed.`);
    }
    out(`  ✓ archive checksum matches ${meta.signature === "checksums+sigstore" ? "signed " : ""}checksums.`);
    provenance =
      meta.signature === "checksums+sigstore"
        ? { method: "cosign", verified: true, at, identity: identities[engine], issuer: identities.issuer }
        : { method: "checksums", verified: true, at };
  }

  // Extract the binary, compute its SHA256 (the verify-before-exec pin).
  const memberPath = await extractMember(archivePath, entry, plat, platDir);
  const sha = sha256Hex(await readFile(memberPath));

  if (!updateLockfile) {
    if (!entry.sha256) {
      throw new Error(`${engine} [${plat}]: shipped lockfile has no SHA256 pin; refusing user repair.`);
    }
    if (sha.toLowerCase() !== entry.sha256.toLowerCase()) {
      throw new Error(
        `${engine} [${plat}]: extracted binary does not match the immutable shipped pin ` +
        `(expected ${entry.sha256}, got ${sha}). Fail-closed.`,
      );
    }
  }

  // Current platform: place a runnable copy in the managed bin dir.
  let installed = false;
  if (install) {
    const runName = isWinPlatform(plat) ? `${entry.binary}.exe` : entry.binary;
    const dest = join(MANAGED_BIN, runName);
    await atomicInstallBinary(memberPath, dest);
    installed = true;
    out(`  ✓ installed ${dest}`);
  }
  out(
    updateLockfile
      ? `  ✓ pinned sha256 ${sha}${install ? "" : "  (cross-platform pin; not installed/run on this machine)"}`
      : `  ✓ matched immutable shipped sha256 ${sha}`,
  );

  // Only the maintainer pinning command may mutate the packaged lockfile.
  if (updateLockfile) {
    entry.sha256 = sha;
    entry.provenance = provenance;
    delete entry._verify;
  }
  return { engine, platform: plat, sha256: sha, provenance, installed };
}

async function replaceDirectory(staged: string, dest: string): Promise<void> {
  const backup = `${dest}.${process.pid}.${Date.now()}.backup`;
  let movedExisting = false;
  let replacementInstalled = false;
  try {
    try {
      await rename(dest, backup);
      movedExisting = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    try {
      await rename(staged, dest);
      replacementInstalled = true;
    } catch (error) {
      if (movedExisting) {
        try {
          await rename(backup, dest);
          movedExisting = false;
        } catch (restoreError) {
          throw new AggregateError(
            [error, restoreError],
            `Failed to install the staged Trivy DB and restore the previous DB. Backup preserved at ${backup}.`,
          );
        }
      }
      throw error;
    }
    if (movedExisting && replacementInstalled) {
      await rm(backup, { recursive: true, force: true });
      movedExisting = false;
    }
  } finally {
    if (!movedExisting) await rm(backup, { recursive: true, force: true }).catch(() => {});
  }
}

async function populateTrivyDb(): Promise<string | undefined> {
  const trivyBin = join(MANAGED_BIN, process.platform === "win32" ? "trivy.exe" : "trivy");
  const stagingCache = join(MANAGED_ROOT, `.trivy-cache-repair-${process.pid}-${Date.now()}`);
  const stagingDbDir = join(stagingCache, "db");
  out("• Trivy vuln DB — downloading offline snapshot (install-time only)…");
  try {
    await mkdir(stagingCache, { recursive: true });
    const r = await run(trivyBin, ["fs", "--download-db-only", "--cache-dir", stagingCache]);
    if (r.code !== 0) {
      throw new Error(`Trivy DB download failed (exit ${r.code}): ${r.stderr.trim().slice(0, 400)}`);
    }
    await stat(join(stagingDbDir, "trivy.db"));
    const meta = JSON.parse(
      await readFile(join(stagingDbDir, "metadata.json"), "utf8"),
    ) as { DownloadedAt?: string };
    const dbDigest = await sha256FileStreaming(join(stagingDbDir, "trivy.db"));
    await mkdir(MANAGED_TRIVY_CACHE, { recursive: true });
    // Clear the old signature before swapping DB content. Any interruption then
    // degrades conservatively to provenance_missing; it can never associate the
    // previous DB signature with newly-installed DB bytes.
    await rm(MANAGED_TRIVY_DB_PROVENANCE, { force: true });
    await replaceDirectory(stagingDbDir, join(MANAGED_TRIVY_CACHE, "db"));
    await writeTrivyDbContentDigest(dbDigest);
    out(`  ✓ Trivy vulnerability DB content signature recorded (${dbDigest.slice(0, 23)}…).`);
    out(`  ✓ Trivy DB ready (downloaded ${meta.DownloadedAt ?? "?"}).`);
    return meta.DownloadedAt;
  } finally {
    await rm(stagingCache, { recursive: true, force: true }).catch(() => {});
  }
}

export interface EngineRepairPlan {
  engines: EngineName[];
  refresh_trivy_db: boolean;
  blockers: string[];
}

export function planEngineRepair(
  status: EngineSetupStatus,
  selected: EngineName[] = ENGINE_ORDER,
  forceDbRefresh = false,
): EngineRepairPlan {
  const selectedSet = new Set(selected);
  const blockers = status.engines
    .filter(
      (engine) =>
        selectedSet.has(engine.engine) &&
        ["unsupported_platform", "unpinned", "lockfile_error"].includes(engine.state),
    )
    .map((engine) =>
      engine.state === "unsupported_platform"
        ? `${engine.engine} is unsupported on ${status.platform}`
        : `${engine.engine} has invalid packaged pin state (${engine.state}); reinstall CodeInspectus`,
    );
  const engines = status.engines
    .filter(
      (engine) =>
        selectedSet.has(engine.engine) &&
        engine.state !== "ready" &&
        !["unsupported_platform", "unpinned", "lockfile_error"].includes(engine.state),
    )
    .map((engine) => engine.engine);
  const trivySelected = selectedSet.has("trivy");
  const trivySupported = !status.engines.some(
    (engine) => engine.engine === "trivy" && engine.state === "unsupported_platform",
  );
  return {
    engines,
    refresh_trivy_db:
      trivySelected && trivySupported && (forceDbRefresh || status.trivy_db.state !== "ready"),
    blockers,
  };
}

function parseRepairArgs(args: string[]): { selected: EngineName[]; refreshDb: boolean } {
  const refreshDb = args.includes("--refresh-db");
  const unknown = args.filter(
    (arg) => arg !== "--refresh-db" && !ENGINE_ORDER.includes(arg as EngineName),
  );
  if (unknown.length) {
    throw new Error(
      `Unknown repair-engines argument(s): ${unknown.join(", ")}. ` +
      "Use --refresh-db or an engine name (opengrep, gitleaks, trivy).",
    );
  }
  const selected = args.filter((arg) => ENGINE_ORDER.includes(arg as EngineName)) as EngineName[];
  return { selected: selected.length ? [...new Set(selected)] : ENGINE_ORDER, refreshDb };
}

const REPAIR_LOCK = join(MANAGED_ROOT, ".repair-engines.lock");
const STALE_REPAIR_LOCK_MS = 1000 * 60 * 60 * 2;

function processIsRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

async function acquireRepairLock(): Promise<() => Promise<void>> {
  async function create(): Promise<void> {
    await mkdir(REPAIR_LOCK);
    await writeFile(
      join(REPAIR_LOCK, "owner.json"),
      JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() }),
      "utf8",
    );
  }

  await mkdir(MANAGED_ROOT, { recursive: true });
  try {
    await create();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const info = await stat(REPAIR_LOCK).catch(() => undefined);
    const owner = await readFile(join(REPAIR_LOCK, "owner.json"), "utf8")
      .then((raw) => JSON.parse(raw) as { pid?: unknown })
      .catch(() => undefined);
    const ownerPid = typeof owner?.pid === "number" ? owner.pid : undefined;
    const ownerActive = ownerPid !== undefined && processIsRunning(ownerPid);
    const recentOwnerlessLock = ownerPid === undefined && (!info || Date.now() - info.mtimeMs <= STALE_REPAIR_LOCK_MS);
    if (ownerActive || recentOwnerlessLock) {
      throw new Error(
        `Another engine repair is already running${ownerPid ? ` (pid ${ownerPid})` : ""} (${REPAIR_LOCK}). ` +
        "Wait for it to finish, then retry.",
      );
    }
    await rm(REPAIR_LOCK, { recursive: true, force: true });
    await create();
  }
  return async () => {
    await rm(REPAIR_LOCK, { recursive: true, force: true });
  };
}

/** User-facing, incremental repair. Never mutates the packaged engines.lock.json. */
export async function repairEngines(args: string[]): Promise<void> {
  const { selected, refreshDb } = parseRepairArgs(args);
  const fullScope = selected.length === ENGINE_ORDER.length;
  const firstStatus = await inspectEngineSetup();
  let plan = planEngineRepair(firstStatus, selected, refreshDb);
  if (plan.blockers.length) throw new Error(plan.blockers.join("; "));
  if (!plan.engines.length && !plan.refresh_trivy_db) {
    out(
      fullScope
        ? "✓ Engine setup ready. Shipped pins, managed binaries, and Trivy DB state need no repair."
        : "✓ Selected repair scope is healthy; no download needed. Unselected engine/DB state was not changed.",
    );
    return;
  }

  const releaseLock = await acquireRepairLock();
  try {
    // Re-evaluate under the lock so two near-simultaneous processes never repeat
    // a download based on the same stale preflight.
    plan = planEngineRepair(await inspectEngineSetup(), selected, refreshDb);
    if (plan.blockers.length) throw new Error(plan.blockers.join("; "));
    if (!plan.engines.length && !plan.refresh_trivy_db) {
      out(
        fullScope
          ? "✓ Engine setup was repaired by another process; nothing to do."
          : "✓ Selected repair scope was repaired by another process; unselected state was not changed.",
      );
      return;
    }

    const lock = await loadLockfile();
    const current = platformKey();
    out("CodeInspectus repair-engines — explicit install-time network step.");
    out(`Host platform: ${current}  Managed dir: ${MANAGED_ROOT}`);
    out(`Repair plan: engines ${plan.engines.join(", ") || "(none)"}; Trivy DB ${plan.refresh_trivy_db ? "refresh" : "unchanged"}.\n`);

    await mkdir(MANAGED_BIN, { recursive: true });
    await mkdir(MANAGED_TRIVY_CACHE, { recursive: true });
    const staging = join(tmpdir(), `ci-repair-${process.pid}-${Date.now()}`);
    await mkdir(staging, { recursive: true });
    try {
      const identities = (lock.sigstore_identities ?? {}) as Record<string, string>;
      const needsCosign = plan.engines.some(
        (engine) => lock.engines[engine]?.signature !== "checksums",
      );
      const cosignBin = needsCosign ? await hasCosign() : false;
      if (needsCosign && !cosignBin) {
        throw new Error(
          "cosign is required to verify the selected Opengrep/Trivy release artifacts. " +
          "Install cosign, then rerun repair-engines.",
        );
      }

      const checksumsCache = new Map<EngineName, Map<string, string>>();
      for (const engine of plan.engines) {
        await pinEnginePlatform(
          engine,
          current,
          lock,
          identities,
          cosignBin,
          staging,
          checksumsCache,
          true,
          false,
        );
      }
      if (plan.refresh_trivy_db) await populateTrivyDb();
    } finally {
      await rm(staging, { recursive: true, force: true }).catch(() => {});
    }

    const finalStatus = await inspectEngineSetup();
    const finalPlan = planEngineRepair(finalStatus, selected, false);
    if (finalPlan.blockers.length || finalPlan.engines.length || finalPlan.refresh_trivy_db) {
      throw new Error(
        `Repair finished but preflight is still ${finalStatus.state}. ` +
        "Inspect `codeinspectus_list_rules` engine_setup details and retry.",
      );
    }
    out("\n✓ Engine repair complete. Packaged pins were not modified; scans remain offline.");
  } finally {
    await releaseLock();
  }
}

/** Backward-compatible user alias; explicit install historically refreshed the DB. */
export async function installEngines(args: string[]): Promise<void> {
  const maintainerFlags = args.some(
    (arg) => arg === "--all-platforms" || arg === "--platform" || arg === "--pin-only",
  );
  if (maintainerFlags) {
    err("! install-engines maintainer flags are deprecated; use pin-engines. Continuing compatibly.");
    await pinEngines(args);
    return;
  }
  await repairEngines(args.includes("--refresh-db") ? args : [...args, "--refresh-db"]);
}

export async function pinEngines(args: string[]): Promise<void> {
  const lock = await loadLockfile();
  const current = platformKey();

  // Parse flags.
  const allPlatforms = args.includes("--all-platforms");
  // --pin-only: record SHA256 + provenance only; never install/run a binary or
  // fetch the Trivy DB. Intended for CI matrix runners that pin their own platform.
  const pinOnly = args.includes("--pin-only");
  const platFlags: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--platform" && args[i + 1]) platFlags.push(args[++i] as string);
  }
  const engineFilter = args.filter((a) => !a.startsWith("--") && ENGINE_ORDER.includes(a as EngineName)) as EngineName[];
  const engines = engineFilter.length ? engineFilter : ENGINE_ORDER;

  // Determine target platforms.
  let platforms: string[];
  if (allPlatforms) {
    const set = new Set<string>();
    for (const e of engines) for (const k of Object.keys(lock.engines[e]?.platforms ?? {})) set.add(k);
    platforms = [...set];
  } else if (platFlags.length) {
    platforms = platFlags;
  } else {
    platforms = [current];
  }

  out("CodeInspectus pin-engines — maintainer release-pinning step (networked).");
  out(`Host platform: ${current}  Targets: ${platforms.join(", ")}  Managed dir: ${MANAGED_ROOT}\n`);

  await mkdir(MANAGED_BIN, { recursive: true });
  await mkdir(MANAGED_TRIVY_CACHE, { recursive: true });
  const staging = join(tmpdir(), `ci-install-${Date.now()}`);
  await mkdir(staging, { recursive: true });

  const identities = (lock.sigstore_identities ?? {}) as Record<string, string>;
  const cosignBin = await hasCosign();
  if (!cosignBin) {
    err("cosign is NOT installed. Signature verification is mandatory for opengrep and trivy;");
    err("those engines will FAIL to pin until cosign is available. Install: `brew install cosign`.\n");
  }

  const checksumsCache = new Map<EngineName, Map<string, string>>();
  const pinned: PinResult[] = [];
  const failures: Array<{ engine: EngineName; platform: string; reason: string }> = [];
  let currentInstalledTrivy = false;

  for (const plat of platforms) {
    for (const engine of engines) {
      const install = !pinOnly && plat === current;
      try {
        const r = await pinEnginePlatform(
          engine,
          plat,
          lock,
          identities,
          cosignBin,
          staging,
          checksumsCache,
          install,
          true,
        );
        pinned.push(r);
        if (r.installed && engine === "trivy") currentInstalledTrivy = true;
      } catch (e) {
        const reason = (e as Error).message;
        failures.push({ engine, platform: plat, reason });
        err(`  ✗ ${engine} [${plat}] NOT pinned: ${reason}\n`);
      }
    }
  }

  lock.generated_at = new Date().toISOString();
  await saveLockfile(lock);
  out("\n✓ engines.lock.json updated with verified SHA256 pins + provenance.");

  if (currentInstalledTrivy) await populateTrivyDb();

  await rm(staging, { recursive: true, force: true }).catch(() => {});

  out(`\nDone. Pinned ${pinned.length} (engine x platform). Installed-runnable: ${pinned.filter((p) => p.installed).map((p) => p.engine).join(", ") || "(none)"}.`);
  if (failures.length) {
    err(`\n${failures.length} engine x platform combos were NOT pinned (fail-closed). They remain null in the lockfile:`);
    for (const f of failures) err(`  - ${f.engine} [${f.platform}]: ${f.reason}`);
    err("Populate them by running pin-engines on that OS (or via the CI matrix in .github/workflows/pin-engines.yml).");
    process.exitCode = 1;
  }
}

export async function verifyEnginesCli(): Promise<void> {
  const deep = process.argv.includes("--deep");
  const { resolveEngine, EngineUnavailableError } = await import("./engines/resolve.js");
  const { getPlatformEntry } = await import("./engines/lockfile.js");
  const lock = await loadLockfile();
  out(`Verifying engine binaries against engines.lock.json (platform ${platformKey()})${deep ? " [deep: live cosign re-check]" : ""}:\n`);
  let anyBad = false;

  for (const engine of ENGINE_ORDER) {
    try {
      const r = await resolveEngine(engine, lock); // SHA256 pin check (throws on mismatch/unpinned)
      const entry = getPlatformEntry(lock, engine);
      const prov = entry?.provenance;
      if (!prov || !prov.verified) {
        anyBad = true;
        err(`  ✗ ${engine} v${r.version}: SHA pin OK but NO recorded provenance — reinstall the package or contact the maintainer (fail-closed).`);
        continue;
      }
      const provLabel = prov.method === "cosign" ? `cosign-verified (${prov.identity})` : "checksum-verified";
      out(`  ✓ ${engine} v${r.version}: SHA pin OK (${r.sha256.slice(0, 16)}…), ${provLabel} at install (${prov.at}).`);
      if (deep) {
        const ok = await deepVerify(engine, lock);
        if (!ok) {
          anyBad = true;
          err(`    ✗ ${engine}: deep cosign re-verification FAILED.`);
        } else {
          out(`    ✓ ${engine}: deep signature re-verification passed.`);
        }
      }
    } catch (e) {
      anyBad = true;
      const msg = e instanceof EngineUnavailableError ? e.message : (e as Error).message;
      err(`  ✗ ${engine}: ${msg}`);
    }
  }
  if (anyBad) process.exitCode = 1;
}

/** Live cosign re-verification using cached provenance artifacts (network for tlog). */
async function deepVerify(engine: EngineName, lock: Lockfile): Promise<boolean> {
  const { getPlatformEntry } = await import("./engines/lockfile.js");
  const meta = lock.engines[engine];
  const entry = getPlatformEntry(lock, engine);
  const identities = (lock.sigstore_identities ?? {}) as Record<string, string>;
  const issuer = identities.issuer;
  const identity = identities[engine];
  const dir = join(MANAGED_PROVENANCE, engine);
  if (!meta || !entry) return false;

  if (meta.signature === "cosign") {
    const blob = join(MANAGED_BIN, process.platform === "win32" ? `${entry.binary}.exe` : entry.binary);
    const r = await verifyCertSig({
      blob,
      certPath: join(dir, `${entry.asset}.cert`),
      sigPath: join(dir, `${entry.asset}.sig`),
      identity: identity!,
      issuer: issuer!,
    });
    return r.ok;
  }
  if (meta.signature === "checksums+sigstore" && meta.checksums_asset) {
    const r = await verifyBundle({
      blob: join(dir, meta.checksums_asset),
      bundlePath: join(dir, `${meta.checksums_asset}.sigstore.json`),
      identity: identity!,
      issuer: issuer!,
    });
    return r.ok;
  }
  return true; // gitleaks: no signature; SHA-pin match is the guarantee.
}
