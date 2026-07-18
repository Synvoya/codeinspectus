/**
 * install-engines — the ONLY network step, install-time only (PRD §7, §12).
 *
 * Modes:
 *   install-engines                  Pin + INSTALL the current platform, then fetch the Trivy DB.
 *   install-engines --platform <k>   Pin platform <k> (repeatable). Installs/run only if <k> is current.
 *   install-engines --all-platforms  Pin every platform in the lockfile; install the current one + DB.
 *   (trailing engine names)          Restrict to those engines (opengrep|gitleaks|trivy).
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

import { mkdir, writeFile, readFile, rm, chmod, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import {
  MANAGED_BIN,
  MANAGED_TRIVY_CACHE,
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
import { recordTrivyDbContentDigest } from "./provenance.js";

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
    const base = f.split("/").pop()!.replace(new RegExp(`^${engine}-`), "");
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

async function pinEnginePlatform(
  engine: EngineName,
  plat: string,
  lock: Lockfile,
  identities: Record<string, string>,
  cosignBin: boolean,
  staging: string,
  checksumsCache: Map<EngineName, Map<string, string>>,
  install: boolean,
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

  // Current platform: place a runnable copy in the managed bin dir.
  let installed = false;
  if (install) {
    const runName = isWinPlatform(plat) ? `${entry.binary}.exe` : entry.binary;
    const dest = join(MANAGED_BIN, runName);
    await mkdir(MANAGED_BIN, { recursive: true });
    await copyFile(memberPath, dest);
    await chmod(dest, 0o755).catch(() => {});
    installed = true;
    out(`  ✓ installed ${dest}`);
  }
  out(`  ✓ pinned sha256 ${sha}${install ? "" : "  (cross-platform pin; not installed/run on this machine)"}`);

  // Persist into the lockfile entry.
  entry.sha256 = sha;
  entry.provenance = provenance;
  delete entry._verify;
  return { engine, platform: plat, sha256: sha, provenance, installed };
}

async function populateTrivyDb(): Promise<string | undefined> {
  const trivyBin = join(MANAGED_BIN, process.platform === "win32" ? "trivy.exe" : "trivy");
  out("• Trivy vuln DB — downloading offline snapshot (install-time only)…");
  const r = await run(trivyBin, ["fs", "--download-db-only", "--cache-dir", MANAGED_TRIVY_CACHE]);
  if (r.code !== 0) {
    err(`  ! Trivy DB download failed (exit ${r.code}): ${r.stderr.trim().slice(0, 400)}`);
    return undefined;
  }
  const dbDigest = await recordTrivyDbContentDigest();
  out(`  ✓ Trivy vulnerability DB content signature recorded (${dbDigest.slice(0, 23)}…).`);
  try {
    const meta = JSON.parse(
      await readFile(join(MANAGED_TRIVY_CACHE, "db", "metadata.json"), "utf8"),
    ) as { DownloadedAt?: string };
    out(`  ✓ Trivy DB ready (downloaded ${meta.DownloadedAt ?? "?"}).`);
    return meta.DownloadedAt;
  } catch {
    out("  ✓ Trivy DB download reported success.");
    return undefined;
  }
}

export async function installEngines(args: string[]): Promise<void> {
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

  out("CodeInspectus install-engines — install-time network step (PRD §7).");
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
        const r = await pinEnginePlatform(engine, plat, lock, identities, cosignBin, staging, checksumsCache, install);
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
    err("Populate them by running install-engines on that OS (or via the CI matrix in .github/workflows/pin-engines.yml).");
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
        err(`  ✗ ${engine} v${r.version}: SHA pin OK but NO recorded provenance — re-run install-engines (fail-closed).`);
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
