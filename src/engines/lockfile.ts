/**
 * Lockfile loader. The lockfile holds SHA256 pins per engine per platform and
 * is the authority for the verify-before-exec guardrail (PRD §0.2).
 */

import { readFile, writeFile } from "node:fs/promises";
import { ENGINES_LOCKFILE, type EngineName } from "../config.js";

export interface Provenance {
  /**
   * "cosign" (signature-verified) | "checksums" (checksum-only; no publisher signature) |
   * "slsa" (checksum-matched asset whose SLSA provenance attestation verified).
   */
  method: "cosign" | "checksums" | "slsa";
  verified: boolean;
  at: string;
  identity?: string;
  issuer?: string;
}

export interface PlatformEntry {
  asset: string;
  archive: "raw" | "tar.gz" | "zip";
  binary: string;
  sha256: string | null;
  /** Runtime ABI required by this upstream asset, when narrower than the OS key. */
  runtime?: { libc: "glibc" };
  /** Exact upstream release-asset bytes, recorded during release pinning. */
  download_size_bytes?: number;
  provenance?: Provenance;
  _verify?: string;
}

export interface EngineLockEntry {
  version: string;
  repo: string;
  release_base: string;
  signature: "cosign" | "checksums" | "checksums+sigstore" | "checksums+slsa";
  checksums_asset: string | null;
  /** SLSA provenance bundle published with the release (checksums+slsa only). */
  attestation_asset?: string;
  platforms: Record<string, PlatformEntry>;
  _security_note?: string;
}

export interface Lockfile {
  schema_version: number;
  generated_at: string | null;
  sigstore_identities?: Record<string, string>;
  /** Pinned `owner/repo` the SLSA attestation must come from, per checksums+slsa engine. */
  slsa_workflow_repositories?: Record<string, string>;
  engines: Record<EngineName, EngineLockEntry>;
  /** Bootstrap tools are not scanners, but use the same immutable release-pin shape. */
  verifiers?: { cosign: EngineLockEntry };
}

/** Node platform/arch → lockfile platform key. */
export function platformKey(): string {
  const platform = process.platform; // 'darwin' | 'linux' | 'win32'
  const arch = process.arch; // 'arm64' | 'x64'
  return `${platform}-${arch}`;
}

export type LinuxLibc = "glibc" | "non-glibc" | "unknown";

/** Detect the ABI of the running Node process without executing external tools. */
export function linuxLibc(): LinuxLibc {
  if (process.platform !== "linux") return "unknown";
  try {
    const report = process.report?.getReport() as { header?: { glibcVersionRuntime?: string } } | undefined;
    return report?.header?.glibcVersionRuntime ? "glibc" : "non-glibc";
  } catch {
    return "unknown";
  }
}

export function platformRuntimeIssue(
  entry: PlatformEntry,
  platform = process.platform,
  libc = linuxLibc(),
): string | undefined {
  if (platform !== "linux" || entry.runtime?.libc !== "glibc" || libc === "glibc") return undefined;
  return libc === "non-glibc"
    ? "The pinned upstream binary requires glibc, but this Linux runtime is non-glibc (for example Alpine/musl)."
    : "The pinned upstream binary requires glibc, but this Linux runtime ABI could not be verified.";
}

export async function loadLockfile(): Promise<Lockfile> {
  const raw = await readFile(ENGINES_LOCKFILE, "utf8");
  return JSON.parse(raw) as Lockfile;
}

export async function saveLockfile(lock: Lockfile): Promise<void> {
  await writeFile(ENGINES_LOCKFILE, JSON.stringify(lock, null, 2) + "\n", "utf8");
}

export function getPlatformEntry(
  lock: Lockfile,
  engine: EngineName,
  key = platformKey(),
): PlatformEntry | undefined {
  return lock.engines[engine]?.platforms[key];
}
