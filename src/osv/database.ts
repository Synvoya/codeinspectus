/**
 * Per-ecosystem OSV vulnerability databases for osv-scanner.
 *
 * osv-scanner 2.7.0 reads `<root>/osv-scalibr/<Ecosystem>/all.zip` when run offline. This module is the
 * only place that downloads those archives, and only an install-time caller that already holds the
 * user's explicit consent may call it. Scans never touch the network.
 *
 * OSV publishes no signature for these archives, so the integrity model is TLS to the one allow-listed
 * host plus a SHA-256 recorded at install time (and a zip structure check). The record is what lets a
 * later rescan prove which database a result came from.
 *
 * Ordering rule, same as the Trivy DB (docs/context/gotchas.md): download and verify into a staging
 * file, delete the old provenance record, swap the archive into place, then write the new record. Any
 * interruption degrades to `provenance_missing`; the old signature is never left beside new bytes.
 */

import { createHash, randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { lstat, mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { dirname, join } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import { inflateRawSync } from "node:zlib";

import { MANAGED_OSV_DB, MANAGED_PROVENANCE, TRIVY_DB_STALE_AFTER_MS } from "../config.js";
import type { InstallIo } from "../install.js";
import { osvDatabaseComponent, sha256FileStreaming } from "../provenance.js";
import type { OsvDatabaseHealth } from "../types.js";
import { isOsvEcosystem, OSV_DB_SIZE_ESTIMATES, OSV_ECOSYSTEMS, type OsvEcosystem } from "./ecosystems.js";

const OSV_DB_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";
const MIN_DOWNLOAD_LIMIT_BYTES = 1024 ** 3;

export interface OsvDbRecord {
  component: string;
  ecosystem: OsvEcosystem;
  /** `sha256:<hex>` of the archive as installed. */
  signature: string;
  source_url: string;
  bytes: number;
  /** Upstream `Last-Modified`, normalised to ISO 8601, when the server sent one. */
  last_modified?: string;
  recorded_at: string;
}

/** The archive's URL; the ecosystem is one percent-encoded path segment ("GitHub Actions" → `GitHub%20Actions`). */
export function osvDbSourceUrl(ecosystem: OsvEcosystem): string {
  return `${OSV_DB_BASE_URL}/${encodeURIComponent(ecosystem)}/all.zip`;
}

/** Where osv-scanner 2.7.0 looks for an ecosystem's archive. */
export function osvDbZipPath(ecosystem: OsvEcosystem): string {
  return join(MANAGED_OSV_DB, "osv-scalibr", ecosystem, "all.zip");
}

/** The most a download may be: four times the measured size, and at least 1 GiB (the archives grow). */
export function osvDbDownloadLimit(ecosystem: OsvEcosystem): number {
  return Math.max(4 * OSV_DB_SIZE_ESTIMATES[ecosystem], MIN_DOWNLOAD_LIMIT_BYTES);
}

function osvDbRecordPath(ecosystem: OsvEcosystem): string {
  return join(MANAGED_PROVENANCE, "osv-scanner", `${ecosystem}.json`);
}

/** MiB, or KiB below 1 MiB (Pub's archive is ~25 KiB and would otherwise read as 0.0 MiB). */
export function approxSize(bytes: number): string {
  return bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KiB` : `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

// ── zip structure check ─────────────────────────────────────────────────────

const EOCD_SIGNATURE = 0x06054b50;
const EOCD_LENGTH = 22;
const ZIP64_LOCATOR_SIGNATURE = 0x07064b50;
const ZIP64_LOCATOR_LENGTH = 20;
const ZIP64_EOCD_SIGNATURE = 0x06064b50;
const ZIP64_EOCD_LENGTH = 56;
const CENTRAL_HEADER_SIGNATURE = 0x02014b50;
const MAX_ZIP_COMMENT = 0xffff;

async function readAt(handle: FileHandle, length: number, position: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  if (bytesRead !== length) throw new Error("file is truncated");
  return buffer;
}

/** Reads `length` bytes at `position`, or throws "file is truncated". */
type ReadAt = (length: number, position: number) => Promise<Buffer>;

interface CentralDirectory {
  entries: number;
  offset: number;
  size: number;
}

/**
 * Locate the central directory: find the end-of-central-directory record (following the ZIP64 locator when
 * the 16/32-bit fields overflow, as the large npm archive's do) and check the directory lies inside the file
 * and starts with a central-directory header. Throws a short reason when it does not.
 */
async function locateCentralDirectory(read: ReadAt, size: number): Promise<CentralDirectory> {
  if (size < EOCD_LENGTH) throw new Error("file is too short");
  const tailLength = Math.min(size, EOCD_LENGTH + MAX_ZIP_COMMENT);
  const tail = await read(tailLength, size - tailLength);

  let eocd = -1;
  for (let index = tailLength - EOCD_LENGTH; index >= 0; index--) {
    if (tail.readUInt32LE(index) === EOCD_SIGNATURE && index + EOCD_LENGTH + tail.readUInt16LE(index + 20) === tailLength) {
      eocd = index;
      break;
    }
  }
  if (eocd < 0) throw new Error("no end-of-central-directory record");

  const eocdPosition = size - tailLength + eocd;
  let entries = tail.readUInt16LE(eocd + 10);
  let directorySize = tail.readUInt32LE(eocd + 12);
  let directoryOffset = tail.readUInt32LE(eocd + 16);
  let directoryLimit = eocdPosition;

  if (entries === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff) {
    if (eocdPosition < ZIP64_LOCATOR_LENGTH) throw new Error("ZIP64 locator is missing");
    const locator = await read(ZIP64_LOCATOR_LENGTH, eocdPosition - ZIP64_LOCATOR_LENGTH);
    if (locator.readUInt32LE(0) !== ZIP64_LOCATOR_SIGNATURE) throw new Error("ZIP64 locator is missing");
    const recordPosition = Number(locator.readBigUInt64LE(8));
    if (!Number.isSafeInteger(recordPosition) || recordPosition < 0 || recordPosition + ZIP64_EOCD_LENGTH > size) {
      throw new Error("ZIP64 end-of-central-directory record is out of range");
    }
    const record = await read(ZIP64_EOCD_LENGTH, recordPosition);
    if (record.readUInt32LE(0) !== ZIP64_EOCD_SIGNATURE) throw new Error("ZIP64 end-of-central-directory record is invalid");
    entries = Number(record.readBigUInt64LE(32));
    directorySize = Number(record.readBigUInt64LE(40));
    directoryOffset = Number(record.readBigUInt64LE(48));
    directoryLimit = recordPosition;
  }

  if (entries === 0) throw new Error("archive has no entries");
  if (!Number.isSafeInteger(entries) || !Number.isSafeInteger(directoryOffset) || !Number.isSafeInteger(directorySize) ||
    directorySize < 46 || directoryOffset + directorySize > directoryLimit) {
    throw new Error("central directory lies outside the file");
  }
  const header = await read(4, directoryOffset);
  if (header.readUInt32LE(0) !== CENTRAL_HEADER_SIGNATURE) throw new Error("central directory is unreadable");
  return { entries, offset: directoryOffset, size: directorySize };
}

/**
 * Prove the central directory opens without reading the archive body (see locateCentralDirectory).
 * Throws a short reason when it does not.
 */
async function assertZipCentralDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    const { size } = await handle.stat();
    await locateCentralDirectory((length, position) => readAt(handle, length, position), size);
  } finally {
    await handle.close().catch(() => undefined);
  }
}

// ── bounded in-process zip reading ──────────────────────────────────────────

const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const LOCAL_HEADER_LENGTH = 30;
const CENTRAL_HEADER_LENGTH = 46;

/** Hard bounds for reading an archive whole in memory: hostile or damaged archives fail closed. */
export interface ZipReadLimits {
  maxArchiveBytes: number;
  maxEntries: number;
  /** Largest inflated entry that is read. */
  maxEntryBytes: number;
  /** Sum of the inflated entries that are read. */
  maxTotalBytes: number;
}

export interface ZipArchive {
  /** `sha256:<hex>` of the archive bytes, comparable with an install record's signature. */
  sha256: string;
  entries: Array<{ name: string; data: Buffer }>;
}

/**
 * Read an archive's accepted entries in memory, with no new dependency: the same central-directory location
 * as the install-time check, then every central header in order, stored (0) or deflated (8) entries only.
 * Throws a short reason, never returns a partial read, when anything is outside the limits or cannot be read
 * whole (an encrypted, ZIP64-sized or otherwise unsupported entry, data outside the file, an inflated size
 * other than the one declared). Entries the filter does not accept are never inflated.
 */
export async function readZipArchive(path: string, limits: ZipReadLimits, accept: (name: string) => boolean): Promise<ZipArchive> {
  const info = await lstat(path);
  if (!info.isFile()) throw new Error("archive is not a regular file");
  if (info.size > limits.maxArchiveBytes) throw new Error(`archive is larger than ${limits.maxArchiveBytes} bytes`);
  const bytes = await readFile(path);
  if (bytes.length > limits.maxArchiveBytes) throw new Error(`archive is larger than ${limits.maxArchiveBytes} bytes`);
  const read: ReadAt = async (length, position) => {
    if (position < 0 || position + length > bytes.length) throw new Error("file is truncated");
    return bytes.subarray(position, position + length);
  };
  const directory = await locateCentralDirectory(read, bytes.length);
  if (directory.entries > limits.maxEntries) throw new Error(`archive has more than ${limits.maxEntries} entries`);

  const entries: ZipArchive["entries"] = [];
  const end = directory.offset + directory.size;
  let at = directory.offset;
  let total = 0;
  for (let index = 0; index < directory.entries; index++) {
    if (at + CENTRAL_HEADER_LENGTH > end || bytes.readUInt32LE(at) !== CENTRAL_HEADER_SIGNATURE) throw new Error("central directory is unreadable");
    const flags = bytes.readUInt16LE(at + 8);
    const method = bytes.readUInt16LE(at + 10);
    const compressed = bytes.readUInt32LE(at + 20);
    const size = bytes.readUInt32LE(at + 24);
    const nameLength = bytes.readUInt16LE(at + 28);
    const next = at + CENTRAL_HEADER_LENGTH + nameLength + bytes.readUInt16LE(at + 30) + bytes.readUInt16LE(at + 32);
    const localOffset = bytes.readUInt32LE(at + 42);
    if (next > end) throw new Error("central directory is unreadable");
    const name = bytes.subarray(at + CENTRAL_HEADER_LENGTH, at + CENTRAL_HEADER_LENGTH + nameLength).toString("utf8");
    at = next;
    if (name.endsWith("/") || !accept(name)) continue;
    if ((flags & 0x1) !== 0) throw new Error(`entry ${index + 1} is encrypted`);
    if (method !== 0 && method !== 8) throw new Error(`entry ${index + 1} uses unsupported compression method ${method}`);
    if (compressed === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff) throw new Error(`entry ${index + 1} needs ZIP64 sizes`);
    if (size > limits.maxEntryBytes) throw new Error(`entry ${index + 1} is larger than ${limits.maxEntryBytes} bytes`);
    total += size;
    if (total > limits.maxTotalBytes) throw new Error(`entries hold more than ${limits.maxTotalBytes} bytes`);
    if (localOffset + LOCAL_HEADER_LENGTH > directory.offset || bytes.readUInt32LE(localOffset) !== LOCAL_HEADER_SIGNATURE) {
      throw new Error(`entry ${index + 1} lies outside the archive body`);
    }
    const start = localOffset + LOCAL_HEADER_LENGTH + bytes.readUInt16LE(localOffset + 26) + bytes.readUInt16LE(localOffset + 28);
    if (start + compressed > directory.offset) throw new Error(`entry ${index + 1} lies outside the archive body`);
    const body = bytes.subarray(start, start + compressed);
    let data: Buffer;
    try {
      // Inflation stops at the declared size: a lying header cannot make the output grow.
      data = method === 0 ? Buffer.from(body) : inflateRawSync(body, { maxOutputLength: Math.max(1, size) });
    } catch {
      throw new Error(`entry ${index + 1} is corrupt`);
    }
    if (data.length !== size) throw new Error(`entry ${index + 1} is corrupt`);
    entries.push({ name, data });
  }
  // A directory longer than its end record says (a lying entry count) would otherwise be read only in part.
  if (at !== end) throw new Error("central directory holds more entries than its end record counts");
  return { sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`, entries };
}

// ── provenance records ──────────────────────────────────────────────────────

function validRecord(value: unknown, ecosystem: OsvEcosystem): value is OsvDbRecord {
  if (!value || typeof value !== "object") return false;
  const record = value as Partial<OsvDbRecord>;
  return record.ecosystem === ecosystem &&
    record.component === osvDatabaseComponent(ecosystem) &&
    typeof record.signature === "string" && /^sha256:[a-f0-9]{64}$/.test(record.signature) &&
    record.source_url === osvDbSourceUrl(ecosystem) &&
    typeof record.bytes === "number" && Number.isSafeInteger(record.bytes) && record.bytes >= 0 &&
    typeof record.recorded_at === "string" && Number.isFinite(Date.parse(record.recorded_at)) &&
    (record.last_modified === undefined || typeof record.last_modified === "string");
}

/** The install-time record for an ecosystem, or undefined when absent or not trustworthy. */
export async function readOsvDbRecord(ecosystem: OsvEcosystem): Promise<OsvDbRecord | undefined> {
  try {
    const parsed: unknown = JSON.parse(await readFile(osvDbRecordPath(ecosystem), "utf8"));
    return validRecord(parsed, ecosystem) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

async function writeOsvDbRecord(record: OsvDbRecord): Promise<void> {
  const path = osvDbRecordPath(record.ecosystem);
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(record, null, 2)}\n`, "utf8");
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

// ── install ─────────────────────────────────────────────────────────────────

/**
 * Download one ecosystem's database. Network access; call only after explicit user consent.
 * Fails closed: an error before the swap (download, size limit, length or zip check) leaves the previous
 * archive and record exactly as they were. The old record is deleted just before the swap, so a failure
 * after that point leaves the database `provenance_missing`, never an old record beside new bytes. The
 * staging file is always removed.
 */
export async function installOsvEcosystemDb(
  ecosystem: OsvEcosystem,
  io: InstallIo,
  maxBytes: number = osvDbDownloadLimit(ecosystem),
): Promise<OsvDbRecord> {
  if (!isOsvEcosystem(ecosystem)) {
    throw new Error(`Unsupported OSV ecosystem "${String(ecosystem)}". Allowed: ${OSV_ECOSYSTEMS.join(", ")}.`);
  }
  const sourceUrl = osvDbSourceUrl(ecosystem);
  const destination = osvDbZipPath(ecosystem);
  const stagingDirectory = join(MANAGED_OSV_DB, ".staging");
  const staged = join(stagingDirectory, `${ecosystem}-${process.pid}-${randomUUID()}.zip`);

  io.stdout(`• OSV ${ecosystem} database — downloading (~${approxSize(OSV_DB_SIZE_ESTIMATES[ecosystem])} estimated; install-time only)…`);
  try {
    await mkdir(stagingDirectory, { recursive: true });
    // Redirects are refused: the archive may only come from the allow-listed host.
    const response = await fetch(sourceUrl, { redirect: "error" });
    if (!response.ok) {
      throw new Error(`OSV ${ecosystem} database download failed (${response.status} ${response.statusText}): ${sourceUrl}`);
    }
    if (!response.body) throw new Error(`OSV ${ecosystem} database download returned no body: ${sourceUrl}`);
    const tooLarge = (): Error => new Error(
      `OSV ${ecosystem} database download exceeds the ${approxSize(maxBytes)} limit (four times its measured size, at least 1 GiB) ` +
      "and was stopped; the existing database was left unchanged.",
    );
    const advertised = Number(response.headers.get("content-length"));
    if (Number.isSafeInteger(advertised) && advertised > maxBytes) {
      await response.body.cancel().catch(() => undefined);
      throw tooLarge();
    }
    let received = 0;
    await pipeline(
      Readable.fromWeb(response.body as unknown as WebReadableStream),
      // Counted as it streams: a missing or false Content-Length must not let a download fill the disk.
      new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          received += chunk.length;
          if (received > maxBytes) callback(tooLarge());
          else callback(null, chunk);
        },
      }),
      createWriteStream(staged, { flags: "wx" }),
    );

    const { size } = await stat(staged);
    if (Number.isSafeInteger(advertised) && advertised > 0 && advertised !== size) {
      throw new Error(`OSV ${ecosystem} database length mismatch (expected ${advertised} bytes, got ${size}).`);
    }
    try {
      await assertZipCentralDirectory(staged);
    } catch (error) {
      throw new Error(
        `OSV ${ecosystem} database is not a valid zip archive (${(error as Error).message}); the existing database was left unchanged.`,
      );
    }
    const signature = await sha256FileStreaming(staged);
    const lastModified = Date.parse(response.headers.get("last-modified") ?? "");

    // Clear the old record first so an interruption after the swap can only read as provenance_missing.
    await rm(osvDbRecordPath(ecosystem), { force: true });
    await mkdir(dirname(destination), { recursive: true });
    await rename(staged, destination);

    const record: OsvDbRecord = {
      component: osvDatabaseComponent(ecosystem),
      ecosystem,
      signature,
      source_url: sourceUrl,
      bytes: size,
      ...(Number.isFinite(lastModified) ? { last_modified: new Date(lastModified).toISOString() } : {}),
      recorded_at: new Date().toISOString(),
    };
    await writeOsvDbRecord(record);
    io.stdout(`  ✓ OSV ${ecosystem} database ready (${approxSize(size)}); SHA-256 recorded (${signature.slice(0, 23)}…).`);
    return record;
  } finally {
    await rm(staged, { force: true }).catch(() => undefined);
  }
}

// ── health ──────────────────────────────────────────────────────────────────

/**
 * Health of the databases that are installed (an ecosystem with no archive is simply absent: databases
 * are per-repository and optional). Offline, and cheap: one stat and one small JSON read each, never a
 * hash of the archive.
 */
export async function inspectOsvDatabases(nowMs = Date.now()): Promise<OsvDatabaseHealth[]> {
  const results = await Promise.all(OSV_ECOSYSTEMS.map(async (ecosystem): Promise<OsvDatabaseHealth | undefined> => {
    const archive = await stat(osvDbZipPath(ecosystem)).catch(() => undefined);
    if (!archive?.isFile()) return undefined;
    const record = await readOsvDbRecord(ecosystem);
    // A record that does not describe the archive on disk proves nothing about it.
    if (!record || record.bytes !== archive.size) return { ecosystem, state: "provenance_missing" };
    const stale = nowMs - Date.parse(record.recorded_at) > TRIVY_DB_STALE_AFTER_MS;
    return { ecosystem, state: stale ? "stale" : "ready", downloaded_at: record.recorded_at };
  }));
  return results.filter((item): item is OsvDatabaseHealth => item !== undefined);
}
