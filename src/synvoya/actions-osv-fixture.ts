/**
 * Test and eval support only (never imported by the product): an OSV "GitHub Actions" all.zip built from the
 * GHSA records (CC-BY-4.0) copied verbatim into fixtures/synvoya/actions-osv/ from the installed database,
 * plus an install record that matches it.
 */

import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { crc32, deflateRawSync } from "node:zlib";

import type { OsvDbRecord } from "../osv/database.js";
import { sha256Hex } from "../util/hash.js";

export const ACTIONS_OSV_FIXTURES = join(process.cwd(), "fixtures", "synvoya", "actions-osv");

/** A deflated zip of the given entries, in order. */
export function zipEntries(entries: ReadonlyArray<{ name: string; data: Buffer }>): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const body = deflateRawSync(entry.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc32(entry.data), 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    parts.push(local, name, body);
    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(8, 10);
    header.writeUInt32LE(crc32(entry.data), 16);
    header.writeUInt32LE(body.length, 20);
    header.writeUInt32LE(entry.data.length, 24);
    header.writeUInt16LE(name.length, 28);
    header.writeUInt32LE(offset, 42);
    central.push(header, name);
    offset += 30 + name.length + body.length;
  }
  const directory = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(directory.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, eocd]);
}

/** The fixture records, sorted by file name. */
export async function actionsFixtureRecords(): Promise<Array<{ name: string; data: Buffer }>> {
  const names = (await readdir(ACTIONS_OSV_FIXTURES)).filter((name) => name.endsWith(".json")).sort();
  return Promise.all(names.map(async (name) => ({ name, data: await readFile(join(ACTIONS_OSV_FIXTURES, name)) })));
}

/** Writes `<dir>/all.zip` from the fixture records; returns its path and a matching install record. */
export async function writeActionsFixtureDb(dir: string): Promise<{ zipPath: string; record: OsvDbRecord }> {
  const bytes = zipEntries(await actionsFixtureRecords());
  const zipPath = join(dir, "all.zip");
  await writeFile(zipPath, bytes);
  return {
    zipPath,
    record: {
      component: "osv-scanner:vulnerability-db:GitHub Actions",
      ecosystem: "GitHub Actions",
      signature: `sha256:${sha256Hex(bytes)}`,
      source_url: "https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip",
      bytes: bytes.length,
      last_modified: "2026-10-30T20:33:08.000Z",
      recorded_at: "2026-11-04T00:00:00.000Z",
    },
  };
}
