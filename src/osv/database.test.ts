import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { crc32, deflateRawSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { OsvEcosystem } from "./ecosystems.js";

const harness = vi.hoisted(() => ({
  root: `${process.env.TMPDIR ?? process.env.TEMP ?? "/tmp"}/ci-osv-db-test-${process.pid}-${Date.now()}`,
  /** When set, a write whose path matches throws, simulating a crash right after the DB swap. */
  failWriteMatching: undefined as RegExp | undefined,
}));

vi.mock("../config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../config.js")>();
  return {
    ...actual,
    MANAGED_OSV_DB: `${harness.root}/osv-db`,
    MANAGED_PROVENANCE: `${harness.root}/provenance`,
  };
});

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    writeFile: (async (...args: Parameters<typeof actual.writeFile>) => {
      if (harness.failWriteMatching?.test(String(args[0]))) throw new Error("simulated crash after swap");
      return await actual.writeFile(...args);
    }) as typeof actual.writeFile,
  };
});

const { inspectOsvDatabases, installOsvEcosystemDb, osvDbDownloadLimit, osvDbSourceUrl, osvDbZipPath, readOsvDbRecord, readZipArchive } = await import("./database.js");
const { OSV_DB_SIZE_ESTIMATES, OSV_ECOSYSTEMS } = await import("./ecosystems.js");

const ALLOWED_URL = (ecosystem: string) => `https://osv-vulnerabilities.storage.googleapis.com/${ecosystem}/all.zip`;
const recordPath = (ecosystem: string) => join(harness.root, "provenance", "osv-scanner", `${ecosystem}.json`);
const sha256 = (bytes: Buffer) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const io = () => ({ stdout: vi.fn(), stderr: vi.fn() });

interface ZipOptions { zip64?: boolean; comment?: string; deflate?: boolean }

/** Minimal spec-conformant stored zip so the central-directory check runs against real structure. */
function buildZip(entries: Array<{ name: string; data: string; flags?: number; method?: number; size?: number }>, options: ZipOptions = {}): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const raw = Buffer.from(entry.data);
    const crc = crc32(raw);
    const method = entry.method ?? (options.deflate ? 8 : 0);
    const data = method === 8 ? deflateRawSync(raw) : raw;
    const size = entry.size ?? raw.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(entry.flags ?? 0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(33, 12); // DOS date 1980-01-01
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    parts.push(local, name, data);

    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(entry.flags ?? 0, 8);
    header.writeUInt16LE(method, 10);
    header.writeUInt16LE(33, 14);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(data.length, 20);
    header.writeUInt32LE(size, 24);
    header.writeUInt16LE(name.length, 28);
    header.writeUInt32LE(offset, 42);
    central.push(header, name);
    offset += local.length + name.length + data.length;
  }
  const centralBytes = Buffer.concat(central);
  const comment = Buffer.from(options.comment ?? "");
  const tail: Buffer[] = [];
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(comment.length, 20);
  if (options.zip64) {
    const record = Buffer.alloc(56);
    record.writeUInt32LE(0x06064b50, 0);
    record.writeBigUInt64LE(44n, 4);
    record.writeUInt16LE(45, 12);
    record.writeUInt16LE(45, 14);
    record.writeBigUInt64LE(BigInt(entries.length), 24);
    record.writeBigUInt64LE(BigInt(entries.length), 32);
    record.writeBigUInt64LE(BigInt(centralBytes.length), 40);
    record.writeBigUInt64LE(BigInt(offset), 48);
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    locator.writeBigUInt64LE(BigInt(offset + centralBytes.length), 8);
    locator.writeUInt32LE(1, 16);
    eocd.writeUInt16LE(0xffff, 8);
    eocd.writeUInt16LE(0xffff, 10);
    eocd.writeUInt32LE(0xffffffff, 12);
    eocd.writeUInt32LE(0xffffffff, 16);
    tail.push(record, locator);
  } else {
    eocd.writeUInt16LE(entries.length, 8);
    eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(centralBytes.length, 12);
    eocd.writeUInt32LE(offset, 16);
  }
  return Buffer.concat([...parts, centralBytes, ...tail, eocd, comment]);
}

const zipV1 = buildZip([{ name: "PYSEC-2026-1.json", data: '{"id":"PYSEC-2026-1"}' }]);
const zipV2 = buildZip([
  { name: "PYSEC-2026-1.json", data: '{"id":"PYSEC-2026-1"}' },
  { name: "MAL-2026-2144.json", data: '{"id":"MAL-2026-2144"}' },
]);

function stubFetch(body: ConstructorParameters<typeof Response>[0], init: ResponseInit = { status: 200 }) {
  const fetchStub = vi.fn(async (_url: unknown, _init?: unknown) => new Response(body, init));
  vi.stubGlobal("fetch", fetchStub);
  return fetchStub;
}

beforeEach(async () => {
  harness.failWriteMatching = undefined;
  await rm(harness.root, { recursive: true, force: true });
  await mkdir(harness.root, { recursive: true });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  harness.failWriteMatching = undefined;
  await rm(harness.root, { recursive: true, force: true });
});

describe("consented OSV database install", () => {
  test("install stages, verifies the zip, swaps, then writes provenance", async () => {
    const fetchStub = stubFetch(zipV1, { status: 200, headers: { "last-modified": "Thu, 15 Oct 2026 20:33:04 GMT" } });
    const messages = io();

    const record = await installOsvEcosystemDb("PyPI", messages);

    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(fetchStub.mock.calls[0]?.[0]).toBe(ALLOWED_URL("PyPI"));
    expect(osvDbZipPath("PyPI")).toBe(join(harness.root, "osv-db", "osv-scalibr", "PyPI", "all.zip"));
    expect(await readFile(osvDbZipPath("PyPI"))).toEqual(zipV1);
    expect(record).toMatchObject({
      component: "osv-scanner:vulnerability-db:PyPI",
      ecosystem: "PyPI",
      signature: sha256(zipV1),
      source_url: ALLOWED_URL("PyPI"),
      bytes: zipV1.length,
      last_modified: "2026-10-15T20:33:04.000Z",
    });
    expect(Number.isFinite(Date.parse(record.recorded_at))).toBe(true);
    expect(JSON.parse(await readFile(recordPath("PyPI"), "utf8"))).toEqual(record);
    expect(await readOsvDbRecord("PyPI")).toEqual(record);
    expect(await readOsvDbRecord("npm")).toBeUndefined();
    // Nothing staged is left behind.
    expect(await readdir(join(harness.root, "osv-db", ".staging"))).toEqual([]);
    expect(messages.stdout.mock.calls.flat().join("\n")).toContain("PyPI");
  });

  test("the old database and its provenance stay untouched until the replacement is fully downloaded and verified", async () => {
    stubFetch(zipV1);
    const first = await installOsvEcosystemDb("PyPI", io());

    let observedWhileDownloading: { zip: Buffer; record: unknown } | undefined;
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        observedWhileDownloading = {
          zip: await readFile(osvDbZipPath("PyPI")),
          record: JSON.parse(await readFile(recordPath("PyPI"), "utf8")),
        };
        controller.enqueue(zipV2);
        controller.close();
      },
    });
    stubFetch(stream);
    const second = await installOsvEcosystemDb("PyPI", io());

    expect(observedWhileDownloading?.zip).toEqual(zipV1);
    expect(observedWhileDownloading?.record).toEqual(first);
    expect(await readFile(osvDbZipPath("PyPI"))).toEqual(zipV2);
    expect(second.signature).toBe(sha256(zipV2));
    expect(await readOsvDbRecord("PyPI")).toEqual(second);
  });

  test("a crash after the swap degrades to provenance_missing, never old signature over new bytes", async () => {
    stubFetch(zipV1);
    await installOsvEcosystemDb("PyPI", io());

    stubFetch(zipV2);
    harness.failWriteMatching = /PyPI\.json/;
    await expect(installOsvEcosystemDb("PyPI", io())).rejects.toThrow("simulated crash after swap");

    expect(await readFile(osvDbZipPath("PyPI"))).toEqual(zipV2);
    expect(await readOsvDbRecord("PyPI")).toBeUndefined();
    expect(await inspectOsvDatabases()).toEqual([{ ecosystem: "PyPI", state: "provenance_missing" }]);
  });

  test("interrupted download keeps the old DB and old provenance", async () => {
    stubFetch(zipV1);
    const first = await installOsvEcosystemDb("PyPI", io());

    let sent = false;
    stubFetch(new ReadableStream<Uint8Array>({
      pull(controller) {
        if (!sent) {
          sent = true;
          controller.enqueue(zipV2.subarray(0, 40));
        } else {
          controller.error(new Error("connection reset"));
        }
      },
    }));

    await expect(installOsvEcosystemDb("PyPI", io())).rejects.toThrow("connection reset");

    expect(await readFile(osvDbZipPath("PyPI"))).toEqual(zipV1);
    expect(await readOsvDbRecord("PyPI")).toEqual(first);
    expect(await readdir(join(harness.root, "osv-db", ".staging"))).toEqual([]);
  });

  test("caps each download at four times its measured size, and at least 1 GiB", () => {
    for (const ecosystem of OSV_ECOSYSTEMS) {
      expect(osvDbDownloadLimit(ecosystem), ecosystem).toBe(Math.max(4 * OSV_DB_SIZE_ESTIMATES[ecosystem], 1024 ** 3));
    }
    expect(osvDbDownloadLimit("Pub")).toBe(1024 ** 3);
  });

  test("an oversized stream is stopped at the cap: staging removed, old DB and record kept, clear error", async () => {
    stubFetch(zipV1);
    const first = await installOsvEcosystemDb("PyPI", io());

    const chunk = new Uint8Array(1024 * 1024);
    let sent = 0;
    // No Content-Length: only counting the streamed bytes can stop it.
    stubFetch(new ReadableStream<Uint8Array>({
      pull(controller) {
        sent += 1;
        controller.enqueue(chunk);
      },
    }));

    await expect(installOsvEcosystemDb("PyPI", io(), 2 * 1024 * 1024)).rejects.toThrow(
      /OSV PyPI database download exceeds the 2\.0 MiB limit .*existing database was left unchanged/,
    );

    expect(sent).toBeLessThan(10); // the endless stream was abandoned, not drained
    expect(await readFile(osvDbZipPath("PyPI"))).toEqual(zipV1);
    expect(await readOsvDbRecord("PyPI")).toEqual(first);
    expect(await readdir(join(harness.root, "osv-db", ".staging"))).toEqual([]);
  });

  test("an advertised length over the default cap is refused before the body is read", async () => {
    let pulled = false;
    stubFetch(
      // highWaterMark 0: pull runs only when something reads the body.
      new ReadableStream<Uint8Array>({
        pull(controller) {
          pulled = true;
          controller.enqueue(zipV1);
          controller.close();
        },
      }, { highWaterMark: 0 }),
      { status: 200, headers: { "content-length": String(1024 ** 3 + 1) } },
    );

    await expect(installOsvEcosystemDb("Pub", io())).rejects.toThrow(/exceeds the 1024\.0 MiB limit/);

    expect(pulled).toBe(false);
    await expect(stat(osvDbZipPath("Pub"))).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readOsvDbRecord("Pub")).toBeUndefined();
  });

  test("rejects a non-allow-listed ecosystem before any fetch", async () => {
    const fetchStub = stubFetch(zipV1);

    await expect(installOsvEcosystemDb("Debian" as OsvEcosystem, io())).rejects.toThrow(/Debian/);
    await expect(installOsvEcosystemDb("../PyPI" as OsvEcosystem, io())).rejects.toThrow();

    expect(fetchStub).not.toHaveBeenCalled();
    await expect(stat(join(harness.root, "osv-db"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("a non-zip payload fails closed and leaves an existing database alone", async () => {
    stubFetch(zipV1);
    const first = await installOsvEcosystemDb("PyPI", io());

    stubFetch("<html>403 Forbidden</html>");
    await expect(installOsvEcosystemDb("PyPI", io())).rejects.toThrow(/not a valid zip/);

    expect(await readFile(osvDbZipPath("PyPI"))).toEqual(zipV1);
    expect(await readOsvDbRecord("PyPI")).toEqual(first);

    stubFetch("<html>403 Forbidden</html>");
    await expect(installOsvEcosystemDb("npm", io())).rejects.toThrow(/not a valid zip/);
    await expect(stat(osvDbZipPath("npm"))).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readOsvDbRecord("npm")).toBeUndefined();
  });

  test("a truncated archive fails closed", async () => {
    stubFetch(zipV2.subarray(0, zipV2.length - 10));
    await expect(installOsvEcosystemDb("PyPI", io())).rejects.toThrow(/not a valid zip/);
    await expect(stat(osvDbZipPath("PyPI"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("an archive with no entries is not a database", async () => {
    stubFetch(buildZip([]));
    await expect(installOsvEcosystemDb("PyPI", io())).rejects.toThrow(/not a valid zip/);
  });

  test("a body shorter than the advertised length fails closed", async () => {
    stubFetch(zipV1, { status: 200, headers: { "content-length": String(zipV1.length + 100) } });
    await expect(installOsvEcosystemDb("PyPI", io())).rejects.toThrow(/length/);
    await expect(stat(osvDbZipPath("PyPI"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("an HTTP error status fails closed", async () => {
    stubFetch("missing", { status: 404, statusText: "Not Found" });
    await expect(installOsvEcosystemDb("PyPI", io())).rejects.toThrow(/404/);
    await expect(stat(osvDbZipPath("PyPI"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("refuses redirects away from the allow-listed host", async () => {
    const fetchStub = stubFetch(zipV1);
    await installOsvEcosystemDb("PyPI", io());
    expect(fetchStub.mock.calls[0]?.[1]).toMatchObject({ redirect: "error" });
  });

  test("accepts ZIP64 archives and archives with an end-of-archive comment", async () => {
    stubFetch(buildZip([{ name: "a.json", data: "{}" }], { zip64: true, comment: "generated by test" }));
    const record = await installOsvEcosystemDb("npm", io());
    expect(record.ecosystem).toBe("npm");

    stubFetch(buildZip([{ name: "b.json", data: "{}" }], { comment: "PK\u0005\u0006 not a real record" }));
    await expect(installOsvEcosystemDb("Go", io())).resolves.toMatchObject({ ecosystem: "Go" });
  });
});

describe("OSV database health and provenance reads", () => {
  async function seed(ecosystem: OsvEcosystem, zip: Buffer, record?: Record<string, unknown> | string): Promise<void> {
    await mkdir(dirname(osvDbZipPath(ecosystem)), { recursive: true });
    await writeFile(osvDbZipPath(ecosystem), zip);
    if (record !== undefined) {
      await mkdir(dirname(recordPath(ecosystem)), { recursive: true });
      await writeFile(recordPath(ecosystem), typeof record === "string" ? record : JSON.stringify(record));
    }
  }
  const validRecord = (ecosystem: OsvEcosystem, zip: Buffer, recordedAt: string) => ({
    component: `osv-scanner:vulnerability-db:${ecosystem}`,
    ecosystem,
    signature: sha256(zip),
    source_url: ALLOWED_URL(ecosystem),
    bytes: zip.length,
    recorded_at: recordedAt,
  });
  const NOW = Date.parse("2026-10-30T00:00:00.000Z");

  test("reports installed databases only, classified ready, stale or provenance_missing", async () => {
    expect(await inspectOsvDatabases(NOW)).toEqual([]);

    await seed("npm", zipV1, validRecord("npm", zipV1, "2026-10-29T00:00:00.000Z"));
    await seed("PyPI", zipV1, validRecord("PyPI", zipV1, "2026-10-22T23:59:59.000Z"));
    await seed("Go", zipV1);
    await seed("Pub", zipV1, validRecord("Pub", zipV2, "2026-10-29T00:00:00.000Z")); // size does not match the file

    expect(await inspectOsvDatabases(NOW)).toEqual([
      { ecosystem: "npm", state: "ready", downloaded_at: "2026-10-29T00:00:00.000Z" },
      { ecosystem: "PyPI", state: "stale", downloaded_at: "2026-10-22T23:59:59.000Z" },
      { ecosystem: "Go", state: "provenance_missing" },
      { ecosystem: "Pub", state: "provenance_missing" },
    ]);
  });

  test("a record without a database does not make an ecosystem installed", async () => {
    await mkdir(dirname(recordPath("npm")), { recursive: true });
    await writeFile(recordPath("npm"), JSON.stringify(validRecord("npm", zipV1, "2026-10-29T00:00:00.000Z")));
    expect(await inspectOsvDatabases(NOW)).toEqual([]);
  });

  test("readOsvDbRecord rejects malformed, mismatched or tampered records", async () => {
    const good = validRecord("PyPI", zipV1, "2026-10-29T00:00:00.000Z");
    await seed("PyPI", zipV1, "not json");
    expect(await readOsvDbRecord("PyPI")).toBeUndefined();

    for (const bad of [
      { ...good, ecosystem: "npm" },
      { ...good, signature: "sha256:abc" },
      { ...good, bytes: -1 },
      { ...good, source_url: "https://evil.example/PyPI/all.zip" },
      { ...good, recorded_at: "yesterday-ish" },
    ]) {
      await writeFile(recordPath("PyPI"), JSON.stringify(bad));
      expect(await readOsvDbRecord("PyPI"), JSON.stringify(bad)).toBeUndefined();
    }

    await writeFile(recordPath("PyPI"), JSON.stringify(good));
    expect(await readOsvDbRecord("PyPI")).toEqual(good);
  });
});

describe("bounded in-process zip reading (the Synvoya Actions matcher's archive)", () => {
  const LIMITS = { maxArchiveBytes: 1024 * 1024, maxEntries: 10, maxEntryBytes: 1024, maxTotalBytes: 4096 };
  const archive = join(harness.root, "archive.zip");
  const read = async (zip: Buffer, limits = LIMITS, accept = (name: string) => name.endsWith(".json")) => {
    await mkdir(harness.root, { recursive: true });
    await writeFile(archive, zip);
    return readZipArchive(archive, limits, accept);
  };

  test("the GitHub Actions archive URL encodes the space in its ecosystem name", () => {
    expect(osvDbSourceUrl("GitHub Actions")).toBe("https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip");
    expect(osvDbSourceUrl("crates.io")).toBe(ALLOWED_URL("crates.io"));
  });

  test("reads stored and deflated entries, skips unaccepted names without inflating them, and hashes the bytes", async () => {
    const deflated = buildZip([
      { name: "GHSA-1.json", data: '{"id":"GHSA-1"}' },
      { name: "README.txt", data: "x".repeat(5000) },
      { name: "dir/", data: "" },
    ], { deflate: true });
    const result = await read(deflated);
    expect(result.sha256).toBe(sha256(deflated));
    expect(result.entries.map((entry) => [entry.name, entry.data.toString("utf8")])).toEqual([["GHSA-1.json", '{"id":"GHSA-1"}']]);
    const stored = await read(buildZip([{ name: "a.json", data: "{}" }, { name: "b.json", data: "[]" }], { zip64: true }));
    expect(stored.entries.map((entry) => entry.name)).toEqual(["a.json", "b.json"]);
  });

  test("fails closed on anything it cannot read whole: caps, encryption, methods, sizes and bounds", async () => {
    const many = buildZip(Array.from({ length: 11 }, (_, index) => ({ name: `${index}.json`, data: "{}" })));
    await expect(read(many)).rejects.toThrow(/more than 10 entries/);
    await expect(read(buildZip([{ name: "big.json", data: "x".repeat(1025) }], { deflate: true }))).rejects.toThrow(/larger than 1024 bytes/);
    const total = buildZip(Array.from({ length: 5 }, (_, index) => ({ name: `${index}.json`, data: "y".repeat(1000) })), { deflate: true });
    await expect(read(total)).rejects.toThrow(/more than 4096 bytes/);
    await expect(read(buildZip([{ name: "e.json", data: "{}", flags: 1 }]))).rejects.toThrow(/encrypted/);
    await expect(read(buildZip([{ name: "m.json", data: "{}", method: 12 }]))).rejects.toThrow(/compression method 12/);
    // The central directory understates the entry: inflating past the declared size stops, never grows.
    await expect(read(buildZip([{ name: "s.json", data: "z".repeat(900), size: 10 }], { deflate: true }))).rejects.toThrow(/corrupt/);
    await expect(read(Buffer.alloc(2048))).rejects.toThrow(/end-of-central-directory/);
    await expect(read(buildZip([{ name: "a.json", data: "{}" }]), { ...LIMITS, maxArchiveBytes: 16 })).rejects.toThrow(/larger than 16 bytes/);
    // A local header pointing past the central directory.
    const shifted = buildZip([{ name: "a.json", data: "{}" }]);
    const directory = shifted.length - 22 - 46 - "a.json".length;
    shifted.writeUInt32LE(0x7fff, directory + 42);
    await expect(read(shifted)).rejects.toThrow(/outside/);
    // Review C4 (probe P5): an end record that counts fewer entries than the directory holds is never read in part.
    const lying = buildZip([{ name: "a.json", data: "{}" }, { name: "b.json", data: "[]" }]);
    lying.writeUInt16LE(1, lying.length - 22 + 8);
    lying.writeUInt16LE(1, lying.length - 22 + 10);
    await expect(read(lying)).rejects.toThrow(/central directory/);
  });

  test("a missing archive or one that is not a regular file is an error, never an empty read", async () => {
    await expect(readZipArchive(join(harness.root, "absent.zip"), LIMITS, () => true)).rejects.toThrow();
    await mkdir(join(harness.root, "folder.zip"), { recursive: true });
    await expect(readZipArchive(join(harness.root, "folder.zip"), LIMITS, () => true)).rejects.toThrow(/not a regular file/);
  });
});
