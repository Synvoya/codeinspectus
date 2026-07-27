#!/usr/bin/env node
/**
 * Maintainer-only refresh of the bundled offline OSV Pub advisory snapshot.
 *
 * Runtime scans never call this script and never use the network. Refreshes are
 * deliberate source-tree changes that must be reviewed, tested, and released.
 */

import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const INDEX_URL = "https://storage.googleapis.com/osv-vulnerabilities/Pub/modified_id.csv";
export const RECORD_BASE_URL = "https://storage.googleapis.com/osv-vulnerabilities/Pub";
export const MAX_INDEX_BYTES = 1024 * 1024;
export const MAX_RECORD_BYTES = 2 * 1024 * 1024;
export const OUTPUT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../detection-db/osv-pub/snapshot.json",
);

export function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export async function fetchBounded(url, maxBytes, fetchImpl = fetch) {
  const response = await fetchImpl(url, {
    headers: { "user-agent": "CodeInspectus OSV Pub snapshot maintainer" },
  });
  if (!response.ok) throw new Error(`Fetch failed (${response.status}) for ${url}`);
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error(`Refusing oversized upstream response (${declaredLength} bytes) from ${url}`);
  }
  const chunks = [];
  let received = 0;
  if (!response.body) throw new Error(`Fetch returned no response body for ${url}`);
  const reader = response.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error(`Refusing oversized upstream response (more than ${maxBytes} bytes) from ${url}`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = Buffer.concat(chunks, received);
  const header = (name) => response.headers.get(name) ?? undefined;
  return {
    bytes,
    http: {
      etag: header("etag"),
      last_modified: header("last-modified"),
      generation: header("x-goog-generation"),
      crc32c_md5: header("x-goog-hash"),
    },
  };
}

export function parseIndex(raw) {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("OSV Pub index was empty");
  const entries = trimmed.split(/\r?\n/).map((line, index) => {
    const comma = line.indexOf(",");
    if (comma <= 0) throw new Error(`Malformed OSV Pub index line ${index + 1}`);
    const modified = line.slice(0, comma);
    const id = line.slice(comma + 1);
    if (!/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(id)) {
      throw new Error(`Unexpected OSV Pub advisory id '${id}'`);
    }
    if (!/^\d{4}-\d{2}-\d{2}T/.test(modified)) {
      throw new Error(`Unexpected OSV Pub modified timestamp '${modified}'`);
    }
    return { id, modified };
  });
  if (!entries.length) throw new Error("OSV Pub index was empty");
  const ids = entries.map((entry) => entry.id);
  if (new Set(ids).size !== ids.length) throw new Error("OSV Pub index contained duplicate ids");
  return entries;
}

export function severity(value, id) {
  const mapped = {
    CRITICAL: "critical",
    HIGH: "high",
    MODERATE: "medium",
    MEDIUM: "medium",
    LOW: "low",
  }[String(value ?? "").toUpperCase()];
  if (!mapped) throw new Error(`${id} has no supported source severity`);
  return mapped;
}

export function normalizeRecord(record, expectedEntry, rawBytes) {
  const { id: expectedId, modified: expectedModified } = expectedEntry;
  if (!record || record.id !== expectedId) {
    throw new Error(`OSV Pub record id mismatch for ${expectedId}`);
  }
  if (record.modified !== expectedModified) {
    throw new Error(`${expectedId} modified timestamp disagrees with the OSV Pub index`);
  }
  if (!/^1\./.test(record.schema_version ?? "")) {
    throw new Error(`${expectedId} has an unsupported OSV schema version`);
  }
  if (record.withdrawn) {
    return {
      withdrawn: record.withdrawn,
      raw_sha256: sha256(rawBytes),
      source_schema_version: record.schema_version,
    };
  }
  if (record.database_specific?.github_reviewed !== true) {
    throw new Error(`${expectedId} is not GitHub-reviewed`);
  }
  const affected = (record.affected ?? [])
    .filter((item) => item?.package?.ecosystem === "Pub")
    .map((item) => {
      const name = item.package?.name;
      if (typeof name !== "string" || !/^[a-z_][a-z0-9_]*$/.test(name)) {
        throw new Error(`${expectedId} contains an invalid Pub package name`);
      }
      const versions = [...new Set(item.versions ?? [])];
      if (
        !versions.length ||
        versions.some((version) => typeof version !== "string" || !version || version.length > 4096)
      ) {
        throw new Error(`${expectedId}/${name} has no exact affected-version inventory`);
      }
      const source = item.database_specific?.source;
      if (
        typeof source !== "string" ||
        !source.startsWith("https://github.com/github/advisory-database/")
      ) {
        throw new Error(`${expectedId}/${name} has an unexpected advisory data source`);
      }
      const ecosystemRanges = (item.ranges ?? [])
        .filter((range) => range?.type === "ECOSYSTEM")
        .map((range) => ({
          type: "ECOSYSTEM",
          events: (range.events ?? []).map((event) => ({ ...event })),
        }));
      return {
        package: name,
        purl: `pkg:pub/${name}`,
        versions: versions.sort(),
        ranges: ecosystemRanges,
        source,
      };
    });
  if (!affected.length) throw new Error(`${expectedId} did not contain a Pub affected package`);
  if (affected.length !== 1) {
    throw new Error(
      `${expectedId} contains ${affected.length} Pub affected-package entries; ` +
      "package-qualified multi-package advisory matching is not supported",
    );
  }
  const cwe = [...new Set(record.database_specific?.cwe_ids ?? [])].sort();
  if (!cwe.length || cwe.some((id) => !/^CWE-\d+$/.test(id))) {
    throw new Error(`${expectedId} has no valid CWE inventory`);
  }
  const references = [...new Set((record.references ?? [])
    .map((reference) => reference?.url)
    .filter((url) => typeof url === "string" && /^https:\/\//.test(url)))]
    .sort();
  return {
    id: expectedId,
    source_schema_version: record.schema_version,
    source_database: "GitHub Advisory Database",
    published: record.published,
    modified: record.modified,
    github_reviewed_at: record.database_specific?.github_reviewed_at,
    aliases: [...new Set(record.aliases ?? [])].sort(),
    summary: record.summary,
    severity: severity(record.database_specific?.severity, expectedId),
    severity_vectors: (record.severity ?? []).map((entry) => {
      if (
        !entry || typeof entry.type !== "string" || typeof entry.score !== "string" ||
        !entry.type.startsWith("CVSS_V")
      ) {
        throw new Error(`${expectedId} contains an unsupported severity vector`);
      }
      return { type: entry.type, score: entry.score };
    }),
    cwe,
    references,
    raw_sha256: sha256(rawBytes),
    source_license: "CC-BY-4.0",
    affected,
  };
}

export async function buildSnapshot(options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const checkedAt = options.checkedAt ?? new Date().toISOString();
  const indexResponse = await fetchBounded(INDEX_URL, MAX_INDEX_BYTES, fetchImpl);
  const indexBytes = indexResponse.bytes;
  const indexText = indexBytes.toString("utf8");
  const entries = parseIndex(indexText);
  const rawRecords = new Map();
  for (const entry of entries) {
    const response = await fetchBounded(
      `${RECORD_BASE_URL}/${entry.id}.json`,
      MAX_RECORD_BYTES,
      fetchImpl,
    );
    rawRecords.set(entry.id, response.bytes);
  }
  const confirmedIndexResponse = await fetchBounded(INDEX_URL, MAX_INDEX_BYTES, fetchImpl);
  if (!indexBytes.equals(confirmedIndexResponse.bytes)) {
    throw new Error("OSV Pub index changed during refresh; retry to produce a coherent snapshot");
  }

  const advisories = [];
  const withdrawn = [];
  for (const entry of entries) {
    const bytes = rawRecords.get(entry.id);
    let record;
    try {
      record = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error(`${entry.id} record was not valid JSON`);
    }
    const normalized = normalizeRecord(record, entry, bytes);
    if ("withdrawn" in normalized) {
      withdrawn.push({
        id: entry.id,
        withdrawn: normalized.withdrawn,
        raw_sha256: normalized.raw_sha256,
        source_schema_version: normalized.source_schema_version,
      });
    }
    else advisories.push(normalized);
  }
  advisories.sort((left, right) => left.id.localeCompare(right.id));
  withdrawn.sort((left, right) => left.id.localeCompare(right.id));

  const recordsHash = createHash("sha256");
  for (const id of [...rawRecords.keys()].sort()) {
    recordsHash.update(id).update("\0").update(rawRecords.get(id)).update("\0");
  }
  const packageNames = new Set(
    advisories.flatMap((advisory) => advisory.affected.map((item) => item.package)),
  );
  const sourceSchemaVersions = [...new Set([
    ...advisories.map((advisory) => advisory.source_schema_version),
    ...withdrawn.map((record) => record.source_schema_version),
  ])].sort();
  const normalizedPayloadSha256 = sha256(Buffer.from(JSON.stringify({ advisories, withdrawn })));
  const snapshot = {
    schema_version: "1.0.0",
    snapshot: {
      ecosystem: "Pub",
      snapshot_version: undefined,
      checked_at: checkedAt,
      latest_record_modified: entries.map((entry) => entry.modified).sort().at(-1),
      source_index_url: INDEX_URL,
      source_index_sha256: sha256(indexBytes),
      source_index_http: indexResponse.http,
      source_records_sha256: `sha256:${recordsHash.digest("hex")}`,
      source_records_digest_algorithm:
        "SHA-256 over advisory id, NUL, raw JSON bytes, NUL in ascending advisory-id order",
      normalized_payload_sha256: normalizedPayloadSha256,
      source_schema_versions: sourceSchemaVersions,
      generator_revision: "3:single-package-coherent-index-record-normalizer",
      transformations: [
        "retained only affected entries whose package ecosystem is Pub",
        "rejected active advisories with multiple Pub affected-package entries pending package-qualified identity support",
        "excluded withdrawn records from active matching while retaining their identities and digests",
        "retained reviewed advisory identity, severity, CWE, references, exact versions, ranges, and provenance",
        "sorted active and withdrawn records by advisory id and normalized set-like fields",
      ],
      upstream_record_count: entries.length,
      advisory_count: advisories.length,
      affected_package_count: packageNames.size,
      withdrawn_record_count: withdrawn.length,
      withdrawn_records: withdrawn,
      matching: "exact-enumerated-versions",
      license: "CC-BY-4.0",
      attribution: "OSV.dev Pub ecosystem export; source records from the GitHub Advisory Database.",
    },
    advisories,
  };
  snapshot.snapshot.snapshot_version =
    `${snapshot.snapshot.checked_at.slice(0, 10)}.${snapshot.snapshot.source_index_sha256.slice(7, 19)}`;
  return snapshot;
}

export async function refreshSnapshot(options = {}) {
  const output = options.output ?? OUTPUT;
  const snapshot = await buildSnapshot(options);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
  console.error(
    `Wrote ${snapshot.snapshot.advisory_count} active Pub advisories across ` +
      `${snapshot.snapshot.affected_package_count} packages to ${output}`,
  );
  return snapshot;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  refreshSnapshot().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
