/**
 * Runtime reader for the bundled, normalized OSV Pub snapshot.
 *
 * Scans never contact OSV. The maintainer refresh script writes this asset and
 * this reader validates it before any dependency result is trusted.
 */

import { readFile } from "node:fs/promises";
import { z } from "zod";

import { OSV_PUB_SNAPSHOT } from "../config.js";
import { signature } from "../provenance.js";

const MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024;
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const timestampSchema = z.string().regex(
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/,
);
const advisoryIdSchema = z.string().regex(/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/);
const packageNameSchema = z.string().regex(/^[a-z_][a-z0-9_]*$/);

const rangeEventSchema = z
  .object({
    introduced: z.string().optional(),
    fixed: z.string().optional(),
    last_affected: z.string().optional(),
    limit: z.string().optional(),
  })
  .strict()
  .refine((event) => Object.values(event).filter((value) => value !== undefined).length === 1, {
    message: "Each OSV range event must contain exactly one boundary.",
  });

const affectedSchema = z
  .object({
    package: packageNameSchema,
    purl: z.string().regex(/^pkg:pub\/[a-z_][a-z0-9_]*$/),
    versions: z.array(z.string().min(1)).min(1),
    ranges: z.array(
      z.object({
        type: z.literal("ECOSYSTEM"),
        events: z.array(rangeEventSchema),
      }).strict(),
    ),
    source: z.string().url().startsWith("https://github.com/github/advisory-database/"),
  })
  .strict();

const advisorySchema = z
  .object({
    id: advisoryIdSchema,
    source_schema_version: z.string().regex(/^1\.\d+(?:\.\d+)?$/),
    source_database: z.literal("GitHub Advisory Database"),
    published: timestampSchema,
    modified: timestampSchema,
    github_reviewed_at: timestampSchema.optional(),
    aliases: z.array(z.string().min(1)),
    summary: z.string().min(1),
    severity: z.enum(["critical", "high", "medium", "low", "info"]),
    severity_vectors: z.array(
      z.object({ type: z.string().startsWith("CVSS_V"), score: z.string().min(1) }).strict(),
    ),
    cwe: z.array(z.string().regex(/^CWE-\d+$/)).min(1),
    references: z.array(z.string().url()),
    raw_sha256: digestSchema,
    source_license: z.literal("CC-BY-4.0"),
    affected: z.array(affectedSchema).length(1),
  })
  .strict();

const snapshotSchema = z
  .object({
    schema_version: z.literal("1.0.0"),
    snapshot: z
      .object({
        ecosystem: z.literal("Pub"),
        snapshot_version: z.string().regex(/^\d{4}-\d{2}-\d{2}\.[a-f0-9]{12}$/),
        checked_at: timestampSchema,
        latest_record_modified: timestampSchema,
        source_index_url: z.literal(
          "https://storage.googleapis.com/osv-vulnerabilities/Pub/modified_id.csv",
        ),
        source_index_sha256: digestSchema,
        source_index_http: z.object({
          etag: z.string().optional(),
          last_modified: z.string().optional(),
          generation: z.string().optional(),
          crc32c_md5: z.string().optional(),
        }).strict(),
        source_records_sha256: digestSchema,
        source_records_digest_algorithm: z.string().min(1),
        normalized_payload_sha256: digestSchema,
        source_schema_versions: z.array(z.string().regex(/^1\.\d+(?:\.\d+)?$/)).min(1),
        generator_revision: z.string().min(1),
        transformations: z.array(z.string().min(1)).min(1),
        upstream_record_count: z.number().int().nonnegative(),
        advisory_count: z.number().int().nonnegative(),
        affected_package_count: z.number().int().nonnegative(),
        withdrawn_record_count: z.number().int().nonnegative(),
        withdrawn_records: z.array(
          z.object({
            id: advisoryIdSchema,
            withdrawn: timestampSchema,
            raw_sha256: digestSchema,
            source_schema_version: z.string().regex(/^1\.\d+(?:\.\d+)?$/),
          }).strict(),
        ),
        matching: z.literal("exact-enumerated-versions"),
        license: z.literal("CC-BY-4.0"),
        attribution: z.string().min(1),
      })
      .strict(),
    advisories: z.array(advisorySchema),
  })
  .strict();

export type PubAdvisorySnapshot = z.infer<typeof snapshotSchema>;
export type PubAdvisory = PubAdvisorySnapshot["advisories"][number];
export type PubAffectedPackage = PubAdvisory["affected"][number];

export interface LoadedPubSnapshot {
  data: PubAdvisorySnapshot;
  content_signature: string;
}

interface LoadPubSnapshotOptions {
  /** Test seam for proving parsed bytes and provenance bytes are identical. */
  readBytes?: (path: string) => Promise<Buffer>;
}

function assertUnique(values: readonly string[], label: string): void {
  if (new Set(values).size !== values.length) {
    throw new Error(`Invalid bundled OSV Pub snapshot: duplicate ${label}.`);
  }
}

function validateSnapshotConsistency(data: PubAdvisorySnapshot): void {
  const { snapshot, advisories } = data;
  if (snapshot.advisory_count !== advisories.length) {
    throw new Error("Invalid bundled OSV Pub snapshot: advisory count does not match payload.");
  }
  if (snapshot.withdrawn_record_count !== snapshot.withdrawn_records.length) {
    throw new Error("Invalid bundled OSV Pub snapshot: withdrawn count does not match payload.");
  }
  if (snapshot.upstream_record_count !== advisories.length + snapshot.withdrawn_records.length) {
    throw new Error("Invalid bundled OSV Pub snapshot: upstream record count is inconsistent.");
  }

  const advisoryIds = advisories.map((advisory) => advisory.id);
  const withdrawnIds = snapshot.withdrawn_records.map((record) => record.id);
  assertUnique(advisoryIds, "active advisory id");
  assertUnique(withdrawnIds, "withdrawn advisory id");
  if (advisoryIds.some((id) => withdrawnIds.includes(id))) {
    throw new Error("Invalid bundled OSV Pub snapshot: an advisory is both active and withdrawn.");
  }

  const packageNames = new Set<string>();
  for (const advisory of advisories) {
    assertUnique(advisory.aliases, `${advisory.id} alias`);
    assertUnique(advisory.cwe, `${advisory.id} CWE`);
    for (const affected of advisory.affected) {
      if (affected.purl !== `pkg:pub/${affected.package}`) {
        throw new Error(`Invalid bundled OSV Pub snapshot: ${advisory.id} has a mismatched purl.`);
      }
      assertUnique(affected.versions, `${advisory.id}/${affected.package} affected version`);
      packageNames.add(affected.package);
    }
  }
  if (snapshot.affected_package_count !== packageNames.size) {
    throw new Error("Invalid bundled OSV Pub snapshot: affected package count does not match payload.");
  }
  const normalizedDigest = signature(JSON.stringify({
    advisories,
    withdrawn: snapshot.withdrawn_records,
  }));
  if (snapshot.normalized_payload_sha256 !== normalizedDigest) {
    throw new Error("Invalid bundled OSV Pub snapshot: normalized payload digest does not match.");
  }
  const sourceSchemaVersions = [...new Set([
    ...advisories.map((advisory) => advisory.source_schema_version),
    ...snapshot.withdrawn_records.map((record) => record.source_schema_version),
  ])].sort();
  if (JSON.stringify(snapshot.source_schema_versions) !== JSON.stringify(sourceSchemaVersions)) {
    throw new Error("Invalid bundled OSV Pub snapshot: source schema inventory does not match payload.");
  }
}

export async function loadPubSnapshot(
  path = OSV_PUB_SNAPSHOT,
  options: LoadPubSnapshotOptions = {},
): Promise<LoadedPubSnapshot> {
  const bytes = await (options.readBytes ?? ((snapshotPath: string) => readFile(snapshotPath)))(path);
  if (bytes.length > MAX_SNAPSHOT_BYTES) {
    throw new Error(`Bundled OSV Pub snapshot exceeds ${MAX_SNAPSHOT_BYTES} bytes.`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("Bundled OSV Pub snapshot is not valid JSON.");
  }
  const data = snapshotSchema.parse(parsed);
  validateSnapshotConsistency(data);
  // Hash the exact bytes that were parsed. A second path read can race an atomic snapshot
  // replacement and associate database A's findings with database B's provenance signature.
  return { data, content_signature: signature(bytes) };
}

export function fixedVersions(affected: PubAffectedPackage): string[] {
  return [...new Set(
    affected.ranges.flatMap((range) =>
      range.events.flatMap((event) => event.fixed === undefined ? [] : [event.fixed]),
    ),
  )];
}
