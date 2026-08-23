import { randomUUID } from "node:crypto";
import { z } from "zod";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { CODEINSPECTUS_AI_VERSION, DETECTION_DB_DIR, SERVER_VERSION, type EngineName } from "../config.js";
import { createJsonExport, redactFindingForOutput } from "../export/model.js";
import { createSarifExport } from "../export/sarif.js";
import { EXPORT_SCHEMA_VERSION, aggregateCoverageEnvelopeSchema, jsonExportSchema, sarifExportSchema } from "../export/schemas.js";
import { createUnavailableRepositoryTrust } from "../repository-trust/schemas.js";
import { getPlatformEntry, loadLockfile, platformKey } from "../engines/lockfile.js";
import { inspectOutputDirectory, pathIsWithin } from "../path-safety.js";
import { redactSnippet } from "../redact.js";
import { storedScanResultSchema } from "../schemas.js";
import { summarizeScan } from "../summarize.js";
import { normalizeStoredScanForRuntime, type StoredScanResult } from "../store.js";
import { sha256Hex } from "../util/hash.js";
import {
  BUNDLE_SCHEMA_URI,
  BUNDLE_SCHEMA_VERSION,
  bundleCoverageSchema,
  bundleFindingsSchema,
  bundleManifestSchema,
  type BundleManifest,
} from "./schemas.js";

const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const MAX_BUNDLE_BYTES = 64 * 1024 * 1024;
const EXPECTED_ARTIFACTS = [
  "findings.json",
  "coverage.json",
  "report.md",
  "results.sarif",
  "artifacts/scan-record.json",
  "artifacts/export.json",
] as const;

const MEDIA_TYPES: Record<(typeof EXPECTED_ARTIFACTS)[number], string> = {
  "findings.json": "application/json",
  "coverage.json": "application/json",
  "report.md": "text/markdown",
  "results.sarif": "application/sarif+json",
  "artifacts/scan-record.json": "application/vnd.codeinspectus.scan+json",
  "artifacts/export.json": "application/vnd.codeinspectus.export+json",
};

const legacyJsonExportV2Schema = z.object({
  $schema: z.literal("https://codeinspectus.com/schemas/v2.0.0/export.schema.json"),
  schema_version: z.literal("2.0.0"),
  generated_by: z.object({ name: z.literal("codeinspectus"), version: z.string() }),
  scan: z.object({ id: z.string() }).passthrough(),
  coverage: aggregateCoverageEnvelopeSchema,
  findings: z.array(z.unknown()),
}).passthrough();

const legacySarifV2Schema = z.object({
  version: z.literal("2.1.0"),
  runs: z.array(z.object({
    results: z.array(z.unknown()),
    properties: z.object({
      codeinspectus_schema_version: z.literal("2.0.0"),
      scan_id: z.string(),
    }).passthrough(),
  }).passthrough()).length(1),
}).passthrough();

export function validateLegacyV2BundlePayloads(input: {
  rawExport: unknown;
  rawSarif: unknown;
  scanId: string;
  findings: unknown[];
  coverage: unknown;
}): void {
  const legacyExport = legacyJsonExportV2Schema.parse(input.rawExport);
  const legacySarif = legacySarifV2Schema.parse(input.rawSarif);
  if (
    legacyExport.scan.id !== input.scanId ||
    legacySarif.runs[0]!.properties.scan_id !== input.scanId
  ) {
    throw new Error("Bundle artifacts do not share the manifest scan identity.");
  }
  if (
    !isDeepStrictEqual(legacyExport.findings, input.findings) ||
    !isDeepStrictEqual(legacyExport.coverage, input.coverage)
  ) {
    throw new Error("Legacy bundle findings, coverage, or SARIF do not match the sealed V2 export.");
  }

  const canonicalV3Export = jsonExportSchema.parse({
    ...(input.rawExport as Record<string, unknown>),
    $schema: "https://codeinspectus.com/schemas/v3.0.0/export.schema.json",
    schema_version: "3.0.0",
    repository_trust: createUnavailableRepositoryTrust(),
  });
  const canonicalLegacySarif = createSarifExport(canonicalV3Export);
  const run = canonicalLegacySarif.runs[0]!;
  run.tool.driver.version = legacyExport.generated_by.version;
  delete run.invocations[0]?.properties.repository_trust;
  delete run.properties.repository_trust;
  run.properties.codeinspectus_schema_version = "2.0.0";
  for (const result of run.results) {
    result.fingerprints = { "codeinspectus/v2": result.fingerprints["codeinspectus/v3"]! };
  }
  if (!isDeepStrictEqual(canonicalLegacySarif, legacySarif)) {
    throw new Error("Legacy bundle findings, coverage, or SARIF do not match the sealed V2 export.");
  }
}

export interface VerifiedBundle {
  directory: string;
  manifest: BundleManifest;
  scan: StoredScanResult;
  contents: Record<(typeof EXPECTED_ARTIFACTS)[number], Buffer>;
}

function jsonBytes(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function manifestPayloadHash(manifest: Omit<BundleManifest, "seal">): string {
  return sha256Hex(jsonBytes(manifest));
}

function deepRedact<T>(value: T): T {
  if (typeof value === "string") return redactSnippet(value) as T;
  if (Array.isArray(value)) return value.map(deepRedact) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, deepRedact(entry)])) as T;
  }
  return value;
}

function redactedStoredScan(scan: StoredScanResult): StoredScanResult {
  const aggregate = createJsonExport(scan).coverage.aggregate;
  const findings = scan.findings.map((finding) => {
    const projected = redactFindingForOutput(finding, aggregate);
    const { coverage_context: _coverage, triage_context: _triage, ...stored } = projected;
    return stored;
  });
  return storedScanResultSchema.parse(deepRedact({ ...scan, findings })) as unknown as StoredScanResult;
}

async function detectionDatabase(): Promise<{ version: string; date: string }> {
  const raw = await safeReadFile(join(DETECTION_DB_DIR, "manifest.json"), MAX_ARTIFACT_BYTES);
  const parsed = JSON.parse(raw.toString("utf8")) as { version?: unknown; date?: unknown };
  if (typeof parsed.version !== "string" || typeof parsed.date !== "string") throw new Error("Detection database manifest is missing version/date metadata.");
  return { version: parsed.version, date: parsed.date };
}

async function commodityEngines(scan: StoredScanResult): Promise<BundleManifest["commodity_engines"]> {
  const lock = await loadLockfile();
  const key = scan.engine_setup?.platform ?? platformKey();
  return (["opengrep", "gitleaks", "trivy"] as EngineName[]).map((engine) => {
    const detail = scan.engine_details.find((entry) => entry.engine === engine);
    const health = scan.engine_setup?.engines.find((entry) => entry.engine === engine);
    const pin = getPlatformEntry(lock, engine, key)?.sha256;
    const verified = Boolean(detail?.ran && health?.state === "ready" && pin && detail.version === lock.engines[engine].version);
    return {
      engine,
      version: detail?.version ?? lock.engines[engine].version,
      ran: detail?.ran ?? false,
      integrity_state: verified ? "verified" as const : health?.state === "missing" || detail?.available === false ? "unavailable" as const : "not_recorded" as const,
      ...(verified ? { verified_sha256: pin! } : {}),
    };
  });
}

function completedAt(scan: StoredScanResult): string {
  const start = Date.parse(scan.started_at);
  if (!Number.isFinite(start)) throw new Error("Stored scan has an invalid start timestamp.");
  return new Date(start + Math.max(0, scan.duration_ms)).toISOString();
}

async function buildBundle(scanInput: StoredScanResult, sealedAt = new Date().toISOString()): Promise<{
  manifest: BundleManifest;
  files: Record<(typeof EXPECTED_ARTIFACTS)[number], Buffer>;
}> {
  const scan = redactedStoredScan(scanInput);
  const exportDocument = jsonExportSchema.parse(createJsonExport(scan));
  const sarif = sarifExportSchema.parse(createSarifExport(exportDocument));
  const findings = bundleFindingsSchema.parse({ schema_version: BUNDLE_SCHEMA_VERSION, scan_id: scan.scan_id, findings: exportDocument.findings });
  const coverage = bundleCoverageSchema.parse({ schema_version: BUNDLE_SCHEMA_VERSION, scan_id: scan.scan_id, coverage: exportDocument.coverage });
  const files = {
    "findings.json": jsonBytes(findings),
    "coverage.json": jsonBytes(coverage),
    "report.md": Buffer.from(`${summarizeScan(normalizeStoredScanForRuntime(scan))}\n`, "utf8"),
    "results.sarif": jsonBytes(sarif),
    "artifacts/scan-record.json": jsonBytes(scan),
    "artifacts/export.json": jsonBytes(exportDocument),
  };
  const manifestWithoutSeal: Omit<BundleManifest, "seal"> = {
    $schema: BUNDLE_SCHEMA_URI,
    schema_version: BUNDLE_SCHEMA_VERSION,
    bundle_id: `bundle-${randomUUID()}`,
    created_by: { name: "codeinspectus", version: SERVER_VERSION },
    schemas: { bundle: BUNDLE_SCHEMA_VERSION, export: EXPORT_SCHEMA_VERSION, sarif: "2.1.0", stored_scan: "2.0.0" },
    detection_database: await detectionDatabase(),
    native_engine: { name: "codeinspectus-ai", version: CODEINSPECTUS_AI_VERSION },
    engine_platform: scan.engine_setup?.platform ?? "not-recorded",
    commodity_engines: await commodityEngines(scan),
    component_signatures: scan.component_signatures ?? {},
    target: {
      path: scan.target,
      ...(scan.repository_root ? { repository_root: scan.repository_root } : {}),
      ...(scan.git_scope?.mode === "commit_diff" && scan.git_scope.head
        ? { git_revision: { commit: scan.git_scope.head.commit, source: "commit_diff_head" as const } }
        : {}),
    },
    scan_id: scan.scan_id,
    ...(scan.scan_config ? { scan_configuration: scan.scan_config } : {}),
    scan_scope: scan.git_scope ?? { mode: "whole_target", target: scan.target },
    timestamps: { started_at: scan.started_at, completed_at: completedAt(scan), sealed_at: sealedAt },
    artifacts: EXPECTED_ARTIFACTS.map((path) => ({ path, media_type: MEDIA_TYPES[path], bytes: files[path].length, sha256: sha256Hex(files[path]) })),
  };
  return {
    files,
    manifest: bundleManifestSchema.parse({ ...manifestWithoutSeal, seal: { algorithm: "sha256", manifest_payload_sha256: manifestPayloadHash(manifestWithoutSeal) } }),
  };
}

export async function createSealedBundle(scan: StoredScanResult, outputDirectory: string): Promise<BundleManifest> {
  const boundary = scan.repository_root ?? scan.target;
  const inspection = await inspectOutputDirectory(outputDirectory, boundary, false);
  if (!inspection.safe || !inspection.resolved_path) throw new Error(inspection.error ?? "Unsafe bundle output directory.");
  if (inspection.exists) throw new Error(`Bundle output directory already exists: ${inspection.resolved_path}`);
  const parent = dirname(inspection.resolved_path);
  const parentMetadata = await lstat(parent).catch(() => undefined);
  if (!parentMetadata?.isDirectory() || parentMetadata.isSymbolicLink()) throw new Error(`Bundle output parent must be an existing non-symbolic directory: ${parent}`);
  const temporary = join(parent, `.${basename(inspection.resolved_path)}.${randomUUID()}.tmp`);
  const { manifest, files } = await buildBundle(scan);
  try {
    await mkdir(join(temporary, "artifacts"), { recursive: true });
    for (const path of EXPECTED_ARTIFACTS) await writeFile(join(temporary, path), files[path], { flag: "wx" });
    await writeFile(join(temporary, "scan-manifest.json"), jsonBytes(manifest), { flag: "wx" });
    await rename(temporary, inspection.resolved_path);
    return manifest;
  } catch (error) {
    await rm(temporary, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}

async function safeReadFile(path: string, maxBytes: number): Promise<Buffer> {
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > maxBytes) throw new Error(`Bundle artifact is not a bounded regular file: ${path}`);
    const content = await handle.readFile();
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || content.length !== before.size) {
      throw new Error(`Bundle artifact changed while being verified: ${path}`);
    }
    return content;
  } finally {
    await handle.close();
  }
}

async function actualBundlePaths(directory: string): Promise<string[]> {
  const paths: string[] = [];
  let entriesSeen = 0;
  const walk = async (current: string): Promise<void> => {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      entriesSeen++;
      if (entriesSeen > EXPECTED_ARTIFACTS.length + 2) throw new Error("Bundle contains unexpected extra entries.");
      const absolute = join(current, entry.name);
      const rel = relative(directory, absolute).split(sep).join("/");
      if (entry.isSymbolicLink()) throw new Error(`Symbolic links are forbidden in sealed bundles: ${rel}`);
      if (entry.isDirectory()) {
        if (rel !== "artifacts") throw new Error(`Unexpected bundle directory: ${rel}`);
        await walk(absolute);
      }
      else if (entry.isFile()) paths.push(rel);
      else throw new Error(`Unsupported bundle entry type: ${rel}`);
    }
  };
  await walk(directory);
  return paths.sort();
}

export async function verifySealedBundle(inputDirectory: string): Promise<VerifiedBundle> {
  const directory = resolve(inputDirectory);
  const metadata = await lstat(directory).catch(() => undefined);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink()) throw new Error("Bundle path must be a non-symbolic directory.");
  const actual = await actualBundlePaths(directory);
  const expected = ["scan-manifest.json", ...EXPECTED_ARTIFACTS].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`Bundle file set is not exact; expected ${expected.join(", ")}.`);

  const manifestBytes = await safeReadFile(join(directory, "scan-manifest.json"), MAX_ARTIFACT_BYTES);
  let rawManifest: unknown;
  try { rawManifest = JSON.parse(manifestBytes.toString("utf8")); }
  catch { throw new Error("Bundle manifest is not valid JSON."); }
  const manifest = bundleManifestSchema.parse(rawManifest);
  const { seal, ...payload } = manifest;
  if (manifestPayloadHash(payload) !== seal.manifest_payload_sha256) throw new Error("Bundle manifest seal does not match its payload.");

  const contents = {} as VerifiedBundle["contents"];
  let total = 0;
  for (const artifact of manifest.artifacts) {
    const absolute = resolve(directory, artifact.path);
    if (!pathIsWithin(directory, absolute) || relative(directory, absolute).split(sep).join("/") !== artifact.path) throw new Error(`Bundle artifact path escapes its directory: ${artifact.path}`);
    const content = await safeReadFile(absolute, MAX_ARTIFACT_BYTES);
    total += content.length;
    if (total > MAX_BUNDLE_BYTES) throw new Error(`Bundle exceeds the ${MAX_BUNDLE_BYTES}-byte verification limit.`);
    if (content.length !== artifact.bytes || sha256Hex(content) !== artifact.sha256) throw new Error(`Bundle artifact integrity check failed: ${artifact.path}`);
    contents[artifact.path] = content;
  }

  const findings = bundleFindingsSchema.parse(JSON.parse(contents["findings.json"].toString("utf8")));
  const coverage = bundleCoverageSchema.parse(JSON.parse(contents["coverage.json"].toString("utf8")));
  const rawSarif = JSON.parse(contents["results.sarif"].toString("utf8")) as unknown;
  const rawExport = JSON.parse(contents["artifacts/export.json"].toString("utf8")) as unknown;
  const scan = storedScanResultSchema.parse(JSON.parse(contents["artifacts/scan-record.json"].toString("utf8"))) as unknown as StoredScanResult;
  if (manifest.schemas.export === "3.0.0") {
    const sarif = sarifExportSchema.parse(rawSarif);
    const sealedExport = jsonExportSchema.parse(rawExport);
    if (findings.scan_id !== manifest.scan_id || coverage.scan_id !== manifest.scan_id || sealedExport.scan.id !== manifest.scan_id || scan.scan_id !== manifest.scan_id) throw new Error("Bundle artifacts do not share the manifest scan identity.");
    if (JSON.stringify(sealedExport.findings) !== JSON.stringify(findings.findings) || JSON.stringify(sealedExport.coverage) !== JSON.stringify(coverage.coverage) || JSON.stringify(createSarifExport(sealedExport)) !== JSON.stringify(sarif)) {
      throw new Error("Bundle findings, coverage, or SARIF do not match the sealed canonical export.");
    }
  } else {
    if (findings.scan_id !== manifest.scan_id || coverage.scan_id !== manifest.scan_id || scan.scan_id !== manifest.scan_id) {
      throw new Error("Bundle artifacts do not share the manifest scan identity.");
    }
    validateLegacyV2BundlePayloads({
      rawExport,
      rawSarif,
      scanId: manifest.scan_id,
      findings: findings.findings,
      coverage: coverage.coverage,
    });
  }
  return { directory, manifest, scan, contents };
}
