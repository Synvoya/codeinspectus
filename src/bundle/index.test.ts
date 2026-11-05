import { createHash } from "node:crypto";
import { mkdtemp, readFile, realpath, rename, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { Ajv } from "ajv";
import type { StoredScanResult } from "../store.js";
import { createJsonExport } from "../export/model.js";
import { createSarifExport } from "../export/sarif.js";
import { createSealedBundle, validateLegacyV2BundlePayloads, verifySealedBundle } from "./index.js";
import { bundleManifestSchema } from "./schemas.js";

const cleanup: string[] = [];

async function root(): Promise<string> {
  const directory = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-bundle-test-"));
  cleanup.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function scan(id = "00000000-0000-4000-8000-000000000001", startedAt = "2026-07-30T00:00:00.000Z"): StoredScanResult {
  return {
    scan_id: `scan-${id}`, target: "/fixture/repo", repository_root: "/fixture/repo", started_at: startedAt, duration_ms: 10,
    engines_run: ["opengrep@1.33.1", "gitleaks@8.30.1", "trivy@0.76.1", "codeinspectus-ai@5.13.0"],
    engine_details: ["opengrep", "gitleaks", "trivy"].map((engine) => ({ engine: engine as "opengrep" | "gitleaks" | "trivy", version: engine === "opengrep" ? "1.33.1" : engine === "gitleaks" ? "8.30.1" : "0.76.1", available: true, ran: true, finding_count: engine === "gitleaks" ? 1 : 0, duration_ms: 1 })),
    offline: true, detected_technologies: [], pack_coverage: [],
    summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
    findings: [{ id: "CI-0001", fingerprint: "fp-1", title: "Secret", severity: "high", engine: "gitleaks", engines: ["gitleaks"], rule_id: "generic-secret", cwe: ["CWE-798"], location: { file: "src/config.ts", start_line: 1, end_line: 1, snippet: "RAW-BUNDLE-SECRET-9081726354" }, message: "RAW-BUNDLE-SECRET-9081726354", remediation: { summary: "Remove secret", steps: [], references: [] }, frameworks: [], confidence: "high", is_secret: true, producer_components: ["engine:gitleaks"] }],
    truncated: false, total_findings_before_limit: 1, disclaimer: "test", warnings: [], secret_coverage: "verified",
    component_signatures: { "engine:gitleaks": "sha256:test" },
    engine_setup: { state: "ready", platform: "darwin-arm64", engines: [
      { engine: "opengrep", version: "1.33.1", state: "ready" },
      { engine: "gitleaks", version: "8.30.1", state: "ready" },
      { engine: "trivy", version: "0.76.1", state: "ready" },
    ], trivy_db: { state: "ready" }, network_required: false },
    git_safety: { state: "clean" }, scan_config: { scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 200 },
    storage_schema_version: "2.0.0", canonical_findings: true,
  };
}

async function createdBundle(input: StoredScanResult = scan()): Promise<string> {
  const parent = await root();
  const directory = join(parent, "scan-results");
  await createSealedBundle(input, directory);
  return directory;
}

/** Sealed by the released 3.3.2 CLI (`bundle create`) from a scan of fixtures/vulnerable-app; local paths were rewritten to /fixture/* before sealing. */
const BUNDLE_SEALED_BY_3_3_2 = "fixtures/sealed-bundle-3.3.2/bundle";

function jsonSchemaValidator(path: string) {
  return readFile(path, "utf8").then((text) => new Ajv({ strict: false, validateSchema: false, formats: { "date-time": true } }).compile(JSON.parse(text)));
}

describe("sealed scan bundles", () => {
  test("retains a bounded V2 export/SARIF compatibility path", () => {
    const scanId = "scan-00000000-0000-4000-8000-000000000001";
    const source = createJsonExport(scan());
    const rawExport = structuredClone(source) as Record<string, unknown>;
    rawExport.$schema = "https://codeinspectus.com/schemas/v2.0.0/export.schema.json";
    rawExport.schema_version = "2.0.0";
    delete rawExport.repository_trust;
    const rawSarif = createSarifExport(source);
    const run = rawSarif.runs[0]!;
    delete run.invocations[0]?.properties.repository_trust;
    delete run.properties.repository_trust;
    run.properties.codeinspectus_schema_version = "2.0.0";
    for (const result of run.results) {
      result.fingerprints = { "codeinspectus/v2": result.fingerprints["codeinspectus/v3"]! };
    }
    const findings = source.findings;
    const coverage = source.coverage;
    expect(() => validateLegacyV2BundlePayloads({ rawExport, rawSarif, scanId, findings, coverage })).not.toThrow();
    expect(() => validateLegacyV2BundlePayloads({ rawExport, rawSarif, scanId: `${scanId}-other`, findings, coverage })).toThrow(/identity/i);
    rawSarif.runs[0]!.results[0]!.message.text = "tampered";
    expect(() => validateLegacyV2BundlePayloads({ rawExport, rawSarif, scanId, findings, coverage })).toThrow(/do not match/i);
  });

  test("creates an exact redacted bundle and verifies every artifact before loading the scan", async () => {
    const directory = await createdBundle();
    const verified = await verifySealedBundle(directory);
    expect(verified.manifest).toMatchObject({
      schema_version: "1.1.0", scan_id: scan().scan_id,
      detection_database: { version: "2.0.0", date: "2026-11-05" },
      native_engine: { name: "codeinspectus-ai", version: "5.20.0" },
      schemas: { export: "3.0.0" },
      artifacts: expect.arrayContaining([expect.objectContaining({ path: "artifacts/scan-record.json", sha256: expect.stringMatching(/^[0-9a-f]{64}$/) })]),
    });
    const ran = verified.manifest.commodity_engines.filter((engine) => engine.ran);
    expect(ran.map((engine) => engine.engine)).toEqual(["opengrep", "gitleaks", "trivy"]);
    expect(ran.every((engine) => engine.integrity_state === "verified" && /^[0-9a-f]{64}$/.test(engine.verified_sha256!))).toBe(true);
    const allBytes = (await Promise.all(["scan-manifest.json", "findings.json", "coverage.json", "report.md", "results.sarif", "artifacts/scan-record.json", "artifacts/export.json"].map((path) => readFile(join(directory, path))))).map(String).join("\n");
    expect(allBytes).not.toContain("RAW-BUNDLE-SECRET-9081726354");
    expect(verified.scan.findings[0]?.message).toMatch(/redacted/i);
    expect(allBytes).toContain('"repository_trust"');
  });

  test("validates actual manifests against the packaged schema and rejects duplicated identities", async () => {
    const directory = await createdBundle();
    const manifest = JSON.parse(await readFile(join(directory, "scan-manifest.json"), "utf8"));
    const validate = await jsonSchemaValidator("schemas/codeinspectus-bundle-manifest-1.1.0.schema.json");
    expect(validate(manifest), JSON.stringify(validate.errors)).toBe(true);
    const duplicateEngine = structuredClone(manifest);
    duplicateEngine.commodity_engines[1].engine = "opengrep";
    expect(validate(duplicateEngine)).toBe(false);
    const duplicateArtifact = structuredClone(manifest);
    duplicateArtifact.artifacts[1].path = duplicateArtifact.artifacts[0].path;
    expect(validate(duplicateArtifact)).toBe(false);
  });

  test("new bundles seal 1.1.0 with four commodity engines", async () => {
    const verified = await verifySealedBundle(await createdBundle());
    expect(verified.manifest).toMatchObject({
      $schema: "https://codeinspectus.com/schemas/bundle/1.1.0/manifest.schema.json",
      schema_version: "1.1.0",
      schemas: { bundle: "1.1.0" },
    });
    expect(verified.manifest.commodity_engines.map((engine) => engine.engine)).toEqual(["opengrep", "gitleaks", "trivy", "osv-scanner"]);
    // The fixture scan predates osv-scanner: it did not run, so its integrity is not recorded.
    expect(verified.manifest.commodity_engines[3]).toEqual({ engine: "osv-scanner", version: "2.7.0", ran: false, integrity_state: "not_recorded" });
    for (const path of ["findings.json", "coverage.json"] as const) {
      expect(JSON.parse(verified.contents[path].toString("utf8")).schema_version).toBe("1.1.0");
    }
  });

  test("records osv-scanner integrity with the same mapping as the other commodity engines", async () => {
    const ranScan = scan();
    ranScan.engine_details.push({ engine: "osv-scanner", version: "2.7.0", available: true, ran: true, finding_count: 0, duration_ms: 1 });
    ranScan.engine_setup!.engines.push({ engine: "osv-scanner", version: "2.7.0", state: "ready" });
    const ran = (await verifySealedBundle(await createdBundle(ranScan))).manifest.commodity_engines[3];
    expect(ran).toEqual({ engine: "osv-scanner", version: "2.7.0", ran: true, integrity_state: "verified", verified_sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });

    // A machine without osv-scanner seals it unavailable, exactly as a missing opengrep, gitleaks or trivy.
    const missingScan = scan();
    missingScan.engine_setup!.engines.push({ engine: "osv-scanner", version: "2.7.0", state: "missing" });
    const missing = (await verifySealedBundle(await createdBundle(missingScan))).manifest.commodity_engines[3];
    expect(missing).toEqual({ engine: "osv-scanner", version: "2.7.0", ran: false, integrity_state: "unavailable" });

    // Installed but not run (not applicable, or vuln not selected): integrity is not recorded.
    const idleScan = scan();
    idleScan.engine_setup!.engines.push({ engine: "osv-scanner", version: "2.7.0", state: "ready" });
    const idle = (await verifySealedBundle(await createdBundle(idleScan))).manifest.commodity_engines[3];
    expect(idle).toEqual({ engine: "osv-scanner", version: "2.7.0", ran: false, integrity_state: "not_recorded" });
  });

  test("1.0.0 bundles sealed by 3.3.2 still verify", async () => {
    const verified = await verifySealedBundle(BUNDLE_SEALED_BY_3_3_2);
    expect(verified.manifest).toMatchObject({
      $schema: "https://codeinspectus.com/schemas/bundle/1.0.0/manifest.schema.json",
      schema_version: "1.0.0",
      created_by: { name: "codeinspectus", version: "3.3.2" },
      schemas: { bundle: "1.0.0", export: "3.0.0" },
    });
    expect(verified.manifest.commodity_engines.map((engine) => engine.engine)).toEqual(["opengrep", "gitleaks", "trivy"]);
    expect(verified.scan.scan_id).toBe(verified.manifest.scan_id);
    expect(verified.scan.findings.length).toBeGreaterThan(0);
    expect(JSON.parse(verified.contents["findings.json"].toString("utf8")).schema_version).toBe("1.0.0");
  });

  test("each manifest version pins its own commodity engine set and schema identity", async () => {
    const legacy = JSON.parse(await readFile(join(BUNDLE_SEALED_BY_3_3_2, "scan-manifest.json"), "utf8"));
    const current = JSON.parse(await readFile(join(await createdBundle(), "scan-manifest.json"), "utf8"));
    expect(bundleManifestSchema.safeParse(legacy).success).toBe(true);
    expect(bundleManifestSchema.safeParse(current).success).toBe(true);

    const legacyWithOsv = structuredClone(legacy);
    legacyWithOsv.commodity_engines.push({ engine: "osv-scanner", version: "2.7.0", ran: false, integrity_state: "not_recorded" });
    const currentWithoutOsv = structuredClone(current);
    currentWithoutOsv.commodity_engines.pop();
    const currentDuplicateOsv = structuredClone(current);
    currentDuplicateOsv.commodity_engines[2] = { ...currentDuplicateOsv.commodity_engines[3] };
    const mixedIdentity = structuredClone(current);
    mixedIdentity.$schema = legacy.$schema;
    const mixedSchemas = structuredClone(current);
    mixedSchemas.schemas.bundle = "1.0.0";
    for (const invalid of [legacyWithOsv, currentWithoutOsv, currentDuplicateOsv, mixedIdentity, mixedSchemas]) {
      expect(bundleManifestSchema.safeParse(invalid).success).toBe(false);
    }

    const validateLegacy = await jsonSchemaValidator("schemas/codeinspectus-bundle-manifest-1.0.0.schema.json");
    const validateCurrent = await jsonSchemaValidator("schemas/codeinspectus-bundle-manifest-1.1.0.schema.json");
    expect(validateLegacy(legacy), JSON.stringify(validateLegacy.errors)).toBe(true);
    expect(validateLegacy(current)).toBe(false);
    expect(validateCurrent(legacy)).toBe(false);
    for (const invalid of [currentWithoutOsv, currentDuplicateOsv, mixedIdentity, mixedSchemas]) {
      expect(validateCurrent(invalid)).toBe(false);
    }
  });

  test("rejects missing, corrupted, swapped, extra, and traversal-shaped artifacts", async () => {
    const missing = await createdBundle();
    await unlink(join(missing, "coverage.json"));
    await expect(verifySealedBundle(missing)).rejects.toThrow(/file set|expected/i);

    const corrupted = await createdBundle();
    await writeFile(join(corrupted, "report.md"), "tampered\n");
    await expect(verifySealedBundle(corrupted)).rejects.toThrow(/integrity check failed/i);

    const swapped = await createdBundle();
    await rename(join(swapped, "findings.json"), join(swapped, "swap.tmp"));
    await rename(join(swapped, "coverage.json"), join(swapped, "findings.json"));
    await rename(join(swapped, "swap.tmp"), join(swapped, "coverage.json"));
    await expect(verifySealedBundle(swapped)).rejects.toThrow(/integrity check failed/i);

    const extra = await createdBundle();
    await writeFile(join(extra, "unexpected.txt"), "not sealed\n");
    await expect(verifySealedBundle(extra)).rejects.toThrow(/unexpected|file set/i);

    const traversal = await createdBundle();
    const manifestPath = join(traversal, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.artifacts[0].path = "../outside.json";
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await expect(verifySealedBundle(traversal)).rejects.toThrow();
  });

  test("refuses existing destinations and repository-contained bundle writes", async () => {
    const parent = await root();
    await expect(createSealedBundle(scan(), parent)).rejects.toThrow(/already exists/i);
    const insideScan = scan();
    insideScan.target = parent;
    insideScan.repository_root = parent;
    await expect(createSealedBundle(insideScan, join(parent, "scan-results"))).rejects.toThrow(/inside the scan target/i);
    await expect(createSealedBundle(scan(), `${parent}/../escape`)).rejects.toThrow(/traversal/i);
  });

  test("a scan that recorded its licence choice still seals a manifest in the 1.x shape", async () => {
    const licensed = scan();
    licensed.scan_config = { ...licensed.scan_config!, include_licenses: false };
    const directory = join(await root(), "licence-choice");
    await createSealedBundle(licensed, directory);
    const manifest = (await verifySealedBundle(directory)).manifest;
    expect(manifest.scan_configuration).toEqual({ scanners: ["sast", "secret", "vuln", "misconfig", "license", "ai"], max_findings: 200 });
  });

  test("sealing is additive and accepts a tolerant older stored scan without rewriting it", async () => {
    const legacy = scan();
    delete legacy.storage_schema_version;
    delete legacy.canonical_findings;
    delete (legacy as Partial<StoredScanResult>).git_safety;
    delete legacy.scan_config;
    const before = structuredClone(legacy);
    const parent = await root();
    const directory = join(parent, "legacy-bundle");
    await createSealedBundle(legacy, directory);
    const verified = await verifySealedBundle(directory);
    expect(legacy).toEqual(before);
    expect(verified.scan.canonical_findings).toBeUndefined();
    expect(JSON.parse(verified.contents["artifacts/export.json"].toString("utf8")).coverage.aggregate).toBe("unknown");
  });

  test.each([
    ["a top-level key", (manifest: Record<string, any>) => { manifest.attestation = { verdict: "no vulnerabilities" }; }],
    ["a nested key", (manifest: Record<string, any>) => { manifest.scan_scope.note = "reviewed"; }],
    ["an artifact entry key", (manifest: Record<string, any>) => { manifest.artifacts[0].approved = true; }],
  ])("rejects manifest content outside the seal: %s", async (_label, mutate) => {
    const directory = await createdBundle();
    const path = join(directory, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(path, "utf8"));
    mutate(manifest);
    await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);

    await expect(verifySealedBundle(directory)).rejects.toThrow(/outside the seal/i);
  });

  test("rejects findings or coverage whose schema version differs from the manifest, even when re-sealed", async () => {
    for (const artifact of ["findings.json", "coverage.json"]) {
      const directory = await createdBundle();
      const document = JSON.parse(await readFile(join(directory, artifact), "utf8"));
      document.schema_version = "1.0.0";
      const bytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`, "utf8");
      await writeFile(join(directory, artifact), bytes);
      // Re-seal the manifest so only the version mismatch is left to catch.
      const path = join(directory, "scan-manifest.json");
      const { seal, ...payload } = JSON.parse(await readFile(path, "utf8"));
      const entry = payload.artifacts.find((item: { path: string }) => item.path === artifact);
      entry.bytes = bytes.length;
      entry.sha256 = createHash("sha256").update(bytes).digest("hex");
      seal.manifest_payload_sha256 = createHash("sha256").update(`${JSON.stringify(payload, null, 2)}\n`).digest("hex");
      await writeFile(path, `${JSON.stringify({ ...payload, seal }, null, 2)}\n`);
      await expect(verifySealedBundle(directory)).rejects.toThrow(/schema version does not match the manifest/);
    }
  });

  test("detects manifest payload tampering independently of artifact hashes", async () => {
    const directory = await createdBundle();
    const path = join(directory, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(path, "utf8"));
    manifest.created_by.version = "forged";
    await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
    await expect(verifySealedBundle(directory)).rejects.toThrow(/manifest seal/i);
  });
});
