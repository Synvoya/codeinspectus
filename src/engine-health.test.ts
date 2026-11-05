import { describe, expect, test } from "vitest";

import {
  deriveEngineSetupStatus,
  engineSetupMessage,
  ENGINE_REPAIR_COMMAND,
  trivyDbState,
  type EngineHealthProbe,
} from "./engine-health.js";
import { engineSetupSchema } from "./schemas.js";

const NOW = Date.parse("2026-07-26T00:00:00.000Z");

function probes(overrides: Partial<Record<EngineHealthProbe["engine"], Partial<EngineHealthProbe>>> = {}): EngineHealthProbe[] {
  return (["opengrep", "gitleaks", "trivy"] as const).map((engine) => ({
    engine,
    version: engine === "opengrep" ? "1.33.1" : engine === "gitleaks" ? "8.30.1" : "0.76.1",
    available: true,
    ...overrides[engine],
  }));
}

const freshDb = {
  exists: true,
  downloadedAt: "2026-07-25T00:00:00.000Z",
  provenanceRecorded: true,
};

describe("offline engine setup health", () => {
  test("healthy artifacts and a fresh provenance-recorded DB are ready", () => {
    const result = deriveEngineSetupStatus("darwin-arm64", probes(), freshDb, NOW);
    expect(engineSetupSchema.parse(result)).toEqual(result);
    expect(result).toMatchObject({
      state: "ready",
      network_required: false,
      trivy_db: { state: "ready" },
    });
    expect(result.repair_command).toBeUndefined();
  });

  test("missing or mismatched binaries require explicit repair", () => {
    const result = deriveEngineSetupStatus(
      "linux-x64",
      probes({
        opengrep: { available: false, issue: "missing", note: "not installed" },
        trivy: { available: false, issue: "hash_mismatch", note: "pin mismatch" },
      }),
      freshDb,
      NOW,
    );
    expect(result.state).toBe("repair_required");
    expect(result.repair_command).toBe(ENGINE_REPAIR_COMMAND);
    expect(result.engines.map(({ engine, state }) => [engine, state])).toContainEqual([
      "trivy",
      "hash_mismatch",
    ]);
  });

  test("unsupported platforms fail closed without offering an impossible repair", () => {
    const result = deriveEngineSetupStatus(
      "freebsd-x64",
      probes({
        opengrep: { available: false, issue: "unsupported_platform" },
        gitleaks: { available: false, issue: "unsupported_platform" },
        trivy: { available: false, issue: "unsupported_platform" },
      }),
      freshDb,
      NOW,
    );
    expect(result.state).toBe("unsupported_platform");
    expect(result.network_required).toBe(false);
    expect(result.repair_command).toBeUndefined();
  });

  test("a broken packaged pin requires reinstall rather than an impossible repair", () => {
    const result = deriveEngineSetupStatus(
      "darwin-arm64",
      probes({ opengrep: { available: false, issue: "unpinned", note: "shipped pin missing" } }),
      freshDb,
      NOW,
    );
    expect(result.state).toBe("repair_required");
    expect(result.network_required).toBe(false);
    expect(result.repair_command).toBeUndefined();
  });

  test("missing provenance and a stale DB recommend a DB-only refresh", () => {
    const missingProvenance = deriveEngineSetupStatus(
      "darwin-arm64",
      probes(),
      { ...freshDb, provenanceRecorded: false },
      NOW,
    );
    expect(missingProvenance).toMatchObject({
      state: "db_refresh_recommended",
      trivy_db: { state: "provenance_missing" },
      repair_command: ENGINE_REPAIR_COMMAND,
    });

    expect(
      trivyDbState(
        { exists: true, downloadedAt: "2026-07-18T23:59:59.000Z", provenanceRecorded: true },
        NOW,
      ),
    ).toBe("stale");
  });

  test("a missing DB is required setup, not a freshness recommendation", () => {
    const result = deriveEngineSetupStatus(
      "darwin-arm64",
      probes(),
      { exists: false, provenanceRecorded: false },
      NOW,
    );
    expect(result).toMatchObject({
      state: "repair_required",
      trivy_db: { state: "missing" },
      network_required: true,
    });
  });
});

describe("osv-scanner is an additive engine", () => {
  function withOsv(osv: Partial<EngineHealthProbe>, others: Parameters<typeof probes>[0] = {}): EngineHealthProbe[] {
    return [...probes(others), { engine: "osv-scanner", version: "2.7.0", available: true, ...osv }];
  }

  test("a missing osv-scanner keeps the machine ready and is still listed as missing", () => {
    const result = deriveEngineSetupStatus(
      "darwin-arm64",
      withOsv({ available: false, issue: "missing", note: "not installed" }),
      freshDb,
      NOW,
    );
    expect(engineSetupSchema.parse(result)).toEqual(result);
    expect(result).toMatchObject({ state: "ready", network_required: false });
    expect(result.repair_command).toBeUndefined();
    expect(result.engines).toContainEqual({ engine: "osv-scanner", version: "2.7.0", state: "missing", detail: "not installed" });
  });

  test("a missing osv-scanner with a stale Trivy DB recommends a refresh and is not named as an issue", () => {
    const result = deriveEngineSetupStatus(
      "darwin-arm64",
      withOsv({ available: false, issue: "missing" }),
      { ...freshDb, downloadedAt: "2026-07-01T00:00:00.000Z" },
      NOW,
    );
    expect(result).toMatchObject({ state: "db_refresh_recommended", repair_command: ENGINE_REPAIR_COMMAND });
    const message = engineSetupMessage(result);
    expect(message).toContain("Trivy DB stale");
    expect(message).not.toContain("osv-scanner:missing");
    expect(message).toContain("osv-scanner not installed (optional)");
  });

  test.each(["hash_mismatch", "unpinned", "lockfile_error"] as const)("an osv-scanner %s still requires repair", (issue) => {
    const result = deriveEngineSetupStatus("darwin-arm64", withOsv({ available: false, issue }), freshDb, NOW);
    expect(result.state).toBe("repair_required");
  });

  test.each(["opengrep", "gitleaks", "trivy"] as const)("a missing %s still requires repair", (engine) => {
    const result = deriveEngineSetupStatus(
      "darwin-arm64",
      withOsv({}, { [engine]: { available: false, issue: "missing" } }),
      freshDb,
      NOW,
    );
    expect(result).toMatchObject({ state: "repair_required", repair_command: ENGINE_REPAIR_COMMAND });
  });
});

describe("OSV database health", () => {
  const ready = { ecosystem: "npm", state: "ready", downloaded_at: "2026-07-25T00:00:00.000Z" } as const;

  test("fresh OSV databases keep the machine ready and are reported", () => {
    const result = deriveEngineSetupStatus("darwin-arm64", probes(), freshDb, NOW, [ready]);
    expect(engineSetupSchema.parse(result)).toEqual(result);
    expect(result.state).toBe("ready");
    expect(result.osv_databases).toEqual([ready]);
    expect(result.repair_command).toBeUndefined();
  });

  test("no installed OSV database is still ready: databases are per-repository and optional", () => {
    const result = deriveEngineSetupStatus("darwin-arm64", probes(), freshDb, NOW);
    expect(result.state).toBe("ready");
    expect(result.osv_databases).toEqual([]);
  });

  test("a stale OSV database recommends a refresh without calling current findings incomplete", () => {
    const result = deriveEngineSetupStatus("darwin-arm64", probes(), freshDb, NOW, [
      ready,
      { ecosystem: "PyPI", state: "stale", downloaded_at: "2026-07-01T00:00:00.000Z" },
    ]);
    expect(engineSetupSchema.parse(result)).toEqual(result);
    expect(result).toMatchObject({
      state: "db_refresh_recommended",
      repair_command: ENGINE_REPAIR_COMMAND,
      network_required: true,
    });
    expect(engineSetupMessage(result)).toContain("OSV databases PyPI:stale");
    expect(engineSetupMessage(result)).not.toContain("npm");
  });

  test("an OSV database without recorded provenance recommends a refresh like the Trivy DB does", () => {
    const result = deriveEngineSetupStatus("darwin-arm64", probes(), freshDb, NOW, [
      { ecosystem: "Go", state: "provenance_missing" },
    ]);
    expect(result.state).toBe("db_refresh_recommended");
  });

  test("a missing Trivy DB still outranks an OSV refresh recommendation", () => {
    const result = deriveEngineSetupStatus(
      "darwin-arm64",
      probes(),
      { exists: false, provenanceRecorded: false },
      NOW,
      [{ ecosystem: "Go", state: "stale", downloaded_at: "2026-07-01T00:00:00.000Z" }],
    );
    expect(result.state).toBe("repair_required");
  });

  test("scan results stored before OSV databases existed still validate", () => {
    const legacy = deriveEngineSetupStatus("darwin-arm64", probes(), freshDb, NOW);
    delete (legacy as { osv_databases?: unknown }).osv_databases;
    expect(engineSetupSchema.safeParse(legacy).success).toBe(true);
  });
});

