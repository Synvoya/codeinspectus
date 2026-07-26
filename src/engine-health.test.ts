import { describe, expect, test } from "vitest";

import {
  deriveEngineSetupStatus,
  ENGINE_REPAIR_COMMAND,
  trivyDbState,
  type EngineHealthProbe,
} from "./engine-health.js";
import { engineSetupSchema } from "./schemas.js";

const NOW = Date.parse("2026-07-26T00:00:00.000Z");

function probes(overrides: Partial<Record<EngineHealthProbe["engine"], Partial<EngineHealthProbe>>> = {}): EngineHealthProbe[] {
  return (["opengrep", "gitleaks", "trivy"] as const).map((engine) => ({
    engine,
    version: engine === "opengrep" ? "1.23.0" : engine === "gitleaks" ? "8.30.1" : "0.71.2",
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
