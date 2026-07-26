import { describe, expect, test } from "vitest";

import { planEngineRepair } from "./install.js";
import type { EngineSetupStatus } from "./types.js";

function status(overrides: Partial<EngineSetupStatus> = {}): EngineSetupStatus {
  return {
    state: "ready",
    platform: "linux-x64",
    engines: [
      { engine: "opengrep", version: "1.23.0", state: "ready" },
      { engine: "gitleaks", version: "8.30.1", state: "ready" },
      { engine: "trivy", version: "0.71.2", state: "ready" },
    ],
    trivy_db: { state: "ready", downloaded_at: "2026-07-25T00:00:00.000Z" },
    network_required: false,
    ...overrides,
  };
}

describe("incremental engine repair planning", () => {
  test("healthy state is a no-op even after a CodeInspectus-only release", () => {
    expect(planEngineRepair(status())).toEqual({
      engines: [],
      refresh_trivy_db: false,
      blockers: [],
    });
  });

  test("downloads only unhealthy selected engines", () => {
    const current = status({
      state: "repair_required",
      engines: [
        { engine: "opengrep", version: "1.24.0", state: "hash_mismatch" },
        { engine: "gitleaks", version: "8.30.1", state: "ready" },
        { engine: "trivy", version: "0.71.2", state: "ready" },
      ],
      network_required: true,
    });
    expect(planEngineRepair(current)).toMatchObject({ engines: ["opengrep"], refresh_trivy_db: false });
    expect(planEngineRepair(current, ["gitleaks"])).toMatchObject({ engines: [], refresh_trivy_db: false });
  });

  test("missing provenance plans a DB-only refresh and supports an explicit forced refresh", () => {
    const current = status({
      state: "db_refresh_recommended",
      trivy_db: { state: "provenance_missing", downloaded_at: "2026-07-15T00:00:00.000Z" },
      network_required: true,
    });
    expect(planEngineRepair(current)).toEqual({
      engines: [],
      refresh_trivy_db: true,
      blockers: [],
    });
    expect(planEngineRepair(status(), ["trivy"], true).refresh_trivy_db).toBe(true);
    expect(planEngineRepair(current, ["opengrep"]).refresh_trivy_db).toBe(false);
  });

  test("unsupported selected engines are blockers and never scheduled", () => {
    const current = status({
      state: "unsupported_platform",
      engines: [
        { engine: "opengrep", version: "1.23.0", state: "unsupported_platform" },
        { engine: "gitleaks", version: "8.30.1", state: "ready" },
        { engine: "trivy", version: "0.71.2", state: "unsupported_platform" },
      ],
    });
    expect(planEngineRepair(current)).toEqual({
      engines: [],
      refresh_trivy_db: false,
      blockers: ["opengrep is unsupported on linux-x64", "trivy is unsupported on linux-x64"],
    });
  });

  test("invalid packaged pins block user repair instead of mutating the lockfile", () => {
    const current = status({
      state: "repair_required",
      engines: [
        { engine: "opengrep", version: "1.23.0", state: "unpinned" },
        { engine: "gitleaks", version: "8.30.1", state: "ready" },
        { engine: "trivy", version: "0.71.2", state: "ready" },
      ],
    });
    expect(planEngineRepair(current, ["opengrep"])).toEqual({
      engines: [],
      refresh_trivy_db: false,
      blockers: ["opengrep has invalid packaged pin state (unpinned); reinstall CodeInspectus"],
    });
  });
});
