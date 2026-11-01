import { describe, expect, test } from "vitest";

import { parseRepairArgs, planEngineRepair } from "./install.js";
import type { EngineSetupStatus } from "./types.js";

function status(overrides: Partial<EngineSetupStatus> = {}): EngineSetupStatus {
  return {
    state: "ready",
    platform: "linux-x64",
    engines: [
      { engine: "opengrep", version: "1.33.1", state: "ready" },
      { engine: "gitleaks", version: "8.30.1", state: "ready" },
      { engine: "trivy", version: "0.76.1", state: "ready" },
      { engine: "osv-scanner", version: "2.7.0", state: "ready" },
    ],
    trivy_db: { state: "ready", downloaded_at: "2026-07-25T00:00:00.000Z" },
    osv_databases: [],
    network_required: false,
    ...overrides,
  };
}

describe("incremental engine repair planning", () => {
  test("healthy state is a no-op even after a CodeInspectus-only release", () => {
    expect(planEngineRepair(status())).toEqual({
      engines: [],
      refresh_trivy_db: false,
      osv_ecosystems: [],
      blockers: [],
    });
  });

  test("downloads only unhealthy selected engines", () => {
    const current = status({
      state: "repair_required",
      engines: [
        { engine: "opengrep", version: "1.24.0", state: "hash_mismatch" },
        { engine: "gitleaks", version: "8.30.1", state: "ready" },
        { engine: "trivy", version: "0.76.1", state: "ready" },
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
      osv_ecosystems: [],
      blockers: [],
    });
    expect(planEngineRepair(status(), ["trivy"], true).refresh_trivy_db).toBe(true);
    expect(planEngineRepair(current, ["opengrep"]).refresh_trivy_db).toBe(false);
  });

  test("unsupported selected engines are blockers and never scheduled", () => {
    const current = status({
      state: "unsupported_platform",
      engines: [
        { engine: "opengrep", version: "1.33.1", state: "unsupported_platform" },
        { engine: "gitleaks", version: "8.30.1", state: "ready" },
        { engine: "trivy", version: "0.76.1", state: "unsupported_platform" },
      ],
    });
    expect(planEngineRepair(current)).toEqual({
      engines: [],
      refresh_trivy_db: false,
      osv_ecosystems: [],
      blockers: ["opengrep is unsupported on linux-x64", "trivy is unsupported on linux-x64"],
    });
  });

  test("invalid packaged pins block user repair instead of mutating the lockfile", () => {
    const current = status({
      state: "repair_required",
      engines: [
        { engine: "opengrep", version: "1.33.1", state: "unpinned" },
        { engine: "gitleaks", version: "8.30.1", state: "ready" },
        { engine: "trivy", version: "0.76.1", state: "ready" },
      ],
    });
    expect(planEngineRepair(current, ["opengrep"])).toEqual({
      engines: [],
      refresh_trivy_db: false,
      osv_ecosystems: [],
      blockers: ["opengrep has invalid packaged pin state (unpinned); reinstall CodeInspectus"],
    });
  });
});

describe("OSV database repair planning", () => {
  const osvStatus = (osv_databases: NonNullable<EngineSetupStatus["osv_databases"]>) =>
    status({ state: "db_refresh_recommended", osv_databases, network_required: true });

  test("repair plan includes requested OSV ecosystems", () => {
    const args = parseRepairArgs(["--osv-ecosystems", "PyPI"]);
    expect(args.osvEcosystems).toEqual(["PyPI"]);
    expect(planEngineRepair(status(), args.selected, args.refreshDb, args.osvEcosystems)).toEqual({
      engines: [],
      refresh_trivy_db: false,
      osv_ecosystems: ["PyPI"],
      blockers: [],
    });
  });

  test("requested ecosystems that are already ready are skipped unless a refresh is forced", () => {
    const installed = osvStatus([{ ecosystem: "PyPI", state: "ready", downloaded_at: "2026-10-29T00:00:00.000Z" }]);
    expect(planEngineRepair(installed, undefined, false, ["PyPI", "npm"]).osv_ecosystems).toEqual(["npm"]);
    expect(planEngineRepair(installed, undefined, true, ["PyPI", "npm"]).osv_ecosystems).toEqual(["npm", "PyPI"]);
  });

  test("installed databases that went stale or lost provenance are refreshed without being requested", () => {
    const current = osvStatus([
      { ecosystem: "npm", state: "ready" },
      { ecosystem: "PyPI", state: "stale", downloaded_at: "2026-10-01T00:00:00.000Z" },
      { ecosystem: "Go", state: "provenance_missing" },
    ]);
    expect(planEngineRepair(current).osv_ecosystems).toEqual(["PyPI", "Go"]);
  });

  test("an explicit ecosystem list is never widened to other stale databases", () => {
    const current = osvStatus([
      { ecosystem: "npm", state: "stale", downloaded_at: "2026-10-01T00:00:00.000Z" },
      { ecosystem: "PyPI", state: "provenance_missing" },
    ]);
    expect(planEngineRepair(current, undefined, false, ["Go"]).osv_ecosystems).toEqual(["Go"]);
    // A forced refresh also stays inside the list.
    expect(planEngineRepair(current, undefined, true, ["Go"]).osv_ecosystems).toEqual(["Go"]);
    // Only a bare repair (no list) refreshes what is installed but stale.
    expect(planEngineRepair(current).osv_ecosystems).toEqual(["npm", "PyPI"]);
  });

  test("OSV databases are untouched when osv-scanner is outside the repair scope", () => {
    const current = osvStatus([{ ecosystem: "PyPI", state: "stale" }]);
    expect(planEngineRepair(current, ["trivy"], false, ["npm"]).osv_ecosystems).toEqual([]);
  });

  test("an unusable osv-scanner blocks database work instead of planning it", () => {
    const current = status({
      engines: [{ engine: "osv-scanner", version: "2.7.0", state: "unsupported_platform" }],
      osv_databases: [{ ecosystem: "PyPI", state: "stale" }],
    });
    expect(planEngineRepair(current, undefined, false, ["npm"])).toEqual({
      engines: [],
      refresh_trivy_db: false,
      osv_ecosystems: [],
      blockers: ["osv-scanner is unsupported on linux-x64"],
    });
  });

  test("--osv-ecosystems is parsed with its value and does not disturb engine selection", () => {
    expect(parseRepairArgs(["--osv-ecosystems", "pypi,npm"])).toEqual({
      selected: ["opengrep", "gitleaks", "trivy", "osv-scanner"],
      refreshDb: false,
      osvEcosystems: ["npm", "PyPI"],
    });
    expect(parseRepairArgs(["osv-scanner", "--refresh-db", "--osv-ecosystems", "Go"])).toEqual({
      selected: ["osv-scanner"],
      refreshDb: true,
      osvEcosystems: ["Go"],
    });
    expect(parseRepairArgs([]).osvEcosystems).toEqual([]);
  });

  test("malformed OSV arguments fail before any work is planned", () => {
    expect(() => parseRepairArgs(["--osv-ecosystems"])).toThrow(/comma-separated/);
    expect(() => parseRepairArgs(["--osv-ecosystems", "--refresh-db"])).toThrow(/comma-separated/);
    expect(() => parseRepairArgs(["--osv-ecosystems", "npm,Debian"])).toThrow(/Debian/);
    expect(() => parseRepairArgs(["trivy", "--osv-ecosystems", "npm"])).toThrow(/osv-scanner/);
  });
});

