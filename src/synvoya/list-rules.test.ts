import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("../engine-health.js", () => ({
  inspectEngineSetup: vi.fn(async () => ({
    state: "ready", platform: "test-x64",
    engines: [
      { engine: "opengrep", version: "1.33.1", state: "ready" },
      { engine: "gitleaks", version: "8.30.1", state: "ready" },
      { engine: "trivy", version: "0.76.1", state: "ready" },
    ],
    trivy_db: { state: "ready", downloaded_at: "2026-07-26T00:00:00.000Z" },
    network_required: false,
  })),
  engineSetupMessage: () => "Engines ready.",
}));
vi.mock("../engines/trivy.js", () => ({ readTrivyDbDate: vi.fn(async () => "2026-07-26T00:00:00.000Z") }));
vi.mock("../osv/database.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../osv/database.js")>()),
  inspectOsvDatabases: vi.fn(async () => []),
  readOsvDbRecord: vi.fn(async () => undefined),
}));
const dataset = vi.hoisted(() => ({ override: undefined as undefined | (() => Promise<unknown>) }));
vi.mock("./dataset.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("./dataset.js")>();
  return { ...real, loadSynvoyaDataset: (...args: Parameters<typeof real.loadSynvoyaDataset>) => dataset.override ? dataset.override() : real.loadSynvoyaDataset(...args) };
});

const { listRules, synvoyaDatasetLine } = await import("../rules.js");
const { listRulesOutput } = await import("../schemas.js");
const { SYNVOYA_FAMILY_DISPLAY } = await import("./family.js");
const { loadSynvoyaDataset } = await vi.importActual<typeof import("./dataset.js")>("./dataset.js");

afterEach(() => { dataset.override = undefined; });

describe("list_rules Synvoya family", () => {
  test("groups CodeInspectus rules under Synvoya (CodeInspectus) and reports the dataset version and date", async () => {
    const loaded = await loadSynvoyaDataset();
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;

    const result = await listRules({});
    expect(listRulesOutput.parse(result)).toEqual(result);

    const group = result.rule_groups.find((entry) => entry.engine_family === "synvoya");
    expect(group).toMatchObject({ group: SYNVOYA_FAMILY_DISPLAY });
    expect(group!.rule_count).toBeGreaterThan(0);
    const members = result.custom_rules.filter((rule) => rule.engine_family === "synvoya");
    expect(group!.rule_count).toBe(members.length);
    // Raw engine and rule ids are untouched; the family is an extra field.
    expect(members.some((rule) => rule.engine === "codeinspectus-ai" && rule.id === "ci-ai-rls-using-true")).toBe(true);
    expect(members.some((rule) => rule.engine === "gitleaks" && rule.id === "codeinspectus-stripe-live-secret")).toBe(true);
    expect(result.custom_rules.filter((rule) => rule.engine_family === undefined).every((rule) => rule.engine !== "codeinspectus-ai")).toBe(true);

    expect(result.synvoya_dataset).toEqual({
      state: "available", version: loaded.dataset.version, date: loaded.dataset.date, advisory_count: loaded.dataset.advisories.length,
    });
    expect(synvoyaDatasetLine(result.synvoya_dataset)).toBe(
      `Synvoya gap advisories: ${loaded.dataset.version} (${loaded.dataset.date}), ${loaded.dataset.advisories.length} advisories`,
    );
  });

  test("engine rows for family members read Synvoya (CodeInspectus) while the raw engine id stays", async () => {
    const result = await listRules({});
    for (const id of ["codeinspectus-ai", "codeinspectus-pub", "synvoya"] as const) {
      expect(result.engines.find((row) => row.engine === id)).toMatchObject({ engine: id, display_name: SYNVOYA_FAMILY_DISPLAY, engine_family: "synvoya" });
    }
    for (const id of ["opengrep", "gitleaks", "trivy", "osv-scanner"] as const) {
      expect(result.engines.find((row) => row.engine === id)).not.toHaveProperty("display_name");
    }
  });

  test("a dataset that fails to load is reported as unavailable with the reason, never omitted", async () => {
    dataset.override = async () => ({ ok: false, reason: "advisories.json digest mismatch" });
    const result = await listRules({});
    expect(listRulesOutput.parse(result)).toEqual(result);
    expect(result.synvoya_dataset).toEqual({ state: "unavailable", reason: "advisories.json digest mismatch" });
    expect(synvoyaDatasetLine(result.synvoya_dataset)).toBe("Synvoya gap advisories: unavailable (advisories.json digest mismatch)");
    expect(result.engines.find((row) => row.engine === "synvoya")).toMatchObject({ available: false });
  });
});
