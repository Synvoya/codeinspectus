import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";

vi.mock("./engine-health.js", () => ({
  inspectEngineSetup: vi.fn(async () => ({
    state: "ready",
    platform: "test-x64",
    engines: [
      { engine: "opengrep", version: "1.23.0", state: "ready" },
      { engine: "gitleaks", version: "8.30.1", state: "ready" },
      { engine: "trivy", version: "0.71.2", state: "ready" },
    ],
    trivy_db: { state: "ready", downloaded_at: "2026-07-26T00:00:00.000Z" },
    network_required: false,
  })),
}));

vi.mock("./engines/trivy.js", () => ({
  readTrivyDbDate: vi.fn(async () => "2026-07-26T00:00:00.000Z"),
}));

const { listRules } = await import("./rules.js");
const { listRulesOutput } = await import("./schemas.js");
const { nativePackInventory, registeredNativeAnalyzers } = await import("./packs/registry.js");

describe("listRules native pack inventory", () => {
  test("publishes all static native packs and exact rule ownership", async () => {
    const result = await listRules({});
    const nativeRules = result.custom_rules.filter((rule) => rule.engine === "codeinspectus-ai");
    const externalRules = result.custom_rules.filter((rule) => rule.engine !== "codeinspectus-ai");

    expect(listRulesOutput.parse(result)).toEqual(result);
    expect(result.native_packs).toEqual([
      expect.objectContaining({
        id: "javascript-typescript",
        analyzer_count: 8,
        rule_count: 22,
      }),
      expect.objectContaining({
        id: "flutter",
        analyzer_count: 6,
        rule_count: 6,
      }),
      expect.objectContaining({
        id: "android",
        platforms: ["android"],
        analyzer_count: 1,
        rule_count: 4,
      }),
      expect.objectContaining({
        id: "ios",
        platforms: ["ios"],
        analyzer_count: 1,
        rule_count: 4,
      }),
      expect.objectContaining({
        id: "react-native",
        frameworks: ["react-native"],
        analyzer_count: 4,
        rule_count: 4,
      }),
      expect.objectContaining({
        id: "expo",
        frameworks: ["expo"],
        analyzer_count: 2,
        rule_count: 2,
      }),
      expect.objectContaining({
        id: "python-ai-api",
        languages: ["python"],
        analyzer_count: 10,
        rule_count: 10,
      }),
      expect.objectContaining({
        id: "javascript-baseline",
        scanner_kind: "sast",
        analyzer_count: 1,
        rule_count: 2,
      }),
      expect.objectContaining({
        id: "go-ai",
        languages: ["go"],
        frameworks: ["openai"],
        analyzer_count: 1,
        rule_count: 1,
      }),
      expect.objectContaining({
        id: "java-ai",
        languages: ["java"],
        frameworks: ["openai"],
        analyzer_count: 1,
        rule_count: 1,
      }),
      expect.objectContaining({
        id: "csharp-ai",
        languages: ["csharp"],
        frameworks: ["openai"],
        analyzer_count: 1,
        rule_count: 1,
      }),
      expect.objectContaining({
        id: "php-ai",
        languages: ["php"],
        frameworks: ["openai"],
        analyzer_count: 1,
        rule_count: 1,
      }),
      expect.objectContaining({
        id: "rust-ai",
        languages: ["rust"],
        frameworks: ["openai"],
        analyzer_count: 1,
        rule_count: 1,
      }),
      expect.objectContaining({
        id: "ruby-ai",
        languages: ["ruby"],
        frameworks: ["openai"],
        analyzer_count: 1,
        rule_count: 1,
      }),
      expect.objectContaining({
        id: "firebase",
        frameworks: [],
        platforms: ["firebase"],
        analyzer_count: 1,
        rule_count: 3,
      }),
      expect.objectContaining({
        id: "github-actions",
        languages: ["yaml"],
        platforms: ["github-actions"],
        analyzer_count: 1,
        rule_count: 2,
      }),
    ]);
    expect(result.native_packs[0]?.languages).toEqual(expect.arrayContaining(["javascript", "typescript"]));
    expect(result.native_packs[0]?.limitations.join(" ")).toMatch(/rule-specific|not complete/i);
    expect(result.native_packs[1]?.languages).toContain("dart");
    expect(result.native_packs[1]?.frameworks).toContain("flutter");
    expect(result.native_packs[1]?.limitations.join(" ")).toMatch(/source-ordered|does not claim complete/i);
    expect(result.custom_rule_count).toBe(86);
    expect(result.engines.some((engine) => engine.engine === "codeinspectus-pub" && engine.available)).toBe(true);
    expect(result.advisory_databases).toEqual([
      expect.objectContaining({
        engine: "codeinspectus-pub",
        ecosystem: "Pub",
        active_advisories: 11,
        affected_packages: 10,
        matching: "exact-enumerated-versions",
        license: "CC-BY-4.0",
      }),
    ]);
    expect(nativeRules).toHaveLength(65);
    expect(nativeRules.filter((rule) => rule.pack_id === "javascript-typescript")).toHaveLength(22);
    expect(nativeRules.filter((rule) => rule.pack_id === "flutter")).toHaveLength(6);
    expect(nativeRules.filter((rule) => rule.pack_id === "android")).toHaveLength(4);
    expect(nativeRules.filter((rule) => rule.pack_id === "ios")).toHaveLength(4);
    expect(nativeRules.filter((rule) => rule.pack_id === "react-native")).toHaveLength(4);
    expect(nativeRules.filter((rule) => rule.pack_id === "expo")).toHaveLength(2);
    expect(nativeRules.filter((rule) => rule.pack_id === "python-ai-api")).toHaveLength(10);
    expect(nativeRules.filter((rule) => rule.pack_id === "javascript-baseline")).toHaveLength(2);
    expect(nativeRules.filter((rule) => rule.pack_id === "go-ai")).toHaveLength(1);
    expect(nativeRules.filter((rule) => rule.pack_id === "java-ai")).toHaveLength(1);
    expect(nativeRules.filter((rule) => rule.pack_id === "csharp-ai")).toHaveLength(1);
    expect(nativeRules.filter((rule) => rule.pack_id === "php-ai")).toHaveLength(1);
    expect(nativeRules.filter((rule) => rule.pack_id === "rust-ai")).toHaveLength(1);
    expect(nativeRules.filter((rule) => rule.pack_id === "ruby-ai")).toHaveLength(1);
    expect(nativeRules.filter((rule) => rule.pack_id === "firebase")).toHaveLength(3);
    expect(nativeRules.filter((rule) => rule.pack_id === "github-actions")).toHaveLength(2);
    expect(externalRules).toHaveLength(21);
    expect(externalRules.every((rule) => !("pack_id" in rule))).toBe(true);
  });

  test("keeps exact filtered custom rule counts", async () => {
    const [native, opengrep, gitleaks] = await Promise.all([
      listRules({ engine: "codeinspectus-ai" }),
      listRules({ engine: "opengrep" }),
      listRules({ engine: "gitleaks" }),
    ]);

    expect(native.custom_rule_count).toBe(65);
    expect(opengrep.custom_rule_count).toBe(18);
    expect(gitleaks.custom_rule_count).toBe(3);
    expect(native.native_packs).toEqual(opengrep.native_packs);
    expect(opengrep.native_packs).toEqual(gitleaks.native_packs);
  });

  test("keeps manifest and executable registry rule sets exact and unique", async () => {
    const manifest = JSON.parse(
      await readFile(join(process.cwd(), "detection-db", "manifest.json"), "utf8"),
    ) as {
      custom_rules: Array<{ id: string; engine: string; pack_id?: string }>;
    };
    const packs = nativePackInventory();
    const analyzers = registeredNativeAnalyzers("/tmp/codeinspectus-list-rules-inventory");
    const nativeManifestRules = manifest.custom_rules.filter(
      (rule) => rule.engine === "codeinspectus-ai",
    );
    const registeredRules = analyzers.flatMap((analyzer) =>
      analyzer.ruleIds.map((ruleId) => ({ ruleId, packId: analyzer.packId })),
    );

    expect(new Set(packs.map((pack) => pack.pack_id)).size).toBe(packs.length);
    expect(new Set(analyzers.map((analyzer) => analyzer.id)).size).toBe(analyzers.length);
    expect(new Set(nativeManifestRules.map((rule) => rule.id)).size).toBe(nativeManifestRules.length);
    expect(new Set(registeredRules.map((rule) => rule.ruleId)).size).toBe(registeredRules.length);
    expect(registeredRules.map((rule) => rule.ruleId).sort()).toEqual(
      nativeManifestRules.map((rule) => rule.id).sort(),
    );

    const owners = new Map(registeredRules.map((rule) => [rule.ruleId, rule.packId]));
    for (const rule of nativeManifestRules) {
      expect(rule.pack_id).toBe(owners.get(rule.id));
    }
    expect(
      manifest.custom_rules
        .filter((rule) => rule.engine !== "codeinspectus-ai")
        .every((rule) => rule.pack_id === undefined),
    ).toBe(true);
  });
});
