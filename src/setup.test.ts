import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { loadLockfile, type Lockfile } from "./engines/lockfile.js";
import { engineNeedsCosign, parseRepairArgs, planEngineRepair } from "./install.js";
import {
  bootstrapCosign,
  buildSetupPlan,
  declineSetupComponents,
  formatSetupPlan,
  installSetupComponents,
  runSetupCli,
  setupHelp,
} from "./setup.js";
import { createHash } from "node:crypto";
import type { EngineSetupStatus } from "./types.js";
import { setupPlanSchema } from "./schemas.js";

let root: string;
let preferencesPath: string;
let lockfile: Lockfile;

function status(
  states: Partial<Record<"opengrep" | "gitleaks" | "trivy" | "osv-scanner", "ready" | "missing" | "hash_mismatch">> = {},
  db: EngineSetupStatus["trivy_db"]["state"] = "missing",
  osvDatabases: NonNullable<EngineSetupStatus["osv_databases"]> = [],
): EngineSetupStatus {
  const engines = (["opengrep", "gitleaks", "trivy", "osv-scanner"] as const).map((engine) => ({
    engine,
    version: lockfile.engines[engine].version,
    state: states[engine] ?? "ready",
  }));
  return {
    state: engines.some((engine) => engine.state !== "ready") || db === "missing" ? "repair_required" : db === "ready" ? "ready" : "db_refresh_recommended",
    platform: "darwin-arm64",
    engines,
    trivy_db: { state: db },
    osv_databases: osvDatabases,
    network_required: true,
  };
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "codeinspectus-setup-test-"));
  preferencesPath = join(root, "setup-preferences.json");
  lockfile = await loadLockfile();
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await rm(root, { recursive: true, force: true });
});

describe("consent-driven engine setup", () => {
  test("documents every setup approval and preference option", () => {
    expect(setupHelp()).toContain("--status");
    expect(setupHelp()).toContain("--all");
    expect(setupHelp()).toContain("--select opengrep,gitleaks,trivy");
    expect(setupHelp()).toContain("--reset");
    expect(setupHelp()).toContain("--select opengrep,gitleaks,trivy,osv-scanner");
    expect(setupHelp()).toContain("--path <repo>");
    expect(setupHelp()).toContain("--osv-ecosystems");
  });
  test("reports native coverage, exact platform downloads, DB estimate, licenses, and verifier dependency", async () => {
    const plan = await buildSetupPlan({
      status: status({ opengrep: "missing", gitleaks: "missing", trivy: "missing", "osv-scanner": "missing" }),
      lockfile,
      preferencesPath,
      cosignAvailable: false,
    });

    expect(plan.native.rule_count).toBe(72);
    expect(plan.native.download_required).toBe(false);
    expect(plan.components.map((item) => [item.id, item.action, item.download_size_bytes])).toEqual([
      ["opengrep", "download", 47_298_224],
      ["gitleaks", "download", 7_897_593],
      ["trivy", "download", 49_857_297],
      ["osv-scanner", "download", 55_336_530],
    ]);
    expect(plan.verifier).toMatchObject({ required: true, available: false, download_size_bytes: 139_584_002 });
    // Pinned darwin-arm64 asset sizes (engines.lock.json): 47_298_224 + 7_897_593 + 49_857_297 + 55_336_530,
    // plus the 139_584_002 Cosign bootstrap. Database downloads are estimates and never part of this figure.
    expect(plan.exact_download_bytes).toBe(299_973_646);
    expect(plan.estimated_osv_download_bytes).toBe(0);
    expect(plan.estimated_database_disk_bytes).toBeGreaterThan(1_000_000_000);
    const rendered = formatSetupPlan(plan);
    expect(rendered).toContain("72 rules, ready immediately");
    expect(rendered).toContain("License: GNU LGPL 2.1");
    expect(rendered).toContain("Required verifier: Cosign 3.1.2");
    expect(rendered).toContain("database download size changes upstream");
  });

  test("persists declines so first-use planning does not repeatedly select missing components", async () => {
    await declineSetupComponents(["opengrep"], preferencesPath);
    const plan = await buildSetupPlan({
      status: status({ opengrep: "missing" }, "ready"),
      lockfile,
      preferencesPath,
      cosignAvailable: true,
    });

    expect(plan.preference_state).toBe("configured");
    expect(plan.components.find((item) => item.id === "opengrep")?.selected).toBe(false);
    expect(plan.network_required).toBe(false);
  });

  test("refuses networked installation without explicit confirmation", async () => {
    const plan = await buildSetupPlan({
      status: status({ gitleaks: "missing" }, "ready"),
      lockfile,
      preferencesPath,
      cosignAvailable: false,
    });
    const repair = vi.fn();

    await expect(installSetupComponents(["gitleaks"], false, { plan, preferencesPath, repair })).rejects.toThrow(
      "Download confirmation is required",
    );
    expect(repair).not.toHaveBeenCalled();
    await expect(readFile(preferencesPath, "utf8")).rejects.toThrow();
  });

  test("installs only the approved selection and records the choice", async () => {
    const plan = await buildSetupPlan({
      status: status({ gitleaks: "missing" }, "ready"),
      lockfile,
      preferencesPath,
      cosignAvailable: false,
    });
    const repair = vi.fn(async () => undefined);
    const bootstrap = vi.fn(async () => undefined);

    await installSetupComponents(["gitleaks"], true, { plan, preferencesPath, repair, bootstrap });

    expect(repair).toHaveBeenCalledWith(["gitleaks"], expect.any(Object));
    expect(bootstrap).not.toHaveBeenCalled();
    const saved = JSON.parse(await readFile(preferencesPath, "utf8")) as { choices: Record<string, string> };
    expect(saved.choices).toEqual({ opengrep: "declined", gitleaks: "enabled", trivy: "declined", "osv-scanner": "declined" });
  });

  test("needs the Cosign verifier for every lockfile verification method that uses it, whatever the engine", async () => {
    const plan = async (signatures: Record<"opengrep" | "gitleaks" | "trivy", Lockfile["engines"]["trivy"]["signature"]>) => {
      const testLock = structuredClone(lockfile);
      for (const engine of ["opengrep", "gitleaks", "trivy"] as const) testLock.engines[engine].signature = signatures[engine];
      return await buildSetupPlan({
        status: status({ opengrep: "missing", gitleaks: "missing", trivy: "missing" }, "ready"),
        lockfile: testLock,
        preferencesPath,
        cosignAvailable: false,
      });
    };

    const checksumsOnly = { opengrep: "checksums", gitleaks: "checksums", trivy: "checksums" } as const;
    expect((await plan(checksumsOnly)).verifier.required).toBe(false);
    for (const signature of ["cosign", "checksums+sigstore", "checksums+slsa"] as const) {
      expect((await plan({ ...checksumsOnly, gitleaks: signature })).verifier.required).toBe(true);
    }
  });

  test("bootstraps Cosign before installing an engine whose lockfile method needs it", async () => {
    const testLock = structuredClone(lockfile);
    testLock.engines.gitleaks.signature = "checksums+slsa";
    const plan = await buildSetupPlan({
      status: status({ gitleaks: "missing" }, "ready"),
      lockfile: testLock,
      preferencesPath,
      cosignAvailable: false,
    });
    const order: string[] = [];
    const bootstrap = vi.fn(async () => void order.push("bootstrap"));
    const repair = vi.fn(async () => void order.push("repair"));

    await installSetupComponents(["gitleaks"], true, {
      plan,
      preferencesPath,
      repair,
      bootstrap,
      loadLockfile: async () => testLock,
    });

    expect(order).toEqual(["bootstrap", "repair"]);
  });

  test("bootstraps Cosign only after exact size and immutable SHA verification", async () => {
    const bytes = Buffer.from("test-cosign-binary");
    const testLock = structuredClone(lockfile);
    const entry = testLock.verifiers!.cosign.platforms["darwin-arm64"]!;
    entry.download_size_bytes = bytes.byteLength;
    entry.sha256 = createHash("sha256").update(bytes).digest("hex");
    testLock.verifiers!.cosign.release_base = "https://downloads.example/cosign";
    vi.stubGlobal("fetch", vi.fn(async () => new Response(bytes, { status: 200 })));
    const logs: string[] = [];

    await bootstrapCosign(testLock, "darwin-arm64", { stdout: (text) => logs.push(text), stderr: vi.fn() }, {
      managedBin: join(root, "bin"),
      managedReady: async () => false,
    });

    expect(await readFile(join(root, "bin", process.platform === "win32" ? "cosign.exe" : "cosign"))).toEqual(bytes);
    expect(logs.join("\n")).toContain("can take several minutes");
    expect(logs.join("\n")).toContain("SHA-pinned Cosign 3.1.2");
    vi.unstubAllGlobals();
  });

  test("fails closed on a Cosign bootstrap digest mismatch", async () => {
    const testLock = structuredClone(lockfile);
    const entry = testLock.verifiers!.cosign.platforms["darwin-arm64"]!;
    entry.download_size_bytes = 3;
    entry.sha256 = "0".repeat(64);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(Buffer.from("bad"), { status: 200 })));

    await expect(bootstrapCosign(testLock, "darwin-arm64", { stdout: vi.fn(), stderr: vi.fn() }, {
      managedBin: join(root, "bin"),
      managedReady: async () => false,
    })).rejects.toThrow("Cosign SHA256 mismatch");
    await expect(readFile(join(root, "bin", process.platform === "win32" ? "cosign.exe" : "cosign"))).rejects.toThrow();
    vi.unstubAllGlobals();
  });

  test("noninteractive setup never downloads without --all or --select", async () => {
    const plan = await buildSetupPlan({
      status: status({ gitleaks: "missing" }, "ready"), lockfile, preferencesPath, cosignAvailable: true,
    });
    const output: string[] = [];
    const install = vi.fn();
    const exit = await runSetupCli([], {
      plan,
      install,
      io: { stdinIsTTY: false, stdout: (text) => output.push(text), stderr: (text) => output.push(text), question: vi.fn() },
    });

    expect(exit).toBe(2);
    expect(install).not.toHaveBeenCalled();
    expect(output.join("\n")).toContain("needs explicit approval");
  });

  test("automatic setup reports a selected unsupported engine instead of claiming health", async () => {
    const blocked = status({}, "ready");
    blocked.state = "unsupported_platform";
    blocked.engines[0] = {
      engine: "opengrep",
      version: "1.33.1",
      state: "unsupported_platform",
      detail: "This asset requires glibc.",
    };
    const plan = await buildSetupPlan({ status: blocked, lockfile, preferencesPath, cosignAvailable: true });
    const output: string[] = [];
    const install = vi.fn();
    const exit = await runSetupCli([], {
      automatic: true,
      plan,
      install,
      io: { stdinIsTTY: true, stdout: (text) => output.push(text), stderr: (text) => output.push(text), question: vi.fn() },
    });

    expect(exit).toBe(2);
    expect(install).not.toHaveBeenCalled();
    expect(output.join("\n")).toContain("requires glibc");
    expect(output.join("\n")).toContain("not usable on this runtime");
    expect(output.join("\n")).not.toContain("healthy");
  });

  test("interactive component selection dispatches exactly the approved engines", async () => {
    const plan = await buildSetupPlan({
      status: status({ opengrep: "missing", gitleaks: "missing", trivy: "missing" }), lockfile, preferencesPath, cosignAvailable: false,
    });
    const answers = ["select", "opengrep,gitleaks"];
    const install = vi.fn(async () => ({ outcome: "installed" as const, message: "installed", plan }));
    const exit = await runSetupCli([], {
      plan,
      install,
      io: {
        stdinIsTTY: true,
        stdout: vi.fn(),
        stderr: vi.fn(),
        question: vi.fn(async () => answers.shift() ?? ""),
      },
    });

    expect(exit).toBe(0);
    expect(install).toHaveBeenCalledWith(["opengrep", "gitleaks"], true, expect.any(Object));
  });
});

describe("OSV database consent", () => {
  async function repoWith(...files: string[]): Promise<string> {
    const repo = join(root, "repo");
    for (const file of files) {
      await mkdir(join(repo, file, ".."), { recursive: true });
      await writeFile(join(repo, file), "");
    }
    return repo;
  }
  const readyEngines = () => status({}, "ready");

  test("v1 preferences without osv-scanner stay valid", async () => {
    await writeFile(preferencesPath, JSON.stringify({
      schema_version: 1,
      updated_at: "2026-07-01T00:00:00.000Z",
      choices: { opengrep: "enabled", gitleaks: "declined", trivy: "enabled" },
    }));

    const plan = await buildSetupPlan({ status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true });

    expect(plan.preference_state).toBe("configured");
    expect(plan.warnings).toEqual([]);
    expect(Object.fromEntries(plan.components.map((item) => [item.id, item.selected]))).toEqual({
      opengrep: true,
      gitleaks: false,
      trivy: true,
      "osv-scanner": true,
    });
  });

  test("a bad osv-scanner choice or a missing v1 component is still an invalid preference file", async () => {
    const plan = async (choices: Record<string, string>) => {
      await writeFile(preferencesPath, JSON.stringify({ schema_version: 1, updated_at: "2026-07-01T00:00:00.000Z", choices }));
      return await buildSetupPlan({ status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true });
    };
    const v1 = { opengrep: "enabled", gitleaks: "enabled", trivy: "enabled" };

    expect((await plan({ ...v1, "osv-scanner": "declined" })).preference_state).toBe("configured");
    expect((await plan({ ...v1, "osv-scanner": "maybe" })).preference_state).toBe("invalid");
    expect((await plan({ opengrep: "enabled", gitleaks: "enabled", "osv-scanner": "enabled" })).preference_state).toBe("invalid");
  });

  test("plan offers only detected ecosystems with estimates", async () => {
    const target = await repoWith("composer.lock");

    const plan = await buildSetupPlan({ status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true, target });

    expect(plan.osv_databases).toEqual([
      { ecosystem: "Packagist", state: "missing", selected: true, estimated_download_bytes: 11_063_339 },
    ]);
    expect(plan.estimated_osv_download_bytes).toBe(11_063_339);
    expect(plan.exact_download_bytes).toBe(0);
    expect(plan.network_required).toBe(true);
    expect(plan.confirmation_required).toBe(true);
    expect(plan.components.find((item) => item.id === "osv-scanner")).toMatchObject({
      action: "refresh_database",
      selected: true,
    });
  });

  test("a repository with workflows is offered the GitHub Actions database with its size, licence and reader", async () => {
    const target = await repoWith("composer.lock", ".github/workflows/ci.yml");
    const plan = await buildSetupPlan({ status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true, target });
    expect(plan.osv_databases).toEqual([
      { ecosystem: "Packagist", state: "missing", selected: true, estimated_download_bytes: 11_063_339 },
      {
        ecosystem: "GitHub Actions", state: "missing", selected: true, estimated_download_bytes: 100_334,
        note: expect.stringMatching(/^GitHub Advisory Database \(GHSA\) records, CC-BY-4\.0; read by the Synvoya Actions matcher .* never by osv-scanner$/),
      },
    ]);
    const rendered = formatSetupPlan(plan);
    expect(rendered).toContain("[selected] GitHub Actions: missing; ~98 KiB estimated download");
    expect(rendered).toMatch(/\n {4}GitHub Advisory Database \(GHSA\) records, CC-BY-4\.0; read by the Synvoya Actions matcher/);
    expect(setupPlanSchema.safeParse(plan).success).toBe(true);
  });

  test("no target and no explicit list offers no database", async () => {
    const plan = await buildSetupPlan({ status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true });
    expect(plan.osv_databases).toEqual([]);
    expect(plan.estimated_osv_download_bytes).toBe(0);
    expect(plan.network_required).toBe(false);
  });

  test("explicit ecosystems override detection and are listed in allow-list order", async () => {
    const target = await repoWith("composer.lock");
    const plan = await buildSetupPlan({
      status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true, target, osvEcosystems: ["PyPI", "npm"],
    });
    expect(plan.osv_databases.map((item) => [item.ecosystem, item.estimated_download_bytes])).toEqual([
      ["npm", 219_599_455],
      ["PyPI", 37_544_046],
    ]);
    expect(plan.estimated_osv_download_bytes).toBe(219_599_455 + 37_544_046);
  });

  test("installed databases need no download; stale and provenance-missing ones are offered for refresh", async () => {
    const target = await repoWith("composer.lock", "go.mod", "Cargo.lock", "requirements.txt");
    const plan = await buildSetupPlan({
      status: status({}, "ready", [
        { ecosystem: "PyPI", state: "ready", downloaded_at: "2026-10-29T00:00:00.000Z" },
        { ecosystem: "Packagist", state: "stale", downloaded_at: "2026-10-01T00:00:00.000Z" },
        { ecosystem: "Go", state: "provenance_missing" },
        { ecosystem: "npm", state: "ready" },
      ]),
      lockfile, preferencesPath, cosignAvailable: true, target,
    });

    expect(plan.osv_databases.map((item) => [item.ecosystem, item.state])).toEqual([
      ["PyPI", "installed"],
      ["Packagist", "stale"],
      ["Go", "stale"],
      ["crates.io", "missing"],
    ]);
    // Only what would actually be downloaded is counted.
    expect(plan.estimated_osv_download_bytes).toBe(11_063_339 + 12_675_916 + 3_737_559);
  });

  test("a stale installed database is offered for refresh even when the repository is not given", async () => {
    const stale = status({}, "ready", [
      { ecosystem: "PyPI", state: "stale", downloaded_at: "2026-10-01T00:00:00.000Z" },
      { ecosystem: "npm", state: "ready" },
    ]);

    const plan = await buildSetupPlan({ status: stale, lockfile, preferencesPath, cosignAvailable: true });
    expect(plan.osv_databases).toEqual([
      { ecosystem: "PyPI", state: "stale", selected: true, estimated_download_bytes: 37_544_046 },
    ]);
    expect(plan.network_required).toBe(true);

    // ...but an explicit approved list is taken literally and never widened.
    const explicit = await buildSetupPlan({
      status: stale, lockfile, preferencesPath, cosignAvailable: true, osvEcosystems: ["Go"],
    });
    expect(explicit.osv_databases.map((item) => item.ecosystem)).toEqual(["Go"]);
  });

  test("declining osv-scanner selects no database and needs no network", async () => {
    const target = await repoWith("composer.lock");
    const plan = await buildSetupPlan({
      status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true, target, selection: ["opengrep"],
    });
    expect(plan.osv_databases).toEqual([
      { ecosystem: "Packagist", state: "missing", selected: false, estimated_download_bytes: 11_063_339 },
    ]);
    expect(plan.estimated_osv_download_bytes).toBe(0);
    expect(plan.network_required).toBe(false);
  });

  test("a blocked osv-scanner selects no database and estimates no download", async () => {
    const target = await repoWith("composer.lock");
    const blocked = status({}, "ready");
    blocked.engines[3] = { engine: "osv-scanner", version: "2.7.0", state: "unsupported_platform" };
    const plan = await buildSetupPlan({ status: blocked, lockfile, preferencesPath, cosignAvailable: true, target });

    expect(plan.components.find((item) => item.id === "osv-scanner")?.action).toBe("blocked");
    expect(plan.osv_databases).toEqual([
      { ecosystem: "Packagist", state: "missing", selected: false, estimated_download_bytes: 11_063_339 },
    ]);
    expect(plan.estimated_osv_download_bytes).toBe(0);
    expect(formatSetupPlan(plan)).toContain("[blocked] Packagist: missing");
  });

  test("the formatted plan lists each ecosystem with its estimate and the integrity model", async () => {
    const target = await repoWith("composer.lock", "pubspec.lock", "yarn.lock");
    const plan = await buildSetupPlan({
      status: status({}, "ready", [{ ecosystem: "Pub", state: "ready" }]),
      lockfile, preferencesPath, cosignAvailable: true, target,
    });
    const rendered = formatSetupPlan(plan);

    expect(rendered).toContain("integrity: TLS + recorded SHA-256 (OSV publishes no signature)");
    expect(rendered).toMatch(/npm: missing; ~209\.4 MiB/);
    expect(rendered).toMatch(/Packagist: missing; ~10\.6 MiB/);
    expect(rendered).toMatch(/Pub: installed; no download needed/);
    // The binary is already healthy, so only the databases are downloaded; the line must not claim an engine download.
    expect(rendered).toMatch(/OSV-Scanner 2\.7\.0: refresh_database; [\d.]+ MiB upstream asset if a future repair is needed/);
    expect(rendered).toContain("osv-vulnerabilities.storage.googleapis.com");
    expect(rendered).toMatch(/Exact selected binary downloads: 0\.0 MiB/);
    expect(rendered).toMatch(/Estimated OSV database downloads: ~220\.0 MiB/);
  });

  test("the formatted plan explains how to choose databases when none are offered", async () => {
    const plan = await buildSetupPlan({ status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true });
    expect(formatSetupPlan(plan)).toContain("--path <repo>");
  });

  test("databases download only after confirmation, and only those the plan still needs", async () => {
    const target = await repoWith("composer.lock", "requirements.txt");
    const plan = await buildSetupPlan({
      status: status({}, "ready", [{ ecosystem: "PyPI", state: "ready" }]),
      lockfile, preferencesPath, cosignAvailable: true, target,
    });
    const repair = vi.fn(async () => undefined);
    const bootstrap = vi.fn(async () => undefined);

    await expect(installSetupComponents(["osv-scanner"], false, { plan, preferencesPath, repair, bootstrap })).rejects.toThrow(
      "Download confirmation is required",
    );
    expect(repair).not.toHaveBeenCalled();
    await expect(readFile(preferencesPath, "utf8")).rejects.toThrow();

    await installSetupComponents(["osv-scanner"], true, { plan, preferencesPath, repair, bootstrap });

    expect(repair).toHaveBeenCalledWith(["osv-scanner", "--osv-ecosystems", "Packagist"], expect.any(Object));
    expect(bootstrap).not.toHaveBeenCalled();
  });

  describe("the approved plan and the repair it triggers download the same databases", () => {
    const staleNpm = { ecosystem: "npm", state: "stale", downloaded_at: "2026-10-01T00:00:00.000Z" } as const;

    /** Run setup's install against a status, hand the args it gives repair to repair's own planner. */
    async function repairPlanFor(current: EngineSetupStatus, osvEcosystems: readonly ("Go" | "npm")[]) {
      const plan = await buildSetupPlan({ status: current, lockfile, preferencesPath, cosignAvailable: true, osvEcosystems: [...osvEcosystems] });
      const repair = vi.fn(async (_args: string[], _io?: unknown) => undefined);
      // The Cosign bootstrap is stubbed so this test can never reach the network.
      const bootstrap = vi.fn(async () => undefined);
      await installSetupComponents(["osv-scanner"], true, { plan, preferencesPath, repair, bootstrap, osvEcosystems: [...osvEcosystems] });
      const args = repair.mock.calls[0]![0];
      const parsed = parseRepairArgs(args);
      return { plan, args, repairPlan: planEngineRepair(current, parsed.selected, parsed.refreshDb, parsed.osvEcosystems) };
    }

    test("an explicit list with a stale database outside it downloads only the list", async () => {
      const { plan, args, repairPlan } = await repairPlanFor(status({}, "ready", [staleNpm]), ["Go"]);

      expect(plan.osv_databases.map((item) => item.ecosystem)).toEqual(["Go"]);
      expect(plan.estimated_osv_download_bytes).toBe(12_675_916);
      expect(args).toEqual(["osv-scanner", "--osv-ecosystems", "Go"]);
      expect(repairPlan.osv_ecosystems).toEqual(["Go"]);
    });

    test("an explicit list that is already installed still keeps repair from refreshing anything else", async () => {
      // The binary is missing so repair runs, but nothing in the approved list needs a download.
      const { plan, args, repairPlan } = await repairPlanFor(
        status({ "osv-scanner": "missing" }, "ready", [staleNpm, { ecosystem: "Go", state: "ready" }]),
        ["Go"],
      );

      expect(plan.estimated_osv_download_bytes).toBe(0);
      expect(args).toEqual(["osv-scanner", "--osv-ecosystems", "Go"]);
      expect(repairPlan.osv_ecosystems).toEqual([]);
      expect(repairPlan.engines).toEqual(["osv-scanner"]);
    });

    test("with no list, the plan shows exactly the stale databases a bare repair would refresh", async () => {
      const current = status({}, "ready", [staleNpm, { ecosystem: "Go", state: "ready" }]);
      const plan = await buildSetupPlan({ status: current, lockfile, preferencesPath, cosignAvailable: true });
      const repair = vi.fn(async (_args: string[], _io?: unknown) => undefined);
      await installSetupComponents(["osv-scanner"], true, { plan, preferencesPath, repair, bootstrap: vi.fn(async () => undefined) });
      const parsed = parseRepairArgs(repair.mock.calls[0]![0]);

      expect(plan.osv_databases.map((item) => [item.ecosystem, item.state])).toEqual([["npm", "stale"]]);
      expect(planEngineRepair(current, parsed.selected, parsed.refreshDb, parsed.osvEcosystems).osv_ecosystems).toEqual(["npm"]);
      expect(planEngineRepair(current).osv_ecosystems).toEqual(["npm"]);
    });

    test("an empty list is no list, in the plan as in repair", async () => {
      const current = status({}, "ready", [staleNpm]);
      const plan = await buildSetupPlan({ status: current, lockfile, preferencesPath, cosignAvailable: true, osvEcosystems: [] });
      expect(plan.osv_databases.map((item) => item.ecosystem)).toEqual(["npm"]);
    });
  });

  test("refuses a plan whose OSV database selection does not match the selected components", async () => {
    const staleNpm = status({}, "ready", [{ ecosystem: "npm", state: "stale", downloaded_at: "2026-10-01T00:00:00.000Z" }]);
    // Built without osv-scanner, so its stale npm database is listed but not selected.
    const plan = await buildSetupPlan({ status: staleNpm, lockfile, preferencesPath, cosignAvailable: true, selection: ["opengrep"] });
    expect(plan.osv_databases).toEqual([expect.objectContaining({ ecosystem: "npm", selected: false })]);
    const repair = vi.fn(async () => undefined);

    await expect(installSetupComponents(["osv-scanner"], true, { plan, preferencesPath, repair })).rejects.toThrow(/does not match/);
    expect(repair).not.toHaveBeenCalled();
  });

  test("OSV ecosystems without the osv-scanner component are rejected instead of silently ignored", async () => {
    const repair = vi.fn(async () => undefined);
    await expect(installSetupComponents(["gitleaks"], true, {
      preferencesPath, repair, osvEcosystems: ["PyPI"],
      plan: await buildSetupPlan({ status: status({ gitleaks: "missing" }, "ready"), lockfile, preferencesPath, cosignAvailable: true, selection: ["gitleaks"] }),
    })).rejects.toThrow(/osv-scanner/);
    expect(repair).not.toHaveBeenCalled();
  });

  test("the Cosign warning names the engines that actually need it, not a fixed pair", async () => {
    const testLock = structuredClone(lockfile);
    delete testLock.verifiers!.cosign.platforms["darwin-arm64"];
    const plan = await buildSetupPlan({
      status: status({ opengrep: "missing", gitleaks: "missing", "osv-scanner": "missing" }, "ready"),
      lockfile: testLock,
      preferencesPath,
      cosignAvailable: false,
    });

    const warning = plan.warnings.find((item) => item.includes("Cosign has no bootstrap pin"));
    expect(warning).toContain("darwin-arm64");
    expect(warning).toContain("Opengrep, OSV-Scanner installation is blocked");
    expect(warning).not.toContain("Trivy");
    expect(warning).not.toContain("Gitleaks");
  });

  test("any verification method other than plain checksums needs Cosign, in setup and in repair alike", async () => {
    const testLock = structuredClone(lockfile);
    testLock.engines.gitleaks.signature = "future-method" as never;
    expect(engineNeedsCosign(testLock, "gitleaks")).toBe(true);
    expect(engineNeedsCosign(lockfile, "gitleaks")).toBe(false);
    const plan = await buildSetupPlan({
      status: status({ gitleaks: "missing" }, "ready"), lockfile: testLock, preferencesPath, cosignAvailable: false,
    });
    expect(plan.verifier.required).toBe(true);
  });

  test("setup flags --path and --osv-ecosystems reach the installer", async () => {
    const plan = await buildSetupPlan({ status: readyEngines(), lockfile, preferencesPath, cosignAvailable: true });
    const install = vi.fn(async () => ({ outcome: "installed" as const, message: "ok", plan }));
    const out: string[] = [];
    const io = { stdinIsTTY: false, stdout: (text: string) => out.push(text), stderr: (text: string) => out.push(text), question: vi.fn() };

    expect(await runSetupCli(["--select", "osv-scanner", "--path", "repos/app", "--osv-ecosystems", "pypi,npm"], { plan, install, io })).toBe(0);
    expect(install).toHaveBeenCalledWith(
      ["osv-scanner"],
      true,
      expect.objectContaining({ target: resolve("repos/app"), osvEcosystems: ["npm", "PyPI"] }),
    );

    install.mockClear();
    expect(await runSetupCli(["--all", "--path", "repos/app"], { plan, install, io })).toBe(0);
    expect(install).toHaveBeenCalledWith(
      ["opengrep", "gitleaks", "trivy", "osv-scanner"],
      true,
      expect.objectContaining({ target: resolve("repos/app") }),
    );
  });

  test("setup rejects an unknown or incomplete OSV flag before doing anything", async () => {
    const install = vi.fn();
    const out: string[] = [];
    const io = { stdinIsTTY: true, stdout: (text: string) => out.push(text), stderr: (text: string) => out.push(text), question: vi.fn() };

    expect(await runSetupCli(["--all", "--osv-ecosystems", "npm,Debian"], { install, io })).toBe(2);
    expect(out.join("\n")).toContain("Debian");
    expect(await runSetupCli(["--all", "--path"], { install, io })).toBe(2);
    expect(await runSetupCli(["--all", "--osv-ecosystems"], { install, io })).toBe(2);
    // A following flag is never taken as the value.
    expect(await runSetupCli(["--path", "--all"], { install, io })).toBe(2);
    expect(out.join("\n")).toContain("incomplete setup option: --path");
    expect(await runSetupCli(["--select", "--osv-ecosystems", "npm"], { install, io })).toBe(2);
    expect(install).not.toHaveBeenCalled();
  });
});

