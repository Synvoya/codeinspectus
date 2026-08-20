import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { loadLockfile, type Lockfile } from "./engines/lockfile.js";
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

let root: string;
let preferencesPath: string;
let lockfile: Lockfile;

function status(states: Partial<Record<"opengrep" | "gitleaks" | "trivy", "ready" | "missing" | "hash_mismatch">> = {}, db: EngineSetupStatus["trivy_db"]["state"] = "missing"): EngineSetupStatus {
  const engines = (["opengrep", "gitleaks", "trivy"] as const).map((engine) => ({
    engine,
    version: lockfile.engines[engine].version,
    state: states[engine] ?? "ready",
  }));
  return {
    state: engines.some((engine) => engine.state !== "ready") || db === "missing" ? "repair_required" : db === "ready" ? "ready" : "db_refresh_recommended",
    platform: "darwin-arm64",
    engines,
    trivy_db: { state: db },
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
  });
  test("reports native coverage, exact platform downloads, DB estimate, licenses, and verifier dependency", async () => {
    const plan = await buildSetupPlan({
      status: status({ opengrep: "missing", gitleaks: "missing", trivy: "missing" }),
      lockfile,
      preferencesPath,
      cosignAvailable: false,
    });

    expect(plan.native.rule_count).toBe(72);
    expect(plan.native.download_required).toBe(false);
    expect(plan.components.map((item) => [item.id, item.action, item.download_size_bytes])).toEqual([
      ["opengrep", "download", 43_236_128],
      ["gitleaks", "download", 7_897_593],
      ["trivy", "download", 47_498_236],
    ]);
    expect(plan.verifier).toMatchObject({ required: true, available: false, download_size_bytes: 139_584_002 });
    expect(plan.exact_download_bytes).toBe(238_215_959);
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
    expect(saved.choices).toEqual({ opengrep: "declined", gitleaks: "enabled", trivy: "declined" });
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
      version: "1.23.0",
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
