import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

vi.mock("./engine-health.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./engine-health.js")>();
  return { ...original, inspectEngineSetup: vi.fn() };
});

import { inspectEngineSetup } from "./engine-health.js";
import { runPreflight } from "./preflight.js";

const cleanup: string[] = [];

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-preflight-"));
  cleanup.push(root);
  return root;
}

beforeEach(() => {
  vi.mocked(inspectEngineSetup).mockResolvedValue({
    state: "ready",
    platform: "test-x64",
    engines: [
      { engine: "opengrep", version: "1", state: "ready" },
      { engine: "gitleaks", version: "1", state: "ready" },
      { engine: "trivy", version: "1", state: "ready" },
    ],
    trivy_db: { state: "ready", downloaded_at: "2026-07-29T00:00:00.000Z" },
    network_required: false,
  });
});

afterEach(async () => {
  vi.clearAllMocks();
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("offline preflight", () => {
  test("reports canonical target, planned config, applicability, integrity and limits without writing", async () => {
    const root = await temporaryRoot();
    const app = join(root, "app.ts");
    await writeFile(app, "export const safe = true;\n");

    const result = await runPreflight(root, {
      scanners: ["sast", "ai"],
      severity_threshold: "high",
      max_findings: 17,
      output_format: "json",
      include_compliance: false,
    });

    expect(result).toMatchObject({
      ready: true,
      offline: true,
      writes_repository: false,
      target: { canonical_path: root, type: "directory", symlink_safe: true },
      output: { mode: "stdout", safe: true },
      configuration: {
        scanners: ["sast", "ai"],
        severity_threshold: "high",
        max_findings: 17,
        output_format: "json",
        include_compliance: false,
      },
      repair: { required_for_selected_scope: false, network_required: false },
    });
    expect(result.engine_integrity.filter((engine) => engine.selected)).toHaveLength(1);
    expect(result.engine_integrity.find((engine) => engine.engine === "opengrep")).toMatchObject({
      selected: true,
      hash_provenance: "verified",
    });
    expect(result.native_pack_applicability.some((pack) => pack.selected)).toBe(true);
    expect(await realpath(app)).toBe(app);
  });

  test("missing target returns an honest not-ready report", async () => {
    const root = await temporaryRoot();
    const result = await runPreflight(join(root, "missing"));
    expect(result.ready).toBe(false);
    expect(result.target.exists).toBe(false);
    expect(result.errors.join(" ")).toMatch(/not found/i);
  });

  test("plans a new external output directory without creating it", async () => {
    const target = await temporaryRoot();
    const output = join(await temporaryRoot(), "planned-output");
    await writeFile(join(target, "app.ts"), "export {};\n");

    const result = await runPreflight(target, { output_directory: output, output_format: "json" });
    expect(result.output).toMatchObject({
      mode: "directory",
      resolved_path: output,
      exists: false,
      safe: true,
    });
    await expect(realpath(output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("treats one explicitly named in-repository output artifact as approved without writing it", async () => {
    const target = await temporaryRoot();
    const output = join(target, "results.sarif");
    await writeFile(join(target, "app.ts"), "export {};\n");

    const result = await runPreflight(target, { output_file: output, output_format: "sarif" });
    expect(result.output).toMatchObject({
      mode: "file",
      resolved_path: output,
      exists: false,
      inside_target: true,
      approved_inside_target: true,
      safe: true,
    });
    await expect(realpath(output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("selected missing engine makes preflight not ready and reports repair network need", async () => {
    vi.mocked(inspectEngineSetup).mockResolvedValue({
      state: "repair_required",
      platform: "test-x64",
      engines: [
        { engine: "opengrep", version: "1", state: "missing" },
        { engine: "gitleaks", version: "1", state: "ready" },
        { engine: "trivy", version: "1", state: "ready" },
      ],
      trivy_db: { state: "ready" },
      repair_command: "npx codeinspectus repair-engines",
      network_required: true,
    });
    const root = await temporaryRoot();
    await writeFile(join(root, "app.ts"), "export {};\n");

    const result = await runPreflight(root, { scanners: ["sast"] });
    expect(result).toMatchObject({
      ready: false,
      repair: { required_for_selected_scope: true, network_required: true },
    });
    expect(result.engine_integrity[0]).toMatchObject({ state: "missing", hash_provenance: "unverified" });
  });
});
