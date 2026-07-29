import { describe, expect, test, vi } from "vitest";
import { runBundleCli, type BundleCliDependencies } from "./cli.js";
import type { StoredScanResult } from "../store.js";

const scanId = "scan-00000000-0000-4000-8000-000000000001";
const scan = { scan_id: scanId } as StoredScanResult;
const manifest = { bundle_id: "bundle-00000000-0000-4000-8000-000000000001", scan_id: scanId, artifacts: [{}, {}, {}, {}, {}, {}] };

function capture() {
  const stdout: string[] = []; const stderr: string[] = [];
  return { stdout, stderr, io: { stdout: (text: string) => stdout.push(text), stderr: (text: string) => stderr.push(text) } };
}

function dependencies(overrides: Partial<BundleCliDependencies> = {}): BundleCliDependencies {
  return {
    loadScan: vi.fn(async () => scan),
    create: vi.fn(async () => manifest as never),
    verify: vi.fn(async () => ({ manifest, scan, contents: { "artifacts/export.json": Buffer.from("{}\n"), "results.sarif": Buffer.from("{}\n") } }) as never),
    ...overrides,
  };
}

describe("bundle CLI", () => {
  test("create validates the scan ID and delegates one atomic output directory", async () => {
    const output = capture(); const deps = dependencies();
    expect(await runBundleCli(["create", scanId, "--output-dir", "/outside/evidence"], output.io, deps)).toBe(0);
    expect(deps.create).toHaveBeenCalledWith(scan, "/outside/evidence");
    expect(output.stderr).toEqual([]);
  });

  test("verify, export, and compare always call verification first", async () => {
    for (const argv of [["verify", "/bundle"], ["export", "/bundle", "--format", "json"], ["compare", "/old", "/new", "--format", "json"]]) {
      const output = capture(); const verify = vi.fn(async () => ({ manifest, scan, contents: { "artifacts/export.json": Buffer.from("{}\n"), "results.sarif": Buffer.from("{}\n") } }) as never); const deps = dependencies({ verify });
      await runBundleCli(argv, output.io, deps);
      expect(verify).toHaveBeenCalled();
    }
  });

  test("tamper failure exits 2 before export output", async () => {
    const output = capture(); const deps = dependencies({ verify: vi.fn(async () => { throw new Error("artifact integrity check failed"); }) });
    expect(await runBundleCli(["export", "/bundle", "--format", "json"], output.io, deps)).toBe(2);
    expect(output.stdout).toEqual([]);
    expect(output.stderr.join(" ")).toMatch(/integrity check failed/i);
  });

  test.each([
    [[], /usage/i],
    [["create", "../../bad", "--output-dir", "/x"], /scan_id/i],
    [["create", scanId], /output-dir/i],
    [["export", "/bundle"], /requires --format/i],
    [["verify", "/bundle", "--format", "sarif"], /must be text or json/i],
  ])("rejects malformed bundle command %#", async (argv, expected) => {
    const output = capture();
    expect(await runBundleCli(argv as string[], output.io, dependencies())).toBe(2);
    expect(`${output.stdout.join(" ")} ${output.stderr.join(" ")}`).toMatch(expected as RegExp);
  });
});
