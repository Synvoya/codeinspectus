import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

const seen = vi.hoisted(() => ({
  runs: [] as Array<{ cwd: string; entries: string[]; args: string[] }>,
  cache: `${(process.env.TMPDIR ?? process.env.TEMP ?? "/tmp").replace(/[\\/]+$/, "")}/ci-trivy-cwd-cache-${process.pid}`,
}));

vi.mock("../config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../config.js")>();
  return { ...actual, MANAGED_TRIVY_CACHE: seen.cache, MANAGED_TRIVY_DB_META: `${seen.cache}/db/metadata.json` };
});

vi.mock("./resolve.js", () => ({
  EngineUnavailableError: class EngineUnavailableError extends Error {},
  resolveEngine: vi.fn(async () => ({ path: "/test/trivy", version: "0.76.1", sha256: "b".repeat(64) })),
}));

vi.mock("./exec.js", () => ({
  execBinary: vi.fn(async (_binary: string, args: string[], options: { cwd?: string }) => {
    seen.runs.push({ cwd: options.cwd ?? "", entries: await readdir(options.cwd ?? "."), args });
    const output = args[args.indexOf("--output") + 1]!;
    await writeFile(output, JSON.stringify({ version: "2.1.0", runs: [] }), "utf8");
    return { code: 0, stdout: "", stderr: "", timedOut: false };
  }),
}));

const { runTrivy, runTrivySbom } = await import("./trivy.js");

const roots: string[] = [];
afterEach(async () => {
  seen.runs.length = 0;
  await Promise.all([...roots.splice(0), seen.cache].map((root) => rm(root, { recursive: true, force: true })));
});

async function repositoryWithTrivyConfig(): Promise<string> {
  // Each file changed results on the real Trivy 0.76.1 binary when Trivy ran inside the target.
  const target = await mkdtemp(join(tmpdir(), "ci-trivy-target-"));
  roots.push(target);
  await writeFile(join(target, "trivy.yaml"), "severity:\n  - CRITICAL\n", "utf8");
  await writeFile(join(target, ".trivyignore"), "CVE-2026-101898\n", "utf8");
  await writeFile(join(target, "trivy-secret.yaml"), "disable-rules:\n  - stripe-secret-token\n", "utf8");
  return target;
}

describe("Trivy never reads a scanned repository's configuration", () => {
  test("scans run from an empty managed directory with every repository config file disabled", async () => {
    const target = await repositoryWithTrivyConfig();
    const signatures: string[] = [];
    for (const label of ["first", "second"]) {
      const scratch = await mkdtemp(join(tmpdir(), `ci-trivy-scratch-${label}-`));
      roots.push(scratch);
      const output = await runTrivy(target, scratch, ["vuln", "secret"]);
      expect(output.ran).toBe(true);
      signatures.push(output.componentSignatures?.["trivy:invocation"] ?? "");
    }

    for (const run of seen.runs) {
      expect(run.cwd).not.toBe(target);
      expect(run.entries).toEqual([]);
      // An empty value disables loading; an explicit flag also beats TRIVY_CONFIG (verified on 0.76.1).
      // `trivy convert` has no --secret-config; it reads only a config file and an ignore file.
      const flags = run.args[0] === "convert" ? ["--config", "--ignorefile"] : ["--config", "--secret-config", "--ignorefile"];
      for (const flag of flags) expect(run.args[run.args.indexOf(flag) + 1]).toBe("");
    }
    // Pre-release field validation: dev dependencies are analysed, via a JSON report converted to SARIF.
    expect(seen.runs.map((run) => run.args[0])).toEqual(["fs", "convert", "fs", "convert"]);
    expect(seen.runs[0]!.args).toEqual(expect.arrayContaining(["--include-dev-deps", "--list-all-pkgs", "json"]));
    // Managed temporary paths never enter provenance, so rescans stay comparable.
    expect(signatures[0]).toBe(signatures[1]);
  });

  test("SBOM generation runs from an empty managed directory too", async () => {
    const target = await repositoryWithTrivyConfig();
    const result = await runTrivySbom(target, "cyclonedx", join(target, "sbom.json"));
    expect(result.ran).toBe(true);
    expect(seen.runs[0]?.cwd).not.toBe(target);
    expect(seen.runs[0]?.entries).toEqual([]);
    expect(seen.runs[0]?.args[seen.runs[0]!.args.indexOf("--config") + 1]).toBe("");
  });
});
