import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

const seen = vi.hoisted(() => ({ cwd: "", entries: [] as string[], source: "", sourceEntries: [] as string[], uri: "" }));

vi.mock("./resolve.js", () => ({
  EngineUnavailableError: class EngineUnavailableError extends Error {},
  resolveEngine: vi.fn(async () => ({ path: "/test/gitleaks", version: "8.30.1", sha256: "c".repeat(64) })),
}));

vi.mock("./exec.js", () => ({
  execBinary: vi.fn(async (_binary: string, args: string[], options: { cwd?: string }) => {
    seen.cwd = options.cwd ?? "";
    seen.entries = await readdir(seen.cwd);
    seen.source = args[1]!;
    seen.sourceEntries = await readdir(seen.source).catch(() => []);
    const results = seen.uri
      ? [{ ruleId: "generic-api-key", message: { text: "x" }, locations: [{ physicalLocation: { artifactLocation: { uri: `${seen.source}${seen.uri}` }, region: { startLine: 3 } } }] }]
      : [];
    await writeFile(args[args.indexOf("--report-path") + 1]!, JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "gitleaks", rules: [] } }, results }] }), "utf8");
    return { code: 0, stdout: "", stderr: "", timedOut: false };
  }),
}));

const { runGitleaks } = await import("./gitleaks.js");

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("Gitleaks working directory", () => {
  test("a single-file scan never runs beside the file's .gitleaksignore", async () => {
    // Real Gitleaks 8.30.1: run from the file's directory, an absolute entry in that directory's
    // .gitleaksignore hid the finding, and CodeInspectus only inspects the target's own ignore file.
    const directory = await mkdtemp(join(tmpdir(), "ci-gitleaks-single-"));
    const scratch = await mkdtemp(join(tmpdir(), "ci-gitleaks-scratch-"));
    roots.push(directory, scratch);
    const file = join(directory, "config.yml");
    await writeFile(file, "service:\n  name: demo\n", "utf8");
    await writeFile(join(directory, ".gitleaksignore"), `${file}:generic-api-key:2\n`, "utf8");

    const output = await runGitleaks(file, scratch);

    expect(output.ran).toBe(true);
    expect(seen.cwd).toBe(join(scratch, "gitleaks-cwd"));
    expect(seen.entries).toEqual([]);
  });

  // Review I-7: Gitleaks applies its default allowlist to absolute paths, so a target under
  // node_modules/ is scanned through a managed link (trailing separator) and paths map back.
  test("a target whose own folders Gitleaks allowlists is scanned through a managed link", async () => {
    const parent = await mkdtemp(join(tmpdir(), "ci-gitleaks-allowlisted-"));
    const scratch = await mkdtemp(join(tmpdir(), "ci-gitleaks-scratch-"));
    roots.push(parent, scratch);
    const target = join(parent, "node_modules", "pkg");
    await mkdir(target, { recursive: true });
    await writeFile(join(target, "config.yml"), "x\n", "utf8");
    seen.uri = "config.yml";

    const output = await runGitleaks(target, scratch);
    seen.uri = "";

    expect(seen.source).toBe(`${join(scratch, "gitleaks-source", "target")}${sep}`);
    expect(seen.sourceEntries).toEqual(["config.yml"]);
    expect(output.sarif?.runs?.[0]?.results?.[0]?.locations?.[0]?.physicalLocation?.artifactLocation?.uri).toBe(join(target, "config.yml"));
    expect(output.coverageWarnings).toBeUndefined();
    expect(output.componentSignatures?.["gitleaks:invocation"]).toMatch(/^sha256:/);
  });

  test("an ordinary target is scanned at its real path", async () => {
    const target = await mkdtemp(join(tmpdir(), "ci-gitleaks-plain-"));
    const scratch = await mkdtemp(join(tmpdir(), "ci-gitleaks-scratch-"));
    roots.push(target, scratch);
    await runGitleaks(target, scratch);
    expect(seen.source).toBe(target);
  });

  test("a single file under node_modules cannot be linked and reads unverified", async () => {
    const parent = await mkdtemp(join(tmpdir(), "ci-gitleaks-allowlisted-file-"));
    const scratch = await mkdtemp(join(tmpdir(), "ci-gitleaks-scratch-"));
    roots.push(parent, scratch);
    await mkdir(join(parent, "node_modules", "pkg"), { recursive: true });
    const file = join(parent, "node_modules", "pkg", "config.yml");
    await writeFile(file, "x\n", "utf8");

    const output = await runGitleaks(file, scratch);

    expect(seen.source).toBe(file);
    expect(output.coverageWarnings).toEqual([expect.stringMatching(/^Secret coverage unverified: Gitleaks' default allowlist/)]);
  });

  // Final review Minor 5: the junction route is unverified on Windows, so it reads unverified there.
  test("on Windows an allowlisted directory target is not linked and reads unverified", async () => {
    const parent = await mkdtemp(join(tmpdir(), "ci-gitleaks-allowlisted-win-"));
    const scratch = await mkdtemp(join(tmpdir(), "ci-gitleaks-scratch-"));
    roots.push(parent, scratch);
    const target = join(parent, "node_modules", "pkg");
    await mkdir(target, { recursive: true });
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", { ...platform, value: "win32" });
    try {
      const output = await runGitleaks(target, scratch);
      expect(seen.source).toBe(target);
      expect(output.coverageWarnings).toEqual([expect.stringMatching(/^Secret coverage unverified: Gitleaks' default allowlist/)]);
    } finally {
      Object.defineProperty(process, "platform", platform);
    }
  });
});
