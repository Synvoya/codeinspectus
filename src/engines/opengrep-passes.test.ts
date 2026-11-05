import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { OPENGREP_RULES_DIR } from "../config.js";

interface Call { args: string[]; ignoreList: string; logFile: string }
const seen = vi.hoisted(() => ({
  calls: [] as Call[],
  failPack: false,
  packReport: undefined as unknown,
  /** Target-relative files the fake pack pass also skips, beyond the anchored lines of its ignore list. */
  extraPackSkips: [] as string[],
}));

vi.mock("./resolve.js", () => ({
  EngineUnavailableError: class EngineUnavailableError extends Error {},
  resolveEngine: vi.fn(async () => ({ path: "/test/opengrep", version: "1.33.1", sha256: "a".repeat(64) })),
}));

vi.mock("./exec.js", () => ({
  execBinary: vi.fn(async (_binary: string, args: string[], options: { env?: Record<string, string> }) => {
    const ignoreList = await readFile(options.env!.SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE!, "utf8");
    seen.calls.push({ args, ignoreList, logFile: options.env!.SEMGREP_LOG_FILE! });
    const pack = args.some((arg) => arg.includes("synvoya-"));
    if (pack && seen.failPack) return { code: 2, stdout: "", stderr: "Fatal error: out of memory", timedOut: false };
    const sarif = args.find((arg) => arg.startsWith("--sarif-output="))!.slice("--sarif-output=".length);
    const report = args.find((arg) => arg.startsWith("--output="))!.slice("--output=".length);
    await writeFile(sarif, JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: pack ? "pack" : "baseline", rules: [] } }, results: [] }] }), "utf8");
    // Like Opengrep: each anchored pack ignore line is reported as a semgrepignore skip of that file.
    const target = args.at(-1)!;
    const anchored = pack ? ignoreList.split("\n").filter((line) => line.startsWith("/")).map((line) => line.slice(1)) : [];
    const skipped = [...anchored, ...(pack ? seen.extraPackSkips : [])]
      .map((rel) => ({ path: `${target}/${rel}`, reason: "semgrepignore_patterns_match" }));
    await writeFile(report, JSON.stringify(pack && seen.packReport !== undefined
      ? seen.packReport
      : { errors: [], paths: { scanned: [], skipped }, results: [] }), "utf8");
    return { code: 0, stdout: "", stderr: "", timedOut: false };
  }),
}));

const { runOpengrep } = await import("./opengrep.js");

const roots: string[] = [];
beforeEach(() => {
  seen.calls = [];
  seen.failPack = false;
  seen.packReport = undefined;
  seen.extraPackSkips = [];
});
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const minified = "!" + "function(e,t){return e&&t?e.call(t,n[r]):void 0},".repeat(600);

async function fixture(files: Record<string, string>): Promise<{ target: string; scratch: string }> {
  const target = await mkdtemp(join(tmpdir(), "ci-opengrep-passes-"));
  const scratch = await mkdtemp(join(tmpdir(), "ci-opengrep-passes-tmp-"));
  roots.push(target, scratch);
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(target, path, ".."), { recursive: true });
    await writeFile(join(target, path), content, "utf8");
  }
  return { target, scratch };
}

function configs(args: string[]): string[] {
  return args.flatMap((arg, index) => args[index - 1] === "-f" ? [arg] : []);
}

describe("Opengrep baseline and Synvoya pack passes", () => {
  test("the baseline pass keeps every file and its settings; the pack pass skips bundles with an explicit timeout", async () => {
    const { target, scratch } = await fixture({
      "assets/js/ckeditor/ckeditor.js": minified,
      "src/app.js": "const a = require('x');\nmodule.exports = a;\n",
    });

    const output = await runOpengrep(target, scratch);

    expect(output.ran).toBe(true);
    expect(seen.calls).toHaveLength(2);
    const [baseline, pack] = seen.calls as [Call, Call];
    // M4 perf fix: the baseline pass loads every baseline rule file except the taint-mode one.
    expect(configs(baseline.args)).toContain(join(OPENGREP_RULES_DIR, "security-baseline", "xss.yaml"));
    expect(configs(baseline.args)).not.toContain(join(OPENGREP_RULES_DIR, "security-baseline", "injection-taint.yaml"));
    expect(baseline.args).not.toContain("--timeout");
    expect(baseline.ignoreList).not.toContain("ckeditor");
    expect(configs(pack.args)).toEqual([
      join(OPENGREP_RULES_DIR, "security-baseline", "injection-taint.yaml"),
      join(OPENGREP_RULES_DIR, "synvoya-node"),
      join(OPENGREP_RULES_DIR, "synvoya-php"),
    ]);
    expect(pack.args.slice(pack.args.indexOf("--timeout"), pack.args.indexOf("--timeout") + 2)).toEqual(["--timeout", "30"]);
    expect(pack.ignoreList.startsWith(baseline.ignoreList)).toBe(true);
    expect(pack.ignoreList.split("\n")).toContain("/assets/js/ckeditor/ckeditor.js");
    expect(pack.ignoreList).not.toContain("src/app.js");
    expect(pack.logFile).not.toBe(baseline.logFile);
    // Same target argument and working directory: findings map to identical paths and lines.
    expect(pack.args.at(-1)).toBe(target);
    expect(baseline.args.at(-1)).toBe(target);

    expect(output.sarif?.runs?.map((run) => run.tool?.driver?.name)).toEqual(["baseline", "pack"]);
    expect(output.coverageGaps).toEqual([{ id: "third-party-bundles", files: 1, examples: ["assets/js/ckeditor/ckeditor.js"] }]);
    expect(output.coverageWarnings).toBeUndefined();
    expect(output.componentSignatures?.["opengrep:invocation"]).toMatch(/^sha256:/);
    expect(output.componentSignatures?.["opengrep:pack-invocation"]).toMatch(/^sha256:/);
    expect(output.componentSignatures?.["opengrep:pack-invocation"]).not.toBe(output.componentSignatures?.["opengrep:invocation"]);
  });

  test("no bundle means no gap, and the pack invocation records which files it skipped", async () => {
    const clean = await fixture({ "src/app.js": "module.exports = 1;\n" });
    const cleanOutput = await runOpengrep(clean.target, clean.scratch);
    expect(cleanOutput.coverageGaps).toBeUndefined();

    const bundled = await fixture({ "src/app.js": "module.exports = 1;\n", "public/lib.js": minified });
    const bundledOutput = await runOpengrep(bundled.target, bundled.scratch);
    // The baseline invocation does not depend on the target's files; the pack invocation does.
    expect(bundledOutput.componentSignatures?.["opengrep:invocation"]).toBe(cleanOutput.componentSignatures?.["opengrep:invocation"]);
    expect(bundledOutput.componentSignatures?.["opengrep:pack-invocation"]).not.toBe(cleanOutput.componentSignatures?.["opengrep:pack-invocation"]);
  });

  test("a failed pack pass keeps the baseline run, warns, and records no pack invocation", async () => {
    const { target, scratch } = await fixture({ "src/app.js": "module.exports = 1;\n" });
    seen.failPack = true;

    const output = await runOpengrep(target, scratch);

    expect(output.ran).toBe(true);
    expect(output.sarif?.runs?.map((run) => run.tool?.driver?.name)).toEqual(["baseline"]);
    expect(output.componentSignatures?.["opengrep:invocation"]).toMatch(/^sha256:/);
    expect(output.componentSignatures).not.toHaveProperty("opengrep:pack-invocation");
    expect(output.coverageWarnings).toEqual([
      expect.stringMatching(/^Opengrep SAST coverage partial: the bundle-skipping pass \(syn-php-\*, syn-node-\*, ci-baseline-sql-injection-string-build\) produced no SARIF \(exit 2\)\. stderr: Fatal error: out of memory$/),
    ]);
  });

  test("a pack timeout on a first-party file is still a non-acceptable coverage warning", async () => {
    const { target, scratch } = await fixture({ "src/Chart.tsx": "export const x = 1;\n" });
    const file = join(target, "src/Chart.tsx");
    seen.packReport = {
      errors: [{ type: "Timeout", level: "warn", code: 3, path: file, rule_id: "x.syn-node-zip-slip", message: "Timeout" }],
      paths: { scanned: [file], skipped: [{ path: file, reason: "analysis_failed_parser_or_internal_error" }] },
      results: [],
    };

    const output = await runOpengrep(target, scratch);

    expect(output.coverageWarnings).toEqual([
      "Opengrep SAST coverage partial: 1 with a timeout, memory limit or engine error: src/Chart.tsx.",
    ]);
    expect(output.coverageGaps).toBeUndefined();
  });

  // Review item 2 (fail closed): the pack pass must skip exactly the files routing chose.
  test("a pack-pass skip routing did not choose is a warning, and the pack invocation is not recorded", async () => {
    const { target, scratch } = await fixture({ "src/c.js": minified, "src/cX.js": "module.exports = 1;\n" });
    seen.extraPackSkips = ["src/cX.js"];

    const output = await runOpengrep(target, scratch);

    expect(output.ran).toBe(true);
    expect(output.componentSignatures).not.toHaveProperty("opengrep:pack-invocation");
    expect(output.coverageWarnings).toEqual([
      "Opengrep SAST coverage partial: the bundle-skipping pass (syn-php-*, syn-node-*, ci-baseline-sql-injection-string-build) also skipped 1 file(s) bundle routing did not choose, so findings of that pass are unknown there: src/cX.js.",
    ]);
    expect(output.coverageGaps).toEqual([{ id: "third-party-bundles", files: 1, examples: ["src/c.js"] }]);
  });

  // Field (nostroots): the pack's generic rules make Opengrep list skips the baseline pass never reports.
  test("pack-pass skips the managed ignore list explains are expected", async () => {
    const { target, scratch } = await fixture({ "src/c.js": minified });
    seen.extraPackSkips = ["relay/internal/auth/auth_test.go", "node_modules", "web/vendor", "lib/x.min.js", "build/out/a.js"];

    const output = await runOpengrep(target, scratch);

    expect(output.coverageWarnings).toBeUndefined();
    expect(output.componentSignatures?.["opengrep:pack-invocation"]).toMatch(/^sha256:/);
    expect(output.coverageGaps).toEqual([{ id: "third-party-bundles", files: 1, examples: ["src/c.js"] }]);
  });

  test("a chosen bundle the pack pass still scanned is not reported as skipped", async () => {
    const { target, scratch } = await fixture({ "src/c.js": minified });
    seen.packReport = { errors: [], paths: { scanned: [join(target, "src/c.js")], skipped: [] }, results: [] };

    const output = await runOpengrep(target, scratch);

    expect(output.coverageGaps).toBeUndefined();
    expect(output.componentSignatures?.["opengrep:pack-invocation"]).toMatch(/^sha256:/);
  });
});
