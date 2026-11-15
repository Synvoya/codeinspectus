import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { OPENGREP_RULES_DIR } from "../config.js";
import { log } from "../logger.js";

interface Call { args: string[]; ignoreList: string; logFile: string }
const seen = vi.hoisted(() => ({
  calls: [] as Call[],
  failPack: false,
  packReport: undefined as unknown,
  /** Target-relative files the fake pack pass also skips, beyond the anchored lines of its ignore list. */
  extraPackSkips: [] as string[],
}));

const signatures = vi.hoisted(() => ({ elements: [] as string[][] }));
vi.mock("../provenance.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../provenance.js")>();
  return {
    ...original,
    invocationSignature: (engine: string, elements: string[]) => {
      signatures.elements.push(elements);
      return original.invocationSignature(engine as Parameters<typeof original.invocationSignature>[0], elements);
    },
  };
});

const dataset = vi.hoisted(() => ({ unavailable: false }));
vi.mock("../synvoya/dataset.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../synvoya/dataset.js")>();
  return {
    ...original,
    loadSynvoyaDataset: async (...args: Parameters<typeof original.loadSynvoyaDataset>) =>
      dataset.unavailable ? { ok: false as const, reason: "manifest.json is missing or unreadable." } : original.loadSynvoyaDataset(...args),
  };
});

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
  signatures.elements = [];
  dataset.unavailable = false;
});
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const minified = "!" + "function(e,t){return e&&t?e.call(t,n[r]):void 0},".repeat(600);
/** A minified Knockout copy: its name and banner name the same Synvoya library-table entry (4.1 M6). */
const knockout = `/*!\n * Knockout JavaScript library v3.5.1\n * License: MIT\n */\n${minified}\n`;
const LIBRARY_NOTE = "Bundle routing identified 1 third-party library by name and version; the bundle-skipping Opengrep pass " +
  "(syn-php-*, syn-node-*, ci-baseline-sql-injection-string-build) skipped their 1 file(s), part of third-party-bundles " +
  "(the other baseline rules still scanned them): knockout 3.5.1 (public/js/knockout.js).";

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

  // M6 fix round 1: the files each pass could not fully analyze are recorded for rescan proof.
  test("records, per pass, the files Opengrep could not fully analyze", async () => {
    const { target, scratch } = await fixture({ "src/Chart.tsx": "export const x = 1;\n", "src/ok.ts": "export const y = 1;\n" });
    const file = join(target, "src/Chart.tsx");
    seen.packReport = {
      errors: [{ type: "Timeout", level: "warn", code: 3, path: file, rule_id: "x.syn-node-zip-slip", message: "Timeout" }],
      paths: { scanned: [file], skipped: [{ path: file, reason: "analysis_failed_parser_or_internal_error" }] },
      results: [],
    };

    const output = await runOpengrep(target, scratch);
    expect(output.uncheckedFiles).toEqual({ "opengrep:baseline": { files: [], rules: [] }, "opengrep:pack": { files: ["src/Chart.tsx"], rules: [] } });

    seen.packReport = { errors: "malformed" };
    expect((await runOpengrep(target, (await fixture({})).scratch)).uncheckedFiles?.["opengrep:pack"]).toBe("all");
    seen.packReport = undefined;
    seen.failPack = true;
    expect((await runOpengrep(target, (await fixture({})).scratch)).uncheckedFiles?.["opengrep:pack"]).toBe("all");
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

  describe("identified third-party libraries (4.1 M6)", () => {
    test("a library file the pack pass skipped is in the gap, after the 4.0 files, and named in a coverage note", async () => {
      const { target, scratch } = await fixture({ "public/js/knockout.js": knockout, "src/c.js": minified, "src/app.js": "module.exports = 1;\n" });

      const output = await runOpengrep(target, scratch);

      const pack = seen.calls[1]!;
      expect(pack.ignoreList.split("\n")).toEqual(expect.arrayContaining(["/public/js/knockout.js", "/src/c.js"]));
      expect(seen.calls[0]!.ignoreList).not.toContain("knockout");
      expect(output.coverageGaps).toEqual([{ id: "third-party-bundles", files: 2, examples: ["src/c.js", "public/js/knockout.js (identified by name and banner)"] }]);
      expect(output.coverageNotes).toEqual([LIBRARY_NOTE]);
      expect(output.coverageWarnings).toBeUndefined();
      expect(output.componentSignatures?.["opengrep:pack-invocation"]).toMatch(/^sha256:/);
    });

    test("a chosen library file the pack pass did not skip is in neither the gap nor the note", async () => {
      const { target, scratch } = await fixture({ "public/js/knockout.js": knockout });
      seen.packReport = { errors: [], paths: { scanned: [join(target, "public/js/knockout.js")], skipped: [] }, results: [] };

      const output = await runOpengrep(target, scratch);

      expect(output.coverageGaps).toBeUndefined();
      expect(output.coverageNotes).toBeUndefined();
    });

    test("a skip routing did not choose still warns and withholds the pack signature, next to a library", async () => {
      const { target, scratch } = await fixture({ "public/js/knockout.js": knockout, "src/cX.js": "module.exports = 1;\n" });
      seen.extraPackSkips = ["src/cX.js"];

      const output = await runOpengrep(target, scratch);

      expect(output.componentSignatures).not.toHaveProperty("opengrep:pack-invocation");
      expect(output.coverageWarnings).toEqual([
        "Opengrep SAST coverage partial: the bundle-skipping pass (syn-php-*, syn-node-*, ci-baseline-sql-injection-string-build) also skipped 1 file(s) bundle routing did not choose, so findings of that pass are unknown there: src/cX.js.",
      ]);
      expect(output.coverageGaps).toEqual([{ id: "third-party-bundles", files: 1, examples: ["public/js/knockout.js (identified by name and banner)"] }]);
    });

    test("a failed pack pass reports neither the gap nor the note", async () => {
      const { target, scratch } = await fixture({ "public/js/knockout.js": knockout });
      seen.failPack = true;

      const output = await runOpengrep(target, scratch);

      expect(output.coverageGaps).toBeUndefined();
      expect(output.coverageNotes).toBeUndefined();
    });

    test("without the Synvoya library table the JS library rule is off, with one warning", async () => {
      const { target, scratch } = await fixture({ "public/js/knockout.js": knockout, "src/c.js": minified });
      dataset.unavailable = true;
      const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);

      const output = await runOpengrep(target, scratch);

      // The minified copy is then a 4.0 "minified" file: skipped, unlabelled, named in no note.
      expect(output.coverageGaps).toEqual([{ id: "third-party-bundles", files: 2, examples: ["public/js/knockout.js", "src/c.js"] }]);
      expect(output.coverageNotes).toBeUndefined();
      expect(output.coverageWarnings).toBeUndefined();
      expect(warn.mock.calls.filter(([message]) => String(message).includes("library table did not load"))).toHaveLength(1);
      warn.mockRestore();
    });

    test("the pack invocation signature carries the new classifier revision; the baseline's does not", async () => {
      const { target, scratch } = await fixture({ "src/app.js": "module.exports = 1;\n" });

      await runOpengrep(target, scratch);

      expect(signatures.elements).toHaveLength(2);
      const [baseline, pack] = signatures.elements as [string[], string[]];
      expect(pack).toContain("bundle-classifier:3:minified-80pct-code-bytes-dense-lines-open-no-comment+composer-installed+js-library-name-banner");
      expect(baseline.some((element) => element.startsWith("bundle-classifier:"))).toBe(false);
    });

    // Fix round 2, ruling 3: the cap note, like the libraries note, only on a verified pack pass.
    test("the skip-list cap note appears only when the pack pass was verified", async () => {
      const files: Record<string, string> = {
        "lib/pdf/autoload.php": "<?php\n", "lib/pdf/composer/ClassLoader.php": "<?php\n",
        "lib/pdf/composer/installed.json": JSON.stringify({ packages: [{ name: "acme/pdf", version: "v1.0.0", dist: { type: "zip" }, "install-path": "../acme/pdf" }] }),
      };
      for (let index = 0; index < 5_003; index++) files[`lib/pdf/acme/pdf/src/F${index}.php`] = "<?php\n";
      const { target, scratch } = await fixture(files);

      const verified = await runOpengrep(target, scratch);
      expect(verified.coverageNotes?.filter((note) => note.includes("more third-party library file(s) than"))).toEqual([
        "Bundle routing identified 3 more third-party library file(s) than the bundle-skipping Opengrep pass can skip (at most 5000 files); those files stayed in that pass.",
      ]);

      seen.failPack = true;
      const failed = await runOpengrep(target, (await fixture({})).scratch);
      expect(failed.coverageNotes ?? []).toEqual([]);
    }, 60_000);
  });
});
