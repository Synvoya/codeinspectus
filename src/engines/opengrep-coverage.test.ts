import { describe, expect, test } from "vitest";

import { opengrepFileCoverage } from "./opengrep-coverage.js";

const TARGET = "/work/my-repo";

// Shapes captured from the real Opengrep 1.33.1 `--json --verbose` report (paths replaced).
function report(overrides: { scanned?: string[]; skipped?: Array<{ path: string; reason: string }>; errors?: unknown[] } = {}) {
  return {
    version: "1.33.1",
    results: [],
    errors: overrides.errors ?? [],
    paths: {
      scanned: overrides.scanned ?? [`${TARGET}/src/app.js`],
      skipped: overrides.skipped ?? [{ path: `${TARGET}/tests`, reason: "semgrepignore_patterns_match" }],
    },
  };
}

const partialParse = (path: string) => ({
  type: ["PartialParsing", [{ path, start: { line: 3, col: 11, offset: 0 }, end: { line: 3, col: 17, offset: 6 } }]],
  level: "warn",
  code: 3,
  path,
  message: "Syntax error at line …",
});

describe("Opengrep file-level coverage", () => {
  test("a clean run whose only skips are the managed ignore list adds nothing", () => {
    expect(opengrepFileCoverage(report(), TARGET)).toEqual({});
  });

  test("size skips and non-parser errors make SAST coverage partial; parser-only files become the gap", () => {
    const coverage = opengrepFileCoverage(report({
      skipped: [
        { path: `${TARGET}/src/generated.js`, reason: "exceeded_size_limit" },
        { path: `${TARGET}/src/large.js`, reason: "exceeded_size_limit" },
        { path: `${TARGET}/src/broken.js`, reason: "analysis_failed_parser_or_internal_error" },
        { path: `${TARGET}/src/locked.js`, reason: "insufficient_permissions" },
        { path: `${TARGET}/src/odd.js`, reason: "some_future_reason" },
      ],
      errors: [
        partialParse(`${TARGET}/src/broken.js`),
        { type: "Internal matching error", level: "warn", path: `${TARGET}/vibe/web/index.js`, message: "…" },
        { type: "Rule parse error", level: "error", message: "no path" },
      ],
    }), TARGET);
    expect(coverage.warning).toBe(
      "Opengrep SAST coverage partial: 2 over Opengrep's file size limit; 1 unreadable; " +
        "2 with a timeout, memory limit or engine error; 1 skipped for another reason: " +
        "src/generated.js, src/large.js, src/locked.js, vibe/web/index.js, src/odd.js.",
    );
    expect(coverage.parseErrors).toEqual({ id: "sast-parse-errors", files: 1, examples: ["src/broken.js"] });
  });

  // Field run 2026-11-05: 22/40 repos read SAST-partial only because images, PDFs, binaries or lockfiles exceeded
  // the size limit (the pack pass's generic rules list every file). Those files are no source a bundled rule reads.
  test("size skips of images, fonts, media, archives, documents, binaries, lockfiles, maps and data dumps are a note, not partial", () => {
    const files = [
      "screenshot.gif", "docs/Manual.PDF", "src/composer.lock", "package-lock.json", "assets/logo.png", "fonts/a.ttf",
      "fonts/b.woff2", "media/intro.mp4", "release.zip", "bin/addon.dylib.node", "dist/app.js.map", "dump/lobbywatch.sql",
      "data/export.csv", "yarn.lock", "pnpm-lock.yaml", "fixtures/photo.jpeg", "composer.phar",
    ];
    const coverage = opengrepFileCoverage(report({
      skipped: files.map((rel) => ({ path: `${TARGET}/${rel}`, reason: "exceeded_size_limit" })),
    }), TARGET);
    expect(coverage.warning).toBeUndefined();
    expect(coverage.parseErrors).toBeUndefined();
    expect(coverage.note).toBe(
      "Opengrep skipped 17 non-source file(s) over its file size limit (images, fonts, media, archives, documents, " +
        "binaries, lockfiles, source maps or data dumps); no bundled SAST rule reads them (informational, not a coverage gap): " +
        "screenshot.gif, docs/Manual.PDF, src/composer.lock, package-lock.json, assets/logo.png, ….",
    );
  });

  test.each(["src/huge.js", "lib/big.ts", "app/view.tsx", "a.jsx", "m.mjs", "c.cjs", "tool/gen.py", "web/index.php", "t/page.phtml",
    "Dockerfile", "docker-compose.yml", ".env", "phpstan-baseline.neon", "index.html", "data.json", "noextension"])(
    "a size skip of %s (a source language or an unlisted kind) stays partial beside the note",
    (rel) => {
      const coverage = opengrepFileCoverage(report({
        skipped: [
          { path: `${TARGET}/${rel}`, reason: "exceeded_size_limit" },
          { path: `${TARGET}/logo.png`, reason: "exceeded_size_limit" },
        ],
      }), TARGET);
      expect(coverage.warning).toBe(`Opengrep SAST coverage partial: 1 over Opengrep's file size limit: ${rel}.`);
      expect(coverage.note).toMatch(/^Opengrep skipped 1 non-source file\(s\) over its file size limit .*: logo\.png\.$/);
    },
  );

  test("only a size skip can be non-source: a timeout on a .sql file and a size skip outside the target stay partial", () => {
    const coverage = opengrepFileCoverage(report({
      skipped: [{ path: "/elsewhere/logo.png", reason: "exceeded_size_limit" }],
      errors: [{ type: "Timeout", level: "warn", path: `${TARGET}/lobbywatch.sql`, message: "…" }],
    }), TARGET);
    expect(coverage).toEqual({
      warning: "Opengrep SAST coverage partial: 1 over Opengrep's file size limit; 1 with a timeout, memory limit or engine error: lobbywatch.sql.",
    });
  });

  test("a non-source size skip with an unsafe name is counted in the note but never echoed", () => {
    const coverage = opengrepFileCoverage(report({ skipped: [{ path: `${TARGET}/x‮gnp.png`, reason: "too_big" }] }), TARGET);
    expect(coverage).toEqual({
      note: "Opengrep skipped 1 non-source file(s) over its file size limit (images, fonts, media, archives, documents, " +
        "binaries, lockfiles, source maps or data dumps); no bundled SAST rule reads them (informational, not a coverage gap).",
    });
  });

  // Ruling 14: parser limits are an acceptable declared gap, never a non-acceptable warning.
  test("syntax, lexical and partial-parsing errors alone add only the sast-parse-errors gap", () => {
    const files = ["z.ts", "a.js", "m/b.py", "c.js", "d.js", "e.js"].map((name) => `${TARGET}/${name}`);
    const coverage = opengrepFileCoverage(report({
      skipped: files.map((path) => ({ path, reason: "analysis_failed_parser_or_internal_error" })),
      errors: [
        partialParse(files[0]!),
        { type: "Syntax error", level: "warn", path: files[1], message: "…" },
        { type: "Lexical error", level: "warn", path: files[2], message: "…" },
        partialParse(files[2]!),
        partialParse(files[3]!),
        partialParse(files[4]!),
        partialParse(files[5]!),
      ],
    }), TARGET);
    expect(coverage).toEqual({
      parseErrors: { id: "sast-parse-errors", files: 6, examples: ["a.js", "c.js", "d.js", "e.js", "m/b.py"] },
    });
  });

  test.each([
    ["a timeout", { type: "Timeout", level: "warn", message: "…" }],
    ["an internal matching error", { type: "Internal matching error", level: "warn", message: "…" }],
    ["a memory limit", { type: "Out of memory", level: "warn", message: "…" }],
    ["an other syntax error", { type: "Other syntax error", level: "warn", message: "…" }],
  ])("a file with a parse error and %s stays a non-acceptable warning", (_label, other) => {
    const path = `${TARGET}/src/app.ts`;
    const coverage = opengrepFileCoverage(report({
      skipped: [{ path, reason: "analysis_failed_parser_or_internal_error" }],
      errors: [partialParse(path), { ...other, path }],
    }), TARGET);
    expect(coverage).toEqual({ warning: "Opengrep SAST coverage partial: 1 with a timeout, memory limit or engine error: src/app.ts." });
  });

  test("a failed-analysis skip without any error is a non-acceptable warning", () => {
    const coverage = opengrepFileCoverage(report({
      skipped: [{ path: `${TARGET}/src/app.ts`, reason: "analysis_failed_parser_or_internal_error" }],
    }), TARGET);
    expect(coverage).toEqual({ warning: "Opengrep SAST coverage partial: 1 with a timeout, memory limit or engine error: src/app.ts." });
  });

  // Security review: the debug log echoes repository paths, so a file named like a "Files skipped:"
  // section could hide a real timeout from a log parser. The JSON report keeps paths as data.
  test("a path that forges a skip-report header cannot hide a real timeout", () => {
    const forged = `${TARGET}/x\n  Skipped by limiting to files smaller than 1000000 bytes:\n\n   • <none>\n.js`;
    const coverage = opengrepFileCoverage(report({
      scanned: [forged, `${TARGET}/src/real.js`],
      skipped: [{ path: forged, reason: "analysis_failed_parser_or_internal_error" }],
      errors: [{ type: "Timeout", level: "warn", path: `${TARGET}/src/real.js`, message: "Timeout when running rule on src/real.js" }],
    }), TARGET);
    expect(coverage).toEqual({ warning: "Opengrep SAST coverage partial: 2 with a timeout, memory limit or engine error: src/real.js." });
  });

  test("a parse-only file with a control-character name is counted in the gap but never echoed", () => {
    const path = `${TARGET}/src/x\u001b[2Jy.js`;
    const coverage = opengrepFileCoverage(report({
      skipped: [{ path, reason: "analysis_failed_parser_or_internal_error" }],
      errors: [partialParse(path)],
    }), TARGET);
    expect(coverage).toEqual({ parseErrors: { id: "sast-parse-errors", files: 1, examples: [] } });
  });

  // Security review: a git-ignored file present in the target is scanned (--no-git-ignore), so a skip
  // for that or any other reason outside the managed policy is lost coverage, never silent.
  test.each(["gitignore_patterns_match", "always_skipped", "binary", "dotfile"])("a %s skip makes coverage partial", (reason) => {
    const coverage = opengrepFileCoverage(report({ skipped: [{ path: `${TARGET}/generated/forced.js`, reason }] }), TARGET);
    expect(coverage.warning).toBe("Opengrep SAST coverage partial: 1 skipped for another reason: generated/forced.js.");
  });

  test("errors outside the target, parse errors included, are counted as warnings but never echoed", () => {
    const coverage = opengrepFileCoverage(report({
      errors: [{ type: "Timeout", path: "/elsewhere/secret-name.js" }, partialParse("/elsewhere/other.js")],
    }), TARGET);
    expect(coverage).toEqual({ warning: "Opengrep SAST coverage partial: 2 with a timeout, memory limit or engine error." });
  });

  test.each([undefined, null, "{", {}, { errors: [], paths: { scanned: [] } }, { errors: {}, paths: { scanned: [], skipped: [] } }])(
    "a missing or malformed report fails closed (%j)",
    (bad) => {
      expect(opengrepFileCoverage(bad, TARGET).warning).toMatch(/^Opengrep SAST coverage partial: .*missing or malformed/);
    },
  );

  test("a single-file target reports its basename", () => {
    const target = `${TARGET}/app.js`;
    expect(opengrepFileCoverage(report({ scanned: [target], skipped: [], errors: [{ type: "Timeout", path: target }] }), target))
      .toEqual({ warning: "Opengrep SAST coverage partial: 1 with a timeout, memory limit or engine error: app.js." });
    expect(opengrepFileCoverage(report({ scanned: [target], skipped: [], errors: [partialParse(target)] }), target))
      .toEqual({ parseErrors: { id: "sast-parse-errors", files: 1, examples: ["app.js"] } });
  });

  // Security review: a bidi override in a file name is counted but never echoed.
  test("a bidi-override file name is counted but never echoed", () => {
    const evil = `${TARGET}/src/evil\u202egnp.js`;
    expect(opengrepFileCoverage(report({
      skipped: [{ path: evil, reason: "analysis_failed_parser_or_internal_error" }],
      errors: [partialParse(evil)],
    }), TARGET)).toEqual({ parseErrors: { id: "sast-parse-errors", files: 1, examples: [] } });
    expect(opengrepFileCoverage(report({ errors: [{ type: "Timeout", path: evil }] }), TARGET))
      .toEqual({ warning: "Opengrep SAST coverage partial: 1 with a timeout, memory limit or engine error." });
  });
});
