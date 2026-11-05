import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import {
  anchoredIgnorePattern,
  findPackBundles,
  ignoreListMatcher,
  managedIgnorePredicate,
  minifiedSource,
  packIgnoreList,
  thirdPartyBundlesGap,
} from "./opengrep-bundles.js";
import { effectiveOpengrepIgnoreList, OPENGREP_IGNORE_FILE } from "./opengrep.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

/** One minified line the way terser writes it: no indentation, few spaces. */
function minifiedLine(bytes: number): string {
  const unit = "function(e,t){return e&&t?e.call(t,n[r]):void 0},";
  return "!" + unit.repeat(Math.ceil(bytes / unit.length)).slice(0, bytes - 1);
}

/** Readable first-party code: short indented lines. */
function readableCode(lines: number): string {
  return Array.from({ length: lines }, (_, index) => `  const value${index} = compute(input, ${index}); // step ${index}`).join("\n");
}

describe("minified source classification", () => {
  test("a single dense line (ckeditor/freemius shape) is minified, with or without a licence banner", () => {
    expect(minifiedSource(minifiedLine(50_000))).toBe(true);
    expect(minifiedSource(`/*! Library v1.2 | (c) Someone | MIT */${minifiedLine(50_000)}\n`)).toBe(true);
    expect(minifiedSource(`/**\n * Library v1.2\n * (c) Someone\n */\n${minifiedLine(50_000)}\n`)).toBe(true);
  });

  test("a readable bundle (summernote/nostroots shape) is not minified", () => {
    expect(minifiedSource(readableCode(5_000))).toBe(false);
  });

  // Controller ruling: a long comment line must not make a first-party file minified.
  test("a long comment line (inline source map, licence blob) does not make a first-party file minified", () => {
    const sourceMap = `//# sourceMappingURL=data:application/json;base64,${"A".repeat(40_000)}`;
    expect(minifiedSource(`${readableCode(200)}\n${sourceMap}\n`)).toBe(false);
    expect(minifiedSource(`/* ${"x".repeat(40_000)} */\n${readableCode(200)}\n`)).toBe(false);
    expect(minifiedSource(`/*\n${"y".repeat(40_000)}\n*/\n${readableCode(200)}\n`)).toBe(false);
    // PHP line comments start with `#` too; an attribute `#[...]` is code.
    expect(minifiedSource(`<?php\n# ${"z".repeat(40_000)}\n${readableCode(200)}\n`, { php: true })).toBe(false);
  });

  test("long dense lines must hold at least 80% of the code bytes", () => {
    const code = readableCode(100); // ~6.3 KB of short lines
    const shortBytes = code.length;
    expect(minifiedSource(`${code}\n${minifiedLine(shortBytes * 3)}\n`)).toBe(false); // 75%
    expect(minifiedSource(`${code}\n${minifiedLine(shortBytes * 5)}\n`)).toBe(true); // ~83%
  });

  test("a long line of prose-like text with normal spacing is not dense", () => {
    const prose = `const text = "${"lorem ipsum dolor sit amet ".repeat(2_000)}";`;
    expect(minifiedSource(prose)).toBe(false);
  });

  // Review minor 1: a block comment opened mid-line holds no code, so its dense lines never count.
  test("a block comment opened mid-line does not make its dense lines code", () => {
    const dense = "1,2,3,4,5,6,7,8,9,0;".repeat(5_000); // ~100 KB against ~12 KB of code
    expect(minifiedSource(`const a = 1; /*\n${dense}\n*/\n${readableCode(200)}\n`)).toBe(false);
    // A real minified line after the comment closes still counts.
    expect(minifiedSource(`var a = 1; /* note\nmore */\n${minifiedLine(50_000)}\n`)).toBe(true);
  });

  // Field run 2026-11-05: lobbywatch's 890 KB main-bundle.js (concatenated minified libraries) held `accept:"image/*"`
  // on one dense line; the classifier took it for an open comment, the bundle stayed in the pack pass and took 438 s.
  test("a `/*` inside a string on a dense minified line does not hide the dense lines after it", () => {
    const lines = Array.from({ length: 12 }, () => minifiedLine(30_000));
    lines[1] = `${minifiedLine(15_000)}attributes:{accept:"image/*"}},${minifiedLine(15_000)}`;
    lines[6] = `${minifiedLine(15_000)}headers:{Accept:"text/html, */*"},${minifiedLine(15_000)}`;
    expect(minifiedSource(`/*! jQuery v3.6.0 | (c) OpenJS Foundation */\n${lines.join("\n")}\n`)).toBe(true);
  });

  test("short files and empty files are never minified", () => {
    expect(minifiedSource("")).toBe(false);
    expect(minifiedSource("var a=1,b=2;")).toBe(false);
  });
});

describe("pack ignore list", () => {
  // Measured on Opengrep 1.33.1 (review Critical 1): `\*` and `\?` still act as wildcards, and neither `\[` nor
  // `[[]` names a literal `[`. Such a path never goes on the skip list: it would hide its siblings.
  // `{ } , ! # ( ) ^ $ +` and spaces are literal there (a sibling kept its pack finding), so they stay excludable.
  test("anchors each bundle at the scan root; names with literal-safe punctuation are kept verbatim", () => {
    expect(anchoredIgnorePattern("assets/js/ckeditor/ckeditor.js")).toBe("/assets/js/ckeditor/ckeditor.js");
    for (const name of ["src/{a,b}.js", "src/!n.js", "#h.js", "!b.js", "src/(p).js", "src/^r$.js", "src/f+g.js", "src/sp .js"]) {
      expect(anchoredIgnorePattern(name)).toBe(`/${name}`);
    }
  });

  test("refuses glob metacharacters, control characters and trailing blanks: such a file stays in the pack pass", () => {
    for (const name of ["src/c*.js", "src/q?.js", "src/*/x.js", "*.js", "src/b[1].js", "src/d]x.js", "src/back\\slash.js",
      "src/a\nb.js", "src/trailing.js ", ""]) {
      expect(anchoredIgnorePattern(name)).toBeUndefined();
    }
  });

  test("appends the anchored bundles to the baseline list, LF only", () => {
    const list = packIgnoreList("node_modules/\nbuild/\n", ["a/b.js", "c[1].js"]);
    const lines = list.split("\n");
    expect(lines.slice(0, 2)).toEqual(["node_modules/", "build/"]);
    expect(lines).toContain("/a/b.js");
    expect(list).not.toContain("c[1]");
    expect(list).not.toContain("\r");
  });
});

describe("ignore list matcher", () => {
  test("understands every pattern of the managed default list plus BUILD_DIRS", async () => {
    const matcher = ignoreListMatcher(effectiveOpengrepIgnoreList(await readFile(OPENGREP_IGNORE_FILE, "utf8")));
    expect(matcher.unsupported).toEqual([]);
    expect(matcher.ignored("vendor", true)).toBe(true);
    expect(matcher.ignored("a/vendor", true)).toBe(true);
    expect(matcher.ignored("Vendor", true)).toBe(false); // case-sensitive, like Opengrep
    expect(matcher.ignored("vendor", false)).toBe(false); // `vendor/` names directories only
    expect(matcher.ignored("src/app.min.js", false)).toBe(true);
    expect(matcher.ignored("src/app.MIN.js", false)).toBe(false);
    expect(matcher.ignored(".git", false)).toBe(true);
    expect(matcher.ignored("pkg/x_test.go", false)).toBe(true);
    expect(matcher.ignored(".next", true)).toBe(true);
    expect(matcher.ignored("src", true)).toBe(false);
  });

  test("a reported skip is expected when it or a folder above it is on the managed list", () => {
    const ignored = managedIgnorePredicate("node_modules/\nvendor/\n*.min.js\n*_test.go\n.git\n");
    for (const rel of ["node_modules", "a/node_modules/x/index.js", "web/vendor", "lib/x.min.js", "pkg/a_test.go", ".git"]) {
      expect(ignored(rel)).toBe(true);
    }
    for (const rel of ["src/cX.js", "Vendor/a.js", "src/vendor.js"]) expect(ignored(rel)).toBe(false);
  });

  test("reports patterns it cannot evaluate instead of guessing", () => {
    const matcher = ignoreListMatcher("docs/*.md\n/root.js\n**/x\n# comment\n\nok/\n");
    expect(matcher.unsupported).toEqual(["docs/*.md", "/root.js", "**/x"]);
    expect(matcher.ignored("docs/a.md", false)).toBe(false);
    expect(matcher.ignored("ok", true)).toBe(true);
  });
});

describe("pack bundle discovery", () => {
  async function tree(files: Record<string, string>, parent?: string): Promise<string> {
    const base = parent ?? await mkdtemp(join(tmpdir(), "ci-pack-bundles-"));
    if (!parent) roots.push(base);
    for (const [path, content] of Object.entries(files)) {
      await mkdir(join(base, path, ".."), { recursive: true });
      await writeFile(join(base, path), content, "utf8");
    }
    return base;
  }

  const ignore = "node_modules/\nvendor/\n*.min.js\nbuild/\n";

  test("finds minified pack-language files outside ignored folders, target-relative and sorted", async () => {
    const target = await tree({
      "assets/js/ckeditor/ckeditor.js": minifiedLine(30_000),
      "includes/vendors/fremius/pricing.js": `/*! fs */${minifiedLine(30_000)}`,
      "src/app.ts": readableCode(500),
      "src/big.tsx": readableCode(5_000),
      "lib/minified.php": `<?php ${minifiedLine(30_000)}`,
      "vendor/lib/dense.js": minifiedLine(30_000), // ignored by both passes already
      "node_modules/x/index.js": minifiedLine(30_000),
      "public/app.min.js": minifiedLine(30_000),
      "data/blob.json": minifiedLine(30_000), // not a pack language
      "Vendor/upper.js": readableCode(50), // case-sensitive vendor/: first-party, readable
      "includes/vendors/sdk/class-sdk.php": `<?php\n${readableCode(50)}`, // a bundled SDK, readable
      "app/Vendors/own.php": `<?php\n${readableCode(50)}`, // case-sensitive: first-party
    });
    const result = await findPackBundles(target, ignore);
    expect(result.bundles).toEqual([
      "assets/js/ckeditor/ckeditor.js", "includes/vendors/fremius/pricing.js", "includes/vendors/sdk/class-sdk.php", "lib/minified.php",
    ]);
  });

  // Controller ruling: classification uses target-relative paths only, never parent folders.
  test("a checkout under a parent folder named vendor/ or build/ keeps its first-party files", async () => {
    const parent = await mkdtemp(join(tmpdir(), "ci-pack-parent-"));
    roots.push(parent);
    const target = join(parent, "vendors", "vendor", "build", "repo");
    await tree({ "src/app.js": readableCode(300), "src/dense.js": minifiedLine(20_000) }, target);
    expect((await findPackBundles(target, ignore)).bundles).toEqual(["src/dense.js"]);
  });

  // Review minor 2: Opengrep scans an explicit file target whatever its ignore list says, so nothing is skipped.
  test("a single-file target is never reported as skipped", async () => {
    const target = await tree({ "one.js": minifiedLine(20_000) });
    expect((await findPackBundles(join(target, "one.js"), ignore)).bundles).toEqual([]);
  });

  test("files over Opengrep's 1,000,000-byte limit are left to its own size report", async () => {
    const target = await tree({ "huge.js": minifiedLine(1_100_000) });
    expect((await findPackBundles(target, ignore)).bundles).toEqual([]);
  });
});

describe("third-party-bundles gap", () => {
  test("counts every skipped file and names at most 20 displayable examples", () => {
    const files = Array.from({ length: 25 }, (_, index) => `public/js/lib${String(index).padStart(2, "0")}.js`);
    const gap = thirdPartyBundlesGap([...files, "bad‮name.js"]);
    expect(gap).toEqual({ id: "third-party-bundles", files: 26, examples: files.slice(0, 20) });
    expect(thirdPartyBundlesGap([])).toBeUndefined();
  });
});
