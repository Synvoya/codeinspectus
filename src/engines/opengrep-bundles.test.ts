import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, test } from "vitest";

import { loadSynvoyaDataset } from "../synvoya/dataset.js";
import type { LibraryTable } from "../synvoya/types.js";

import {
  anchoredIgnorePattern,
  findPackBundles,
  ignoreListMatcher,
  managedIgnorePredicate,
  minifiedSource,
  packIgnoreList,
  packLibrariesNote,
  packLibraryOverflowNote,
  thirdPartyBundlesGap,
  type BundleReason,
} from "./opengrep-bundles.js";
import type { PackLibrary } from "./opengrep-libraries.js";
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

let table: LibraryTable;
beforeAll(async () => {
  const loaded = await loadSynvoyaDataset();
  if (!loaded.ok) throw new Error(loaded.reason);
  table = loaded.dataset.libraries;
});

const KNOCKOUT_BANNER = "/*!\n * Knockout JavaScript library v3.5.1\n * License: MIT\n */\n";
const COMPOSER_PDF = JSON.stringify({ packages: [
  { name: "acme/pdf", version: "v1.0.0", type: "library", dist: { type: "zip", url: "https://example.invalid/pdf.zip" }, "install-path": "../acme/pdf" },
  { name: "acme/local", version: "dev-main", type: "library", dist: { type: "path", url: "../../packages/local" }, "install-path": "../acme/local" },
] });

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
    // Golden list of the 4.0 classifier (base 274c662) for this tree: unchanged by M6.
    expect(result.bundles).toEqual([
      "assets/js/ckeditor/ckeditor.js", "includes/vendors/fremius/pricing.js", "includes/vendors/sdk/class-sdk.php", "lib/minified.php",
    ]);
    expect([...result.reasons]).toEqual([
      ["assets/js/ckeditor/ckeditor.js", "minified"], ["includes/vendors/fremius/pricing.js", "name"],
      ["includes/vendors/sdk/class-sdk.php", "name"], ["lib/minified.php", "minified"],
    ]);
    expect(result.libraries.size).toBe(0);
    // With the library table too: no file of a 4.0-only tree changes.
    expect(await findPackBundles(target, ignore, { libraryTable: table })).toEqual(result);
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

  test("identified libraries: Composer packages of a renamed vendor tree and JS files whose name and banner agree", async () => {
    const php = `<?php\n${readableCode(40)}\n`;
    const target = await tree({
      "lib/pdf/autoload.php": "<?php // generated\n",
      "lib/pdf/composer/ClassLoader.php": "<?php // generated\n",
      "lib/pdf/composer/autoload_real.php": php,
      "lib/pdf/composer/installed.json": COMPOSER_PDF,
      "lib/pdf/acme/pdf/src/Out.php": php,
      "lib/pdf/acme/pdf/src/Http/Client.php": php,
      "lib/pdf/acme/pdf/README.md": "# pdf\n",
      "lib/pdf/acme/local/src/Out.php": php,
      // A Composer tree under vendor/: ignored by the managed list, never walked.
      "vendor/autoload.php": "<?php\n",
      "vendor/composer/ClassLoader.php": "<?php\n",
      "vendor/composer/installed.json": COMPOSER_PDF,
      "vendor/acme/pdf/src/Out.php": php,
      // A minified copy (evidence beyond the banner) with no risky code.
      "public/js/knockout.js": `${KNOCKOUT_BANNER}${minifiedLine(5_000)}\n`,
      "public/js/bootstrap.js": `${readableCode(40)}\n`,
      "public/js/app.js": `${KNOCKOUT_BANNER}${readableCode(40)}\n`,
      // Name and banner agree, but a readable copy of a version with no sourced release size: stays.
      "public/js/knockout-readable/knockout.js": `${KNOCKOUT_BANNER}${readableCode(40)}\n`,
      "assets/dense.js": minifiedLine(20_000),
      "includes/vendors/sdk.php": php,
    });
    const result = await findPackBundles(target, ignore, { libraryTable: table });
    expect(result.bundles).toEqual([
      "assets/dense.js", "includes/vendors/sdk.php", "lib/pdf/acme/pdf/src/Http/Client.php", "lib/pdf/acme/pdf/src/Out.php", "public/js/knockout.js",
    ]);
    expect(Object.fromEntries(result.reasons)).toEqual({
      "assets/dense.js": "minified",
      "includes/vendors/sdk.php": "name",
      "lib/pdf/acme/pdf/src/Http/Client.php": "composer-package",
      "lib/pdf/acme/pdf/src/Out.php": "composer-package",
      "public/js/knockout.js": "js-library",
    });
    const pdf = { ecosystem: "composer", name: "acme/pdf", version: "v1.0.0", location: "lib/pdf/acme/pdf" };
    expect(Object.fromEntries(result.libraries)).toEqual({
      "lib/pdf/acme/pdf/src/Http/Client.php": pdf,
      "lib/pdf/acme/pdf/src/Out.php": pdf,
      "public/js/knockout.js": { ecosystem: "npm", name: "knockout", version: "3.5.1", location: "public/js/knockout.js" },
    });

    // Without the library table the JS rule is off (the minified copy is then a 4.0 "minified" file); Composer is unchanged.
    const withoutTable = await findPackBundles(target, ignore);
    expect(withoutTable.bundles).toEqual(result.bundles);
    expect(withoutTable.reasons.get("public/js/knockout.js")).toBe("minified");
    expect([...withoutTable.reasons.values()]).not.toContain("js-library");
    expect(withoutTable.libraries.get("lib/pdf/acme/pdf/src/Out.php")).toEqual(pdf);
  });

  // Security review (controller ruling): a fake banner over first-party code never leaves the pack pass.
  test("a fake jquery-1.7.1.js with the right banner over first-party code stays in the pack pass", async () => {
    const banner = "/*!\n * jQuery JavaScript Library v1.7.1\n * http://jquery.com/\n */\n";
    const shell = 'const child_process = require("child_process");\nexports.run = (req, res) => child_process.exec(req.query.cmd);\n';
    const target = await tree({
      "js/jquery-1.7.1.js": `${banner}${readableCode(40)}\n${shell}`,
      // Same banner, minified, but with risky code: not a library (it stays a 4.0 "minified" file).
      "js/min/jquery-1.7.1.js": `${banner}${minifiedLine(5_000)};require("child_process").exec(q)\n`,
    });
    const result = await findPackBundles(target, ignore, { libraryTable: table });
    expect(result.bundles).toEqual(["js/min/jquery-1.7.1.js"]);
    expect(result.reasons.get("js/min/jquery-1.7.1.js")).toBe("minified");
    expect(result.libraries.size).toBe(0);
  });

  // Fix round 1, ruling 2: a readable copy leaves the pass only when its SHA-256 equals a recorded release.
  test("a readable copy is a library only on a release-hash match", async () => {
    const banner = "/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n * Licensed under the MIT license\n */\n";
    const genuine = `${banner}${readableCode(200)}\n`;
    const libraryReleases = [{ npm: "bootstrap", version: "3.3.7", sha256: createHash("sha256").update(genuine).digest("hex"), provenance: "test" }];
    const target = await tree({
      "js/bootstrap.js": genuine,
      // Same banner and size class, one statement appended: no match, stays in the pack pass.
      "edited/bootstrap.js": `${genuine}window.x = 1;\n`,
    });
    const result = await findPackBundles(target, ignore, { libraryTable: table, libraryReleases });
    expect(result.bundles).toEqual(["js/bootstrap.js"]);
    expect(result.libraries.get("js/bootstrap.js")).toEqual({ ecosystem: "npm", name: "bootstrap", version: "3.3.7", location: "js/bootstrap.js" });
    // The shipped table (no entry for this content): nothing leaves the pass.
    expect((await findPackBundles(target, ignore, { libraryTable: table })).bundles).toEqual([]);
  });

  test("Composer markers at the target root classify nothing: the target is scanned as in 4.0", async () => {
    const target = await tree({
      "autoload.php": "<?php\n",
      "composer/ClassLoader.php": "<?php\n",
      "composer/installed.json": COMPOSER_PDF,
      "acme/pdf/src/Out.php": `<?php\n${readableCode(40)}\n`,
    });
    expect((await findPackBundles(target, ignore, { libraryTable: table })).bundles).toEqual([]);
  });

  // Fix round 1, ruling 8: under the skip-list cap, the 4.0 entries come first; library files that do not fit stay in.
  test("the skip-list cap keeps name and minified files first and counts the library files left in the pass", async () => {
    const markers = { "lib/pdf/autoload.php": "<?php\n", "lib/pdf/composer/ClassLoader.php": "<?php\n", "lib/pdf/composer/installed.json": COMPOSER_PDF };
    const target = await tree({
      ...markers,
      "lib/pdf/acme/pdf/a.php": "<?php\n", "lib/pdf/acme/pdf/b.php": "<?php\n", "lib/pdf/acme/pdf/c.php": "<?php\n",
      "z/one.js": minifiedLine(5_000), "z/two.js": minifiedLine(5_000), "z/vendors/three.js": "var a;\n",
    });
    const result = await findPackBundles(target, ignore, { libraryTable: table, maxExcluded: 4 });
    expect(result.bundles).toEqual(["lib/pdf/acme/pdf/a.php", "z/one.js", "z/two.js", "z/vendors/three.js"]);
    expect(result.libraryOverflow).toBe(2);
    expect((await findPackBundles(target, ignore, { libraryTable: table })).libraryOverflow).toBe(0);
    expect(packLibraryOverflowNote(2)).toBe(
      "Bundle routing identified 2 more third-party library file(s) than the bundle-skipping Opengrep pass can skip (at most 5000 files); " +
        "those files stayed in that pass.",
    );
    expect(packLibraryOverflowNote(0)).toBeUndefined();
  });

  test("nested vendor trees: the innermost package root names a file", async () => {
    const markers = (dir: string, installed: unknown): Record<string, string> => ({
      [`${dir}/autoload.php`]: "<?php\n",
      [`${dir}/composer/ClassLoader.php`]: "<?php\n",
      [`${dir}/composer/installed.json`]: JSON.stringify(installed),
    });
    const dist = { type: "zip", url: "https://example.invalid/x.zip" };
    const target = await tree({
      ...markers("libs", [{ name: "outer/app", version: "1.0.0", dist }]),
      ...markers("libs/outer/app/deps", [{ name: "inner/lib", version: "2.0.0", dist }]),
      "libs/outer/app/src/A.php": "<?php\n$a = 1;\n",
      "libs/outer/app/deps/inner/lib/B.php": "<?php\n$b = 1;\n",
    });
    const result = await findPackBundles(target, ignore, { libraryTable: table });
    // The inner tree's own marker files belong to the outer package.
    expect(result.bundles).toEqual([
      "libs/outer/app/deps/autoload.php", "libs/outer/app/deps/composer/ClassLoader.php", "libs/outer/app/deps/inner/lib/B.php", "libs/outer/app/src/A.php",
    ]);
    expect(result.libraries.get("libs/outer/app/deps/autoload.php")?.name).toBe("outer/app");
    expect(result.libraries.get("libs/outer/app/deps/inner/lib/B.php")?.name).toBe("inner/lib");
    expect(result.libraries.get("libs/outer/app/src/A.php")?.name).toBe("outer/app");
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

  test("examples list name and minified files first, then identified library files, each sorted", () => {
    const composer = Array.from({ length: 25 }, (_, index) => `libs/mpdf/mpdf/src/F${String(index).padStart(2, "0")}.php`);
    const skipped = ["assets/z-dense.js", ...composer, "public/js/knockout.js"].sort();
    const reasons = new Map<string, BundleReason>([
      ...composer.map((rel) => [rel, "composer-package"] as const),
      ["assets/z-dense.js", "minified"],
      ["public/js/knockout.js", "js-library"],
    ]);
    const gap = thirdPartyBundlesGap(skipped, reasons);
    expect(gap?.files).toBe(27);
    // At least one example per evidence label: the Knockout file keeps a slot behind 25 Composer files.
    expect(gap?.examples).toEqual(["assets/z-dense.js", ...composer.slice(0, 18).map((rel) => `${rel} (identified by Composer installed.json)`),
      "public/js/knockout.js (identified by name and banner)"]);
    // More than 20 name or minified files leave one slot to each library label present.
    const plain = Array.from({ length: 25 }, (_, index) => `assets/m${String(index).padStart(2, "0")}.js`);
    const mixed = thirdPartyBundlesGap([...plain, "libs/x/a.php"].sort(), new Map([["libs/x/a.php", "composer-package" as BundleReason]]));
    expect(mixed?.examples).toEqual([...plain.slice(0, 19), "libs/x/a.php (identified by Composer installed.json)"]);
    expect(thirdPartyBundlesGap(["public/js/knockout.js"], new Map([["public/js/knockout.js", "js-library"]]))?.examples)
      .toEqual(["public/js/knockout.js (identified by name and banner)"]);
    // Without library reasons the order is the 4.0 one.
    expect(thirdPartyBundlesGap(skipped, new Map([["assets/z-dense.js", "minified"]]))).toEqual(thirdPartyBundlesGap(skipped));
  });
});

describe("identified-libraries coverage note", () => {
  const PREFIX = "Bundle routing identified";
  const MIDDLE = "by name and version; the bundle-skipping Opengrep pass (syn-php-*, syn-node-*, ci-baseline-sql-injection-string-build) skipped their";
  const SUFFIX = "part of third-party-bundles (the other baseline rules still scanned them)";
  const composer = (name: string, root: string): PackLibrary => ({ ecosystem: "composer", name, version: "v1.0.0", location: root });

  test("one library, one file", () => {
    const knockout: PackLibrary = { ecosystem: "npm", name: "knockout", version: "3.5.1", location: "public/js/knockout.js" };
    expect(packLibrariesNote(["public/js/knockout.js"], new Map([["public/js/knockout.js", knockout]]))).toBe(
      `${PREFIX} 1 third-party library ${MIDDLE} 1 file(s), ${SUFFIX}: knockout 3.5.1 (public/js/knockout.js).`,
    );
  });

  test("a library identified without a version is named without one", () => {
    const bootstrap: PackLibrary = { ecosystem: "npm", name: "bootstrap", location: "public/js/bootstrap.js" };
    expect(packLibrariesNote(["public/js/bootstrap.js"], new Map([["public/js/bootstrap.js", bootstrap]]))).toBe(
      `${PREFIX} 1 third-party library ${MIDDLE} 1 file(s), ${SUFFIX}: bootstrap (public/js/bootstrap.js).`,
    );
  });

  test("one library, 512 files", () => {
    const mpdf = composer("mpdf/mpdf", "libs/mpdf/mpdf_8/mpdf/mpdf");
    const files = Array.from({ length: 512 }, (_, index) => `libs/mpdf/mpdf_8/mpdf/mpdf/src/F${index}.php`);
    expect(packLibrariesNote(files, new Map(files.map((rel) => [rel, mpdf])))).toBe(
      `${PREFIX} 1 third-party library ${MIDDLE} 512 file(s), ${SUFFIX}: mpdf/mpdf v1.0.0 (libs/mpdf/mpdf_8/mpdf/mpdf/, 512 files).`,
    );
  });

  test("twelve libraries: ten shown, then the rest counted", () => {
    const libraries = new Map<string, PackLibrary>();
    for (let index = 0; index < 12; index++) {
      const root = `libs/v/p${String(index).padStart(2, "0")}`;
      libraries.set(`${root}/a.php`, composer(`v/p${String(index).padStart(2, "0")}`, root));
    }
    const shown = [...libraries.values()].slice(0, 10).map((library) => `${library.name} v1.0.0 (${library.location}/)`).join(", ");
    expect(packLibrariesNote([...libraries.keys()], libraries)).toBe(
      `${PREFIX} 12 third-party libraries ${MIDDLE} 12 file(s), ${SUFFIX}: ${shown}, and 2 more.`,
    );
  });

  test("a location that cannot be displayed is counted, never shown; only the skipped files count", () => {
    const good = composer("acme/good", "libs/acme/good");
    const bad = composer("acme/bad", "libs/acme/bad\u202e");
    const libraries = new Map<string, PackLibrary>([
      ["libs/acme/good/a.php", good], ["libs/acme/good/b.php", good], ["libs/acme/bad\u202e/a.php", bad], ["libs/acme/good/not-skipped.php", good],
    ]);
    expect(packLibrariesNote(["libs/acme/good/a.php", "libs/acme/good/b.php", "libs/acme/bad\u202e/a.php"], libraries)).toBe(
      `${PREFIX} 2 third-party libraries ${MIDDLE} 3 file(s), ${SUFFIX}: acme/good v1.0.0 (libs/acme/good/, 2 files), and 1 more.`,
    );
    expect(packLibrariesNote(["assets/dense.js"], libraries)).toBeUndefined();
    expect(packLibrariesNote([], new Map())).toBeUndefined();
  });
});
