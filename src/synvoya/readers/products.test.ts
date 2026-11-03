import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { Declaration } from "../types.js";

import { readProducts } from "./products.js";
import { walkCandidates } from "./walk.js";

const FIXTURES = join(process.cwd(), "fixtures", "synvoya", "products");

type Product = "adobe-commerce" | "magento-open-source" | "wordpress";

function decl(
  product: Product,
  spec: string,
  file: string,
  line: number,
  source: string,
  precision: Declaration["precision"] = "exact",
): Declaration {
  return {
    subject: { type: "product", product },
    spec,
    ...(precision === "exact" ? { resolved: spec } : {}),
    precision,
    file,
    line,
    source,
  };
}

const read = (name: string) => readProducts(join(FIXTURES, name));

describe("readProducts: fixtures", () => {
  it("Adobe Commerce from magento/product-enterprise-edition, keeping -pN", async () => {
    const result = await read("magento-ee");
    expect(result.declarations).toEqual([
      decl("adobe-commerce", "2.4.6-p3", "composer.lock", 5, "composer.lock magento/product-enterprise-edition"),
    ]);
    expect(result.parsed).toEqual(["composer.lock"]);
    expect(result.skipped).toEqual([]);
  });

  it("Magento Open Source from magento/product-community-edition", async () => {
    const result = await read("magento-ce");
    expect(result.declarations).toEqual([
      decl("magento-open-source", "2.4.7-p1", "composer.lock", 5, "composer.lock magento/product-community-edition"),
    ]);
  });

  it("a lock with CE, EE and the base package reports Adobe Commerce once (EE wins)", async () => {
    const result = await read("magento-both");
    expect(result.declarations).toEqual([
      decl("adobe-commerce", "2.4.6-p3", "composer.lock", 10, "composer.lock magento/product-enterprise-edition"),
    ]);
  });

  it("WordPress from roots/wordpress, one declaration for the metapackage pair", async () => {
    const result = await read("wp-composer");
    expect(result.declarations).toEqual([decl("wordpress", "6.5.2", "composer.lock", 5, "composer.lock roots/wordpress")]);
  });

  it("WordPress from johnpbloch/wordpress-core", async () => {
    const result = await read("wp-johnpbloch");
    expect(result.declarations).toEqual([decl("wordpress", "6.4.3", "composer.lock", 5, "composer.lock johnpbloch/wordpress-core")]);
  });

  it("WordPress from wp-includes/version.php: line of the assignment", async () => {
    const result = await read("wp-version-php");
    expect(result.declarations).toEqual([
      decl("wordpress", "6.5.2", "wp-includes/version.php", 7, "wp-includes/version.php $wp_version"),
    ]);
  });

  it("double-quoted literal", async () => {
    const result = await read("wp-double-quoted");
    expect(result.declarations).toEqual([
      decl("wordpress", "6.4.3", "wp-includes/version.php", 2, "wp-includes/version.php $wp_version"),
    ]);
  });

  it("a computed value is an unresolved declaration plus a note, found under public/wp/", async () => {
    const result = await read("wp-nonliteral");
    expect(result.declarations).toEqual([
      decl("wordpress", "$core_version . '-custom'", "public/wp/wp-includes/version.php", 2, "wp-includes/version.php $wp_version", "unresolved"),
    ]);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toContain("public/wp/wp-includes/version.php:2");
    expect(result.notes[0]).toContain("not a literal string");
  });

  it("composer.lock and version.php for the same install both report (the evaluator dedupes)", async () => {
    const result = await read("wp-both");
    expect(result.declarations).toEqual([
      decl("wordpress", "6.5.2", "composer.lock", 5, "composer.lock roots/wordpress"),
      decl("wordpress", "6.5.2", "wp-includes/version.php", 2, "wp-includes/version.php $wp_version"),
    ]);
  });
});

describe("readProducts: edge inputs", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-prod-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  const lock = (packages: unknown[], dev: unknown[] = []) => JSON.stringify({ packages, "packages-dev": dev }, null, 2);

  it("reads packages-dev too", async () => {
    await writeFile(join(work, "composer.lock"), lock([], [{ name: "roots/wordpress", version: "6.6.1" }]));
    const result = await readProducts(work);
    expect(result.declarations.map((entry) => [entry.subject, entry.spec])).toEqual([[{ type: "product", product: "wordpress" }, "6.6.1"]]);
  });

  it("magento2-base alone is Magento Open Source", async () => {
    await writeFile(join(work, "composer.lock"), lock([{ name: "magento/magento2-base", version: "2.4.5-p9" }]));
    const result = await readProducts(work);
    expect(result.declarations.map((entry) => [entry.subject, entry.spec])).toEqual([[{ type: "product", product: "magento-open-source" }, "2.4.5-p9"]]);
  });

  it("a branch version such as dev-main is unresolved with a note", async () => {
    await writeFile(join(work, "composer.lock"), lock([{ name: "magento/product-community-edition", version: "dev-main" }]));
    const result = await readProducts(work);
    expect(result.declarations).toHaveLength(1);
    expect(result.declarations[0]).toMatchObject({ precision: "unresolved", spec: "dev-main" });
    expect(result.declarations[0]).not.toHaveProperty("resolved");
    expect(result.notes).toHaveLength(1);
  });

  it("an unrelated lock produces no declarations and is still parsed", async () => {
    await writeFile(join(work, "composer.lock"), lock([{ name: "monolog/monolog", version: "3.5.0" }]));
    const result = await readProducts(work);
    expect(result.declarations).toEqual([]);
    expect(result.parsed).toEqual(["composer.lock"]);
  });

  it("a malformed composer.lock is skipped as malformed", async () => {
    await writeFile(join(work, "composer.lock"), '{"packages": [');
    const result = await readProducts(work);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([{ file: "composer.lock", reason: "malformed" }]);
  });

  it("a non-object composer.lock is malformed", async () => {
    await writeFile(join(work, "composer.lock"), "[]");
    const result = await readProducts(work);
    expect(result.skipped).toEqual([{ file: "composer.lock", reason: "malformed" }]);
  });

  it("single quotes, a BOM and CRLF in version.php", async () => {
    await mkdir(join(work, "wp-includes"));
    await writeFile(join(work, "wp-includes", "version.php"), "﻿<?php\r\n// $wp_version = '1.0';\r\n$wp_version = '6.5';\r\n");
    const result = await readProducts(work);
    expect(result.declarations).toEqual([decl("wordpress", "6.5", "wp-includes/version.php", 3, "wp-includes/version.php $wp_version")]);
  });

  async function versionPhp(body: string) {
    await mkdir(join(work, "wp-includes"), { recursive: true });
    await writeFile(join(work, "wp-includes", "version.php"), body);
    return readProducts(work);
  }

  it.each([
    ["a block-commented decoy", "<?php\n/*\n$wp_version = '1.0.0';\n*/\n$wp_version = '6.5.2';\n", 5],
    ["a line-commented decoy with a semicolon", "<?php\n// old; $wp_version = '1.0.0';\n$wp_version = '6.5.2';\n", 3],
    ["a hash-commented decoy", "<?php\n# $wp_version = '1.0.0';\n$wp_version = '6.5.2';\n", 3],
    ["an inline block comment before the real line", "<?php /* $wp_version = '1.0.0'; */ $wp_version = '6.5.2';\n", 1],
    ["a decoy inside a docblock", "<?php\n/**\n * Was: $wp_version = '1.0.0';\n */\n$wp_version = '6.5.2';\n", 5],
    ["a PHP 8 attribute that is not a comment", "<?php\n#[Attr]\n$wp_version = '6.5.2';\n", 3],
    ["a quote inside a comment", "<?php\n// it's the old one\n$wp_version = '6.5.2';\n", 3],
  ])("ignores %s", async (_name, body, line) => {
    const result = await versionPhp(body);
    expect(result.declarations).toEqual([decl("wordpress", "6.5.2", "wp-includes/version.php", line, "wp-includes/version.php $wp_version")]);
  });

  it("only a commented assignment means no declaration", async () => {
    const result = await versionPhp("<?php\n// $wp_version = '1.0.0';\n/* $wp_version = '2.0.0'; */\n");
    expect(result.declarations).toEqual([]);
    expect(result.parsed).toEqual(["wp-includes/version.php"]);
  });

  it("a comment marker inside a string is not a comment", async () => {
    const result = await versionPhp("<?php\n$x = '// not a comment';\n$wp_version = '6.5.2'; // trailing\n");
    expect(result.declarations).toEqual([decl("wordpress", "6.5.2", "wp-includes/version.php", 3, "wp-includes/version.php $wp_version")]);
  });

  it("reads the real WordPress version.php shape", async () => {
    const result = await versionPhp(`<?php
/**
 * WordPress Version
 *
 * Contains version information for the current WordPress release.
 *
 * @package WordPress
 * @since 1.2.0
 */

/**
 * The WordPress version string.
 *
 * Holds the current version number for WordPress core. Used to bust caches
 * and to enable development mode for scripts when running from the /src directory.
 *
 * @global string $wp_version
 */
$wp_version = '6.5.2';

/**
 * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
 *
 * @global int $wp_db_version
 */
$wp_db_version = 57155;

/**
 * Holds the TinyMCE version.
 *
 * @global string $tinymce_version
 */
$tinymce_version = '49110-20201110';

$required_php_version = '7.0.0';
`);
    expect(result.declarations).toEqual([decl("wordpress", "6.5.2", "wp-includes/version.php", 19, "wp-includes/version.php $wp_version")]);
  });

  it("an interpolating double-quoted value is not a literal", async () => {
    await mkdir(join(work, "wp-includes"));
    await writeFile(join(work, "wp-includes", "version.php"), '<?php\n$wp_version = "6.5.$patch";\n');
    const result = await readProducts(work);
    expect(result.declarations).toHaveLength(1);
    expect(result.declarations[0]).toMatchObject({ precision: "unresolved", line: 2 });
  });

  it("a version.php without $wp_version is parsed and silent", async () => {
    await mkdir(join(work, "wp-includes"));
    await writeFile(join(work, "wp-includes", "version.php"), "<?php\n$other = 1;\n");
    const result = await readProducts(work);
    expect(result.declarations).toEqual([]);
    expect(result.parsed).toEqual(["wp-includes/version.php"]);
  });

  it("ignores a version.php outside wp-includes", async () => {
    await writeFile(join(work, "version.php"), "<?php $wp_version = '6.5.2';");
    await mkdir(join(work, "xwp-includes"));
    await writeFile(join(work, "xwp-includes", "version.php"), "<?php $wp_version = '6.5.2';");
    const result = await readProducts(work);
    expect(result.declarations).toEqual([]);
    expect(result.parsed).toEqual([]);
  });

  it("reads wp-includes/version.php under vendor/ but never under node_modules/, and ignores a vendor composer.lock", async () => {
    const inVendor = join(work, "vendor", "johnpbloch", "wordpress-core", "wp-includes");
    await mkdir(inVendor, { recursive: true });
    await writeFile(join(inVendor, "version.php"), "<?php\n$wp_version = '6.4.3';\n");
    await writeFile(join(work, "vendor", "composer.lock"), lock([{ name: "roots/wordpress", version: "1.0.0" }]));
    const inModules = join(work, "node_modules", "wp", "wp-includes");
    await mkdir(inModules, { recursive: true });
    await writeFile(join(inModules, "version.php"), "<?php\n$wp_version = '5.0.0';\n");
    const result = await readProducts(work);
    expect(result.declarations.map((entry) => [entry.file, entry.spec])).toEqual([
      ["vendor/johnpbloch/wordpress-core/wp-includes/version.php", "6.4.3"],
    ]);
  });

  it("skips a symlinked composer.lock", async (ctx) => {
    await writeFile(join(work, "real.json"), lock([{ name: "roots/wordpress", version: "6.5.2" }]));
    try {
      await symlink(join(work, "real.json"), join(work, "composer.lock"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return ctx.skip();
      throw error;
    }
    const result = await readProducts(work);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([{ file: "composer.lock", reason: "symlink" }]);
  });

  it("accepts a composer.lock above 1 MiB (up to 16 MiB) and skips one above 16 MiB", async () => {
    const filler = Array.from({ length: 20_000 }, (_, index) => ({ name: `vendor/pkg-${index}`, version: "1.0.0", notes: "x".repeat(80) }));
    await writeFile(join(work, "composer.lock"), lock([...filler, { name: "magento/product-enterprise-edition", version: "2.4.7" }]));
    const accepted = await readProducts(work);
    expect(accepted.declarations.map((entry) => entry.spec)).toEqual(["2.4.7"]);
    await writeFile(join(work, "composer.lock"), JSON.stringify({ packages: [], pad: "x".repeat(17 * 1024 * 1024) }));
    const rejected = await readProducts(work);
    expect(rejected.declarations).toEqual([]);
    expect(rejected.skipped).toEqual([{ file: "composer.lock", reason: "oversized" }]);
  });

  it("a lock with more than 400000 containers is skipped as oversized before parsing, with a note", async () => {
    await writeFile(join(work, "composer.lock"), `{"packages":[${"{},".repeat(400_000)}{"name":"roots/wordpress","version":"6.5.2"}]}`);
    const result = await readProducts(work);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([{ file: "composer.lock", reason: "oversized" }]);
    expect(result.notes).toEqual(["composer.lock: more than 400000 JSON containers; not parsed"]);
  });

  it("brackets inside strings do not count toward the container limit", async () => {
    await writeFile(join(work, "composer.lock"), lock([{ name: "roots/wordpress", version: "6.5.2", note: "{".repeat(500_000) }]));
    const result = await readProducts(work);
    expect(result.declarations.map((entry) => entry.spec)).toEqual(["6.5.2"]);
  });

  it("a 16 MiB lock of empty objects is skipped without parsing", async () => {
    const body = `{"packages":[${"{},".repeat(5_580_000)}{}]}`;
    await writeFile(join(work, "composer.lock"), body);
    const result = await readProducts(work);
    expect(result.skipped).toEqual([{ file: "composer.lock", reason: "oversized" }]);
  });

  it("skips a 2 MiB version.php as oversized", async () => {
    await mkdir(join(work, "wp-includes"));
    await writeFile(join(work, "wp-includes", "version.php"), `<?php\n$wp_version = '6.5.2';\n// ${"x".repeat(2 * 1024 * 1024)}`);
    const result = await readProducts(work);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([{ file: "wp-includes/version.php", reason: "oversized" }]);
  });
});

describe("readProducts: hostile inputs", { timeout: 5000 }, () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-prod-hostile-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  async function timed(): Promise<{ result: Awaited<ReturnType<typeof readProducts>>; ms: number }> {
    const started = Date.now();
    const result = await readProducts(work);
    return { result, ms: Date.now() - started };
  }

  it("an expired deadline starts no file", async () => {
    await mkdir(join(work, "wp-includes"));
    await writeFile(join(work, "wp-includes", "version.php"), "<?php\n$wp_version = '6.4.1';\n");
    const controller = new AbortController();
    controller.abort();
    const result = await readProducts(work, { signal: controller.signal });
    expect(result.declarations).toEqual([]);
    expect(result.skipped.every((entry) => entry.reason === "deadline")).toBe(true);
    expect(result.skipped.length).toBeGreaterThan(0);
  });

  it.each([30_000, 100_000, 8_000_000])("a %d-deep nested-array composer.lock is malformed, quickly", async (depth) => {
    await writeFile(join(work, "composer.lock"), `{"packages":${"[".repeat(depth)}${"]".repeat(depth)}}`);
    const { result, ms } = await timed();
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([{ file: "composer.lock", reason: "malformed" }]);
    expect(ms).toBeLessThan(4000);
  });

  it("a 1 MiB composer.lock of nested objects is malformed", async () => {
    const depth = 200_000;
    await writeFile(join(work, "composer.lock"), `${'{"a":'.repeat(depth)}1${"}".repeat(depth)}`);
    const { result, ms } = await timed();
    expect(result.skipped).toEqual([{ file: "composer.lock", reason: "malformed" }]);
    expect(ms).toBeLessThan(4000);
  });

  it("many packages with an unterminated string never throws", async () => {
    await writeFile(join(work, "composer.lock"), `{"packages":[${'{"name":"a","version":"1"},'.repeat(50_000)}{"name":"unterminated`);
    const { result, ms } = await timed();
    expect(result.skipped).toEqual([{ file: "composer.lock", reason: "malformed" }]);
    expect(ms).toBeLessThan(4000);
  });

  it("90k packages stay linear and still find the product", async () => {
    const packages = `${'{"name":"a/b","version":"1.0.0"},'.repeat(90_000)}{"name":"magento/product-community-edition","version":"2.4.6-p3"}`;
    await writeFile(join(work, "composer.lock"), `{"packages":[${packages}]}`);
    const { result, ms } = await timed();
    expect(result.declarations.map((entry) => entry.spec)).toEqual(["2.4.6-p3"]);
    expect(ms).toBeLessThan(4000);
  });

  it("packages past the 100k cap are ignored with a note", async () => {
    const packages = `${'{"name":"a/b","version":"1.0.0"},'.repeat(100_000)}{"name":"magento/product-community-edition","version":"2.4.6-p3"}`;
    await writeFile(join(work, "composer.lock"), `{"packages":[${packages}]}`);
    const { result, ms } = await timed();
    expect(result.declarations).toEqual([]);
    expect(result.notes).toEqual(["composer.lock: more than 100000 packages; the rest is ignored"]);
    expect(ms).toBeLessThan(4000);
  });

  it("a 1 MiB version.php of repeated partial assignments is read quickly", async () => {
    await mkdir(join(work, "wp-includes"));
    await writeFile(join(work, "wp-includes", "version.php"), "$wp_version = \n".repeat(70_000));
    const { result, ms } = await timed();
    expect(result.declarations).toEqual([]);
    expect(ms).toBeLessThan(4000);
  });

  it("an over-long non-literal value is clipped in the declaration and note", async () => {
    await mkdir(join(work, "wp-includes"));
    await writeFile(join(work, "wp-includes", "version.php"), `<?php\n$wp_version = ${"x".repeat(250)};\n`);
    const { result } = await timed();
    expect(result.declarations).toHaveLength(1);
    expect(result.declarations[0]!.spec.length).toBeLessThanOrEqual(129);
    expect(result.notes[0]!.length).toBeLessThan(400);
  });

  it("a populated vendor tree does not disturb the main walk", async () => {
    await mkdir(join(work, "vendor", "org"), { recursive: true });
    for (let index = 0; index < 200; index++) await mkdir(join(work, "vendor", "org", `pkg-${index}`));
    await writeFile(join(work, "composer.lock"), JSON.stringify({ packages: [{ name: "roots/wordpress", version: "6.5.2" }] }));
    const { result } = await timed();
    expect(result.declarations.map((entry) => entry.spec)).toEqual(["6.5.2"]);
  });
});

describe("walkCandidates: vendor option", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-walk-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  const MATCH = [{ basename: "x.txt" }];
  const put = async (path: string) => {
    const full = join(work, ...path.split("/"));
    await mkdir(join(full, ".."), { recursive: true });
    await writeFile(full, "x");
  };

  it("does not enter vendor/ without the option", async () => {
    await put("vendor/a/x.txt");
    await put("x.txt");
    expect((await walkCandidates(work, MATCH)).files).toEqual(["x.txt"]);
  });

  it("shares one entry budget across every vendor directory", async () => {
    for (let dir = 0; dir < 10; dir++) {
      for (let file = 0; file < 40; file++) await put(`pkg${dir}/vendor/f${file}/x.txt`);
    }
    const result = await walkCandidates(work, MATCH, {}, { vendor: { maxDepth: 5, maxEntries: 100 } });
    // 10 vendor dirs x 80 entries each would be 800 entries (400 files) under per-directory budgets.
    expect(result.files.length).toBeLessThan(100);
    expect(result.files.length).toBeGreaterThan(0);
    expect(result.skipped.filter((entry) => entry.reason === "entry-limit")).toHaveLength(1);
  });

  it("bounds depth inside vendor silently", async () => {
    await put("vendor/a/b/x.txt");
    await put("vendor/a/b/c/x.txt");
    const result = await walkCandidates(work, MATCH, {}, { vendor: { maxDepth: 3, maxEntries: 1000 } });
    expect(result.files).toEqual(["vendor/a/b/x.txt"]);
    expect(result.skipped).toEqual([]);
  });

  it("enters a nested vendor/x/vendor under the same budget and depth", async () => {
    await put("vendor/x/vendor/x.txt");
    await put("vendor/x/vendor/y/z/w/x.txt");
    const result = await walkCandidates(work, MATCH, {}, { vendor: { maxDepth: 5, maxEntries: 1000 } });
    expect(result.files).toEqual(["vendor/x/vendor/x.txt"]);
    const tight = await walkCandidates(work, MATCH, {}, { vendor: { maxDepth: 2, maxEntries: 1000 } });
    expect(tight.files).toEqual([]);
  });

  it("never enters node_modules, even inside vendor", async () => {
    await put("vendor/node_modules/x.txt");
    await put("node_modules/x.txt");
    await put("vendor/ok/x.txt");
    const result = await walkCandidates(work, MATCH, {}, { vendor: { maxDepth: 5, maxEntries: 1000 } });
    expect(result.files).toEqual(["vendor/ok/x.txt"]);
  });
});
