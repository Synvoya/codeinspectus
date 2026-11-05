import { lstat, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";

import type { Declaration } from "./types.js";
import { composerPurl, declaredPackageInventory, goStdlibPurl, libraryInventory, npmPurl, parsePurl, SBOM_MAX_COMPONENTS, writeCycloneDx, type SbomItem } from "./sbom.js";

/** The subset of the CycloneDX 1.5 JSON schema (bom-1.5.schema.json) this writer relies on, strict. */
const componentSchema = z.object({
  type: z.literal("library"),
  "bom-ref": z.string().min(1),
  name: z.string().min(1),
  version: z.string().min(1),
  purl: z.string().regex(/^pkg:[a-z][a-z0-9.+-]*\/.+@.+$/),
}).strict();
const bomSchema = z.object({
  bomFormat: z.literal("CycloneDX"),
  specVersion: z.literal("1.5"),
  version: z.number().int().min(1),
  components: z.array(componentSchema),
}).strict();

let work: string;
beforeEach(async () => {
  work = await mkdtemp(join(tmpdir(), "ci-synvoya-sbom-"));
});
afterEach(async () => {
  await rm(work, { recursive: true, force: true });
});

const items: SbomItem[] = [
  { purl: npmPurl("jquery", "1.12.4"), ref: "public/js/jquery-1.12.4.min.js:1" },
  { purl: npmPurl("@popperjs/core", "2.11.8"), ref: "index.html:9" },
  { purl: npmPurl("bootstrap", "3.3.7"), ref: "index.html:4" },
  { purl: npmPurl("jquery", "1.12.4"), ref: "index.html:3" },
];

describe("npmPurl / parsePurl", () => {
  it("percent-encodes the scope's @ and keeps a plain name readable", () => {
    expect(npmPurl("@popperjs/core", "2.11.8")).toBe("pkg:npm/%40popperjs/core@2.11.8");
    expect(npmPurl("jquery", "3.7.10-beta.2")).toBe("pkg:npm/jquery@3.7.10-beta.2");
    expect(npmPurl("chart.js", "2.9.4")).toBe("pkg:npm/chart.js@2.9.4");
    expect(npmPurl("x", "1.0.0+build")).toBe("pkg:npm/x@1.0.0%2Bbuild");
  });

  it("reads back the type, the full package name and the version", () => {
    expect(parsePurl("pkg:npm/%40popperjs/core@2.11.8")).toEqual({ type: "npm", name: "@popperjs/core", version: "2.11.8" });
    expect(parsePurl("pkg:composer/magento/product-community-edition@2.4.7")).toEqual({
      type: "composer",
      name: "magento/product-community-edition",
      version: "2.4.7",
    });
  });

  it("rejects anything that is not a plain purl with a version", () => {
    for (const bad of ["", "pkg:npm/jquery", "npm/jquery@1.0.0", "pkg:npm/@1.0.0", "pkg:npm/%E0%A4%A@1.0.0", "pkg:npm/jquery@1.0.0?x=1", "pkg:npm/a/../b@1.0.0", `pkg:npm/${"a".repeat(600)}@1.0.0`]) {
      expect(parsePurl(bad), bad).toBeUndefined();
    }
  });
});

describe("writeCycloneDx", () => {
  it("writes a CycloneDX 1.5 document whose components name each purl's package and version", async () => {
    const path = join(work, "inventory.cdx.json");
    expect(await writeCycloneDx(items, path)).toEqual({ written: 4, skipped: 0, omittedRefs: [] });
    const bom = bomSchema.parse(JSON.parse(await readFile(path, "utf8")));
    expect(bom.components).toEqual([
      { type: "library", "bom-ref": "index.html:9", name: "@popperjs/core", version: "2.11.8", purl: "pkg:npm/%40popperjs/core@2.11.8" },
      { type: "library", "bom-ref": "index.html:4", name: "bootstrap", version: "3.3.7", purl: "pkg:npm/bootstrap@3.3.7" },
      { type: "library", "bom-ref": "index.html:3", name: "jquery", version: "1.12.4", purl: "pkg:npm/jquery@1.12.4" },
      { type: "library", "bom-ref": "public/js/jquery-1.12.4.min.js:1", name: "jquery", version: "1.12.4", purl: "pkg:npm/jquery@1.12.4" },
    ]);
  });

  it("is byte-for-byte deterministic whatever the input order, and drops exact duplicates", async () => {
    const first = join(work, "a.cdx.json");
    const second = join(work, "b.cdx.json");
    await writeCycloneDx(items, first);
    await writeCycloneDx([...items].reverse().concat(items[0]!), second);
    expect(await readFile(second)).toEqual(await readFile(first));
    expect((await readFile(first, "utf8")).endsWith("}\n")).toBe(true);
  });

  it("skips an item whose purl or ref it cannot write, and names it", async () => {
    const path = join(work, "inventory.cdx.json");
    const result = await writeCycloneDx([...items, { purl: "pkg:npm/jquery", ref: "bad.js:1" }, { purl: npmPurl("x", "1.0.0"), ref: "" }], path);
    expect(result).toEqual({ written: 4, skipped: 2, omittedRefs: ["", "bad.js:1"] });
    expect(bomSchema.parse(JSON.parse(await readFile(path, "utf8"))).components).toHaveLength(4);
  });

  it(`writes at most ${SBOM_MAX_COMPONENTS} components and names the rest`, async () => {
    const many = Array.from({ length: SBOM_MAX_COMPONENTS + 2 }, (_, index) => ({ purl: npmPurl("jquery", "1.12.4"), ref: `f${String(index).padStart(6, "0")}.js:1` }));
    const path = join(work, "inventory.cdx.json");
    const result = await writeCycloneDx(many, path);
    expect(result).toEqual({ written: SBOM_MAX_COMPONENTS, skipped: 2, omittedRefs: ["f020000.js:1", "f020001.js:1"] });
    expect(bomSchema.parse(JSON.parse(await readFile(path, "utf8"))).components).toHaveLength(SBOM_MAX_COMPONENTS);
  });

  it("never writes through an existing file or link", async () => {
    const victim = join(work, "victim.txt");
    await writeFile(victim, "keep");
    const path = join(work, "inventory.cdx.json");
    await symlink(victim, path);
    await expect(writeCycloneDx(items, path)).rejects.toThrow();
    expect(await readFile(victim, "utf8")).toBe("keep");
    expect((await lstat(path)).isSymbolicLink()).toBe(true);
  });
});

describe("libraryInventory", () => {
  const decl = (name: string, spec: string, precision: Declaration["precision"], file: string, line: number): Declaration => ({
    subject: { type: "package", ecosystem: "npm", name },
    spec,
    ...(precision === "exact" ? { resolved: spec } : {}),
    precision,
    file,
    line,
    source: "cdn-url",
    producer: "vendored",
  });

  it("turns exact library declarations into SBOM items that link back to their file and line; floating ones only into notes", () => {
    const inventory = libraryInventory([
      decl("jquery", "1.12.4", "exact", "public/js/jquery-1.12.4.min.js", 1),
      decl("jquery", "3", "floating", "index.html", 7),
      decl("jquery", "latest", "unresolved", "index.html", 8),
      decl("@popperjs/core", "2.11.8", "exact", "index.html", 9),
    ]);
    // Refs are opaque and numbered in (file, line, purl) order, so the SBOM holds no repository path.
    expect(inventory.items).toEqual([
      { purl: "pkg:npm/%40popperjs/core@2.11.8", ref: "lib-1" },
      { purl: "pkg:npm/jquery@1.12.4", ref: "lib-2" },
    ]);
    expect(inventory.byRef.get("lib-1")).toMatchObject({ file: "index.html", line: 9 });
    expect(inventory.byRef.get("lib-2")).toMatchObject({ file: "public/js/jquery-1.12.4.min.js", line: 1 });
    expect(inventory.notes).toEqual([
      'index.html:7: cdn-url names jquery "3", not an exact version; only exact versions of vendored and CDN libraries are checked against the OSV npm database, so a rescan cannot confirm a fix in this file.',
    ]);
    // Review C1: a floating declaration's file was never checked by osv-scanner.
    expect([...inventory.floatingFiles]).toEqual(["index.html"]);
  });

  it("two libraries on one line get distinct refs", () => {
    const inventory = libraryInventory([decl("jquery", "1.12.4", "exact", "index.html", 3), decl("bootstrap", "3.3.7", "exact", "index.html", 3)]);
    expect(inventory.items).toEqual([{ purl: "pkg:npm/bootstrap@3.3.7", ref: "lib-1" }, { purl: "pkg:npm/jquery@1.12.4", ref: "lib-2" }]);
  });

  it("ignores declarations of other readers", () => {
    const runtime: Declaration = { subject: { type: "runtime", runtime: "node" }, spec: "20.1.0", resolved: "20.1.0", precision: "exact", file: ".nvmrc", line: 1, source: ".nvmrc", producer: "runtime" };
    expect(libraryInventory([runtime]).items).toEqual([]);
  });
});

describe("declaredPackageInventory: Magento editions", () => {
  const ALIASES = {
    "Packagist:magento/product-community-edition": "Packagist:magento/community-edition",
    "Packagist:magento/magento2-base": "Packagist:magento/community-edition",
  };
  const edition = (product: string, name: string, spec: string, precision: Declaration["precision"], file = "src/composer.lock", line = 17142): Declaration => ({
    subject: { type: "product", product },
    spec,
    ...(precision === "exact" ? { resolved: spec } : {}),
    precision,
    file,
    line,
    source: `composer.lock ${name}`,
    producer: "products",
  });

  it("checks a Magento Open Source lock under the advisory name GitHub uses, at the original package's file and line", () => {
    const inventory = declaredPackageInventory([edition("magento-open-source", "magento/product-community-edition", "2.4.7-p2", "exact")], ALIASES);
    expect(inventory.packages).toEqual([{
      ref: "composer-1",
      purl: "pkg:composer/magento/community-edition@2.4.7-p2",
      ecosystem: "Packagist",
      name: "magento/community-edition",
      version: "2.4.7-p2",
      declaredName: "magento/product-community-edition",
      decl: expect.objectContaining({ file: "src/composer.lock", line: 17142 }),
    }]);
    expect(inventory.uncheckedFiles.size).toBe(0);
    expect(inventory.notes).toEqual([]);
  });

  it("follows the alias table for magento/magento2-base too", () => {
    const inventory = declaredPackageInventory([edition("magento-open-source", "magento/magento2-base", "2.4.6-p11", "exact", "composer.lock", 5756)], ALIASES);
    expect(inventory.packages.map((pkg) => [pkg.purl, pkg.declaredName, pkg.decl.line])).toEqual([
      ["pkg:composer/magento/community-edition@2.4.6-p11", "magento/magento2-base", 5756],
    ]);
  });

  it("an edition with no alias (Adobe Commerce), or no exact version, is not checked: its file is never SBOM-checked", () => {
    const inventory = declaredPackageInventory([
      edition("adobe-commerce", "magento/product-enterprise-edition", "2.4.7-p2", "exact", "ee/composer.lock", 40),
      edition("magento-open-source", "magento/product-community-edition", "dev-2.4-develop", "unresolved", "dev/composer.lock", 12),
    ], ALIASES);
    expect(inventory.packages).toEqual([]);
    expect([...inventory.uncheckedFiles].sort()).toEqual(["dev/composer.lock", "ee/composer.lock"]);
    expect(inventory.notes).toEqual([
      "ee/composer.lock:40: magento/product-enterprise-edition 2.4.7-p2 has no package name in the OSV Packagist database, so osv-scanner does not check it; a rescan cannot confirm a fix in this file through osv-scanner.",
    ]);
  });

  it("without the alias table nothing is checked under another name", () => {
    const inventory = declaredPackageInventory([edition("magento-open-source", "magento/product-community-edition", "2.4.7-p2", "exact")], {});
    expect(inventory.packages).toEqual([]);
    expect([...inventory.uncheckedFiles]).toEqual(["src/composer.lock"]);
  });

  it("ignores WordPress and other readers' declarations", () => {
    const wordpress = edition("wordpress", "roots/wordpress", "6.5.0", "exact");
    const runtime: Declaration = { subject: { type: "runtime", runtime: "node" }, spec: "20.1.0", resolved: "20.1.0", precision: "exact", file: ".nvmrc", line: 1, source: ".nvmrc", producer: "runtime" };
    const inventory = declaredPackageInventory([wordpress, runtime], ALIASES);
    expect(inventory.packages).toEqual([]);
    expect(inventory.uncheckedFiles.size).toBe(0);
  });

  it("composerPurl percent-encodes each segment and parsePurl reads it back", () => {
    expect(composerPurl("magento/community-edition", "2.4.7-p2")).toBe("pkg:composer/magento/community-edition@2.4.7-p2");
    expect(parsePurl(composerPurl("magento/community-edition", "2.4.7-p2"))).toEqual({ type: "composer", name: "magento/community-edition", version: "2.4.7-p2" });
  });
});

describe("declaredPackageInventory: the Go toolchain", () => {
  const go = (spec: string, precision: Declaration["precision"], file: string, line: number, source: string, producer: Declaration["producer"]): Declaration => ({
    subject: { type: "runtime", runtime: "go" },
    spec,
    ...(precision === "exact" ? { resolved: spec } : {}),
    precision,
    file,
    line,
    source,
    producer,
  });

  it("an exact go.mod toolchain and an exact golang image become the Go standard library at that release", () => {
    const inventory = declaredPackageInventory([
      go("1.22.5", "exact", "go.mod", 5, "go.mod toolchain", "runtime"),
      go("1.23.4", "exact", "build/Dockerfile", 1, "Dockerfile FROM", "images"),
    ], {});
    expect(inventory.packages).toEqual([
      { ref: "go-1", purl: "pkg:golang/stdlib@v1.23.4", ecosystem: "Go", name: "stdlib", version: "v1.23.4", decl: expect.objectContaining({ file: "build/Dockerfile", line: 1 }) },
      { ref: "go-2", purl: "pkg:golang/stdlib@v1.22.5", ecosystem: "Go", name: "stdlib", version: "v1.22.5", decl: expect.objectContaining({ file: "go.mod", line: 5 }) },
    ]);
    expect(inventory.uncheckedFiles.size).toBe(0);
  });

  it("a floating golang image is never checked and keeps its file out; a go.mod `go` minimum is the runtime producer's, not an SBOM input", () => {
    const inventory = declaredPackageInventory([
      go(">=1.22", "range", "go.mod", 3, "go.mod go", "runtime"),
      go("1.22.5", "exact", "go.mod", 5, "go.mod toolchain", "runtime"),
      go("1.23", "floating", "Dockerfile", 1, "Dockerfile FROM", "images"),
    ], {});
    expect(inventory.packages.map((pkg) => pkg.purl)).toEqual(["pkg:golang/stdlib@v1.22.5"]);
    expect([...inventory.uncheckedFiles]).toEqual(["Dockerfile"]);
    expect(inventory.notes).toEqual([
      'Dockerfile:1: Dockerfile FROM names Go "1.23", not an exact release; the Go standard library is checked against the OSV Go database only for an exact go.mod toolchain or golang image, so a rescan cannot confirm a Go fix in this file through osv-scanner.',
    ]);
  });

  it("other Go declarations (setup-go, .tool-versions) are not SBOM inputs and leave their files alone", () => {
    const inventory = declaredPackageInventory([
      go("1.22.5", "exact", ".github/workflows/ci.yml", 9, "actions/setup-go go-version", "runtime"),
      go("1.22.5", "exact", ".tool-versions", 1, ".tool-versions", "runtime"),
    ], {});
    expect(inventory.packages).toEqual([]);
    expect(inventory.uncheckedFiles.size).toBe(0);
  });

  it("an exact release with a suffix is not a Go standard library version osv-scanner can match: not checked", () => {
    const inventory = declaredPackageInventory([go("1.22.5-rc1", "exact", "go.mod", 5, "go.mod toolchain", "runtime")], {});
    expect(inventory.packages).toEqual([]);
    expect([...inventory.uncheckedFiles]).toEqual(["go.mod"]);
  });

  it("goStdlibPurl", () => {
    expect(goStdlibPurl("1.22.5")).toBe("pkg:golang/stdlib@v1.22.5");
    expect(parsePurl(goStdlibPurl("1.22.5"))).toEqual({ type: "golang", name: "stdlib", version: "v1.22.5" });
  });
});
