import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { packageEntryLine, packageLine, readLockfileLines } from "./package-line.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

/** The 1-based line of the package's own entry in a lockfile written to a temporary file. */
async function entry(file: string, text: string, name: string): Promise<number> {
  const root = await mkdtemp(join(tmpdir(), "ci-package-line-"));
  roots.push(root);
  await writeFile(join(root, file), text, "utf8");
  return packageEntryLine(await readLockfileLines(join(root, file)), file, name);
}

/** Lines numbered from 1: `lines("a", "b")` → "a\nb". */
const lines = (...items: string[]): string => items.join("\n");

describe("packageEntryLine: the package's own key, never a longer name that contains it", () => {
  it("package-lock.json v3: node_modules/electron, not electron-updater or the root dependency list", async () => {
    const text = lines(
      "{", '  "lockfileVersion": 3,', '  "packages": {', '    "": {', '      "dependencies": {',
      '        "electron-updater": "^6.8.9"', "      },", '      "devDependencies": {', '        "electron": "^42.11.16"', "      }", "    },",
      '    "node_modules/electron-updater": {', '      "version": "6.8.9"', "    },",
      '    "node_modules/electron": {', '      "version": "42.11.16"', "    }", "  }", "}",
    );
    expect(await entry("package-lock.json", text, "electron")).toBe(15);
    expect(await entry("package-lock.json", text, "electron-updater")).toBe(12);
  });

  it("package-lock.json v1 and nested node_modules", async () => {
    const v1 = lines("{", '  "dependencies": {', '    "electron-updater": {', '      "version": "6.8.9"', "    },", '    "electron": {', '      "version": "42.11.16"', "    }", "  }", "}");
    expect(await entry("package-lock.json", v1, "electron")).toBe(6);
    const nested = lines("{", '  "packages": {', '    "node_modules/a/node_modules/@scope/pkg": {', '      "version": "1.0.0"', "    }", "  }", "}");
    expect(await entry("npm-shrinkwrap.json", nested, "@scope/pkg")).toBe(3);
  });

  it("yarn.lock, pnpm-lock.yaml and bun.lock keys", async () => {
    const yarn = lines('"electron-updater@^6.8.9":', '  version "6.8.9"', "", 'electron@^42.11.16, "electron@npm:^42":', '  version "42.11.16"');
    expect(await entry("yarn.lock", yarn, "electron")).toBe(4);
    const pnpm = lines("importers:", "  .:", "    devDependencies:", "      electron:", "        specifier: ^42", "packages:", "  electron-updater@6.8.9:", "    resolution: {}", "  electron@42.11.16:", "    resolution: {}");
    expect(await entry("pnpm-lock.yaml", pnpm, "electron")).toBe(9);
    const pnpmV6 = lines("packages:", "  /electron-updater@6.8.9:", "    resolution: {}", "  /electron@42.11.16:", "    resolution: {}");
    expect(await entry("pnpm-lock.yaml", pnpmV6, "electron")).toBe(4);
    const bun = lines("{", '  "packages": {', '    "electron-updater": ["electron-updater@6.8.9", {}],', '    "electron": ["electron@42.11.16", {}],', "  }", "}");
    expect(await entry("bun.lock", bun, "electron")).toBe(4);
  });

  it("composer.lock, Python, Ruby, Go and Rust lockfiles", async () => {
    const composer = lines("{", '  "packages": [', "    {", '      "name": "magento/product-community-edition-extra",', "    },", "    {", '      "name": "magento/product-community-edition",', '      "version": "2.4.6-p11"', "    }", "  ]", "}");
    expect(await entry("composer.lock", composer, "magento/product-community-edition")).toBe(7);
    const poetry = lines("[[package]]", 'name = "requests-oauthlib"', "", "[[package]]", 'name = "requests"');
    expect(await entry("poetry.lock", poetry, "requests")).toBe(5);
    expect(await entry("poetry.lock", lines("[[package]]", 'name = "zope-interface"'), "zope.interface")).toBe(2);
    const gems = lines("GEM", "  specs:", "    rails-html-sanitizer (1.6.0)", "      loofah (~> 2.21)", "    rails (7.1.0)");
    expect(await entry("Gemfile.lock", gems, "rails")).toBe(5);
    const gosum = lines("github.com/x/yaml-extra v1.0.0 h1:abc", "github.com/x/yaml v1.2.0 h1:def");
    expect(await entry("go.sum", gosum, "github.com/x/yaml")).toBe(2);
    const cargo = lines("[[package]]", 'name = "serde_json"', "", "[[package]]", 'name = "serde"');
    expect(await entry("Cargo.lock", cargo, "serde")).toBe(5);
  });

  it("any other file: a whole-name match, else line 1", async () => {
    expect(await entry("deps.lock", lines("electron-updater 6.8.9", "electron 42.11.16"), "electron")).toBe(2);
    expect(await entry("deps.lock", lines("nothing here"), "electron")).toBe(1);
    expect(packageEntryLine(undefined, "package-lock.json", "electron")).toBe(1);
  });

  it("packageLine (osv-scanner locations, a fingerprint input) is unchanged: first line containing the name", async () => {
    const root = await mkdtemp(join(tmpdir(), "ci-package-line-"));
    roots.push(root);
    await writeFile(join(root, "package-lock.json"), lines("{", '  "electron-updater": "^6.8.9",', '  "node_modules/electron": {}', "}"));
    expect(packageLine(await readLockfileLines(join(root, "package-lock.json")), "electron")).toBe(2);
  });
});
