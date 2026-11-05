import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { packageEntryLine, readLockfileLines } from "./package-line.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

/** The 1-based line of the package's own entry in a lockfile written to a temporary file. */
async function entry(file: string, text: string, name: string, version?: string): Promise<number> {
  const root = await mkdtemp(join(tmpdir(), "ci-package-line-"));
  roots.push(root);
  await writeFile(join(root, file), text, "utf8");
  return packageEntryLine(await readLockfileLines(join(root, file)), file, name, version);
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

  it("osv-scanner field cases: the versioned entry, never a substring hit or another version's entry", async () => {
    // PicGo pnpm v9: `tar@7.5.2` was reported at `'@babel/helper-compilation-targets@7.27.2':` (first substring
    // match); tar@6.2.1 and tar@7.5.2 are both locked, and each appears again under `snapshots:`.
    const pnpm = lines(
      "lockfileVersion: '9.0'", "packages:", "  '@babel/helper-compilation-targets@7.27.2':", "    resolution: {}",
      "    deprecated: Old versions of tar are not supported", "  tar@6.2.1:", "    resolution: {}",
      "    deprecated: Old versions of tar are not supported", "  tar@7.5.2:", "    resolution: {}",
      "snapshots:", "  tar@6.2.1: {}", "  tar@7.5.2: {}",
    );
    expect(await entry("pnpm-lock.yaml", pnpm, "tar", "7.5.2")).toBe(9);
    expect(await entry("pnpm-lock.yaml", pnpm, "tar", "6.2.1")).toBe(6);
    // cortext: `ws` was reported at `'@wordpress/dataviews':` in the importers section.
    const ws = lines("importers:", "  .:", "    dependencies:", "      '@wordpress/dataviews':", "        version: 1.0.0", "packages:", "  ws@7.5.10:", "    resolution: {}", "  ws@8.18.0:", "    resolution: {}");
    expect(await entry("pnpm-lock.yaml", ws, "ws", "8.18.0")).toBe(9);
    expect(await entry("pnpm-lock.yaml", lines("packages:", "  /ws@7.5.10:", "    resolution: {}", "  /ws@8.18.0:"), "ws", "8.18.0")).toBe(4);
    // personal-management-system: `symfony/http-foundation` was reported at another package's `require` line.
    const composer = lines(
      "{", '    "packages": [', "        {", '            "name": "symfony/security-bundle",', '            "version": "v5.4.0",',
      '            "require": {', '                "symfony/http-foundation": "^5.4 || ^6.0"', "            }", "        },", "        {",
      '            "name": "symfony/http-foundation",', '            "version": "v5.4.0",', "        }", "    ]", "}",
    );
    expect(await entry("composer.lock", composer, "symfony/http-foundation", "5.4.0")).toBe(11);
  });

  it("the version picks between entries of one name in every lockfile format, else the first entry", async () => {
    const lockV3 = lines(
      "{", '  "packages": {', '    "node_modules/tar": {', '      "version": "6.2.1"', "    },",
      '    "node_modules/cacache/node_modules/tar": {', '      "version": "7.5.2"', "    }", "  }", "}",
    );
    expect(await entry("package-lock.json", lockV3, "tar", "7.5.2")).toBe(6);
    expect(await entry("package-lock.json", lockV3, "tar", "6.2.1")).toBe(3);
    expect(await entry("package-lock.json", lockV3, "tar", "9.9.9")).toBe(3);
    const yarn = lines('"@babel/helper-compilation-targets@^7.27.2":', '  version "7.27.2"', "", "tar@^6.1.0:", '  version "6.2.1"', "", "tar@^7.4.3:", '  version "7.5.2"');
    expect(await entry("yarn.lock", yarn, "tar", "7.5.2")).toBe(7);
    const berry = lines('"tar@npm:^6.1.0, tar@npm:^6.1.11":', "  version: 6.2.1", "", '"tar@npm:^7.4.3":', "  version: 7.5.2");
    expect(await entry("yarn.lock", berry, "tar", "7.5.2")).toBe(4);
    const poetry = lines("[[package]]", 'name = "urllib3"', 'version = "1.26.20"', "", "[[package]]", 'name = "urllib3"', 'version = "2.2.3"');
    expect(await entry("poetry.lock", poetry, "urllib3", "2.2.3")).toBe(6);
    const gosum = lines("golang.org/x/net v0.17.0 h1:a", "golang.org/x/net v0.17.0/go.mod h1:b", "golang.org/x/net v0.33.0 h1:c");
    expect(await entry("go.sum", gosum, "golang.org/x/net", "0.33.0")).toBe(3);
    const gems = lines("GEM", "  specs:", "    rack (2.2.8)", "    rack (3.1.8)");
    expect(await entry("Gemfile.lock", gems, "rack", "3.1.8")).toBe(4);
  });
});
