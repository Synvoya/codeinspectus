import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  detectOsvEcosystems,
  detectOsvLockfiles,
  normalizePackageName,
  OSV_DB_SIZE_ESTIMATES,
  OSV_DB_NOTES,
  OSV_ECOSYSTEMS,
  OSV_OVERLAY_ECOSYSTEMS,
  OSV_PUBLISHED_ECOSYSTEMS,
  OSV_SCHEMA_ECOSYSTEMS,
  isOverlaySegment,
  parseOsvEcosystems,
} from "./ecosystems.js";

let root: string;

async function touch(relativePath: string): Promise<void> {
  const path = join(root, relativePath);
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, "");
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "codeinspectus-osv-eco-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("OSV ecosystem allow-list", () => {
  test("rejects distro ecosystems", () => {
    for (const distro of ["Debian", "Alpine", "Ubuntu", "Wolfi", "Chainguard"]) {
      expect(OSV_ECOSYSTEMS as readonly string[]).not.toContain(distro);
    }
  });

  test("lists exactly the language ecosystems, each with a measured size estimate", () => {
    expect([...OSV_ECOSYSTEMS]).toEqual([
      "npm", "PyPI", "Packagist", "Go", "crates.io", "RubyGems", "Maven", "NuGet", "Pub", "GitHub Actions",
    ]);
    expect(OSV_DB_SIZE_ESTIMATES).toEqual({
      npm: 219_599_455,
      PyPI: 37_544_046,
      Packagist: 11_063_339,
      Go: 12_675_916,
      "crates.io": 3_737_559,
      RubyGems: 5_203_275,
      Maven: 10_466_352,
      NuGet: 2_680_919,
      Pub: 25_896,
      "GitHub Actions": 100_334,
    });
  });

  test("names the data licence of the GitHub Actions database, which only the Synvoya Actions matcher reads", () => {
    expect(OSV_DB_NOTES["GitHub Actions"]).toMatch(/GHSA.*CC-BY-4\.0/);
    expect(OSV_DB_NOTES["GitHub Actions"]).toMatch(/never by osv-scanner/);
  });
});

describe("OSV published and schema ecosystems (scan overlay only)", () => {
  test("include every allow-listed ecosystem", () => {
    for (const ecosystem of OSV_ECOSYSTEMS) {
      expect(OSV_PUBLISHED_ECOSYSTEMS).toContain(ecosystem);
      expect(OSV_SCHEMA_ECOSYSTEMS).toContain(ecosystem);
    }
    expect(OSV_PUBLISHED_ECOSYSTEMS).toContain("SwiftURL");
  });

  test("the overlay seeds the union of the allow-list, the bucket list and the schema enum", () => {
    expect(new Set(OSV_OVERLAY_ECOSYSTEMS)).toEqual(
      new Set([...OSV_ECOSYSTEMS, ...OSV_PUBLISHED_ECOSYSTEMS, ...OSV_SCHEMA_ECOSYSTEMS]),
    );
    // In the schema but not in the bucket's ecosystems.txt: a conan.lock stopped osv-scanner 2.7.0 without it.
    expect(OSV_PUBLISHED_ECOSYSTEMS).not.toContain("ConanCenter");
    expect(OSV_OVERLAY_ECOSYSTEMS).toContain("ConanCenter");
    expect(OSV_SCHEMA_ECOSYSTEMS).toHaveLength(53);
  });

  test.each([
    ["bucket list", OSV_PUBLISHED_ECOSYSTEMS],
    ["schema enum", OSV_SCHEMA_ECOSYSTEMS],
    ["overlay union", OSV_OVERLAY_ECOSYSTEMS],
  ])("each %s name is one distinct path segment, also on case-insensitive file systems", (_name, list) => {
    for (const ecosystem of list) {
      // The same check the overlay applies at run time.
      expect(isOverlaySegment(ecosystem)).toBe(true);
      expect(ecosystem).not.toMatch(/[\\/:]/);
    }
    expect(list).not.toContain("[EMPTY]");
    expect(new Set(list.map((ecosystem) => ecosystem.toLowerCase())).size).toBe(list.length);
  });
});

test("isOverlaySegment refuses anything but one plain path segment", () => {
  for (const name of ["PyPI", "crates.io", "Azure Linux", "OSS-Fuzz", "a_b", "ConanCenter", "Console", "COM0", "LPT10"]) {
    expect(isOverlaySegment(name)).toBe(true);
  }
  // Windows reserved device names, with or without an extension, in any case.
  for (const name of ["CON", "con", "PRN", "Aux", "NUL", "nul.zip", "COM1", "com9", "LPT1", "LPT9.x"]) {
    expect(isOverlaySegment(name)).toBe(false);
  }
  for (const name of ["", ".", "..", "../x", "a..b", "a/b", "a\\b", "C:", "Alpine:v3.18", " lead", "-x", "a\u0000b", "x".repeat(65), "Go.", "Go "]) {
    expect(isOverlaySegment(name)).toBe(false);
  }
});

describe("detectOsvEcosystems", () => {
  test("detects ecosystems from lockfile names", async () => {
    await touch("requirements.txt");
    await touch("sub/composer.lock");
    // Dependency trees never contribute: a vendored package's own lockfile is not this repo's.
    await touch("node_modules/x/package-lock.json");

    expect(await detectOsvEcosystems(root)).toEqual(["PyPI", "Packagist"]);
  });

  test("offers the GitHub Actions database for a repository with workflows, never as a lockfile", async () => {
    await touch("requirements.txt");
    await touch(".github/workflows/ci.yml");

    expect(await detectOsvEcosystems(root)).toEqual(["PyPI", "GitHub Actions"]);
    // osv-scanner never reads workflows: they are not lockfiles for its run or its reconciliation.
    expect(await detectOsvLockfiles(root)).toEqual([{ path: "requirements.txt", ecosystem: "PyPI" }]);
  });

  test("does not offer the GitHub Actions database for a workflows folder with no workflow, or a linked one", async () => {
    await touch(".github/workflows/README.md");
    expect(await detectOsvEcosystems(root)).toEqual([]);
    await mkdir(join(root, "elsewhere"), { recursive: true });
    await writeFile(join(root, "elsewhere", "ci.yml"), "on: push\n");
    await symlink(join(root, "elsewhere", "ci.yml"), join(root, ".github", "workflows", "linked.yml"));
    expect(await detectOsvEcosystems(root)).toEqual([]);
  });

  test("lists each lockfile with its ecosystem, relative to the target and sorted by path", async () => {
    await touch("sub/composer.lock");
    await touch("requirements.txt");
    await touch("web/app/package-lock.json");
    await touch("node_modules/x/package-lock.json");

    expect(await detectOsvLockfiles(root)).toEqual([
      { path: "requirements.txt", ecosystem: "PyPI" },
      { path: "sub/composer.lock", ecosystem: "Packagist" },
      { path: "web/app/package-lock.json", ecosystem: "npm" },
    ]);
    expect(await detectOsvLockfiles(join(root, "sub", "composer.lock"))).toEqual([{ path: "composer.lock", ecosystem: "Packagist" }]);
  });

  test("maps every supported lockfile name to its ecosystem, case-insensitively", async () => {
    const expected: Record<string, string> = {
      "package-lock.json": "npm",
      "npm-shrinkwrap.json": "npm",
      "yarn.lock": "npm",
      "pnpm-lock.yaml": "npm",
      "bun.lock": "npm",
      "requirements-dev.txt": "PyPI",
      "poetry.lock": "PyPI",
      "Pipfile.lock": "PyPI",
      "uv.lock": "PyPI",
      "pdm.lock": "PyPI",
      "composer.lock": "Packagist",
      "go.mod": "Go",
      "Cargo.lock": "crates.io",
      "Gemfile.lock": "RubyGems",
      "pom.xml": "Maven",
      "gradle.lockfile": "Maven",
      "packages.lock.json": "NuGet",
      "pubspec.lock": "Pub",
    };
    for (const [name, ecosystem] of Object.entries(expected)) {
      const dir = await mkdtemp(join(root, "case-"));
      await writeFile(join(dir, name), "");
      expect(await detectOsvEcosystems(dir), name).toEqual([ecosystem]);
    }
    const upper = await mkdtemp(join(root, "case-"));
    await writeFile(join(upper, "CARGO.LOCK"), "");
    expect(await detectOsvEcosystems(upper)).toEqual(["crates.io"]);
  });

  test("returns ecosystems in allow-list order whatever the discovery order", async () => {
    for (const name of ["pubspec.lock", "Gemfile.lock", "go.mod", "yarn.lock"]) await touch(name);
    expect(await detectOsvEcosystems(root)).toEqual(["npm", "Go", "RubyGems", "Pub"]);
  });

  test("ignores non-lockfiles and other generated or VCS trees", async () => {
    await touch("package.json");
    await touch("requirements.md");
    await touch("notes/requirements.txt.bak");
    await touch(".git/composer.lock");
    await touch("vendor/Cargo.lock");
    await touch("dist/yarn.lock");
    expect(await detectOsvEcosystems(root)).toEqual([]);
  });

  test("does not follow symlinks out of the target", async () => {
    const outside = await mkdtemp(join(tmpdir(), "codeinspectus-osv-outside-"));
    try {
      await writeFile(join(outside, "Cargo.lock"), "");
      await symlink(outside, join(root, "linked"));
      await symlink(join(outside, "Cargo.lock"), join(root, "go.mod"));
      expect(await detectOsvEcosystems(root)).toEqual([]);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  test("accepts a single lockfile as the target and tolerates a missing target", async () => {
    await touch("poetry.lock");
    expect(await detectOsvEcosystems(join(root, "poetry.lock"))).toEqual(["PyPI"]);
    expect(await detectOsvEcosystems(join(root, "does-not-exist"))).toEqual([]);
  });
});

describe("parseOsvEcosystems", () => {
  test("canonicalises case and de-duplicates in allow-list order", () => {
    expect(parseOsvEcosystems("pypi, NPM,pypi,crates.io")).toEqual(["npm", "PyPI", "crates.io"]);
  });

  test("rejects unknown and distro ecosystems and empty lists", () => {
    expect(() => parseOsvEcosystems("npm,Debian")).toThrow(/Debian/);
    expect(() => parseOsvEcosystems(" , ")).toThrow(/comma-separated/);
  });
});

describe("normalizePackageName", () => {
  test("lowercases and collapses runs of -, _ and . to a single hyphen", () => {
    expect(normalizePackageName("Foo_Bar.baz--qux")).toBe("foo-bar-baz-qux");
    expect(normalizePackageName("Brotli")).toBe("brotli");
    expect(normalizePackageName("zope.interface")).toBe("zope-interface");
    expect(normalizePackageName("a-_.b")).toBe("a-b");
  });
});
