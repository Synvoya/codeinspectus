import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";

import { log } from "../logger.js";
import { loadSynvoyaDataset } from "../synvoya/dataset.js";
import type { LibraryTable } from "../synvoya/types.js";

import {
  COMPOSER_INSTALLED_MAX_BYTES,
  COMPOSER_MAX_PACKAGES,
  COMPOSER_PACKAGE_NAME,
  composerPackageRoots,
  composerVendorTree,
  jsLibraryCorroborated,
  jsLibraryIdentity,
  KNOWN_LIBRARY_RELEASES,
  riskyLibraryCode,
  type PackLibrary,
} from "./opengrep-libraries.js";

const roots: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

/** One Composer package entry as `composer install` writes it (fields the rules read only). */
function pkg(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { name, version: "v1.0.0", type: "library", dist: { type: "zip", url: "https://example.invalid/x.zip" }, ...extra };
}

describe("composerPackageRoots: Composer's install metadata, package by package", () => {
  test("Composer 2: the install-path names the package root below the vendor tree", () => {
    const installed = {
      packages: [pkg("mpdf/mpdf", { version: "v8.2.2", "install-path": "../mpdf/mpdf" })],
      dev: true,
    };
    expect(composerPackageRoots(installed, "libs/mpdf/mpdf_8")).toEqual([
      { ecosystem: "composer", name: "mpdf/mpdf", version: "v8.2.2", location: "libs/mpdf/mpdf_8/mpdf/mpdf" },
    ]);
  });

  test("Composer 1: a top-level array without install-path roots each package at <dir>/<name>", () => {
    const installed = [pkg("phpoffice/phpspreadsheet", { version: "1.29.0" }), pkg("markbaker/matrix", { version: "3.0.1" })];
    expect(composerPackageRoots(installed, "libs/phpspreadsheet")).toEqual([
      { ecosystem: "composer", name: "markbaker/matrix", version: "3.0.1", location: "libs/phpspreadsheet/markbaker/matrix" },
      { ecosystem: "composer", name: "phpoffice/phpspreadsheet", version: "1.29.0", location: "libs/phpspreadsheet/phpoffice/phpspreadsheet" },
    ]);
  });

  test("a vendor tree at the target root has root-relative locations", () => {
    expect(composerPackageRoots({ packages: [pkg("acme/x", { "install-path": "../acme/x" })] }, "")).toEqual([
      { ecosystem: "composer", name: "acme/x", version: "v1.0.0", location: "acme/x" },
    ]);
  });

  test("a VCS source qualifies without an archive dist; duplicates by location keep the first", () => {
    const installed = [
      pkg("acme/x", { dist: undefined, source: { type: "git", url: "https://example.invalid/x.git" } }),
      pkg("acme/x", { version: "v2.0.0" }),
    ];
    expect(composerPackageRoots(installed, "lib")).toEqual([
      { ecosystem: "composer", name: "acme/x", version: "v1.0.0", location: "lib/acme/x" },
    ]);
  });

  test.each<[string, Record<string, unknown>]>([
    ["a path repository (first-party code mirrored into the tree)", pkg("acme/local", { dist: { type: "path", url: "../../packages/local" } })],
    ["an installer path outside the tree", pkg("acme/x", { "install-path": "../../modules/contrib/x" })],
    ["an install-path that normalises outside <dir>/<name>", pkg("acme/x", { "install-path": "../acme/x/../../../app" })],
    ["an install-path to another package's folder", pkg("acme/x", { "install-path": "../acme/y" })],
    ["a non-string install-path", pkg("acme/x", { "install-path": 7 })],
    ["an upper-case name", pkg("Acme/X")],
    ["a name without vendor", pkg("acme")],
    ["a name with dot segments", pkg("../x/y")],
    ["an empty version", pkg("acme/x", { version: "" })],
    ["a 65-character version", pkg("acme/x", { version: `1${"0".repeat(64)}` })],
    ["a version with a space", pkg("acme/x", { version: "1.0 beta" })],
    ["neither an archive dist nor a VCS source", pkg("acme/x", { dist: { type: "file" }, source: { type: "perforce" } })],
    ["no dist and no source", pkg("acme/x", { dist: undefined })],
  ])("rejected: %s", (_label, entry) => {
    expect(composerPackageRoots([entry], "lib")).toEqual([]);
    expect(composerPackageRoots({ packages: [entry] }, "lib")).toEqual([]);
  });

  test("any other shape, or more than 2,000 entries, classifies no package of the tree", () => {
    expect(composerPackageRoots({ packages: { "acme/x": pkg("acme/x") } }, "lib")).toEqual([]);
    expect(composerPackageRoots({ packages: "acme/x" }, "lib")).toEqual([]);
    expect(composerPackageRoots("acme/x", "lib")).toEqual([]);
    expect(composerPackageRoots(null, "lib")).toEqual([]);
    expect(composerPackageRoots([null, pkg("acme/x")], "lib")).toEqual([
      { ecosystem: "composer", name: "acme/x", version: "v1.0.0", location: "lib/acme/x" },
    ]);
    const many = Array.from({ length: COMPOSER_MAX_PACKAGES + 1 }, (_, index) => pkg(`acme/p${index}`));
    expect(composerPackageRoots(many, "lib")).toEqual([]);
    expect(composerPackageRoots({ packages: many }, "lib")).toEqual([]);
    expect(composerPackageRoots(many.slice(0, COMPOSER_MAX_PACKAGES), "lib")).toHaveLength(COMPOSER_MAX_PACKAGES);
  });

  test("the package-name pattern accepts what Composer's own pattern accepts and stays linear on hostile names", () => {
    // Composer's documented pattern, used here only as the reference for equivalence.
    const reference = /^[a-z0-9](?:[_.-]?[a-z0-9]+)*\/[a-z0-9](?:(?:[_.]|-{1,2})?[a-z0-9]+)*$/;
    for (const name of ["mpdf/mpdf", "a/b", "psr/http-message", "my_vendor.x/pkg--name", "a-b/c__d", "a--b/c", "a/b---c", "-a/b", "a/b-", "a/b.", "a//b", "a/b/c", "a.b/c_.d", "0/0"]) {
      expect(COMPOSER_PACKAGE_NAME.test(name), name).toBe(reference.test(name));
    }
    const started = Date.now();
    expect(COMPOSER_PACKAGE_NAME.test(`${"a".repeat(50_000)}!`)).toBe(false);
    expect(COMPOSER_PACKAGE_NAME.test(`a/${"a".repeat(50_000)}!`)).toBe(false);
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});

describe("composerVendorTree: marker files and a bounded no-follow read", () => {
  async function tree(files: Record<string, string>): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), "ci-composer-tree-"));
    roots.push(root);
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(join(root, rel, ".."), { recursive: true });
      await writeFile(join(root, rel), content, "utf8");
    }
    return root;
  }
  const installed = JSON.stringify({ packages: [pkg("acme/pdf", { "install-path": "../acme/pdf" })] });

  test("all three markers: the package roots, and the read is debited from the budget", async () => {
    const root = await tree({ "autoload.php": "<?php\n", "composer/ClassLoader.php": "<?php\n", "composer/installed.json": installed });
    const budget = { bytes: 1_000_000 };
    expect(await composerVendorTree(root, "lib/pdf", budget)).toEqual([
      { ecosystem: "composer", name: "acme/pdf", version: "v1.0.0", location: "lib/pdf/acme/pdf" },
    ]);
    expect(budget.bytes).toBe(1_000_000 - Buffer.byteLength(installed));
  });

  test("no installed.json, or a missing ClassLoader.php or autoload.php: not a vendor tree", async () => {
    expect(await composerVendorTree(await tree({ "autoload.php": "<?php\n" }), "lib", { bytes: 1e9 })).toEqual([]);
    expect(await composerVendorTree(await tree({ "autoload.php": "<?php\n", "composer/installed.json": installed }), "lib", { bytes: 1e9 })).toEqual([]);
    expect(await composerVendorTree(await tree({ "composer/ClassLoader.php": "<?php\n", "composer/installed.json": installed }), "lib", { bytes: 1e9 })).toEqual([]);
  });

  test("a symbolic link as installed.json, a marker or the composer folder: not a vendor tree", async () => {
    const elsewhere = await tree({ "installed.json": installed, "ClassLoader.php": "<?php\n", "composer/ClassLoader.php": "<?php\n", "composer/installed.json": installed });
    const linkedJson = await tree({ "autoload.php": "<?php\n", "composer/ClassLoader.php": "<?php\n" });
    await symlink(join(elsewhere, "installed.json"), join(linkedJson, "composer", "installed.json"));
    expect(await composerVendorTree(linkedJson, "lib", { bytes: 1e9 })).toEqual([]);

    const linkedLoader = await tree({ "autoload.php": "<?php\n", "composer/installed.json": installed });
    await symlink(join(elsewhere, "ClassLoader.php"), join(linkedLoader, "composer", "ClassLoader.php"));
    expect(await composerVendorTree(linkedLoader, "lib", { bytes: 1e9 })).toEqual([]);

    const linkedFolder = await tree({ "autoload.php": "<?php\n" });
    await symlink(join(elsewhere, "composer"), join(linkedFolder, "composer"));
    expect(await composerVendorTree(linkedFolder, "lib", { bytes: 1e9 })).toEqual([]);
  });

  // Fix round 1, ruling 6: the scan target itself is never classified as a vendor tree.
  test("markers at the target root (relDir \"\") classify nothing", async () => {
    const root = await tree({ "autoload.php": "<?php\n", "composer/ClassLoader.php": "<?php\n", "composer/installed.json": installed });
    expect(await composerVendorTree(root, "", { bytes: 1e9 })).toEqual([]);
  });

  test("malformed JSON: no package and one warning naming the file", async () => {
    const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);
    const root = await tree({ "autoload.php": "<?php\n", "composer/ClassLoader.php": "<?php\n", "composer/installed.json": "{\"packages\": [" });
    expect(await composerVendorTree(root, "lib/pdf", { bytes: 1e9 })).toEqual([]);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]![0])).toContain("lib/pdf/composer/installed.json");
  });

  test("a file over 8 MiB is not read: no package and one warning", async () => {
    const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);
    const root = await tree({ "autoload.php": "<?php\n", "composer/ClassLoader.php": "<?php\n", "composer/installed.json": " ".repeat(COMPOSER_INSTALLED_MAX_BYTES + 1) });
    const budget = { bytes: 1e9 };
    expect(await composerVendorTree(root, "libs/big", budget)).toEqual([]);
    expect(budget.bytes).toBe(1e9);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]![0])).toContain("libs/big/composer/installed.json");
  });

  test("a read that does not fit the remaining budget is not made", async () => {
    const root = await tree({ "autoload.php": "<?php\n", "composer/ClassLoader.php": "<?php\n", "composer/installed.json": installed });
    const budget = { bytes: 10 };
    expect(await composerVendorTree(root, "lib", budget)).toEqual([]);
    expect(budget).toEqual({ bytes: 10, exhausted: true });
  });
});

describe("jsLibraryIdentity: file name and banner name the same table library", () => {
  let table: LibraryTable;
  beforeAll(async () => {
    const loaded = await loadSynvoyaDataset();
    if (!loaded.ok) throw new Error(loaded.reason);
    table = loaded.dataset.libraries;
  });

  // First lines of the copies in lobbywatch (MIT-licensed banners).
  const KNOCKOUT = "/*!\n * Knockout JavaScript library v3.5.1\n * (c) The Knockout.js team - http://knockoutjs.com/\n * License: MIT (http://www.opensource.org/licenses/mit-license.php)\n */\n\n(function() {var a = 1;})();\n";
  const JQUERY = "/*!\n * jQuery JavaScript Library v1.7.1\n * http://jquery.com/\n *\n * Copyright 2011, John Resig\n */\n(function( window, undefined ) {\nvar document = window.document;\n})( window );\n";
  const BOOTSTRAP_BANNER = "/*!\n * Bootstrap v4.3.1 (https://getbootstrap.com/)\n */\n";

  test("knockout.js with the Knockout v3.5.1 banner", () => {
    expect(jsLibraryIdentity("components/js/libs/knockout.js", KNOCKOUT, false, table)).toEqual({
      ecosystem: "npm", name: "knockout", version: "3.5.1", location: "components/js/libs/knockout.js",
    });
  });

  test("jquery-1.7.1.js with the jQuery v1.7.1 banner", () => {
    expect(jsLibraryIdentity("scripts/jquery-1.7.1.js", JQUERY, false, table)).toEqual({
      ecosystem: "npm", name: "jquery", version: "1.7.1", location: "scripts/jquery-1.7.1.js",
    });
  });

  test.each<[string, string, string]>([
    ["bootstrap.js without a banner (Laravel's first-party file)", "resources/js/bootstrap.js", "window._ = require('lodash');\n"],
    ["jquery.js starting with a Knockout banner", "js/jquery.js", KNOCKOUT],
    ["jquery-1.7.2.js with a v1.7.1 banner", "js/jquery-1.7.2.js", JQUERY],
    ["app.js with a jQuery banner", "js/app.js", JQUERY],
    ["jquery-1.7.1.intellisense.js", "js/jquery-1.7.1.intellisense.js", JQUERY],
    ["a concatenation: a jQuery banner then a Bootstrap banner", "js/jquery.js", `${JQUERY}${BOOTSTRAP_BANNER}`],
    ["a TypeScript file", "js/jquery.ts", JQUERY],
    ["a banner without a version the table can order", "js/jquery.js", "/*! jQuery vlatest */\nvar a;\n"],
  ])("not identified: %s", (_label, rel, head) => {
    expect(jsLibraryIdentity(rel, head, false, table)).toBeUndefined();
  });

  // Fix round 1, ruling 7: a bare integer is no version (freescout's "Bootstrap v345").
  test("a bare-integer banner version identifies the library without a version", () => {
    expect(jsLibraryIdentity("public/js/bootstrap.js", "/*!\n * Bootstrap v345 (https://getbootstrap.com/)\n */\nvar a;\n", false, table))
      .toEqual({ ecosystem: "npm", name: "bootstrap", location: "public/js/bootstrap.js" });
    // A file name with a version cannot be confirmed by a banner without one.
    expect(jsLibraryIdentity("public/js/bootstrap-3.4.5.js", "/*!\n * Bootstrap v345\n */\nvar a;\n", false, table)).toBeUndefined();
  });

  test("a banner cut by the 4 KiB head is not identified", () => {
    const head = `/* ${"x".repeat(4000)} */\n/*! jQuery v3.7.1 | (c) OpenJS Foundation`;
    expect(jsLibraryIdentity("js/jquery.js", head, true, table)).toBeUndefined();
  });

  test("a byte-order mark before the banner, and an .mjs file, are identified", () => {
    expect(jsLibraryIdentity("js/knockout.js", `﻿${KNOCKOUT}`, false, table)?.version).toBe("3.5.1");
    expect(jsLibraryIdentity("js/knockout.mjs", KNOCKOUT, false, table)).toEqual({
      ecosystem: "npm", name: "knockout", version: "3.5.1", location: "js/knockout.mjs",
    });
  });

  test("the <stem>.<version> and minified name forms agree with the banner version", () => {
    expect(jsLibraryIdentity("js/jquery.1.7.1.js", JQUERY, false, table)?.version).toBe("1.7.1");
    expect(jsLibraryIdentity("js/jquery-1.7.1.slim.js", JQUERY, false, table)?.version).toBe("1.7.1");
    // "v1.7.1" is no version in a file name: the stem is then no table stem.
    expect(jsLibraryIdentity("js/jquery-v1.7.1.js", JQUERY, false, table)).toBeUndefined();
  });
});

describe("jsLibraryCorroborated: evidence beyond the banner (security review, controller ruling)", () => {
  const library = (name: string, version: string): PackLibrary => ({ ecosystem: "npm", name, version, location: `js/${name}.js` });
  const readable = (bytes: number): string => {
    const line = "  var value = compute(input, index); // a readable statement\n";
    return line.repeat(Math.ceil(bytes / line.length)).slice(0, bytes);
  };

  test.each([
    ["child_process", "const cp = require('child_process'); cp.exec(req.query.cmd);"],
    ["require('fs')", "var fs = require('fs');"],
    ["require(\"node:fs\")", "var fs = require(\"node:fs\");"],
    ["eval(", "exports.run = (code) => eval (code);"],
    ["new Function(", "var f = new Function('a', 'return a');"],
    ["fetch( to an absolute URL", "fetch('https://example.invalid/collect', { body: data });"],
    ["fetch( to a protocol-relative URL", "fetch(\"//example.invalid/x\");"],
    ["fetch( to a URL the file computes", "fetch(endpoint + '/x');"],
  ])("risky code: %s", (_label, code) => {
    expect(riskyLibraryCode(`var a = 1;\n${code}\n`)).toBeDefined();
  });

  test("relative fetches and look-alike words are not risky", () => {
    expect(riskyLibraryCode("fetch('/api/items'); fetch(\"./a.json\"); fetch(`../b`); jQuery.globalEval(data); (0, eval)('this');\n")).toBeUndefined();
  });

  test("a minified copy with no risky code is corroborated (a label only: the 4.0 minified rule skips it anyway)", () => {
    const jquery = library("jquery", "3.6.0");
    expect(jsLibraryCorroborated(jquery, Buffer.from("var a=1;"), true)).toEqual(jquery);
    expect(jsLibraryCorroborated(jquery, Buffer.from("var a=1;require('child_process')"), true)).toBeUndefined();
  });

  // Fix round 1, ruling 2: a readable copy leaves the pass only on a release-hash match.
  test("a readable copy needs a SHA-256 equal to a recorded release of that library", () => {
    const content = Buffer.from(readable(5_000));
    const sha256 = createHash("sha256").update(content).digest("hex");
    const releases = [{ npm: "bootstrap", version: "3.3.7", sha256, provenance: "test" }];
    const bootstrap = library("bootstrap", "3.3.7");
    expect(jsLibraryCorroborated(bootstrap, content, false, releases)).toEqual(bootstrap);
    // One byte more, another library, another version: no.
    expect(jsLibraryCorroborated(bootstrap, Buffer.concat([content, Buffer.from("\n")]), false, releases)).toBeUndefined();
    expect(jsLibraryCorroborated(library("moment", "3.3.7"), content, false, releases)).toBeUndefined();
    expect(jsLibraryCorroborated(library("bootstrap", "3.3.6"), content, false, releases)).toBeUndefined();
    // A banner without a version takes the release's version.
    expect(jsLibraryCorroborated({ ecosystem: "npm", name: "bootstrap", location: "js/b.js" }, content, false, releases))
      .toEqual({ ecosystem: "npm", name: "bootstrap", version: "3.3.7", location: "js/b.js" });
    // The shipped table holds the three field releases, each with its hash and provenance.
    expect(KNOWN_LIBRARY_RELEASES.map((entry) => `${entry.npm}@${entry.version}`)).toEqual(["bootstrap@3.3.7", "moment@2.29.4", "select2@4.0.5"]);
    expect(KNOWN_LIBRARY_RELEASES.every((entry) => /^[0-9a-f]{64}$/.test(entry.sha256) && entry.provenance.length > 0)).toBe(true);
    // Without a match, the size of a release is not enough.
    expect(jsLibraryCorroborated(bootstrap, Buffer.from(readable(69_707)), false)).toBeUndefined();
  });
});
