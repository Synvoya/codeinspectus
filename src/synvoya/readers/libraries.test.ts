import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { loadSynvoyaDataset } from "../dataset.js";
import type { Declaration, LibraryTable } from "../types.js";

import { readLibraries } from "./libraries.js";

const FIXTURES = join(process.cwd(), "fixtures", "synvoya", "libraries");

let table: LibraryTable;
beforeAll(async () => {
  const loaded = await loadSynvoyaDataset();
  if (!loaded.ok) throw new Error(loaded.reason);
  table = loaded.dataset.libraries;
});

type Source = "banner" | "file-name" | "cdn-url";

function exact(name: string, version: string, file: string, line: number, source: Source): Declaration {
  return {
    subject: { type: "package", ecosystem: "npm", name },
    spec: version,
    resolved: version,
    precision: "exact",
    file,
    line,
    source,
  };
}

function floating(name: string, spec: string, file: string, line: number, source: Source): Declaration {
  return { subject: { type: "package", ecosystem: "npm", name }, spec, precision: "floating", file, line, source };
}

function unresolved(name: string, spec: string, file: string, line: number, source: Source): Declaration {
  return { subject: { type: "package", ecosystem: "npm", name }, spec, precision: "unresolved", file, line, source, noted: true };
}

const byPlace = (a: Declaration, b: Declaration): number =>
  a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.spec < b.spec ? -1 : 1);

async function read(name: string) {
  const result = await readLibraries(join(FIXTURES, name), table);
  return { ...result, declarations: [...result.declarations].sort(byPlace) };
}

describe("readLibraries: banner comments", () => {
  it("reads a banner comment from each library's own banner shape, with the line of the comment", async () => {
    const result = await read("banner");
    expect(result.declarations).toEqual(
      [
        exact("bootstrap", "4.3.1", "js/both.js", 1, "banner"),
        exact("jquery", "3.1.1", "js/both.js", 4, "banner"),
        exact("bootstrap", "4.3.1", "js/bootstrap.js", 2, "banner"),
        exact("jquery", "3.1.1", "js/jquery.min.js", 1, "banner"),
        exact("moment", "2.29.1", "js/moment.js", 1, "banner"),
        exact("react-dom", "17.0.2", "js/react-dom.production.min.js", 1, "banner"),
        exact("react", "17.0.2", "js/react.production.min.js", 1, "banner"),
        exact("underscore", "1.9.1", "js/underscore.js", 3, "banner"),
      ].sort(byPlace),
    );
    expect([...result.parsed].sort()).toEqual([
      "js/both.js",
      "js/bootstrap.js",
      "js/jquery.min.js",
      "js/moment.js",
      "js/react-dom.production.min.js",
      "js/react.production.min.js",
      "js/underscore.js",
    ].sort());
    expect(result.skipped).toEqual([]);
    expect(result.notes).toEqual([]);
  });
});

describe("readLibraries: file names", () => {
  it("reads <stem>-<version>(.min).js and <stem>.<version>.js for a table stem only", async () => {
    const result = await read("file-name");
    expect(result.declarations).toEqual(
      [
        floating("jquery", "3", "static/js/jquery-3.min.js", 1, "file-name"),
        // The banner and the name agree: one declaration, the banner's.
        exact("jquery", "3.1.1", "static/js/jquery-3.1.1.js", 1, "banner"),
        exact("jquery", "3.1.1", "static/js/jquery-3.1.1.min.js", 1, "file-name"),
        exact("jquery-ui", "1.12.1", "static/js/jquery-ui-1.12.1.min.js", 1, "file-name"),
        exact("lodash", "4.17.21", "static/js/lodash.4.17.21.js", 1, "file-name"),
        exact("select2", "4.0.13", "static/js/select2-4.0.13.js", 1, "file-name"),
      ].sort(byPlace),
    );
    // jquery-migrate, my-jquery-plugin, chart (not the chart.js stem) and an unversioned name declare nothing.
    expect(result.parsed).toHaveLength(10);
    expect(result.skipped).toEqual([]);
  });
});

describe("readLibraries: CDN URLs", () => {
  it("reads an explicit version from each listed host, once per library and version in a file", async () => {
    const result = await read("cdn");
    expect(result.declarations).toEqual([
      exact("jquery", "3.6.0", "index.html", 4, "cdn-url"),
      exact("bootstrap", "5.3.2", "index.html", 5, "cdn-url"),
      exact("@popperjs/core", "2.11.8", "index.html", 6, "cdn-url"),
      exact("lodash", "4.17.21", "index.html", 7, "cdn-url"),
      exact("jquery", "3.5.1", "index.html", 8, "cdn-url"),
      exact("jquery-ui", "1.12.1", "index.html", 9, "cdn-url"),
      exact("bootstrap", "4.3.1", "index.html", 10, "cdn-url"),
      exact("jquery-ui", "1.11.4", "index.html", 11, "cdn-url"),
    ]);
    expect(result.parsed).toEqual(["index.html"]);
  });

  it("a major or major.minor is floating; latest, a missing version and a range are unresolved with a note, never exact", async () => {
    const result = await read("versions");
    expect(result.declarations).toEqual([
      floating("jquery", "3", "index.html", 1, "cdn-url"),
      floating("jquery", "3.6", "index.html", 2, "cdn-url"),
      floating("vue", "2", "index.html", 3, "cdn-url"),
      unresolved("axios", "latest", "index.html", 4, "cdn-url"),
      unresolved("react", "", "index.html", 5, "cdn-url"),
      unresolved("underscore", "^1.13.0", "index.html", 6, "cdn-url"),
      unresolved("jquery", "latest", "index.html", 7, "cdn-url"),
      exact("dompurify", "2.3.0-beta.1", "index.html", 9, "cdn-url"),
    ]);
    expect(result.notes).toHaveLength(4);
    expect(result.notes[0]).toContain("index.html:4");
    expect(result.notes[0]).toContain("axios");
    expect(result.unjudged).toEqual(["index.html"]);
    expect(result.parsed).toEqual(["index.html"]);
  });
});

describe("readLibraries: text that is not evidence", () => {
  it("a name in a string literal or comment, a banner after byte 4096, an inline comment, a third-party bundle and look-alike hosts declare nothing", async () => {
    const result = await read("decoys");
    expect(result.declarations).toEqual([]);
    expect(result.parsed).toHaveLength(6);
    expect(result.skipped).toEqual([]);
  });
});

describe("readLibraries: scope", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-lib-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  async function put(rel: string, content: string): Promise<void> {
    await mkdir(join(work, ...rel.split("/").slice(0, -1)), { recursive: true });
    await writeFile(join(work, ...rel.split("/")), content);
  }

  it("skips node_modules and build output, reads asset folders named vendor, ignores a composer vendor tree", async () => {
    await put("node_modules/x/jquery-3.0.0.js", "var a;");
    await put("dist/jquery-3.0.1.js", "var a;");
    await put("public/vendor/jquery-3.0.2.min.js", "var a;");
    await put("vendor/acme/jquery-3.0.3.js", "var a;");
    await put("src/vendor/x/jquery-3.0.4.js", "var a;");
    await put("web/js/jquery-3.0.5.js", "var a;");
    const result = await readLibraries(work, table);
    expect(result.declarations.map((entry) => entry.file).sort()).toEqual(["public/vendor/jquery-3.0.2.min.js", "web/js/jquery-3.0.5.js"]);
  });

  it("reads markup and template files for CDN URLs", async () => {
    const tag = (n: number) => `<script src="https://unpkg.com/lodash@4.17.${n}/lodash.js"></script>\n`;
    const files = ["a.html", "a.htm", "a.php", "a.blade.php", "a.twig", "a.erb", "a.vue", "a.svelte", "a.jsx", "a.tsx", "a.ejs", "a.hbs", "a.mjs", "a.js"];
    for (const [index, name] of files.entries()) await put(`t/${name}`, tag(index));
    await put("t/a.txt", tag(99));
    const result = await readLibraries(work, table);
    expect(result.declarations).toHaveLength(files.length);
    expect(result.parsed.sort()).toEqual(files.map((name) => `t/${name}`).sort());
  });

  it("never follows a symlink and says so", async () => {
    await put("real/lib-1.0.0.js", "var a;");
    await put("outside.js", "/*! jQuery v3.1.1 */");
    await mkdir(join(work, "static"), { recursive: true });
    try {
      await symlink(join(work, "outside.js"), join(work, "static", "jquery-3.1.1.js"));
    } catch {
      return; // symlinks unavailable on this platform
    }
    const result = await readLibraries(work, table);
    expect(result.skipped).toContainEqual({ file: "static/jquery-3.1.1.js", reason: "symlink" });
    expect(result.declarations.filter((entry) => entry.file.startsWith("static/"))).toEqual([]);
  });

  it("a single-file scan reads only that file", async () => {
    await put("a/jquery-3.1.1.js", "var a;");
    await put("b/lodash-4.17.21.js", "var a;");
    const result = await readLibraries(work, table, { only: "b/lodash-4.17.21.js" });
    expect(result.declarations).toEqual([exact("lodash", "4.17.21", "b/lodash-4.17.21.js", 1, "file-name")]);
    expect(result.parsed).toEqual(["b/lodash-4.17.21.js"]);
  });

  it("an expired deadline reads nothing and reports every file as skipped", async () => {
    await put("a/jquery-3.1.1.js", "var a;");
    await put("b.html", "<script src='https://unpkg.com/lodash@4.17.21/x.js'>");
    const controller = new AbortController();
    controller.abort();
    const result = await readLibraries(work, table, { signal: controller.signal });
    expect(result.declarations).toEqual([]);
    expect(result.parsed).toEqual([]);
    expect(result.skipped.length).toBeGreaterThan(0);
    expect(result.skipped.every((entry) => entry.reason === "deadline")).toBe(true);
  });
});

describe("readLibraries: fix round", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-lib-fix-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  async function put(rel: string, content: string): Promise<void> {
    await mkdir(join(work, ...rel.split("/").slice(0, -1)), { recursive: true });
    await writeFile(join(work, ...rel.split("/")), content);
  }

  const names = (result: { declarations: Declaration[] }): string[] =>
    result.declarations.map((entry) => `${entry.subject.type === "package" ? entry.subject.name : ""}@${entry.spec}:${entry.precision}`).sort();

  describe("a banner cut by the 4 KiB head is never read as a shorter version", () => {
    /** A file whose banner version `3.7.10-beta.2` is cut after `cutAfter` characters of the version by byte 4096. */
    function straddling(cutAfter: number, opener = "/*!"): string {
      const banner = `${opener} jQuery v3.7.10-beta.2 | (c) OpenJS Foundation */\n`;
      const versionAt = banner.indexOf("3.7.10-beta.2");
      const prefixLength = 4096 - versionAt - cutAfter;
      // One filler block comment fills the head up to the banner.
      const filler = `/* ${"x".repeat(prefixLength - 7)} */\n`;
      expect(filler.length).toBe(prefixLength);
      return filler + banner + "var a;\n".repeat(50);
    }

    for (const cutAfter of [5, 6, 12]) {
      it(`declares nothing when the head ends ${cutAfter} characters into the version`, async () => {
        await put("jq.js", straddling(cutAfter));
        const result = await readLibraries(work, table);
        expect(names(result)).toEqual([]);
      });
    }

    it("a //-comment banner whose last line is cut at the head edge is dropped", async () => {
      const banner = "//! moment.js\n//! version : 2.29.10\nvar tail = 1;\n";
      const edge = banner.indexOf("2.29.10") + "2.29.1".length;
      const filler = `var p="${"x".repeat(4096 - edge - 10)}";\n`;
      expect(filler.length + edge).toBe(4096);
      await put("m.js", filler + banner);
      expect(names(await readLibraries(work, table))).toEqual([]);
    });

    it("the same //-comment banner, whole inside the head, declares the full version", async () => {
      await put("m.js", "//! moment.js\n//! version : 2.29.10\nvar tail = 1;\n");
      expect(names(await readLibraries(work, table))).toEqual(["moment@2.29.10:exact"]);
    });

    it("the same block banner, whole inside the head, declares the full version", async () => {
      await put("jq.js", `/* ${"x".repeat(3000)} */\n/*! jQuery v3.7.10 | (c) OpenJS Foundation */\nvar a;\n`);
      expect(names(await readLibraries(work, table))).toEqual(["jquery@3.7.10:exact"]);
    });

    it("a short file ending in an unterminated banner is read whole", async () => {
      await put("jq.js", "/*! jQuery v3.1.1 | (c) JS Foundation");
      expect(names(await readLibraries(work, table))).toEqual(["jquery@3.1.1:exact"]);
    });
  });

  describe("a CDN URL that names another resource declares nothing", () => {
    for (const url of [
      "https://cdn.jsdelivr.net/npm/jquery@3.7.1/../evil",
      "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/../../evil/x.js",
      "https://unpkg.com/jquery@3.7.1/%2e%2e/evil",
      "https://unpkg.com/jquery@3.7.1/%2E%2E%2Fevil",
      "https://unpkg.com/jquery@3.7.1/a%5cb",
      "https://unpkg.com/jquery@3.7.1/./x.js",
    ]) {
      it(url, async () => {
        await put("a.html", `<script src="${url}"></script>\n`);
        expect(names(await readLibraries(work, table))).toEqual([]);
      });
    }

    it("a dot inside a file name is fine", async () => {
      await put("a.html", '<script src="https://unpkg.com/jquery@3.7.1/dist/jquery.min.js"></script>\n');
      expect(names(await readLibraries(work, table))).toEqual(["jquery@3.7.1:exact"]);
    });
  });

  describe("a URL embedded in another URL is not a CDN reference", () => {
    for (const text of [
      "https://evil.example/?u=https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
      "https://evil.example/https://unpkg.com/lodash@4.17.21/x.js",
      "foo/https://unpkg.com/lodash@4.17.21/x.js",
      "//evil.example//unpkg.com/lodash@4.17.21/x.js",
    ]) {
      it(text, async () => {
        await put("a.html", `<a href="${text}">x</a>\n`);
        expect(names(await readLibraries(work, table))).toEqual([]);
      });
    }

    it("quotes, brackets, spaces, = and a leading colon still delimit a real reference", async () => {
      await put(
        "a.html",
        [
          '<script src="https://unpkg.com/lodash@4.17.21/x.js">',
          "<script src='//unpkg.com/axios@0.21.1/x.js'>",
          "<script src=https://unpkg.com/vue@2.6.14/x.js>",
          "url(https://unpkg.com/react@17.0.2/x.js)",
          "{src:https://unpkg.com/moment@2.29.1/x.js}",
          "import x from https://unpkg.com/underscore@1.13.1/x.js",
        ].join("\n"),
      );
      expect(names(await readLibraries(work, table))).toEqual([
        "axios@0.21.1:exact",
        "lodash@4.17.21:exact",
        "moment@2.29.1:exact",
        "react@17.0.2:exact",
        "underscore@1.13.1:exact",
        "vue@2.6.14:exact",
      ]);
    });
  });

  describe("versions", () => {
    it("only a known pre-release marker keeps a file-name version exact", async () => {
      for (const name of ["jquery-3.7.1-custom.js", "lodash-4.17.21+evil.js", "jquery-3.8.0-rc.1.min.js", "react-18.0.0-beta2.js"]) await put(`s/${name}`, "var a;");
      const result = await readLibraries(work, table);
      expect(names(result)).toEqual(["jquery@3.7.1-custom:unresolved", "jquery@3.8.0-rc.1:exact", "react@18.0.0-beta2:exact"].sort());
    });
  });

  describe("vendor and vendors asset folders", () => {
    it("reads public/vendor and assets/vendors, never node_modules, still skips dist", async () => {
      await put("public/vendor/jquery/jquery-1.12.4.min.js", "var a;");
      await put("assets/vendors/bootstrap/bootstrap.min.js", "/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n */\nvar b;");
      await put("assets/vendors/node_modules/x/jquery-3.0.0.js", "var a;");
      await put("assets/node_modules/jquery-3.0.1.js", "var a;");
      await put("assets/dist/jquery-3.0.2.js", "var a;");
      await put("includes/vendors/sdk/jquery-3.0.3.js", "var a;");
      await put("vendors/jquery-3.0.4.js", "var a;");
      const result = await readLibraries(work, table);
      expect(result.declarations.map((entry) => `${entry.file} ${entry.source}`).sort()).toEqual([
        "assets/vendors/bootstrap/bootstrap.min.js banner",
        "public/vendor/jquery/jquery-1.12.4.min.js file-name",
      ]);
      expect(names(result)).toEqual(["bootstrap@3.3.7:exact", "jquery@1.12.4:exact"]);
    });

    it("a vendor folder nested below an asset root inside another vendor folder is read", async () => {
      await put("app/vendor/acme/public/vendor/jquery-3.0.0.js", "var a;");
      await put("app/vendor/acme/lib/jquery-3.0.1.js", "var a;");
      const result = await readLibraries(work, table);
      expect(result.declarations.map((entry) => entry.file)).toEqual(["app/vendor/acme/public/vendor/jquery-3.0.0.js"]);
    });

    it("Rails vendor/assets is an asset root; the rest of a Rails vendor folder is not", async () => {
      await put("vendor/assets/javascripts/jquery-1.12.4.min.js", "var a;");
      await put("engines/billing/vendor/assets/javascripts/jquery-3.0.0.js", "var a;");
      await put("vendor/bundle/ruby/gems/x/jquery-3.0.1.js", "var a;");
      await put("vendor/javascripts/jquery-3.0.2.js", "var a;");
      await put("vendor/assetsx/jquery-3.0.3.js", "var a;");
      const result = await readLibraries(work, table);
      expect(result.declarations.map((entry) => entry.file).sort()).toEqual([
        "engines/billing/vendor/assets/javascripts/jquery-3.0.0.js",
        "vendor/assets/javascripts/jquery-1.12.4.min.js",
      ]);
    });
  });

  it("files left unread after the per-scan declaration cap are listed as capped, not silently dropped", async () => {
    for (let file = 0; file < 40; file++) {
      const lines = Array.from({ length: 60 }, (_, n) => `<script src="https://unpkg.com/jquery@${file + 1}.${n}.0/x.js"></script>`);
      await put(`p${String(file).padStart(2, "0")}.html`, `${lines.join("\n")}\n`);
    }
    const result = await readLibraries(work, table);
    const listed = new Set([...result.parsed, ...result.skipped.map((entry) => entry.file)]);
    expect(listed.size).toBe(40);
    expect(result.parsed.length + result.skipped.filter((entry) => entry.reason === "capped").length).toBe(40);
  });
});

describe("readLibraries: partially read files are never checked", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-lib-cap-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  it("a file over 1 MiB keeps what the first MiB declares but is skipped as capped, not parsed", async () => {
    const head = '/*! jQuery v3.1.1 | (c) JS Foundation */\n<script src="https://unpkg.com/lodash@4.17.21/x.js">\n';
    const filler = "a".repeat(1024 * 1024);
    const tail = '\n<script src="https://unpkg.com/axios@0.21.1/x.js">\n';
    await writeFile(join(work, "big.js"), head + filler + tail);
    const result = await readLibraries(work, table);
    expect(result.declarations.map((entry) => `${entry.subject.type === "package" ? entry.subject.name : ""}@${entry.spec}`).sort()).toEqual(["jquery@3.1.1", "lodash@4.17.21"]);
    expect(result.skipped).toContainEqual({ file: "big.js", reason: "capped" });
    expect(result.parsed).toEqual([]);
  });

  it("more than 64 declarations in a file: the first 64 are kept, the file is capped with a note", async () => {
    const lines = Array.from({ length: 200 }, (_, n) => `<script src="https://unpkg.com/jquery@1.${n}.0/x.js"></script>`);
    await writeFile(join(work, "many.html"), `${lines.join("\n")}\n`);
    const result = await readLibraries(work, table);
    expect(result.declarations).toHaveLength(64);
    expect(result.skipped).toContainEqual({ file: "many.html", reason: "capped" });
    expect(result.parsed).toEqual([]);
    expect(result.notes.some((note) => note.includes("many.html"))).toBe(true);
  });

  it("past 2000 declarations in a scan the reader stops with a priority note", async () => {
    for (let file = 0; file < 40; file++) {
      const lines = Array.from({ length: 60 }, (_, n) => `<script src="https://unpkg.com/jquery@${file + 1}.${n}.0/x.js"></script>`);
      await writeFile(join(work, `p${String(file).padStart(2, "0")}.html`), `${lines.join("\n")}\n`);
    }
    const result = await readLibraries(work, table);
    expect(result.declarations).toHaveLength(2000);
    expect(result.priorityNotes).toHaveLength(1);
    expect(result.priorityNotes![0]).toContain("2000");
    expect(result.skipped.some((entry) => entry.reason === "capped")).toBe(true);
  });
});

describe("readLibraries: hostile inputs", { timeout: 20_000 }, () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-lib-hostile-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  async function timed<T>(run: () => Promise<T>): Promise<{ value: T; ms: number }> {
    const started = Date.now();
    const value = await run();
    return { value, ms: Date.now() - started };
  }

  it("a 1 MiB single-line minified file is read in linear time", async () => {
    await writeFile(join(work, "bundle.min.js"), "a=b+1;".repeat(Math.floor((1024 * 1024) / 6)).padEnd(1024 * 1024, ";"));
    const { value, ms } = await timed(() => readLibraries(work, table));
    expect(value.declarations).toEqual([]);
    expect(value.parsed).toEqual(["bundle.min.js"]);
    expect(ms).toBeLessThan(15_000);
  });

  it("a 1 MiB single line of repeated CDN hosts and comment openers stays linear and deduplicates", async () => {
    const unit = "//unpkg.com/lodash@4.17.21/ /*! // /* ";
    await writeFile(join(work, "dense.min.js"), unit.repeat(Math.floor((1024 * 1024) / unit.length)));
    const { value, ms } = await timed(() => readLibraries(work, table));
    expect(value.declarations).toHaveLength(1);
    expect(ms).toBeLessThan(15_000);
  });

  it("100k CDN URLs over several files cap per file and per scan", async () => {
    for (let file = 0; file < 5; file++) {
      const lines = Array.from({ length: 20_000 }, (_, n) => `//unpkg.com/jquery@${file}.${n}.0/`);
      await writeFile(join(work, `urls${file}.html`), lines.join("\n"));
    }
    const { value, ms } = await timed(() => readLibraries(work, table));
    expect(value.declarations).toHaveLength(5 * 64);
    expect(value.parsed).toEqual([]);
    expect(ms).toBeLessThan(15_000);
  });

  it("100k CDN URLs in one file are read to the 1 MiB cap and no further", async () => {
    const lines = Array.from({ length: 100_000 }, (_, n) => `//unpkg.com/a@${n}/`);
    await writeFile(join(work, "all.html"), lines.join("\n"));
    const { value, ms } = await timed(() => readLibraries(work, table));
    expect(value.declarations).toEqual([]);
    expect(value.skipped).toContainEqual({ file: "all.html", reason: "capped" });
    expect(ms).toBeLessThan(15_000);
  });

  it("10k <script> tags in one page stop at the per-file cap", async () => {
    const tags = Array.from({ length: 10_000 }, (_, n) => `<script src="https://cdn.jsdelivr.net/npm/vue@2.${n}.0/dist/vue.js"></script>`);
    await writeFile(join(work, "page.html"), tags.join("\n"));
    const { value, ms } = await timed(() => readLibraries(work, table));
    expect(value.declarations).toHaveLength(64);
    expect(value.skipped).toContainEqual({ file: "page.html", reason: "capped" });
    expect(ms).toBeLessThan(15_000);
  });

  it("thousands of unterminated comment openers at line starts stay linear", async () => {
    await writeFile(join(work, "openers.js"), "/*\n".repeat(1_000_000 / 3));
    await writeFile(join(work, "lines.js"), "//x\n".repeat(200_000));
    const { value, ms } = await timed(() => readLibraries(work, table));
    expect(value.declarations).toEqual([]);
    expect(ms).toBeLessThan(15_000);
  });

  it("every banner regex of the shipped table is fast on adversarial comment text", () => {
    const probes = [
      "x".repeat(1024),
      " ".repeat(1024),
      `jQuery v${"1.".repeat(500)}`,
      `@license React v1.2.3${" ".repeat(900)}`,
      `Copyright (c) Tiny Technologies, Inc.${"\n".repeat(900)}`,
      `moment.js${" ".repeat(500)}version${" ".repeat(400)}:`,
    ];
    const started = Date.now();
    for (const library of table.libraries) {
      for (const source of library.banners) {
        const re = new RegExp(source);
        for (const probe of probes) re.exec(probe);
      }
    }
    expect(Date.now() - started).toBeLessThan(500);
  });
});
