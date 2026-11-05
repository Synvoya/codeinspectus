import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { COVERAGE_GAP_IDS, SAST_COVERED_LANGUAGES, actionsUncheckedGap, describeCoverageGap, discoverCoverageGaps, gapsFromFiles } from "./coverage-gaps.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function tree(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "ci-coverage-gaps-"));
  roots.push(root);
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content, "utf8");
  }
  return root;
}

// Field re-test G1/G4: PHP had no SAST and deno.lock, bun.lockb and lockfile-less manifests were read
// by no engine, yet coverage read complete (fixtures php-sast, deno-lock, bun-lockb, npm-nolock,
// composer-nolock; ultimatemember, Trustroots).
describe("declared coverage gaps", () => {
  test("names each gap with its file count and examples, outside skipped and locked inputs", async () => {
    const root = await tree({
      // The Synvoya PHP pack covers PHP source (.php, .phtml): no php-sast gap for these.
      "src/index.php": "<?php echo $_GET['q'];\n",
      "src/view.phtml": "<?= $x ?>\n",
      // Twig templates are not PHP to Opengrep and remain the php-sast gap.
      "src/view.twig": "{{ q }}\n",
      "vendor/acme/lib/base.twig": "{{ q }}\n",
      ".next/server/app/page.twig": "{{ q }}\n",
      // Review M3: Opengrep's skip list is case-sensitive, so Build/ is scanned and counted.
      "Build/Gen.twig": "{{ q }}\n",
      // Fix round 3: only BUILD_DIRS are skipped; Opengrep scans coverage/, so it is counted.
      "coverage/lcov-report/x.twig": "{{ q }}\n",
      "tests/helper.rb": "puts 1\n",
      "cmd/main.go": "package main\n",
      "app.ts": "export {};\n",
      "deno.lock": "{}\n",
      "edge/bun.lockb": "\u0000",
      "web/bun.lockb": "\u0000",
      "web/bun.lock": "{}\n",
      "package.json": JSON.stringify({ dependencies: { axios: "1.18.0" } }),
      "tools/package.json": JSON.stringify({ scripts: { build: "tsc" } }),
      "broken/package.json": "{ not json",
      "mono/yarn.lock": "",
      "mono/package.json": JSON.stringify({ private: true, workspaces: ["packages/*"] }),
      "mono/packages/a/package.json": JSON.stringify({ devDependencies: { vitest: "^3" } }),
      "composer.json": JSON.stringify({ require: { php: ">=8.1", "ext-json": "*", "monolog/monolog": "^3" } }),
      "plugin/composer.json": JSON.stringify({ require: { php: ">=7.4" } }),
      "locked/composer.json": JSON.stringify({ require: { "guzzlehttp/guzzle": "^7" } }),
      "locked/composer.lock": "{}\n",
      // Review I-3: Trivy 0.76.1 reads package-lock.json but not npm-shrinkwrap.json.
      "cli/package.json": JSON.stringify({ dependencies: { lodash: "4.17.4" } }),
      "cli/npm-shrinkwrap.json": "{}\n",
      "both/package.json": JSON.stringify({ dependencies: { lodash: "4.17.4" } }),
      "both/npm-shrinkwrap.json": "{}\n",
      "both/package-lock.json": "{}\n",
    });

    const { gaps, limitation } = await discoverCoverageGaps(root);

    expect(limitation).toBeUndefined();
    expect(gaps).toEqual([
      { id: "php-sast", files: 3, examples: ["Build/Gen.twig", "coverage/lcov-report/x.twig", "src/view.twig"] },
      { id: "go-sast", files: 1, examples: ["cmd/main.go"] },
      { id: "deno-lock", files: 1, examples: ["deno.lock"] },
      { id: "bun-lockb", files: 1, examples: ["edge/bun.lockb"] },
      { id: "no-lockfile-npm", files: 2, examples: ["broken/package.json", "package.json"] },
      { id: "no-lockfile-composer", files: 1, examples: ["composer.json"] },
      { id: "npm-shrinkwrap-unread", files: 1, examples: ["cli/npm-shrinkwrap.json"] },
    ]);
  });

  // Review I-2 / Ruling 15: real Opengrep 1.33.1 neither scans nor lists .vue/.svelte/.astro files and
  // the native packs skip them, so their script code is a gap; shell, PowerShell and Makefiles are a note.
  test("component files and further languages are gaps; scripts are an informational note", async () => {
    const root = await tree({
      "src/App.vue": "<script setup>eval(location.hash)</script>\n",
      "src/routes/+page.svelte": "<script>let x = 1;</script>\n",
      "src/pages/index.astro": "---\nconst x = 1;\n---\n",
      "ios/AppDelegate.m": "@implementation AppDelegate\n@end\n",
      "ios/Bridge.mm": "\n",
      "lib/app.ex": "defmodule App do\nend\n",
      "scripts/fmt.lua": "print(1)\n",
      "contracts/Token.sol": "pragma solidity ^0.8.0;\n",
      "Makefile": "all:\n",
      "build.mk": "X=1\n",
      "scripts/release.sh": "#!/bin/sh\n",
      "scripts/setup.ps1": "Write-Host 1\n",
    });

    const { gaps, scriptNote } = await discoverCoverageGaps(root);

    expect(gaps).toEqual([
      { id: "vue-sast", files: 1, examples: ["src/App.vue"] },
      { id: "svelte-sast", files: 1, examples: ["src/routes/+page.svelte"] },
      { id: "astro-sast", files: 1, examples: ["src/pages/index.astro"] },
      { id: "objc-sast", files: 2, examples: ["ios/AppDelegate.m", "ios/Bridge.mm"] },
      { id: "elixir-sast", files: 1, examples: ["lib/app.ex"] },
      { id: "lua-sast", files: 1, examples: ["scripts/fmt.lua"] },
      { id: "solidity-sast", files: 1, examples: ["contracts/Token.sol"] },
    ]);
    expect(scriptNote).toBe(
      "No bundled SAST rules read 1 shell, 1 PowerShell, 2 Makefile file(s) (informational, not a coverage gap): " +
        "Makefile, build.mk, scripts/release.sh, scripts/setup.ps1.",
    );
    expect(describeCoverageGap(gaps[0]!, false)).toBe(
      "1 .vue component file(s) have script code no bundled SAST rule or native pack reads (vue-sast): src/App.vue.",
    );
  });

  // Security review: gap and note examples never show a name with a bidi override or separator.
  test("unsafe file names are counted but not shown as examples", async () => {
    const { gaps, scriptNote } = await discoverCoverageGaps(await tree({
      "src/evil\u202egnp.twig": "{{ q }}\n",
      "src/ok.twig": "{{ q }}\n",
      "bin/run\u2028x.sh": "#!/bin/sh\n",
    }));
    expect(gaps).toEqual([{ id: "php-sast", files: 2, examples: ["src/ok.twig"] }]);
    expect(scriptNote).toBe("No bundled SAST rules read 1 shell file(s) (informational, not a coverage gap).");
  });

  // Fix round 3: server templates with embedded code count toward their language gap.
  test("server templates count toward their language", async () => {
    const { gaps } = await discoverCoverageGaps(await tree({
      "web/index.jsp": "<% out.println(request.getParameter(\"q\")); %>\n",
      "web/page.jspx": "<jsp:root/>\n",
      "app/views/home.html.erb": "<%= params[:q] %>\n",
      "Pages/Index.cshtml": "@Html.Raw(Model.Q)\n",
      "Components/Counter.razor": "@code { }\n",
      "resources/views/home.blade.php": "{!! $q !!}\n",
      "templates/base.html.twig": "{{ q|raw }}\n",
    }));
    expect(gaps).toEqual([
      // The Synvoya PHP pack parses .blade.php as PHP (plus a Blade raw-output rule); Twig stays a gap.
      { id: "php-sast", files: 1, examples: ["templates/base.html.twig"] },
      { id: "ruby-sast", files: 1, examples: ["app/views/home.html.erb"] },
      { id: "java-sast", files: 2, examples: ["web/index.jsp", "web/page.jspx"] },
      { id: "csharp-sast", files: 2, examples: ["Components/Counter.razor", "Pages/Index.cshtml"] },
    ]);
  });

  // Online recheck items 7 and 8: inputs with no advisory data in any bundled engine.
  test("WordPress plugins and themes and third-party GitHub Actions are gaps", async () => {
    const lock = JSON.stringify({ packages: [
      { name: "wpackagist-plugin/contact-form-7", version: "5.1.1" },
      { name: "wpackagist-theme/twentytwenty", version: "1.0" },
      { name: "guzzlehttp/guzzle", version: "7.9.3" },
    ] }, null, 4);
    const { gaps } = await discoverCoverageGaps(await tree({
      "composer.json": JSON.stringify({ require: { "wpackagist-plugin/contact-form-7": "5.1.1" } }),
      "composer.lock": lock,
      "wp-content/plugins/akismet/akismet.php": "<?php\n/**\n * Plugin Name: Akismet Anti-spam\n */\n",
      "wp-content/plugins/akismet/class.akismet.php": "<?php\n",
      "wp-content/plugins/hello.php": "<?php\n/*\nPlugin Name: Hello Dolly\n*/\n",
      "wp-content/plugins/not-a-plugin/readme.php": "<?php echo 1;\n",
      ".github/workflows/ci.yml": [
        "on: pull_request_target",
        "jobs:",
        "  t:",
        "    uses: org/shared/.github/workflows/build.yml@main",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - uses: 'tj-actions/changed-files@v35'",
        "      - uses: ./.github/actions/local",
        "      - uses: actions/checkout@v4",
      ].join("\n"),
    }));
    expect(gaps.filter((gap) => gap.id === "wordpress-plugins" || gap.id === "actions-unchecked")).toEqual([
      { id: "wordpress-plugins", files: 4, examples: [
        "composer.lock: wpackagist-plugin/contact-form-7", "composer.lock: wpackagist-theme/twentytwenty",
        "wp-content/plugins/akismet", "wp-content/plugins/hello.php"] },
      { id: "actions-unchecked", files: 3, examples: [
        "org/shared/.github/workflows/build.yml@main (.github/workflows/ci.yml)",
        "actions/checkout@v4 (.github/workflows/ci.yml)", "tj-actions/changed-files@v35 (.github/workflows/ci.yml)"] },
    ]);
  });

  // Task M2-5: once the Synvoya Actions matcher ran, only the references it could not evaluate stay in the gap.
  test("discovery lists every workflow reference and file; the gap keeps only references the Actions matcher did not evaluate", async () => {
    const workflow = "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: tj-actions/changed-files@main\n      - uses: docker://alpine:3.20\n";
    const discovery = await discoverCoverageGaps(await tree({
      ".github/workflows/a.yml": workflow,
      ".github/workflows/b.yml": "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n",
    }));
    expect(discovery.actionReferences).toEqual([
      { reference: "actions/checkout@v4", file: ".github/workflows/a.yml" },
      { reference: "tj-actions/changed-files@main", file: ".github/workflows/a.yml" },
      { reference: "docker://alpine:3.20", file: ".github/workflows/a.yml" },
      { reference: "actions/checkout@v4", file: ".github/workflows/b.yml" },
    ]);
    // Discovery alone: every reference, once, as before.
    expect(discovery.gaps.find((gap) => gap.id === "actions-unchecked")?.files).toBe(3);
    const evaluated = new Set([".github/workflows/a.yml\0actions/checkout@v4"]);
    // b.yml's checkout was not evaluated (say its file was skipped), so that reference stays, named with b.yml;
    // a composite action's reference the reader saw but could not evaluate joins the gap.
    expect(actionsUncheckedGap([...discovery.actionReferences!, { reference: "x/y@dev", file: "action.yml" }], evaluated)).toEqual({
      id: "actions-unchecked", files: 4, examples: [
        "actions/checkout@v4 (.github/workflows/b.yml)", "tj-actions/changed-files@main (.github/workflows/a.yml)",
        "docker://alpine:3.20 (.github/workflows/a.yml)", "x/y@dev (action.yml)",
      ],
    });
    const all = new Set(discovery.actionReferences!.map((entry) => `${entry.file}\0${entry.reference}`));
    expect(actionsUncheckedGap(discovery.actionReferences!, all)).toBeUndefined();
  });

  // Security review: repeated entries in a crafted lockfile are counted once, in linear time.
  test("a lockfile of 200,000 repeated WordPress entries is read fast and counted once", async () => {
    const lock = `{"packages": [${Array.from({ length: 200_000 }, () => '{"name": "wpackagist-plugin/x"}').join(",")}]}`;
    const started = performance.now();
    const { gaps } = await gapsFromFiles(["composer.lock"], async () => lock);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(gaps).toEqual([{ id: "wordpress-plugins", files: 1, examples: ["composer.lock: wpackagist-plugin/x"] }]);
  });

  // Review I-1: Trivy 0.76.1 drops Maven test and provided dependencies even with --include-dev-deps
  // (jackson-databind 2.9.1: 74 advisories without a scope, 0 with one).
  test("test- and provided-scoped Maven dependencies are dev-deps-unscanned", async () => {
    const pom = [
      "<project><dependencies>",
      "<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.0</version></dependency>",
      "<dependency>\n  <groupId>com.fasterxml.jackson.core</groupId>\n  <artifactId>jackson-databind</artifactId>\n  <version>2.9.1</version>\n  <scope>test</scope>\n</dependency>",
      "<dependency><groupId>javax.servlet</groupId><artifactId>servlet-api</artifactId><scope> provided </scope></dependency>",
      "<dependency><groupId>javax.servlet</groupId><artifactId>servlet-api</artifactId><scope>provided</scope></dependency>",
      "<dependency><groupId>junit</groupId><artifactId>junit</artifactId><scope>runtime</scope></dependency>",
      "</dependencies></project>",
    ].join("\n");
    const { gaps } = await gapsFromFiles(["pom.xml", "lib/pom.xml"], async (rel) => rel === "pom.xml" ? pom : undefined);
    expect(gaps).toEqual([{
      id: "dev-deps-unscanned",
      files: 3,
      examples: ["pom.xml: com.fasterxml.jackson.core:jackson-databind (test)", "pom.xml: javax.servlet:servlet-api (provided)", "lib/pom.xml (unreadable)"],
    }]);
  });

  // Re-review N-2: Trivy 0.76.1 also drops system-scoped and optional dependencies (executed: 0 of 74
  // advisories each), and cannot resolve a scope set through a property.
  test("system, optional and property-scoped Maven dependencies are dev-deps-unscanned", async () => {
    const dependency = (artifact: string, extra: string) =>
      `<dependency><groupId>g</groupId><artifactId>${artifact}</artifactId>${extra}</dependency>`;
    const pom = [
      dependency("sys", "<scope>system</scope><systemPath>/x.jar</systemPath>"),
      dependency("opt", "<optional> true </optional>"),
      dependency("prop", "<scope>${dep.scope}</scope>"),
      dependency("optprop", "<optional>${opt}</optional>"),
      dependency("required", "<optional>false</optional>"),
      dependency("compile", "<scope>compile</scope>"),
    ].join("\n");
    const { gaps } = await gapsFromFiles(["pom.xml"], async () => pom);
    expect(gaps).toEqual([{
      id: "dev-deps-unscanned",
      files: 4,
      examples: ["pom.xml: g:sys (system)", "pom.xml: g:opt (optional)", "pom.xml: g:prop (scope ${dep.scope})", "pom.xml: g:optprop (optional ${opt})"],
    }]);
  });

  test("a pom.xml of 200,000 unclosed dependency tags is read in linear time", async () => {
    const started = performance.now();
    const { gaps } = await gapsFromFiles(["pom.xml"], async () => "<dependency>".repeat(200_000));
    expect(performance.now() - started).toBeLessThan(500);
    expect(gaps).toEqual([]);
  });

  // Re-review N-1: `<groupId>\s*([^<]{1,200}?)\s*</groupId>` backtracked cubically on a tag followed by
  // whitespace and no closing tag (48.5 s for a 1 MiB pom.xml).
  test("a pom.xml of coordinate tags followed by whitespace is read fast", async () => {
    const size = 1024 * 1024 - 100;
    const pom = "<dependency><scope>test</scope>" + ("<groupId>" + " ".repeat(300)).repeat(Math.floor(size / 310)) + "</dependency>";
    const started = performance.now();
    const { gaps } = await gapsFromFiles(["pom.xml"], async () => pom);
    expect(performance.now() - started).toBeLessThan(500);
    expect(gaps).toEqual([{ id: "dev-deps-unscanned", files: 1, examples: ["pom.xml: ?:? (test)"] }]);
    const spaced = "<dependency><groupId>\n  com.x \n</groupId><artifactId> a </artifactId><scope>test</scope></dependency>";
    expect((await gapsFromFiles(["pom.xml"], async () => spaced)).gaps[0]?.examples).toEqual(["pom.xml: com.x:a (test)"]);
  });

  test("a workflow of blank lines is read in linear time", async () => {
    const started = performance.now();
    const { gaps } = await gapsFromFiles([".github/workflows/x.yml"], async () => "\n".repeat(1024 * 1024));
    expect(performance.now() - started).toBeLessThan(200);
    expect(gaps).toEqual([]);
  });

  test("a tree without scripts has no script note", async () => {
    expect((await discoverCoverageGaps(await tree({ "app.ts": "export {};\n" }))).scriptNote).toBeUndefined();
  });

  // Review M4 ruling: a parent lockfile covers a nested package.json only when that parent declares
  // the folder as a workspace; composer.lock covers only the composer.json beside it.
  test("a parent lockfile covers only declared workspaces", async () => {
    const deps = JSON.stringify({ dependencies: { lodash: "4.17.4" } });
    const root = await tree({
      "package.json": JSON.stringify({ private: true, workspaces: { packages: ["packages/*", "apps/**", "!packages/legacy"] } }),
      "package-lock.json": "{}\n",
      "packages/ui/package.json": deps,
      "packages/legacy/package.json": deps,
      "apps/web/admin/package.json": deps,
      "examples/basic/package.json": deps,
      "docs/package.json": deps,
      "pnpm-root/pnpm-lock.yaml": "",
      "pnpm-root/pnpm-workspace.yaml": "packages:\n  - 'libs/*'\n",
      "pnpm-root/libs/core/package.json": deps,
      "pnpm-root/tools/package.json": deps,
      "php/composer.lock": "{}\n",
      "php/plugins/x/composer.json": JSON.stringify({ require: { "monolog/monolog": "^3" } }),
      "php/composer.json": JSON.stringify({ require: { "monolog/monolog": "^3" } }),
    });

    const { gaps } = await discoverCoverageGaps(root);

    expect(gaps).toEqual([
      { id: "no-lockfile-npm", files: 4, examples: ["docs/package.json", "examples/basic/package.json", "packages/legacy/package.json", "pnpm-root/tools/package.json"] },
      { id: "no-lockfile-composer", files: 1, examples: ["php/plugins/x/composer.json"] },
    ]);
  });

  // Security review: workspace globs come from the scanned repository; compiled to a backtracking
  // RegExp, `*a*a*…b` against a long folder name never finished. The matcher is segment-wise and linear.
  test("an adversarial workspace glob against long paths finishes quickly", async () => {
    const deps = JSON.stringify({ dependencies: { lodash: "4.17.4" } });
    const longName = "a".repeat(5000);
    const deep = "a/".repeat(2000);
    const sources: Record<string, string> = {
      "package.json": JSON.stringify({ workspaces: [`${"*a".repeat(120)}b`, `${"**/".repeat(60)}b`, "packages/*"] }),
      [`${longName}/package.json`]: deps,
      [`${deep}package.json`]: deps,
      "packages/ui/package.json": deps,
    };
    const files = ["package-lock.json", ...Object.keys(sources)];
    const started = performance.now();
    const { gaps } = await gapsFromFiles(files, async (rel) => sources[rel]);
    expect(performance.now() - started).toBeLessThan(50);
    expect(gaps.map((gap) => [gap.id, gap.files])).toEqual([["no-lockfile-npm", 2]]);
  });

  test.each([
    ["more than 64 patterns", Array.from({ length: 65 }, (_, index) => (index === 0 ? "packages/*" : `other${index}/*`))],
    ["a pattern over 256 characters", ["packages/*", `${"x".repeat(257)}/*`]],
    ["brace alternatives past the bound", ["packages/*", `{${Array.from({ length: 65 }, (_, index) => `p${index}`).join(",")}}/*`]],
  ])("a declaration with %s is treated as undeclared", async (_label, workspaces) => {
    const sources: Record<string, string> = {
      "package.json": JSON.stringify({ workspaces }),
      "packages/ui/package.json": JSON.stringify({ dependencies: { lodash: "4.17.4" } }),
    };
    const { gaps } = await gapsFromFiles(["package-lock.json", ...Object.keys(sources)], async (rel) => sources[rel]);
    expect(gaps).toEqual([{ id: "no-lockfile-npm", files: 1, examples: ["packages/ui/package.json"] }]);
  });

  test("workspace globs support **, ?, {a,b}, ./ and trailing slashes", async () => {
    const deps = JSON.stringify({ dependencies: { lodash: "4.17.4" } });
    const sources: Record<string, string> = {
      "package.json": JSON.stringify({ workspaces: ["./apps/**/", "libs/c?re", "{tools,scripts}/*"] }),
      "apps/package.json": deps,
      "apps/web/admin/package.json": deps,
      "libs/core/package.json": deps,
      "libs/chore/package.json": deps,
      "tools/x/package.json": deps,
      "scripts/y/package.json": deps,
    };
    const { gaps } = await gapsFromFiles(["package-lock.json", ...Object.keys(sources)], async (rel) => sources[rel]);
    expect(gaps).toEqual([{ id: "no-lockfile-npm", files: 1, examples: ["libs/chore/package.json"] }]);
  });

  test("an unparsable workspace declaration covers nothing", async () => {
    const root = await tree({
      "pnpm-lock.yaml": "",
      "pnpm-workspace.yaml": "packages: [unclosed\n",
      "libs/core/package.json": JSON.stringify({ dependencies: { lodash: "4.17.4" } }),
    });
    expect((await discoverCoverageGaps(root)).gaps).toEqual([
      { id: "no-lockfile-npm", files: 1, examples: ["libs/core/package.json"] },
    ]);
  });

  test("describes a gap and marks an accepted one as still not covered", () => {
    const gap = { id: "go-sast" as const, files: 7, examples: ["a.go", "b.go", "c.go", "d.go", "e.go"] };
    expect(describeCoverageGap(gap, false)).toBe(
      "7 go source file(s) have no bundled SAST rules (go-sast): a.go, b.go, c.go, d.go, e.go, ….",
    );
    expect(describeCoverageGap({ id: "php-sast", files: 2, examples: ["a.twig", "b.twig"] }, false)).toBe(
      "2 Twig template file(s) have no bundled SAST rules (the Synvoya PHP pack reads .php, .phtml and .blade.php only) (php-sast): a.twig, b.twig.",
    );
    expect(describeCoverageGap(gap, true)).toMatch(/Accepted with accept_gaps; still not covered\.$/);
  });

  test("describes the Synvoya pack's skipped bundles (M4 Task 4)", () => {
    expect(describeCoverageGap({ id: "third-party-bundles", files: 2, examples: ["assets/js/ckeditor/ckeditor.js", "lib/x.js"] }, false)).toBe(
      "2 vendored or minified bundle file(s) were skipped by the Opengrep taint rules, which cannot finish on them " +
        "(the Synvoya PHP and Node packs and the taint-mode baseline rules: syn-php-*, syn-node-*, ci-baseline-sql-injection-string-build); " +
        "the other baseline Opengrep rules still scanned them (third-party-bundles): " +
        "assets/js/ckeditor/ckeditor.js, lib/x.js.",
    );
  });

  test("ids are stable lowercase strings", () => {
    expect(COVERAGE_GAP_IDS.every((id) => /^[a-z]+(?:-[a-z]+)*$/.test(id))).toBe(true);
    expect(new Set(COVERAGE_GAP_IDS).size).toBe(COVERAGE_GAP_IDS.length);
  });

  test("the SAST-covered languages are exactly the languages the bundled Opengrep rules declare", async () => {
    const directory = join(process.cwd(), "detection-db", "opengrep-rules");
    const declared = new Set<string>();
    const files = (await readdir(directory, { recursive: true })).filter((name) => /\.ya?ml$/.test(name));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      for (const match of (await readFile(join(directory, file), "utf8")).matchAll(/languages:\s*\[([^\]]*)\]/g)) {
        // `generic` (regex over named deploy files) is not a code language and closes no `<language>-sast` gap.
        for (const language of match[1]!.split(",")) if (language.trim() !== "generic") declared.add(language.trim());
      }
    }
    // `generic` rules read configuration files and Blade templates, not a source language.
    declared.delete("generic");
    expect([...declared].sort()).toEqual([...SAST_COVERED_LANGUAGES].sort());
  });
});
