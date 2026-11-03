import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { loadJavaScriptBaselineProject } from "./project.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-js-baseline-"));
  roots.push(root);
  return root;
}

describe("JavaScript baseline project loader", () => {
  test("loads production and test/example source while excluding dependencies", async () => {
    const root = await temporaryRoot();
    for (const directory of ["src", "tests", "examples", "node_modules/pkg"]) {
      await mkdir(join(root, directory), { recursive: true });
    }
    await writeFile(join(root, "src/app.js"), `crypto.createHash("md5");\n`);
    await writeFile(join(root, "tests/app.test.ts"), `crypto.createHash("sha1");\n`);
    await writeFile(join(root, "examples/demo.jsx"), `crypto.createCipher("aes", password);\n`);
    await writeFile(join(root, "node_modules/pkg/index.js"), `crypto.createHash("md5");\n`);

    const project = await loadJavaScriptBaselineProject(root);

    expect(project.limitations).toEqual([]);
    expect(project.files.map((file) => file.path)).toEqual([
      "examples/demo.jsx",
      "src/app.js",
      "tests/app.test.ts",
    ]);
  });

  // Field re-test G8d: monicahq/monica's committed `.yarn/releases/yarn-4.6.0.cjs` (2.7 MB) was the only
  // cause of partial JavaScript coverage. Yarn's tooling and PnP loaders are vendored, not source.
  test("skips Yarn's vendored tooling and PnP loaders like node_modules", async () => {
    const root = await temporaryRoot();
    for (const directory of [
      "src", ".yarn/releases", ".yarn/plugins/@yarnpkg", ".yarn/sdks/typescript", ".yarn/cache", ".yarn/unplugged/pkg",
      "packages/web/.yarn/releases",
    ]) {
      await mkdir(join(root, directory), { recursive: true });
    }
    const oversized = `/* ${"x".repeat(64)} */\n`;
    await writeFile(join(root, "package.json"), "{}\n");
    await writeFile(join(root, "packages/web/package.json"), "{}\n");
    await writeFile(join(root, "src/app.js"), `crypto.createHash("md5");\n`);
    await writeFile(join(root, ".yarn/releases/yarn-4.6.0.cjs"), oversized);
    await writeFile(join(root, ".yarn/plugins/@yarnpkg/plugin-workspace-tools.cjs"), oversized);
    await writeFile(join(root, ".yarn/sdks/typescript/index.js"), oversized);
    await writeFile(join(root, ".yarn/unplugged/pkg/index.js"), `crypto.createHash("md5");\n`);
    await writeFile(join(root, "packages/web/.yarn/releases/yarn.cjs"), oversized);
    await writeFile(join(root, ".pnp.cjs"), oversized);
    await writeFile(join(root, ".pnp.loader.mjs"), oversized);

    const project = await loadJavaScriptBaselineProject(root, { maxSourceBytes: 32 });

    expect(project.limitations).toEqual([]);
    expect(project.files.map((file) => file.path)).toEqual(["src/app.js"]);
  });

  // Review: a folder merely named `.yarn` (no package.json beside it) or an unknown `.yarn/` subfolder
  // must not hide source from the native packs.
  test("never skips source in other .yarn folders", async () => {
    const root = await temporaryRoot();
    for (const directory of [".yarn/custom", "lib/.yarn/releases"]) await mkdir(join(root, directory), { recursive: true });
    await writeFile(join(root, "package.json"), "{}\n");
    await writeFile(join(root, ".yarn/custom/hidden.js"), `crypto.createHash("md5");\n`);
    await writeFile(join(root, "lib/.yarn/releases/hidden.js"), `crypto.createHash("md5");\n`);
    await writeFile(join(root, "lib/.pnp.cjs"), `crypto.createHash("md5");\n`);

    const project = await loadJavaScriptBaselineProject(root);

    expect(project.files.map((file) => file.path)).toEqual([
      ".yarn/custom/hidden.js",
      "lib/.pnp.cjs",
      "lib/.yarn/releases/hidden.js",
    ]);
  });

  test("direct-file scans use a basename and malformed input fails closed", async () => {
    const root = await temporaryRoot();
    const direct = join(root, "direct.mts");
    const malformed = join(root, "broken.ts");
    await writeFile(direct, `createHash("md5");\n`);
    await writeFile(malformed, `createHash("md5";\n`);

    const fileProject = await loadJavaScriptBaselineProject(direct);
    const directoryProject = await loadJavaScriptBaselineProject(root);

    expect(fileProject.files.map((file) => file.path)).toEqual([basename(direct)]);
    expect(directoryProject.files.map((file) => file.path)).toEqual(["direct.mts"]);
    // Pre-release field validation: an unparsed file is the declared gap native-parse-errors (a record).
    expect(directoryProject.gaps).toEqual([{ id: "native-parse-errors", path: "broken.ts" }]);
  });

  test("does not follow a symbolic-link target", async () => {
    const root = await temporaryRoot();
    const source = join(root, "source.js");
    const link = join(root, "linked.js");
    await writeFile(source, `createHash("md5");\n`);
    try {
      await symlink(source, link);
    } catch {
      return;
    }

    const project = await loadJavaScriptBaselineProject(link);
    expect(project.files).toEqual([]);
    expect(project.limitations?.join(" ")).toMatch(/symbolic-link path/i);
  });

  test("a symlink with a non-source name is not a coverage gap", async () => {
    const root = await temporaryRoot();
    await writeFile(join(root, "AGENTS.md"), "# agents\n");
    await writeFile(join(root, "app.ts"), `createHash("md5");\n`);
    try {
      await symlink("AGENTS.md", join(root, "CLAUDE.md"));
    } catch {
      return;
    }

    const project = await loadJavaScriptBaselineProject(root);

    expect(project.limitations).toEqual([]);
  });

  test("source-named and directory links are gaps even when they resolve inside the project", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "vendor"));
    await writeFile(join(root, "vendor", "impl.ts"), `createHash("md5");\n`);
    try {
      await symlink(join("vendor", "impl.ts"), join(root, "alias.ts"));
      await symlink("vendor", join(root, "lib"));
    } catch {
      return;
    }

    const project = await loadJavaScriptBaselineProject(root);

    expect(project.gaps).toEqual(expect.arrayContaining([
      { id: "symlinked-paths", path: "alias.ts" },
      { id: "symlinked-paths", path: "lib" },
    ]));
  });

  test("a symlink to source outside the project is still disclosed", async () => {
    const root = await temporaryRoot();
    const outside = await temporaryRoot();
    await writeFile(join(outside, "external.ts"), `createHash("md5");\n`);
    try {
      await symlink(join(outside, "external.ts"), join(root, "external.ts"));
    } catch {
      return;
    }

    const project = await loadJavaScriptBaselineProject(root);

    // Ruling 30 (I-3): a target outside the root is unanalysed, so it is not an acceptable gap.
    expect(project.gaps ?? []).toEqual([]);
    expect(project.limitations?.join(" ")).toMatch(/symbolic-link path external\.ts/);
  });

  // Ruling 30 (I-3): symlinked-paths only when the real target is inside the root and this walker
  // visits it; a link into node_modules/ or beyond the depth bound stays a non-acceptable limitation.
  test("a link into node_modules or beyond the depth bound is not an acceptable gap", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "node_modules", "pkg"), { recursive: true });
    await writeFile(join(root, "node_modules", "pkg", "index.js"), `createHash("md5");\n`);
    // `z` sorts after the links, so the walk reaches them before its own depth stop.
    await mkdir(join(root, "z", "y", "x"), { recursive: true });
    await writeFile(join(root, "z", "y", "x", "deep.ts"), `createHash("md5");\n`);
    try {
      await symlink(join("node_modules", "pkg"), join(root, "dep"));
      await symlink(join("node_modules", "pkg", "index.js"), join(root, "dep.js"));
      await symlink(join("z", "y", "x"), join(root, "deep"));
    } catch {
      return;
    }

    const project = await loadJavaScriptBaselineProject(root, { maxDepth: 2 });

    expect(project.gaps ?? []).toEqual([]);
    const limitations = project.limitations?.join(" ") ?? "";
    for (const link of ["dep", "dep.js", "deep"]) expect(limitations).toContain(`symbolic-link path ${link} `);
  });

  // Ruling 29: cap-collectif hit the 1,000,000-token project bound, a free-text note no gap id could
  // accept. Files past the budget are now counted as the structured gap native-token-budget.
  test("files past the project token budget are a declared gap, each counted once", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "b"));
    for (const file of ["a.js", "b/c.js", "d.js"]) await writeFile(join(root, file), `crypto.createHash("md5");\n`);

    const project = await loadJavaScriptBaselineProject(root, { maxTotalTokens: 10 });

    expect(project.files.map((file) => file.path)).toEqual(["a.js"]);
    expect(project.limitations).toEqual([]);
    expect(project.gaps).toEqual([
      { id: "native-token-budget", path: "b/c.js" },
      { id: "native-token-budget", path: "d.js" },
    ]);
  });

  test("a direct file over the project token budget is a declared gap", async () => {
    const root = await temporaryRoot();
    const direct = join(root, "big.js");
    await writeFile(direct, `crypto.createHash("md5");\n`);

    const project = await loadJavaScriptBaselineProject(direct, { maxTotalTokens: 3 });

    expect(project.files).toEqual([]);
    expect(project.limitations).toEqual([]);
    expect(project.gaps).toEqual([{ id: "native-token-budget", path: "big.js" }]);
  });

  // Review I-2: a file over the native lexing line cap is the declared gap oversized-files.
  test("a source file with an over-long line is an oversized-files gap", async () => {
    const root = await temporaryRoot();
    await writeFile(join(root, "bundle.js"), `var a = "${"x".repeat(70_000)}";\n`);
    await writeFile(join(root, "app.js"), `crypto.createHash("md5");\n`);

    const project = await loadJavaScriptBaselineProject(root);

    expect(project.files.map((file) => file.path)).toEqual(["app.js"]);
    expect(project.gaps).toEqual([{ id: "oversized-files", path: "bundle.js" }]);
  });
});

