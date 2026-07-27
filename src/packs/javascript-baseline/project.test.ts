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
    expect(directoryProject.limitations?.join(" ")).toMatch(/structurally malformed.*broken\.ts/i);
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
});
