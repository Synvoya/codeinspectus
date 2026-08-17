import { afterEach, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createCachedPythonProjectLoader, loadPythonProject } from "./project.js";
import { parsePythonSource } from "./python.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function project(): Promise<string> {
  const directory = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-python-project-"));
  directories.push(directory);
  return directory;
}

describe("bounded Python project loader", () => {
  test("loads production Python while excluding generated and corpus trees", async () => {
    const directory = await project();
    await mkdir(join(directory, "src"));
    await mkdir(join(directory, "tests"));
    await mkdir(join(directory, "examples"));
    await mkdir(join(directory, ".venv"));
    await writeFile(join(directory, "src", "app.py"), "actual()\n", "utf8");
    await writeFile(join(directory, "src", "service_pb2.py"), "generated()\n", "utf8");
    await writeFile(join(directory, "src", "test_inline.py"), "planted()\n", "utf8");
    await writeFile(join(directory, "tests", "test_app.py"), "planted()\n", "utf8");
    await writeFile(join(directory, "examples", "demo.py"), "planted()\n", "utf8");
    await writeFile(join(directory, ".venv", "dependency.py"), "planted()\n", "utf8");

    const loaded = await loadPythonProject(directory);

    expect(loaded.files.map((file) => file.path)).toEqual(["src/app.py"]);
  });

  test("loads valid bare-yield and starred-target source without a parser limitation", async () => {
    const directory = await project();
    await writeFile(join(directory, "timer.py"), `
def timer():
    yield

for code, *parameters in control_codes:
    consume(code, parameters)
`, "utf8");

    const loaded = await loadPythonProject(directory);

    expect(loaded.files.map((file) => file.path)).toEqual(["timer.py"]);
    expect(loaded.limitations ?? []).toEqual([]);
  });

  test("skips unsupported and invalid source encodings", async () => {
    const directory = await project();
    await writeFile(
      join(directory, "latin.py"),
      Buffer.from("# -*- coding: latin-1 -*-\nvalue = '\\xe9'\n", "latin1"),
    );
    await writeFile(join(directory, "invalid.py"), Buffer.from([0xff, 0xfe, 0xfd]));

    const loaded = await loadPythonProject(directory);

    expect(loaded.files).toEqual([]);
    expect(loaded.limitations?.join(" ")).toMatch(/unsupported latin-1 encoding/i);
    expect(loaded.limitations?.join(" ")).toMatch(/not valid UTF-8/i);
  });

  test("skips generated-code headers", async () => {
    const directory = await project();
    await writeFile(
      join(directory, "client.py"),
      "# Generated from service schema. DO NOT EDIT.\nplanted()\n",
      "utf8",
    );

    const loaded = await loadPythonProject(directory);

    expect(loaded.files).toEqual([]);
    expect(loaded.limitations?.join(" ")).toMatch(/generated Python source client\.py/i);
  });

  test("allows an explicitly targeted Python file inside an excluded corpus", async () => {
    const directory = await project();
    await mkdir(join(directory, "tests"));
    const target = join(directory, "tests", "test_app.py");
    await writeFile(target, "targeted()\n", "utf8");

    const loaded = await loadPythonProject(target);

    expect(loaded.files.map((file) => file.path)).toEqual(["test_app.py"]);
  });

  test("never follows source symlinks", async () => {
    const directory = await project();
    const outside = join(directory, "outside.py");
    await writeFile(outside, "outside()\n", "utf8");
    await mkdir(join(directory, "src"));
    await symlink(outside, join(directory, "src", "linked.py"));

    const loaded = await loadPythonProject(directory);

    expect(loaded.files.map((file) => file.path)).toEqual(["outside.py"]);
    expect(loaded.limitations?.join(" ")).toMatch(/symbolic-link Python source path src\/linked\.py/i);
  });

  test("rejects a directory target reached through a symbolic-link ancestor", async () => {
    const directory = await project();
    const inside = join(directory, "inside");
    const outside = join(directory, "outside");
    await mkdir(inside);
    await mkdir(join(outside, "repository"), { recursive: true });
    await writeFile(join(outside, "repository", "app.py"), "OUTSIDE_DIRECTORY_SENTINEL()\n", "utf8");
    await symlink(outside, join(inside, "bridge"));

    const loaded = await loadPythonProject(join(inside, "bridge", "repository"));

    expect(loaded.files).toEqual([]);
    expect(loaded.files.flatMap((file) => file.tokens.map((token) => token.value)))
      .not.toContain("OUTSIDE_DIRECTORY_SENTINEL");
    expect(loaded.limitations?.join(" ")).toMatch(/symbolic-link ancestor/i);
  });

  test("rejects a direct-file target reached through a symbolic-link ancestor", async () => {
    const directory = await project();
    const inside = join(directory, "inside");
    const outside = join(directory, "outside");
    await mkdir(inside);
    await mkdir(join(outside, "repository"), { recursive: true });
    await writeFile(join(outside, "repository", "app.py"), "OUTSIDE_FILE_SENTINEL()\n", "utf8");
    await symlink(outside, join(inside, "bridge"));

    const loaded = await loadPythonProject(join(inside, "bridge", "repository", "app.py"));

    expect(loaded.files).toEqual([]);
    expect(loaded.files.flatMap((file) => file.tokens.map((token) => token.value)))
      .not.toContain("OUTSIDE_FILE_SENTINEL");
    expect(loaded.limitations?.join(" ")).toMatch(/symbolic-link ancestor/i);
  });

  test("reports malformed inputs and project bounds instead of emitting partial documents", async () => {
    const directory = await project();
    await writeFile(join(directory, "a.py"), "broken = ([)]\n", "utf8");
    await writeFile(join(directory, "b.py"), "first()\n", "utf8");
    await writeFile(join(directory, "c.py"), "second()\n", "utf8");

    const loaded = await loadPythonProject(directory, { maxSourceFiles: 2 });

    expect(loaded.files.map((file) => file.path)).toEqual(["b.py"]);
    expect(loaded.limitations?.join(" ")).toMatch(/parser-invalid Python source a\.py/i);
    expect(loaded.limitations?.join(" ")).toMatch(/2-file project bound/i);
  });

  test("charges malformed source against the aggregate byte bound", async () => {
    const directory = await project();
    const malformed = "broken = ([)]\n";
    await writeFile(join(directory, "a.py"), malformed, "utf8");
    await writeFile(join(directory, "b.py"), "actual()\n", "utf8");

    const loaded = await loadPythonProject(directory, {
      maxTotalBytes: Buffer.byteLength(malformed),
    });

    expect(loaded.files).toEqual([]);
    expect(loaded.limitations?.join(" ")).toMatch(/parser-invalid Python source a\.py/i);
    expect(loaded.limitations?.join(" ")).toMatch(/total-source project bound/i);
    expect(loaded.limitations?.join(" ")).not.toMatch(/b\.py/i);
  });

  test("charges malformed source against the aggregate token bound", async () => {
    const directory = await project();
    const malformed = "broken = ([)]\n";
    const tokenCount = parsePythonSource("a.py", malformed).tokens.length;
    await writeFile(join(directory, "a.py"), malformed, "utf8");
    await writeFile(join(directory, "b.py"), "actual()\n", "utf8");

    const loaded = await loadPythonProject(directory, { maxTotalTokens: tokenCount });

    expect(loaded.files).toEqual([]);
    expect(loaded.limitations?.join(" ")).toMatch(/parser-invalid Python source a\.py/i);
    expect(loaded.limitations?.join(" ")).toMatch(/token project bound/i);
    expect(loaded.limitations?.join(" ")).not.toMatch(/b\.py/i);
  });

  test("charges parser-invalid source against the aggregate syntax-tree node bound", async () => {
    const directory = await project();
    const malformed = "value = if True\nother = 1\nthird = 2\n";
    const nodeCount = parsePythonSource("a.py", malformed).cstNodeCount;
    await writeFile(join(directory, "a.py"), malformed, "utf8");
    await writeFile(join(directory, "b.py"), "actual()\n", "utf8");

    const loaded = await loadPythonProject(directory, { maxTotalCstNodes: nodeCount });

    expect(loaded.files).toEqual([]);
    expect(loaded.limitations?.join(" ")).toMatch(/parser-invalid Python source a\.py/i);
    expect(loaded.limitations?.join(" ")).toMatch(/node project bound/i);
    expect(loaded.limitations?.join(" ")).not.toMatch(/b\.py/i);
  });

  test("shares one parse inside a pack loader but a new loader observes fixes", async () => {
    const directory = await project();
    const target = join(directory, "app.py");
    await writeFile(target, "before()\n", "utf8");
    const load = createCachedPythonProjectLoader(directory);
    const first = await load();
    await writeFile(target, "after()\n", "utf8");

    expect(await load()).toBe(first);
    expect((await createCachedPythonProjectLoader(directory)()).files[0]?.tokens[0]?.value).toBe("after");
  });
});
