import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { resolveGoProject } from "./project.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-go-project-"));
  roots.push(root);
  return root;
}

describe("Go project loader", () => {
  it("loads production Go while excluding tests, generated files, and dependency trees", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "vendor", "example"), { recursive: true });
    await mkdir(join(root, "testdata"), { recursive: true });
    await writeFile(join(root, "main.go"), "package main\n");
    await writeFile(join(root, "main_test.go"), "package main\n");
    await writeFile(join(root, "schema.pb.go"), "package main\n");
    await writeFile(join(root, "vendor", "example", "dependency.go"), "package example\n");
    await writeFile(join(root, "testdata", "fixture.go"), "package fixture\n");

    const project = await resolveGoProject(root);
    expect(project.files.map((file) => file.path)).toEqual(["main.go"]);
  });

  it("does not follow direct file or directory-entry symbolic links", async () => {
    const root = await temporaryRoot();
    const outside = join(root, "outside.go");
    await writeFile(outside, "package outside\n");
    await mkdir(join(root, "project"));
    await symlink(outside, join(root, "project", "linked.go"));

    const directory = await resolveGoProject(join(root, "project"));
    expect(directory.files).toEqual([]);
    expect(directory.limitations?.join(" ")).toContain("symbolic-link Go source entry linked.go");

    const direct = await resolveGoProject(join(root, "project", "linked.go"));
    expect(direct.files).toEqual([]);
    expect(direct.limitations?.join(" ")).toContain("symbolic-link Go source target");
  });
});
