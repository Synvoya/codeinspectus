import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { resolveJavaProject } from "./project.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-java-project-"));
  roots.push(root);
  return root;
}

describe("Java project loader", () => {
  it("loads production Java while excluding tests, generated files, and build trees", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "src", "main", "java"), { recursive: true });
    await mkdir(join(root, "src", "test", "java"), { recursive: true });
    await mkdir(join(root, "target", "generated-sources"), { recursive: true });
    await writeFile(join(root, "src", "main", "java", "Agent.java"), "class Agent {}\n");
    await writeFile(join(root, "src", "main", "java", "AgentTest.java"), "class AgentTest {}\n");
    await writeFile(join(root, "src", "test", "java", "Fixture.java"), "class Fixture {}\n");
    await writeFile(join(root, "target", "generated-sources", "Generated.java"), "class Generated {}\n");

    const project = await resolveJavaProject(root);
    expect(project.files.map((file) => file.path)).toEqual(["src/main/java/Agent.java"]);
  });

  it("does not follow direct file or directory-entry symbolic links", async () => {
    const root = await temporaryRoot();
    const outside = join(root, "Outside.java");
    await writeFile(outside, "class Outside {}\n");
    await mkdir(join(root, "project"));
    await symlink(outside, join(root, "project", "Linked.java"));

    const directory = await resolveJavaProject(join(root, "project"));
    expect(directory.files).toEqual([]);
    expect(directory.limitations?.join(" ")).toContain("symbolic-link Java source entry Linked.java");

    const direct = await resolveJavaProject(join(root, "project", "Linked.java"));
    expect(direct.files).toEqual([]);
    expect(direct.limitations?.join(" ")).toContain("symbolic-link Java source target");
  });
});
