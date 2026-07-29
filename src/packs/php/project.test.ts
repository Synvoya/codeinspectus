import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { resolvePhpProject } from "./project.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-php-project-"));
  roots.push(root);
  return root;
}

describe("PHP project loader", () => {
  it("loads production PHP while excluding tests, generated files, dependencies, and caches", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, "tests"), { recursive: true });
    await mkdir(join(root, "vendor"), { recursive: true });
    await writeFile(join(root, "src", "Agent.php"), "<?php class Agent {}\n");
    await writeFile(join(root, "src", "AgentTest.php"), "<?php class AgentTest {}\n");
    await writeFile(join(root, "src", "Agent.generated.php"), "<?php class Generated {}\n");
    await writeFile(join(root, "tests", "Fixture.php"), "<?php class Fixture {}\n");
    await writeFile(join(root, "vendor", "Dependency.php"), "<?php class Dependency {}\n");

    const project = await resolvePhpProject(root);
    expect(project.files.map((file) => file.path)).toEqual(["src/Agent.php"]);
  });

  it("does not follow direct file or directory-entry symbolic links", async () => {
    const root = await temporaryRoot();
    const outside = join(root, "Outside.php");
    await writeFile(outside, "<?php class Outside {}\n");
    await mkdir(join(root, "project"));
    await symlink(outside, join(root, "project", "Linked.php"));

    const directory = await resolvePhpProject(join(root, "project"));
    expect(directory.files).toEqual([]);
    expect(directory.limitations?.join(" ")).toContain("symbolic-link PHP source entry Linked.php");

    const direct = await resolvePhpProject(join(root, "project", "Linked.php"));
    expect(direct.files).toEqual([]);
    expect(direct.limitations?.join(" ")).toContain("symbolic-link PHP source target");
  });
});
