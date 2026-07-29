import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { resolveRubyProject } from "./project.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-ruby-project-"));
  roots.push(root);
  return root;
}

describe("Ruby project loader", () => {
  it("loads production Ruby while excluding specs, generated files, dependencies, and caches", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "lib"), { recursive: true });
    await mkdir(join(root, "spec"), { recursive: true });
    await mkdir(join(root, "vendor"), { recursive: true });
    await writeFile(join(root, "lib", "agent.rb"), "class Agent; end\n");
    await writeFile(join(root, "lib", "agent_spec.rb"), "RSpec.describe Agent; end\n");
    await writeFile(join(root, "lib", "schema.generated.rb"), "# generated; do not edit\n");
    await writeFile(join(root, "spec", "agent.rb"), "RSpec.describe Agent; end\n");
    await writeFile(join(root, "vendor", "dependency.rb"), "class Dependency; end\n");

    const project = await resolveRubyProject(root);
    expect(project.files.map((file) => file.path)).toEqual(["lib/agent.rb"]);
  });

  it("does not follow direct file or directory-entry symbolic links", async () => {
    const root = await temporaryRoot();
    const outside = join(root, "outside.rb");
    await writeFile(outside, "class Outside; end\n");
    await mkdir(join(root, "project"));
    await symlink(outside, join(root, "project", "linked.rb"));

    const directory = await resolveRubyProject(join(root, "project"));
    expect(directory.files).toEqual([]);
    expect(directory.limitations?.join(" ")).toContain("symbolic-link Ruby source entry linked.rb");

    const direct = await resolveRubyProject(join(root, "project", "linked.rb"));
    expect(direct.files).toEqual([]);
    expect(direct.limitations?.join(" ")).toContain("symbolic-link Ruby source target");
  });
});
