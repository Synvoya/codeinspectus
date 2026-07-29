import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { resolveRustProject } from "./project.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-rust-project-"));
  roots.push(root);
  return root;
}

describe("Rust project loader", () => {
  it("loads production Rust while excluding tests, examples, generated files, and target trees", async () => {
    const root = await temporaryRoot();
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, "tests"), { recursive: true });
    await mkdir(join(root, "examples"), { recursive: true });
    await mkdir(join(root, "target", "debug"), { recursive: true });
    await writeFile(join(root, "src", "main.rs"), "fn main() {}\n");
    await writeFile(join(root, "src", "schema.generated.rs"), "// generated; do not edit\n");
    await writeFile(join(root, "tests", "agent.rs"), "fn test_agent() {}\n");
    await writeFile(join(root, "examples", "demo.rs"), "fn main() {}\n");
    await writeFile(join(root, "target", "debug", "build.rs"), "fn main() {}\n");

    const project = await resolveRustProject(root);
    expect(project.files.map((file) => file.path)).toEqual(["src/main.rs"]);
  });

  it("does not follow direct file or directory-entry symbolic links", async () => {
    const root = await temporaryRoot();
    const outside = join(root, "outside.rs");
    await writeFile(outside, "fn outside() {}\n");
    await mkdir(join(root, "project"));
    await symlink(outside, join(root, "project", "linked.rs"));

    const directory = await resolveRustProject(join(root, "project"));
    expect(directory.files).toEqual([]);
    expect(directory.limitations?.join(" ")).toContain("symbolic-link Rust source entry linked.rs");

    const direct = await resolveRustProject(join(root, "project", "linked.rs"));
    expect(direct.files).toEqual([]);
    expect(direct.limitations?.join(" ")).toContain("symbolic-link Rust source target");
  });
});
