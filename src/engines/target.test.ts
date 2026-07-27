import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { engineWorkingDirectory } from "./target.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("external engine working directory", () => {
  it("uses a directory target directly and a file target's parent", async () => {
    const root = await mkdtemp(join(tmpdir(), "ci-engine-cwd-"));
    roots.push(root);
    const file = join(root, "pubspec.lock");
    await writeFile(file, "packages: {}\n", "utf8");

    expect(await engineWorkingDirectory(root)).toBe(root);
    expect(await engineWorkingDirectory(file)).toBe(root);
  });

  it("does not follow a directly targeted symlink to choose cwd", async () => {
    const root = await mkdtemp(join(tmpdir(), "ci-engine-cwd-link-"));
    const outside = await mkdtemp(join(tmpdir(), "ci-engine-cwd-outside-"));
    roots.push(root, outside);
    const real = join(outside, "pubspec.lock");
    const linked = join(root, "pubspec.lock");
    await writeFile(real, "packages: {}\n", "utf8");
    await symlink(real, linked);

    expect(await engineWorkingDirectory(linked)).toBe(root);
  });
});
