import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import {
  containsTraversalSegment,
  inspectOutputDirectory,
  inspectTargetPath,
  outputContainmentRoot,
  pathIsWithin,
} from "./path-safety.js";

const cleanup: string[] = [];

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-path-safety-"));
  cleanup.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("scan target safety", () => {
  test("accepts canonical regular directory and file targets", async () => {
    const root = await temporaryRoot();
    const file = join(root, "app.ts");
    await writeFile(file, "export const safe = true;\n");

    await expect(inspectTargetPath(root)).resolves.toMatchObject({
      canonical_path: root,
      exists: true,
      supported: true,
      type: "directory",
      symlink_safe: true,
      containment: "canonical_target_root",
    });
    await expect(inspectTargetPath(file)).resolves.toMatchObject({
      canonical_path: file,
      exists: true,
      supported: true,
      type: "file",
      symlink_safe: true,
      containment: "canonical_target_root",
    });
  });

  test("missing targets fail closed without creating anything", async () => {
    const root = await temporaryRoot();
    const missing = join(root, "missing");
    const result = await inspectTargetPath(missing);
    expect(result).toMatchObject({ exists: false, supported: false, symlink_safe: true });
    await expect(readFile(missing)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects a symlink leaf and canonicalizes a target below a symlink ancestor", async () => {
    const root = await temporaryRoot();
    const real = join(root, "real");
    const linked = join(root, "linked");
    await mkdir(real);
    await writeFile(join(real, "app.ts"), "export {};\n");
    await symlink(real, linked);

    await expect(inspectTargetPath(linked)).resolves.toMatchObject({ supported: false, symlink_safe: false });
    await expect(inspectTargetPath(join(linked, "app.ts"))).resolves.toMatchObject({
      canonical_path: join(real, "app.ts"),
      supported: true,
      symlink_safe: true,
    });
  });
});

describe("output safety", () => {
  test("recognizes exact containment without prefix confusion", async () => {
    const root = await temporaryRoot();
    expect(pathIsWithin(root, join(root, "reports"))).toBe(true);
    expect(pathIsWithin(root, `${root}-other`)).toBe(false);
  });

  test("rejects traversal-shaped output and does not create it", async () => {
    const root = await temporaryRoot();
    const result = await inspectOutputDirectory(`${root}/reports/../escape`, root, false);
    expect(result).toMatchObject({ safe: false, symlink_safe: false });
    expect(result.error).toMatch(/traversal/i);
  });

  test("requires explicit approval for output inside the scan target", async () => {
    const root = await temporaryRoot();
    const output = join(root, "reports");
    const refused = await inspectOutputDirectory(output, root, false);
    expect(refused).toMatchObject({ safe: false, inside_target: true });
    expect(refused.error).toMatch(/allow-output-in-target/i);

    const approved = await inspectOutputDirectory(output, root, true);
    expect(approved).toMatchObject({ safe: true, inside_target: true, approved_inside_target: true });
  });

  test("uses a direct file's parent as the conservative no-write boundary", async () => {
    const root = await temporaryRoot();
    const file = join(root, "app.ts");
    const reports = join(root, "reports");
    await writeFile(file, "export {};\n");
    const target = await inspectTargetPath(file);
    expect(outputContainmentRoot(target)).toBe(root);

    const refused = await inspectOutputDirectory(reports, outputContainmentRoot(target), false);
    expect(refused).toMatchObject({ safe: false, inside_target: true });
    const approved = await inspectOutputDirectory(reports, outputContainmentRoot(target), true);
    expect(approved).toMatchObject({ safe: true, inside_target: true });
  });

  test("uses the enclosing Git root as the write boundary for a nested direct file", async () => {
    const root = await temporaryRoot();
    const nested = join(root, "src");
    const file = join(nested, "app.ts");
    const reports = join(root, "reports");
    await mkdir(join(root, ".git"));
    await mkdir(nested);
    await writeFile(file, "export {};\n");

    const target = await inspectTargetPath(file);
    expect(target.repository_root).toBe(root);
    expect(outputContainmentRoot(target)).toBe(root);
    await expect(inspectOutputDirectory(reports, outputContainmentRoot(target), false)).resolves.toMatchObject({
      safe: false,
      inside_target: true,
    });
  });

  test("rejects an output directory reached through a symlink", async () => {
    const root = await temporaryRoot();
    const outside = await temporaryRoot();
    const linked = join(root, "linked-output");
    await symlink(outside, linked);
    const result = await inspectOutputDirectory(linked, root, true);
    expect(result).toMatchObject({ safe: false, symlink_safe: false });
  });
});

describe("portable lexical parsing", () => {
  test("recognizes traversal with POSIX or Windows separators without rejecting dotted names", () => {
    expect(containsTraversalSegment("../reports")).toBe(true);
    expect(containsTraversalSegment("..\\reports")).toBe(true);
    expect(containsTraversalSegment("C:\\repo\\..\\reports")).toBe(true);
    expect(containsTraversalSegment("C:\\repo\\safe..name")).toBe(false);
  });
});
