import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { writeExportFile } from "./writer.js";

const cleanup: string[] = [];
async function root(): Promise<string> { const value = await mkdtemp(join(await realpath(tmpdir()), "ci-export-")); cleanup.push(value); return value; }
afterEach(async () => Promise.all(cleanup.splice(0).map((value) => rm(value, { recursive: true, force: true }))));

describe("atomic exact-file export", () => {
  test("writes the explicitly selected file outside the repository boundary", async () => {
    const repo = await root(); const out = await root(); const file = join(out, "result.json");
    await writeExportFile(file, "{\"ok\":true}\n", repo);
    expect(await readFile(file, "utf8")).toBe("{\"ok\":true}\n");
  });

  test("rejects traversal and symlink output components", async () => {
    const repo = await root(); const out = await root();
    await expect(writeExportFile(`${out}/../escaped.json`, "x", repo)).rejects.toThrow(/traversal/i);
    const actual = join(out, "actual"); await mkdir(actual); await symlink(actual, join(out, "linked"));
    await expect(writeExportFile(join(out, "linked", "x.json"), "x", repo)).rejects.toThrow(/symbolic/i);
  });

  test("requires explicit approval inside the repository and then writes atomically", async () => {
    const repo = await root(); const file = join(repo, "report.json"); await writeFile(join(repo, "source.ts"), "x");
    await expect(writeExportFile(file, "x", repo)).rejects.toThrow(/allow-output-in-target/i);
    await writeExportFile(file, "approved", repo, true);
    expect(await readFile(file, "utf8")).toBe("approved");
  });
});
