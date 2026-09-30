/**
 * `generate_sbom` is a non-destructive managed write. A caller-chosen output_path must never
 * replace an existing file that is not an SBOM, and must be an explicit absolute JSON path.
 */
import { describe, expect, test } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateSbom } from "./sbom.js";

async function project(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-sbom-output-"));
  await writeFile(join(dir, "package.json"), '{"name":"fixture","version":"1.0.0"}\n');
  await writeFile(join(dir, "keep.ts"), "export const keep = true;\n");
  return dir;
}

describe("generate_sbom output_path safety", () => {
  test("refuses to overwrite an existing non-SBOM file", async () => {
    const dir = await project();

    await expect(generateSbom({ path: dir, output_path: join(dir, "keep.ts") })).rejects.toThrow(/not an SBOM|\.json/i);
    expect(await readFile(join(dir, "keep.ts"), "utf8")).toBe("export const keep = true;\n");
  });

  test("refuses to overwrite an existing JSON file that is not an SBOM", async () => {
    const dir = await project();

    await expect(generateSbom({ path: dir, output_path: join(dir, "package.json") })).rejects.toThrow(/not an SBOM/i);
    expect(await readFile(join(dir, "package.json"), "utf8")).toBe('{"name":"fixture","version":"1.0.0"}\n');
  });

  test("refuses a relative output_path that would resolve against the server's working directory", async () => {
    const dir = await project();

    await expect(generateSbom({ path: dir, output_path: "sbom.json" })).rejects.toThrow(/absolute/i);
  });
});
