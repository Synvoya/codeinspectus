/**
 * SBOM generation via Trivy (PRD §8). CycloneDX or SPDX.
 *
 * Read-only discipline (PRD §11): by default the SBOM is written to the managed
 * dir (~/.codeinspectus/sbom/), NOT into the user's repo. The user can opt into a
 * specific location by passing output_path.
 */

import { z } from "zod";
import { mkdir, readFile, stat } from "node:fs/promises";
import { join, basename, dirname } from "node:path";
import { resolve as resolvePath } from "node:path";
import { MANAGED_ROOT } from "./config.js";
import { runTrivySbom } from "./engines/trivy.js";
import type { sbomOutput } from "./schemas.js";
import type { GenerateSbomInput } from "./schemas.js";

type SbomResult = z.infer<typeof sbomOutput>;

function countComponents(json: unknown, format: string): number {
  try {
    const obj = json as Record<string, unknown>;
    if (format === "spdx") {
      const pkgs = obj.packages;
      return Array.isArray(pkgs) ? pkgs.length : 0;
    }
    const comps = obj.components;
    return Array.isArray(comps) ? comps.length : 0;
  } catch {
    return 0;
  }
}

export async function generateSbom(input: GenerateSbomInput): Promise<SbomResult> {
  const format = input.format ?? "cyclonedx";
  const target = resolvePath(input.path);
  try {
    await stat(target);
  } catch {
    throw new Error(`Path not found: ${target}. Provide an absolute path to an existing project.`);
  }

  const base = basename(target.replace(/\/$/, "")) || "project";
  const defaultOut = join(MANAGED_ROOT, "sbom", `${base}.${format}.json`);
  const outputPath = input.output_path ? resolvePath(input.output_path) : defaultOut;
  await mkdir(dirname(outputPath), { recursive: true });

  const run = await runTrivySbom(target, format, outputPath);
  if (!run.ran) {
    return {
      format,
      output_path: outputPath,
      component_count: 0,
      generated: false,
      note:
        run.note ??
        "SBOM generation failed. Ensure Trivy is installed (`codeinspectus install-engines`).",
    };
  }

  let componentCount = 0;
  try {
    componentCount = countComponents(JSON.parse(await readFile(outputPath, "utf8")), format);
  } catch {
    /* keep 0 */
  }

  return {
    format,
    output_path: outputPath,
    component_count: componentCount,
    generated: true,
    ...(input.output_path
      ? {}
      : { note: `Written to the managed dir (read-only mode). Pass output_path to choose a location.` }),
  };
}
