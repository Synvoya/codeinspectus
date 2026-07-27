/**
 * CycloneDX/SPDX generation via Trivy plus first-party Pub inventory and fallback (PRD §8).
 *
 * Read-only discipline (PRD §11): by default the SBOM is written to the managed
 * dir (~/.codeinspectus/sbom/), NOT into the user's repo. The user can opt into a
 * specific location by passing output_path.
 */

import { z } from "zod";
import { randomUUID } from "node:crypto";
import { mkdir, rename, rm, stat, writeFile } from "node:fs/promises";
import { join, basename, dirname } from "node:path";
import { resolve as resolvePath } from "node:path";
import { MANAGED_ROOT } from "./config.js";
import { runTrivySbom } from "./engines/trivy.js";
import type { sbomOutput } from "./schemas.js";
import type { GenerateSbomInput } from "./schemas.js";
import { loadPubLockfiles } from "./pub/lockfile.js";
import {
  generatePubSbom,
  mergePubSbom,
  type PubSbomPackage,
} from "./pub/sbom.js";

type SbomResult = z.infer<typeof sbomOutput>;
const SUPPORTED_TRIVY_CYCLONEDX_VERSIONS = new Set(["1.4", "1.5", "1.6", "1.7"]);

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

function validateTrivyDocument(
  document: Record<string, unknown>,
  format: "cyclonedx" | "spdx",
): void {
  if (format === "cyclonedx") {
    if (
      document.bomFormat !== "CycloneDX" ||
      typeof document.specVersion !== "string" ||
      !SUPPORTED_TRIVY_CYCLONEDX_VERSIONS.has(document.specVersion) ||
      !Number.isInteger(document.version) ||
      (document.components !== undefined && !Array.isArray(document.components))
    ) {
      throw new Error("Trivy CycloneDX output is missing required format metadata or components.");
    }
    return;
  }
  const creationInfo = document.creationInfo;
  if (
    document.spdxVersion !== "SPDX-2.3" ||
    document.dataLicense !== "CC0-1.0" ||
    document.SPDXID !== "SPDXRef-DOCUMENT" ||
    typeof document.name !== "string" || !document.name ||
    typeof document.documentNamespace !== "string" || !document.documentNamespace ||
    !creationInfo || typeof creationInfo !== "object" || Array.isArray(creationInfo) ||
    typeof (creationInfo as Record<string, unknown>).created !== "string" ||
    !Array.isArray((creationInfo as Record<string, unknown>).creators) ||
    !Array.isArray(document.packages)
  ) {
    throw new Error("Trivy SPDX output is missing required SPDX-2.3 document metadata or packages.");
  }
}

function ecosystemLabel(type: string): string {
  return ({
    pub: "Pub",
    pypi: "PyPI",
    cargo: "Cargo",
    golang: "Go",
    maven: "Maven",
    nuget: "NuGet",
    gem: "RubyGems",
  } as Record<string, string>)[type] ?? type;
}

function purlType(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  return /^pkg:([a-z0-9.+-]+)\//i.exec(value)?.[1]?.toLowerCase();
}

function documentEcosystems(
  document: Record<string, unknown>,
  format: "cyclonedx" | "spdx",
): string[] {
  const types = new Set<string>();
  if (format === "cyclonedx") {
    for (const component of Array.isArray(document.components) ? document.components : []) {
      if (!component || typeof component !== "object" || Array.isArray(component)) continue;
      const type = purlType((component as Record<string, unknown>).purl);
      if (type) types.add(ecosystemLabel(type));
    }
  } else {
    for (const pkg of Array.isArray(document.packages) ? document.packages : []) {
      if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) continue;
      const externalRefs = (pkg as Record<string, unknown>).externalRefs;
      if (!Array.isArray(externalRefs)) continue;
      for (const candidate of externalRefs) {
        if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
        const reference = candidate as Record<string, unknown>;
        if (String(reference.referenceType).toLowerCase() !== "purl") continue;
        const type = purlType(reference.referenceLocator);
        if (type) types.add(ecosystemLabel(type));
      }
    }
  }
  return [...types].sort();
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function hasPubDiscoverySignal(load: Awaited<ReturnType<typeof loadPubLockfiles>>): boolean {
  const skipped = load.skipped;
  return load.lockfiles.length > 0
    || skipped.symlinked_lockfiles > 0
    || skipped.symlinked_paths > 0
    || skipped.oversized_lockfiles > 0
    || skipped.unreadable_lockfiles > 0
    || skipped.malformed_lockfiles > 0
    || skipped.lockfiles_beyond_limit > 0
    || skipped.lockfiles_beyond_total_bytes > 0
    || skipped.unreadable_directories > 0
    || skipped.directories_beyond_depth > 0
    || skipped.traversal_limit_reached > 0;
}

async function writeJsonAtomic(path: string, document: Record<string, unknown>): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, "utf8");
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

function toSbomPackage(pkg: Awaited<ReturnType<typeof loadPubLockfiles>>["packages"][number]): PubSbomPackage {
  return {
    name: pkg.name,
    version: pkg.version,
    version_line: pkg.version_line,
    dependency: pkg.dependency,
    direct: pkg.direct,
    source: pkg.source,
    description: pkg.description,
    registry: pkg.registry,
    lockfile: pkg.lockfile_path,
  };
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

  const [trivyRun, pubLoad] = await Promise.all([
    runTrivySbom(target, format, outputPath),
    loadPubLockfiles(target),
  ]);
  const pubPackages = pubLoad.packages.map(toSbomPackage);
  const parsedLockfiles = pubLoad.lockfiles.filter((lockfile) => lockfile.status === "parsed").length;
  const pubApplicable = hasPubDiscoverySignal(pubLoad);
  const baseNote = input.output_path
    ? undefined
    : "Written to the managed dir (outside your repo) by default. Pass output_path to choose a location.";

  let trivyDocument: Record<string, unknown> | undefined;
  let trivyFailure = trivyRun.note;
  if (trivyRun.ran) {
    try {
      if (!trivyRun.content) throw new Error("Trivy returned no fresh staged SBOM content");
      const parsed: unknown = JSON.parse(trivyRun.content);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("SBOM root is not an object");
      }
      const candidate = parsed as Record<string, unknown>;
      validateTrivyDocument(candidate, format);
      trivyDocument = candidate;
    } catch (error) {
      trivyFailure = `Trivy reported success but its SBOM could not be validated: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  const generatedNative = parsedLockfiles > 0
    ? generatePubSbom(pubPackages, format, {
        created: new Date().toISOString(),
        document_name: `${base} Pub dependencies`,
      })
    : undefined;
  const limitations = unique([
    ...(pubApplicable ? pubLoad.notes : []),
    ...(generatedNative?.limitations ?? []),
    ...(parsedLockfiles > 0
      ? ["A Pub lockfile is a resolved inventory, not a complete dependency graph; Flutter projects may also contain Gradle, CocoaPods, and Swift dependencies."]
      : []),
    ...(trivyFailure ? [trivyFailure] : []),
  ]);

  let document: Record<string, unknown> | undefined;
  let providers: Array<"trivy" | "codeinspectus-pub"> = [];
  let coverageState: "combined" | "native_only" | "trivy_only" | "unavailable" = "unavailable";

  if (trivyDocument && generatedNative) {
    try {
      document = mergePubSbom(trivyDocument, pubPackages, format).document;
      providers = ["trivy", "codeinspectus-pub"];
      coverageState = "combined";
    } catch (error) {
      document = trivyDocument;
      providers = ["trivy"];
      coverageState = "trivy_only";
      limitations.push(`Native Pub SBOM merge failed; preserved the Trivy artifact: ${error instanceof Error ? error.message : String(error)}`);
    }
  } else if (trivyDocument) {
    document = trivyDocument;
    providers = ["trivy"];
    coverageState = "trivy_only";
  } else if (generatedNative) {
    document = generatedNative.document;
    providers = ["codeinspectus-pub"];
    coverageState = "native_only";
  }

  if (document) await writeJsonAtomic(outputPath, document);

  if (!document) {
    return {
      format,
      output_path: outputPath,
      component_count: 0,
      generated: false,
      offline: true,
      providers,
      ecosystems: [],
      coverage_state: "unavailable",
      lockfiles_analyzed: parsedLockfiles,
      limitations: unique(limitations),
      note: unique([
        baseNote ?? "",
        trivyFailure ?? "SBOM generation failed. Ensure Trivy is installed (`codeinspectus repair-engines`).",
        parsedLockfiles === 0 ? "No parseable pubspec.lock was available for native fallback." : "",
      ]).join(" "),
    };
  }

  return {
    format,
    output_path: outputPath,
    component_count: countComponents(document, format),
    generated: true,
    offline: true,
    providers,
    ecosystems: documentEcosystems(document, format),
    coverage_state: coverageState,
    lockfiles_analyzed: parsedLockfiles,
    limitations: unique(limitations),
    ...(baseNote ? { note: baseNote } : {}),
  };
}
