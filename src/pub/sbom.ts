/**
 * Pure Pub SBOM document helpers.
 *
 * The scanner owns filesystem reads and artifact writes. This module accepts
 * already-parsed lockfile packages and only inventories packages resolved from
 * the official Pub registry. Custom-hosted, git, path, and SDK dependencies are
 * deliberately excluded until their provenance can be represented accurately.
 */

import { createHash } from "node:crypto";

export type PubSbomFormat = "cyclonedx" | "spdx";

/** Structural subset of a parsed package from src/pub/lockfile.ts. */
export interface PubSbomPackage {
  name: string;
  version: string;
  version_line: number;
  dependency: string;
  direct: boolean;
  source: string;
  description: {
    name?: string;
    url?: string;
    sha256?: string;
  };
  registry: "official" | "custom" | "non_hosted";
  lockfile: string;
}

export interface PubSbomCoverage {
  input_package_count: number;
  official_hosted_package_count: number;
  native_component_count: number;
  duplicate_component_count: number;
  skipped_non_official_count: number;
  skipped_invalid_identity_count: number;
  invalid_sha256_count: number;
}

export interface PubSbomResult {
  document: Record<string, unknown>;
  coverage: PubSbomCoverage;
  limitations: string[];
}

export interface PubSbomMergeResult extends PubSbomResult {
  added_component_count: number;
  merged_component_count: number;
}

export interface PubSbomDocumentOptions {
  /** SPDX requires an honest generation timestamp; callers must supply it. */
  created?: string;
  document_name?: string;
  document_namespace?: string;
}

interface NativePubComponent {
  name: string;
  version: string;
  purl: string;
  dependencies: string[];
  directness: boolean[];
  lockfiles: string[];
  sha256: string[];
}

interface NativeInventory {
  components: NativePubComponent[];
  coverage: PubSbomCoverage;
  limitations: string[];
}

const PUB_PACKAGE_NAME_RE = /^[a-z_][a-z0-9_]*$/;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const SPDX_CREATED_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const DEFAULT_DOCUMENT_NAME = "CodeInspectus Pub dependency inventory";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort(compareText);
}

function encodePurlPart(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

export function pubPackagePurl(name: string, version: string): string {
  return `pkg:pub/${encodePurlPart(name)}@${encodePurlPart(version)}`;
}

function isOfficialHosted(pkg: PubSbomPackage): boolean {
  return pkg.source === "hosted" && pkg.registry === "official";
}

function packageSortKey(pkg: PubSbomPackage): string {
  return [pkg.name, pkg.version, pkg.lockfile, String(pkg.version_line)].join("\u0000");
}

export function selectOfficialHostedPubPackages(
  packages: readonly PubSbomPackage[],
): PubSbomPackage[] {
  return packages
    .filter(isOfficialHosted)
    .slice()
    .sort((left, right) => compareText(packageSortKey(left), packageSortKey(right)));
}

function hasValidIdentity(pkg: PubSbomPackage): boolean {
  return PUB_PACKAGE_NAME_RE.test(pkg.name) && pkg.version.length > 0 && !/\s/.test(pkg.version);
}

function buildInventory(packages: readonly PubSbomPackage[]): NativeInventory {
  const official = selectOfficialHostedPubPackages(packages);
  const grouped = new Map<string, {
    name: string;
    version: string;
    dependencies: Set<string>;
    directness: Set<boolean>;
    lockfiles: Set<string>;
    sha256: Set<string>;
  }>();
  let invalidIdentityCount = 0;
  let invalidSha256Count = 0;
  let validOfficialEntryCount = 0;

  for (const pkg of official) {
    if (!hasValidIdentity(pkg)) {
      invalidIdentityCount += 1;
      continue;
    }
    validOfficialEntryCount += 1;
    const purl = pubPackagePurl(pkg.name, pkg.version);
    let component = grouped.get(purl);
    if (!component) {
      component = {
        name: pkg.name,
        version: pkg.version,
        dependencies: new Set<string>(),
        directness: new Set<boolean>(),
        lockfiles: new Set<string>(),
        sha256: new Set<string>(),
      };
      grouped.set(purl, component);
    }
    if (pkg.dependency.length > 0) component.dependencies.add(pkg.dependency);
    component.directness.add(pkg.direct);
    if (pkg.lockfile.length > 0) component.lockfiles.add(pkg.lockfile);

    const digest = pkg.description.sha256;
    if (digest !== undefined && digest.length > 0) {
      if (SHA256_RE.test(digest)) component.sha256.add(digest.toLowerCase());
      else invalidSha256Count += 1;
    }
  }

  const components = [...grouped.entries()]
    .sort(([left], [right]) => compareText(left, right))
    .map(([purl, component]) => ({
      name: component.name,
      version: component.version,
      purl,
      dependencies: uniqueSorted(component.dependencies),
      directness: [...component.directness].sort((left, right) => Number(right) - Number(left)),
      lockfiles: uniqueSorted(component.lockfiles),
      sha256: uniqueSorted(component.sha256),
    }));

  const skippedNonOfficial = packages.length - official.length;
  const coverage: PubSbomCoverage = {
    input_package_count: packages.length,
    official_hosted_package_count: official.length,
    native_component_count: components.length,
    duplicate_component_count: validOfficialEntryCount - components.length,
    skipped_non_official_count: skippedNonOfficial,
    skipped_invalid_identity_count: invalidIdentityCount,
    invalid_sha256_count: invalidSha256Count,
  };

  const limitations = [
    "Only packages resolved from the official Pub registry are inventoried; custom-hosted, git, path, and SDK dependencies are excluded.",
    "Dependency relationships are not emitted because pubspec.lock does not contain a complete dependency graph.",
    "Package licenses and suppliers are not inferred because pubspec.lock does not provide authoritative values.",
  ];
  if (skippedNonOfficial > 0) {
    limitations.push(
      `${skippedNonOfficial} non-official or non-hosted lockfile package entr${skippedNonOfficial === 1 ? "y was" : "ies were"} excluded.`,
    );
  }
  if (invalidIdentityCount > 0) {
    limitations.push(
      `${invalidIdentityCount} official package entr${invalidIdentityCount === 1 ? "y had" : "ies had"} an invalid name or version and ${invalidIdentityCount === 1 ? "was" : "were"} excluded.`,
    );
  }
  if (invalidSha256Count > 0) {
    limitations.push(
      `${invalidSha256Count} malformed SHA-256 value${invalidSha256Count === 1 ? " was" : "s were"} omitted.`,
    );
  }

  return { components, coverage, limitations };
}

function cycloneProperties(component: NativePubComponent): Array<Record<string, string>> {
  return [
    ...component.dependencies.map((value) => ({ name: "codeinspectus:pub:dependency", value })),
    ...component.directness.map((value) => ({ name: "codeinspectus:pub:direct", value: String(value) })),
    ...component.lockfiles.map((value) => ({ name: "codeinspectus:pub:lockfile", value })),
  ];
}

function cycloneComponent(component: NativePubComponent): Record<string, unknown> {
  return {
    type: "library",
    name: component.name,
    version: component.version,
    purl: component.purl,
    ...(component.sha256.length === 0
      ? {}
      : {
          hashes: component.sha256.map((content) => ({ alg: "SHA-256", content })),
        }),
    properties: cycloneProperties(component),
  };
}

function metadataComment(component: NativePubComponent): string {
  return `CodeInspectus Pub lockfile metadata: ${JSON.stringify({
    dependencies: component.dependencies,
    direct: component.directness,
    lockfiles: component.lockfiles,
  })}`;
}

function spdxId(purl: string): string {
  return `SPDXRef-Pub-${createHash("sha256").update(purl).digest("hex").slice(0, 24)}`;
}

function spdxPackage(component: NativePubComponent): Record<string, unknown> {
  return {
    SPDXID: spdxId(component.purl),
    name: component.name,
    versionInfo: component.version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    ...(component.sha256.length === 0
      ? {}
      : {
          checksums: component.sha256.map((checksumValue) => ({
            algorithm: "SHA256",
            checksumValue,
          })),
        }),
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: component.purl,
      },
    ],
    comment: metadataComment(component),
  };
}

function validateSpdxOptions(
  options: PubSbomDocumentOptions,
  components: readonly NativePubComponent[],
): { created: string; name: string; namespace: string } {
  if (options.created === undefined || !SPDX_CREATED_RE.test(options.created)) {
    throw new Error("SPDX Pub SBOM generation requires an RFC 3339 UTC created timestamp.");
  }
  const name = options.document_name ?? DEFAULT_DOCUMENT_NAME;
  if (name.trim().length === 0) throw new Error("SPDX Pub SBOM document_name cannot be empty.");

  const canonical = JSON.stringify({
    created: options.created,
    name,
    components,
  });
  const digest = createHash("sha256").update(canonical).digest("hex");
  const namespace = options.document_namespace ?? `https://codeinspectus.com/sbom/pub/${digest}`;
  try {
    const parsed = new URL(namespace);
    if (parsed.hash.length > 0) throw new Error("fragment");
  } catch {
    throw new Error("SPDX Pub SBOM document_namespace must be an absolute URI without a fragment.");
  }
  return { created: options.created, name, namespace };
}

function generatedCycloneDocument(components: readonly NativePubComponent[]): Record<string, unknown> {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    components: components.map(cycloneComponent),
  };
}

function generatedSpdxDocument(
  components: readonly NativePubComponent[],
  options: PubSbomDocumentOptions,
): Record<string, unknown> {
  const metadata = validateSpdxOptions(options, components);
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: metadata.name,
    documentNamespace: metadata.namespace,
    creationInfo: {
      created: metadata.created,
      creators: ["Tool: CodeInspectus"],
    },
    packages: components.map(spdxPackage),
  };
}

export function generatePubSbom(
  packages: readonly PubSbomPackage[],
  format: PubSbomFormat,
  options: PubSbomDocumentOptions = {},
): PubSbomResult {
  const inventory = buildInventory(packages);
  return {
    document:
      format === "cyclonedx"
        ? generatedCycloneDocument(inventory.components)
        : generatedSpdxDocument(inventory.components, options),
    coverage: inventory.coverage,
    limitations: inventory.limitations,
  };
}

function asDocument(value: unknown, format: PubSbomFormat): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Cannot merge Pub components into a non-object ${format} SBOM.`);
  }
  return value as Record<string, unknown>;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function objectArray(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  const objects: Record<string, unknown>[] = [];
  for (const entry of value) {
    const object = objectValue(entry);
    if (object) objects.push(object);
  }
  return objects;
}

function canonicalPubPurl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const match = /^pkg:pub\/([^@?#]+)@([^?#]+)(?:[?#].*)?$/i.exec(value);
  if (!match?.[1] || !match[2]) return undefined;
  try {
    return pubPackagePurl(decodeURIComponent(match[1]).toLowerCase(), decodeURIComponent(match[2]));
  } catch {
    return undefined;
  }
}

function cycloneIdentities(component: Record<string, unknown>): string[] {
  const purl = canonicalPubPurl(component.purl);
  return purl === undefined ? [] : [`purl:${purl}`];
}

function spdxPurl(component: Record<string, unknown>): string | undefined {
  if (!Array.isArray(component.externalRefs)) return undefined;
  for (const candidate of component.externalRefs) {
    const reference = objectValue(candidate);
    if (!reference) continue;
    if (
      typeof reference.referenceType === "string" &&
      reference.referenceType.toLowerCase() === "purl"
    ) {
      const purl = canonicalPubPurl(reference.referenceLocator);
      if (purl !== undefined) return purl;
    }
  }
  return undefined;
}

function spdxIdentities(component: Record<string, unknown>): string[] {
  const purl = spdxPurl(component);
  return purl === undefined ? [] : [`purl:${purl}`];
}

function mergeArrayField(
  existing: Record<string, unknown>,
  field: string,
  additions: readonly Record<string, unknown>[],
  identity: (entry: Record<string, unknown>) => string,
): Record<string, unknown> {
  if (additions.length === 0) return existing;
  const currentValue = existing[field];
  if (currentValue !== undefined && !Array.isArray(currentValue)) return existing;
  const current = Array.isArray(currentValue) ? currentValue : [];
  const known = new Set<string>();
  for (const entry of current) {
    const object = objectValue(entry);
    if (object) known.add(identity(object));
  }
  const appended = additions.filter((entry) => {
    const key = identity(entry);
    if (known.has(key)) return false;
    known.add(key);
    return true;
  });
  return appended.length === 0 ? existing : { ...existing, [field]: [...current, ...appended] };
}

function mergeCycloneComponent(
  existing: Record<string, unknown>,
  native: Record<string, unknown>,
): Record<string, unknown> {
  let merged = { ...existing };
  for (const field of ["type", "name", "version", "purl"] as const) {
    if (merged[field] === undefined) merged[field] = native[field];
  }
  const hashes = objectArray(native.hashes);
  merged = mergeArrayField(
    merged,
    "hashes",
    hashes,
    (entry) => `${String(entry.alg).toUpperCase()}\u0000${String(entry.content).toLowerCase()}`,
  );
  const properties = objectArray(native.properties);
  return mergeArrayField(
    merged,
    "properties",
    properties,
    (entry) => `${String(entry.name)}\u0000${String(entry.value)}`,
  );
}

function mergeSpdxPackage(
  existing: Record<string, unknown>,
  native: Record<string, unknown>,
): Record<string, unknown> {
  let merged = { ...existing };
  const checksums = objectArray(native.checksums);
  merged = mergeArrayField(
    merged,
    "checksums",
    checksums,
    (entry) =>
      `${String(entry.algorithm).toUpperCase()}\u0000${String(entry.checksumValue).toLowerCase()}`,
  );
  const externalRefs = objectArray(native.externalRefs);
  merged = mergeArrayField(
    merged,
    "externalRefs",
    externalRefs,
    (entry) => {
      const purl =
        typeof entry.referenceType === "string" && entry.referenceType.toLowerCase() === "purl"
          ? canonicalPubPurl(entry.referenceLocator)
          : undefined;
      return purl === undefined
        ? `${String(entry.referenceCategory)}\u0000${String(entry.referenceType)}\u0000${String(entry.referenceLocator)}`
        : `purl\u0000${purl}`;
    },
  );

  const nativeComment = native.comment;
  if (typeof nativeComment === "string") {
    if (merged.comment === undefined || merged.comment === "") merged.comment = nativeComment;
    else if (typeof merged.comment === "string" && !merged.comment.includes(nativeComment)) {
      merged.comment = `${merged.comment}\n${nativeComment}`;
    }
  }
  return merged;
}

function mergeComponents(
  existingValues: unknown[],
  nativeValues: Record<string, unknown>[],
  identities: (component: Record<string, unknown>) => string[],
  merge: (
    existing: Record<string, unknown>,
    native: Record<string, unknown>,
  ) => Record<string, unknown>,
): { values: unknown[]; added: number; merged: number } {
  const output = existingValues.slice();
  const firstIndex = new Map<string, number>();
  output.forEach((value, index) => {
    const component = objectValue(value);
    if (!component) return;
    for (const identity of identities(component)) {
      if (!firstIndex.has(identity)) firstIndex.set(identity, index);
    }
  });

  let added = 0;
  let mergedCount = 0;
  for (const native of nativeValues) {
    const nativeIdentities = identities(native);
    const match = nativeIdentities
      .map((identity) => firstIndex.get(identity))
      .find((index) => index !== undefined);
    if (match === undefined) {
      const nextIndex = output.length;
      output.push(native);
      for (const identity of nativeIdentities) {
        if (!firstIndex.has(identity)) firstIndex.set(identity, nextIndex);
      }
      added += 1;
      continue;
    }

    const existing = objectValue(output[match]);
    if (!existing) continue;
    output[match] = merge(existing, native);
    for (const identity of identities(output[match] as Record<string, unknown>)) {
      if (!firstIndex.has(identity)) firstIndex.set(identity, match);
    }
    mergedCount += 1;
  }
  return { values: output, added, merged: mergedCount };
}

function mergeCyclone(
  existingValue: unknown,
  nativeComponents: readonly NativePubComponent[],
): { document: Record<string, unknown>; added: number; merged: number } {
  const existing = asDocument(existingValue, "cyclonedx");
  if (existing.components !== undefined && !Array.isArray(existing.components)) {
    throw new Error("Cannot merge Pub components: CycloneDX components must be an array.");
  }
  const components = Array.isArray(existing.components) ? existing.components : [];
  const result = mergeComponents(
    components,
    nativeComponents.map(cycloneComponent),
    cycloneIdentities,
    mergeCycloneComponent,
  );
  return {
    document: {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      ...existing,
      components: result.values,
    },
    added: result.added,
    merged: result.merged,
  };
}

function mergeSpdx(
  existingValue: unknown,
  nativeComponents: readonly NativePubComponent[],
): { document: Record<string, unknown>; added: number; merged: number } {
  const existing = asDocument(existingValue, "spdx");
  if (existing.packages !== undefined && !Array.isArray(existing.packages)) {
    throw new Error("Cannot merge Pub components: SPDX packages must be an array.");
  }
  const packages = Array.isArray(existing.packages) ? existing.packages : [];
  const result = mergeComponents(
    packages,
    nativeComponents.map(spdxPackage),
    spdxIdentities,
    mergeSpdxPackage,
  );
  return {
    document: { ...existing, packages: result.values },
    added: result.added,
    merged: result.merged,
  };
}

export function mergePubSbom(
  existing: unknown,
  packages: readonly PubSbomPackage[],
  format: PubSbomFormat,
): PubSbomMergeResult {
  const inventory = buildInventory(packages);
  const result =
    format === "cyclonedx"
      ? mergeCyclone(existing, inventory.components)
      : mergeSpdx(existing, inventory.components);
  return {
    document: result.document,
    coverage: inventory.coverage,
    limitations: inventory.limitations,
    added_component_count: result.added,
    merged_component_count: result.merged,
  };
}
