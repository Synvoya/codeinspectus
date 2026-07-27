/** Bounded, read-only iOS repository-configuration loading. */

import { lstat, readFile, readdir } from "node:fs/promises";
import { basename, dirname, extname, isAbsolute, join, relative, resolve } from "node:path";

import { parseXmlPlist, type PlistDictionary } from "./plist.js";
import { releaseConfigurationReferences } from "./pbx.js";

const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_PROJECT_FILE_BYTES = 4 * 1024 * 1024;
const MAX_PROJECT_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_CONFIG_FILES = 256;
const MAX_VISITED_ENTRIES = 50_000;
const MAX_DIRECTORY_DEPTH = 32;
const MAX_LIMITATIONS = 20;

const IGNORED_DIRECTORIES = new Set([
  ".cache",
  ".dart_tool",
  ".git",
  ".gradle",
  ".pub-cache",
  ".swiftpm",
  ".symlinks",
  "build",
  "carthage",
  "coverage",
  "deriveddata",
  "demo",
  "demos",
  "dist",
  "example",
  "examples",
  "macos",
  "node_modules",
  "osx",
  "pods",
  "sample",
  "samples",
  "test",
  "tests",
  "vendor",
  "xcuserdata",
]);

export type IosConfigurationKind = "info" | "entitlements";

export interface IosConfigurationDocument {
  path: string;
  kind: IosConfigurationKind;
  root: PlistDictionary;
}

export interface IosConfigurationProject {
  target: string;
  root: string;
  documents: IosConfigurationDocument[];
  limitations: string[];
}

export type IosConfigurationInput =
  | string
  | IosConfigurationProject
  | Promise<IosConfigurationProject>;

interface DiscoveredFile {
  absolutePath: string;
  relativePath: string;
}

interface Discovery {
  propertyLists: Map<string, DiscoveredFile>;
  entitlements: Map<string, DiscoveredFile>;
  projects: Map<string, DiscoveredFile>;
}

interface ProjectReferences {
  info: Set<string>;
  entitlements: Set<string>;
  releaseCandidates: number;
  releaseConfigurations: number;
  skippedMixedPlatformReferences: number;
  dynamic: number;
  unresolved: number;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function forwardSlash(value: string): string {
  return value.replace(/\\/g, "/");
}

function within(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function limitationCollector(): { add: (message: string) => void; finish: () => string[] } {
  const values = new Set<string>();
  let omitted = 0;
  return {
    add(message) {
      if (values.size < MAX_LIMITATIONS - 1) values.add(message);
      else omitted++;
    },
    finish() {
      return [
        ...values,
        ...(omitted ? [`${omitted} additional iOS configuration limitations omitted.`] : []),
      ].sort(compareText);
    },
  };
}

function isPropertyList(name: string): boolean {
  return extname(name).toLowerCase() === ".plist";
}

function isEntitlements(name: string): boolean {
  return extname(name).toLowerCase() === ".entitlements";
}

function nonProductionNamed(file: DiscoveredFile): boolean {
  const tokens = forwardSlash(file.relativePath)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return tokens.some((token) => [
    "debug",
    "demo",
    "demos",
    "dev",
    "development",
    "example",
    "examples",
    "mock",
    "mocks",
    "profile",
    "sample",
    "samples",
    "test",
    "tests",
  ].includes(token));
}

function emptyDiscovery(): Discovery {
  return {
    propertyLists: new Map(),
    entitlements: new Map(),
    projects: new Map(),
  };
}

function addDiscovered(
  collection: Map<string, DiscoveredFile>,
  absolutePath: string,
  root: string,
): void {
  collection.set(resolve(absolutePath), {
    absolutePath: resolve(absolutePath),
    relativePath: forwardSlash(relative(root, absolutePath)) || basename(absolutePath),
  });
}

async function discoverFiles(
  target: string,
  root: string,
  limitations: ReturnType<typeof limitationCollector>,
): Promise<Discovery> {
  const discovered = emptyDiscovery();
  const metadata = await lstat(target).catch(() => undefined);
  if (!metadata) {
    limitations.add("iOS configuration target was unreadable.");
    return discovered;
  }
  if (metadata.isSymbolicLink()) {
    limitations.add("Skipped symbolic-link iOS configuration target.");
    return discovered;
  }
  if (metadata.isFile()) {
    const lower = basename(target).toLowerCase();
    if (isEntitlements(lower)) addDiscovered(discovered.entitlements, target, root);
    else if (isPropertyList(lower)) addDiscovered(discovered.propertyLists, target, root);
    else if (lower === "project.pbxproj") addDiscovered(discovered.projects, target, root);
    return discovered;
  }
  if (!metadata.isDirectory()) {
    limitations.add("iOS configuration target was not a regular file or directory.");
    return discovered;
  }

  let visitedEntries = 0;
  let traversalStopped = false;
  async function walk(directory: string, depth: number): Promise<void> {
    if (traversalStopped) return;
    if (depth > MAX_DIRECTORY_DEPTH) {
      const rel = forwardSlash(relative(root, directory)) || ".";
      limitations.add(`Skipped iOS configuration directory ${rel} beyond depth ${MAX_DIRECTORY_DEPTH}.`);
      return;
    }
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      const rel = forwardSlash(relative(root, directory)) || ".";
      limitations.add(`Skipped unreadable iOS configuration directory ${rel}.`);
      return;
    }
    entries.sort((left, right) => compareText(left.name, right.name));
    for (const entry of entries) {
      if (++visitedEntries > MAX_VISITED_ENTRIES) {
        limitations.add(
          `Stopped iOS configuration discovery after ${MAX_VISITED_ENTRIES} filesystem entries.`,
        );
        traversalStopped = true;
        return;
      }
      const absolutePath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name.toLowerCase())) continue;
        await walk(absolutePath, depth + 1);
      } else if (entry.isFile()) {
        const lower = entry.name.toLowerCase();
        if (isEntitlements(lower)) addDiscovered(discovered.entitlements, absolutePath, root);
        else if (isPropertyList(lower)) addDiscovered(discovered.propertyLists, absolutePath, root);
        else if (lower === "project.pbxproj") addDiscovered(discovered.projects, absolutePath, root);
      }
      // Never follow symlinks or special filesystem entries outside the target tree.
    }
  }
  await walk(target, 0);
  return discovered;
}

function resolveProjectReference(
  value: string,
  projectRoot: string,
  targetRoot: string,
): string | undefined {
  const replaced = value
    .replace(/\$\((?:SRCROOT|SOURCE_ROOT|PROJECT_DIR)\)/g, ".")
    .replace(/\$\{(?:SRCROOT|SOURCE_ROOT|PROJECT_DIR)\}/g, ".");
  if (/\$\(|\$\{/.test(replaced) || isAbsolute(replaced)) return undefined;
  const absolutePath = resolve(projectRoot, replaced);
  return within(targetRoot, absolutePath) ? absolutePath : undefined;
}

async function collectProjectReferences(
  discovered: Discovery,
  root: string,
  limitations: ReturnType<typeof limitationCollector>,
): Promise<ProjectReferences> {
  const references: ProjectReferences = {
    info: new Set(),
    entitlements: new Set(),
    releaseCandidates: 0,
    releaseConfigurations: 0,
    skippedMixedPlatformReferences: 0,
    dynamic: 0,
    unresolved: 0,
  };
  let projectBytes = 0;
  for (const project of [...discovered.projects.values()].sort((left, right) =>
    compareText(left.relativePath, right.relativePath)
  )) {
    let metadata;
    try {
      metadata = await lstat(project.absolutePath);
    } catch {
      limitations.add(`Skipped unreadable Xcode project configuration ${project.relativePath}.`);
      continue;
    }
    if (metadata.size > MAX_PROJECT_FILE_BYTES) {
      limitations.add(
        `Skipped oversized Xcode project configuration ${project.relativePath} (limit: 4 MiB).`,
      );
      continue;
    }
    if (projectBytes + metadata.size > MAX_PROJECT_TOTAL_BYTES) {
      limitations.add(
        `Skipped Xcode project configuration ${project.relativePath} beyond the 16 MiB project-content bound.`,
      );
      continue;
    }
    projectBytes += metadata.size;
    let content: string;
    try {
      content = await readFile(project.absolutePath, "utf8");
    } catch {
      limitations.add(`Skipped unreadable Xcode project configuration ${project.relativePath}.`);
      continue;
    }
    let release;
    try {
      release = releaseConfigurationReferences(content);
    } catch {
      limitations.add(`Skipped invalid or unsupported Xcode project configuration ${project.relativePath}.`);
      continue;
    }
    references.releaseCandidates += release.releaseCandidates;
    references.releaseConfigurations += release.configurations;
    references.skippedMixedPlatformReferences += release.skippedMixedPlatformReferences;
    // project.pbxproj lives directly inside *.xcodeproj; build-setting paths are
    // relative to the directory that contains that project bundle.
    const projectRoot = dirname(dirname(project.absolutePath));
    for (const reference of release.references) {
      const absolutePath = resolveProjectReference(reference.value, projectRoot, root);
      if (!absolutePath) {
        references.dynamic++;
        continue;
      }
      const collection = reference.setting === "INFOPLIST_FILE"
        ? discovered.propertyLists
        : discovered.entitlements;
      if (!collection.has(absolutePath)) {
        references.unresolved++;
        continue;
      }
      (reference.setting === "INFOPLIST_FILE" ? references.info : references.entitlements)
        .add(absolutePath);
    }
  }
  if (references.dynamic) {
    limitations.add(
      `Skipped ${references.dynamic} dynamic or out-of-target Xcode configuration reference(s).`,
    );
  }
  if (references.unresolved) {
    limitations.add(`Skipped ${references.unresolved} unresolved Xcode configuration reference(s).`);
  }
  if (references.skippedMixedPlatformReferences) {
    limitations.add(
      `Skipped ${references.skippedMixedPlatformReferences} release configuration reference(s) without same-configuration iPhone evidence in a mixed-platform Xcode project.`,
    );
  }
  if (discovered.projects.size > 0 && references.releaseConfigurations === 0) {
    limitations.add(
      references.releaseCandidates > 0
        ? "Release/AppStore Xcode configurations lacked explicit iphoneos/iphonesimulator platform evidence; iOS property lists were not inferred."
        : "No statically parseable iPhone Release/AppStore Xcode build configuration was found; build-selected iOS property lists were not inferred.",
    );
  }
  return references;
}

function selectedConfigurations(
  target: string,
  discovered: Discovery,
  references: ProjectReferences,
  limitations: ReturnType<typeof limitationCollector>,
): Map<string, { file: DiscoveredFile; kind: IosConfigurationKind }> {
  const selected = new Map<string, { file: DiscoveredFile; kind: IosConfigurationKind }>();
  const targetIsFile = [...discovered.propertyLists, ...discovered.entitlements]
    .some(([absolutePath]) => absolutePath === resolve(target));
  let fallbackExcluded = 0;

  const hasProjectSelection = discovered.projects.size > 0;
  for (const file of discovered.propertyLists.values()) {
    const fallbackInfo = !hasProjectSelection && basename(file.absolutePath).toLowerCase() === "info.plist";
    if (!targetIsFile && fallbackInfo && nonProductionNamed(file)) {
      fallbackExcluded++;
      continue;
    }
    if (targetIsFile || fallbackInfo || references.info.has(file.absolutePath)) {
      selected.set(file.absolutePath, { file, kind: "info" });
    }
  }
  const scanAllEntitlements = targetIsFile || discovered.projects.size === 0;
  for (const file of discovered.entitlements.values()) {
    if (!targetIsFile && scanAllEntitlements && nonProductionNamed(file)) {
      fallbackExcluded++;
      continue;
    }
    if (scanAllEntitlements || references.entitlements.has(file.absolutePath)) {
      selected.set(file.absolutePath, { file, kind: "entitlements" });
    }
  }
  if (fallbackExcluded) {
    limitations.add(
      `Excluded ${fallbackExcluded} non-production-named iOS configuration file(s) without static release build selection.`,
    );
  }
  return selected;
}

async function loadSelectedConfigurations(
  selected: Map<string, { file: DiscoveredFile; kind: IosConfigurationKind }>,
  limitations: ReturnType<typeof limitationCollector>,
): Promise<IosConfigurationDocument[]> {
  const ordered = [...selected.values()].sort((left, right) =>
    compareText(left.file.relativePath, right.file.relativePath)
  );
  const documents: IosConfigurationDocument[] = [];
  let totalBytes = 0;
  let beyondFileLimit = 0;
  let beyondTotalLimit = 0;
  for (const [index, selectedFile] of ordered.entries()) {
    const { file, kind } = selectedFile;
    if (index >= MAX_CONFIG_FILES) {
      beyondFileLimit++;
      continue;
    }
    let metadata;
    try {
      metadata = await lstat(file.absolutePath);
    } catch {
      limitations.add(`Skipped unreadable iOS property list ${file.relativePath}.`);
      continue;
    }
    if (!metadata.isFile() || metadata.isSymbolicLink()) continue;
    if (metadata.size > MAX_FILE_BYTES) {
      limitations.add(`Skipped oversized iOS property list ${file.relativePath} (limit: 512 KiB).`);
      continue;
    }
    if (totalBytes + metadata.size > MAX_TOTAL_BYTES) {
      beyondTotalLimit++;
      continue;
    }
    totalBytes += metadata.size;
    let content: string;
    try {
      content = await readFile(file.absolutePath, "utf8");
    } catch {
      limitations.add(`Skipped unreadable iOS property list ${file.relativePath}.`);
      continue;
    }
    if (content.startsWith("bplist")) {
      limitations.add(`Skipped binary iOS property list ${file.relativePath}.`);
      continue;
    }
    try {
      documents.push({ path: file.relativePath, kind, root: parseXmlPlist(content) });
    } catch {
      limitations.add(`Skipped invalid or unsupported iOS property list ${file.relativePath}.`);
    }
  }
  if (beyondFileLimit) {
    limitations.add(
      `Skipped ${beyondFileLimit} iOS property list(s) beyond the ${MAX_CONFIG_FILES}-file bound.`,
    );
  }
  if (beyondTotalLimit) {
    limitations.add(
      `Skipped ${beyondTotalLimit} iOS property list(s) beyond the 8 MiB total-content bound.`,
    );
  }
  return documents;
}

async function loadUncached(target: string): Promise<IosConfigurationProject> {
  const absoluteTarget = resolve(target);
  const targetMetadata = await lstat(absoluteTarget).catch(() => undefined);
  const root = targetMetadata?.isFile() ? dirname(absoluteTarget) : absoluteTarget;
  const limitations = limitationCollector();
  const discovered = await discoverFiles(absoluteTarget, root, limitations);
  const references = await collectProjectReferences(discovered, root, limitations);
  const selected = selectedConfigurations(absoluteTarget, discovered, references, limitations);
  const documents = await loadSelectedConfigurations(selected, limitations);
  return {
    target: absoluteTarget,
    root,
    documents,
    limitations: limitations.finish(),
  };
}

export function loadIosConfigurationProject(target: string): Promise<IosConfigurationProject> {
  return loadUncached(target);
}

export function createCachedIosConfigurationLoader(
  target: string,
): () => Promise<IosConfigurationProject> {
  let cached: Promise<IosConfigurationProject> | undefined;
  return () => cached ??= loadUncached(target);
}

export function resolveIosConfigurationProject(
  input: IosConfigurationInput,
): Promise<IosConfigurationProject> {
  if (typeof input === "string") return loadUncached(input);
  return Promise.resolve(input);
}
