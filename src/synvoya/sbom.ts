/**
 * The per-scan SBOM the Synvoya layer hands to osv-scanner: one CycloneDX 1.5 JSON component per exact
 * declaration of a vendored or CDN library (design §4.4). It is written only into the scan's managed temp
 * directory and never named in a finding or note; each component's opaque `bom-ref` keys the declaration
 * (file and line) it came from, so findings point at the repository, never at the SBOM.
 *
 * Hand-written on purpose (no SBOM library): a fixed key order and a sorted component list make the bytes
 * deterministic for the same input, and nothing but `type`, `bom-ref`, `name`, `version` and `purl` is
 * emitted, so no timestamp, serial number or host detail varies between runs.
 */

import { writeFile } from "node:fs/promises";

import type { Declaration } from "./types.js";

/** One package to check, and the opaque reference that links it back to its declaration. */
export interface SbomItem {
  purl: string;
  ref: string;
}

/** Components per SBOM; the rest are named back to the caller (their files are then not checked). */
export const SBOM_MAX_COMPONENTS = 20_000;
const MAX_PURL_CHARS = 512;
const MAX_REF_CHARS = 256;

/** A purl segment: percent-encoded per the purl spec (`@` in an npm scope becomes `%40`, `+` becomes `%2B`). */
function segment(value: string): string {
  return encodeURIComponent(value);
}

/** `pkg:npm/<name>@<version>`, a scoped name as `pkg:npm/%40scope/name@<version>`. */
export function npmPurl(name: string, version: string): string {
  return `pkg:npm/${name.split("/").map(segment).join("/")}@${segment(version)}`;
}

/** `pkg:composer/<vendor>/<name>@<version>`: osv-scanner reads it as the Packagist package `<vendor>/<name>`. */
export function composerPurl(name: string, version: string): string {
  return `pkg:composer/${name.split("/").map(segment).join("/")}@${segment(version)}`;
}

function decode(value: string): string | undefined {
  try {
    return decodeURIComponent(value);
  } catch {
    return undefined;
  }
}

/**
 * The type, full package name (namespace and name joined by `/`, as osv-scanner and the registries name it)
 * and version of a plain purl; undefined for anything else (qualifiers, subpaths, empty or dot segments).
 */
export function parsePurl(purl: string): { type: string; name: string; version: string } | undefined {
  if (purl.length > MAX_PURL_CHARS) return undefined;
  const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^@?#]+)@([^@/?#]+)$/.exec(purl);
  if (!match) return undefined;
  const segments = match[2]!.split("/").map(decode);
  const version = decode(match[3]!);
  if (version === undefined || version === "" || /[\u0000-\u001f\u007f]/.test(version)) return undefined;
  if (segments.some((part) => part === undefined || part === "" || part === "." || part === ".." || /[\u0000-\u001f\u007f/]/.test(part))) return undefined;
  return { type: match[1]!, name: segments.join("/"), version };
}

const compare = (left: string, right: string): number => (left < right ? -1 : left > right ? 1 : 0);

/**
 * Write `items` to `path` as CycloneDX 1.5 JSON: sorted by purl then ref, exact duplicates dropped, at most
 * SBOM_MAX_COMPONENTS components. `omittedRefs` names every item not written (unreadable purl or ref, or past
 * the cap). The file must not exist yet (`wx`): an existing file or link is never written through.
 */
export async function writeCycloneDx(items: readonly SbomItem[], path: string): Promise<{ written: number; skipped: number; omittedRefs: string[] }> {
  const seen = new Set<string>();
  const sorted = [...items].sort((left, right) => compare(left.purl, right.purl) || compare(left.ref, right.ref));
  const components: Array<Record<string, string>> = [];
  const omittedRefs: string[] = [];
  for (const item of sorted) {
    const key = `${item.purl}\0${item.ref}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const parsed = parsePurl(item.purl);
    if (!parsed || item.ref.length === 0 || item.ref.length > MAX_REF_CHARS || components.length >= SBOM_MAX_COMPONENTS) {
      omittedRefs.push(item.ref);
      continue;
    }
    components.push({ type: "library", "bom-ref": item.ref, name: parsed.name, version: parsed.version, purl: item.purl });
  }
  const document = { bomFormat: "CycloneDX", specVersion: "1.5", version: 1, components };
  await writeFile(path, `${JSON.stringify(document, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  return { written: components.length, skipped: omittedRefs.length, omittedRefs: omittedRefs.sort(compare) };
}

/** The vendored-library declarations as SBOM items, the declaration behind each ref, and notes for the rest. */
export interface LibraryInventory {
  items: SbomItem[];
  byRef: Map<string, Declaration>;
  /** Files holding a floating library declaration: osv-scanner never checks them, so they are never SBOM-checked. */
  floatingFiles: Set<string>;
  /** Floating declarations: never checked by osv-scanner, so the user is told. */
  notes: string[];
}

/**
 * Exact `vendored` npm declarations become items; a floating one only a note, and its file is listed in
 * `floatingFiles` (a floating version can still resolve to an affected release that osv-scanner never saw, so
 * the file was not re-checked); an unresolved one already carries the reader's note. Refs are numbered in
 * (file, line, purl) order, so they are stable for the same declarations.
 */
export function libraryInventory(declarations: readonly Declaration[]): LibraryInventory {
  const libraries = declarations.filter((decl) => decl.producer === "vendored" && decl.subject.type === "package" && decl.subject.ecosystem === "npm");
  const items: SbomItem[] = [];
  const byRef = new Map<string, Declaration>();
  const notes: string[] = [];
  const floatingFiles = new Set<string>();
  const exact = libraries
    .filter((decl) => decl.precision === "exact")
    .map((decl) => ({ decl, purl: npmPurl((decl.subject as { name: string }).name, decl.resolved ?? decl.spec) }))
    .sort((left, right) => compare(left.decl.file, right.decl.file) || left.decl.line - right.decl.line || compare(left.purl, right.purl));
  for (const { decl, purl } of exact) {
    const ref = `lib-${items.length + 1}`;
    items.push({ purl, ref });
    byRef.set(ref, decl);
  }
  for (const decl of libraries) {
    if (decl.precision !== "floating") continue;
    floatingFiles.add(decl.file);
    notes.push(
      `${decl.file}:${decl.line}: ${decl.source} names ${(decl.subject as { name: string }).name} "${decl.spec}", not an exact version; ` +
        "only exact versions of vendored and CDN libraries are checked against the OSV npm database, so a rescan cannot confirm a fix in this file.",
    );
  }
  return { items, byRef, floatingFiles, notes };
}

/**
 * The Go standard library at a release: `pkg:golang/stdlib@v<version>`. The OSV Go database files Go toolchain
 * advisories under the package `stdlib`, and osv-scanner 2.7.0 matches the component `stdlib` with or without
 * the `v` (verified against the real binary and the Go database, 2026-11-04).
 */
export function goStdlibPurl(version: string): string {
  return `pkg:golang/stdlib@${segment(`v${version}`)}`;
}

/** One SBOM component that is not a vendored library, and the declaration behind it. */
export interface SbomPackage {
  ref: string;
  purl: string;
  ecosystem: "Packagist" | "Go";
  /** The name and version osv-scanner lists the component under (the advisory name). */
  name: string;
  version: string;
  decl: Declaration;
  /** The package name the repository declares, when osv-scanner checks it under another (advisory) name. */
  declaredName?: string;
}

export interface DeclaredPackageInventory {
  packages: SbomPackage[];
  /** Files holding a declaration of this kind that osv-scanner does not check: never SBOM-checked. */
  uncheckedFiles: Set<string>;
  notes: string[];
}

const MAGENTO_EDITIONS: ReadonlySet<string> = new Set(["magento-open-source", "adobe-commerce"]);

/**
 * go.mod `toolchain` lines (runtime reader) and golang images (image reader) feed the SBOM. A go.mod `go` line
 * is the minimum Go the module needs, judged by the runtime producer: it is not an SBOM input.
 */
export function isGoSbomInput(decl: Declaration): boolean {
  if (decl.subject.type !== "runtime" || decl.subject.runtime !== "go") return false;
  return decl.producer === "images" || (decl.producer === "runtime" && decl.source === "go.mod toolchain");
}

/**
 * The Go toolchain a go.mod `toolchain` line or a golang image names exactly, as the Go standard library
 * (`stdlib`) at that release. A floating image or an unresolved toolchain names no release: it is not checked,
 * and its file is listed in `uncheckedFiles` (with a note unless the reader already noted it). Other Go
 * declarations (the go.mod `go` minimum, setup-go, .tool-versions) are not SBOM inputs. Refs are numbered in
 * (file, line) order.
 */
function goInventory(declarations: readonly Declaration[], out: DeclaredPackageInventory): void {
  const inputs = declarations.filter(isGoSbomInput).sort((left, right) => compare(left.file, right.file) || left.line - right.line);
  let next = 1;
  for (const decl of inputs) {
    const version = decl.precision === "exact" ? decl.resolved ?? decl.spec : undefined;
    if (version === undefined || !/^\d+\.\d+\.\d+$/.test(version)) {
      out.uncheckedFiles.add(decl.file);
      // An unresolved version already carries the reader's note.
      if (decl.precision !== "unresolved") {
        out.notes.push(
          `${decl.file}:${decl.line}: ${decl.source} names Go "${decl.spec}", not an exact release; the Go standard library is checked ` +
            "against the OSV Go database only for an exact go.mod toolchain or golang image, so a rescan cannot confirm a Go fix in this file through osv-scanner.",
        );
      }
      continue;
    }
    out.packages.push({ ref: `go-${next++}`, purl: goStdlibPurl(version), ecosystem: "Go", name: "stdlib", version: `v${version}`, decl });
  }
}

/**
 * Exact Magento editions read from a composer.lock, as the Packagist package GitHub advisories file them under:
 * `aliases` (the dataset's reviewed "<ecosystem>:<name>" table) maps the locked package (e.g.
 * `magento/product-community-edition`) to the advisory name (`magento/community-edition`). The component keeps
 * the locked package's file and line. An edition with no alias or no exact version is not checked, and its
 * file is listed in `uncheckedFiles`. Refs are numbered in (file, line) order. The Go toolchain follows
 * (goInventory).
 */
export function declaredPackageInventory(declarations: readonly Declaration[], aliases: Readonly<Record<string, string>>): DeclaredPackageInventory {
  const table = new Map<string, string>();
  for (const [from, to] of Object.entries(aliases)) table.set(from.toLowerCase(), to);
  const packages: SbomPackage[] = [];
  const uncheckedFiles = new Set<string>();
  const notes: string[] = [];
  const editions = declarations
    .filter((decl) => decl.producer === "products" && decl.subject.type === "product" && MAGENTO_EDITIONS.has(decl.subject.product))
    .sort((left, right) => compare(left.file, right.file) || left.line - right.line);
  for (const decl of editions) {
    const declared = /^composer\.lock (\S+)$/.exec(decl.source)?.[1];
    const alias = declared === undefined ? undefined : table.get(`packagist:${declared.toLowerCase()}`);
    const name = alias?.startsWith("Packagist:") ? alias.slice("Packagist:".length) : undefined;
    const version = decl.precision === "exact" ? decl.resolved ?? decl.spec : undefined;
    if (declared === undefined || name === undefined || version === undefined) {
      uncheckedFiles.add(decl.file);
      // An unresolved version already carries the reader's note.
      if (version !== undefined) {
        notes.push(
          `${decl.file}:${decl.line}: ${declared ?? decl.source} ${version} has no package name in the OSV Packagist database, ` +
            "so osv-scanner does not check it; a rescan cannot confirm a fix in this file through osv-scanner.",
        );
      }
      continue;
    }
    packages.push({ ref: `composer-${packages.length + 1}`, purl: composerPurl(name, version), ecosystem: "Packagist", name, version, decl, declaredName: declared });
  }
  const inventory = { packages, uncheckedFiles, notes };
  goInventory(declarations, inventory);
  return inventory;
}
