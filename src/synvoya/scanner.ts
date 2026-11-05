/**
 * The Synvoya gap layer in a vulnerability scan (design §8 items 1, 2 and 5).
 *
 * The bundled dataset loads first (fail closed: any integrity or schema failure makes the engine
 * unavailable, never a silent zero). The declaration readers then start at once, concurrently with the
 * other engines, under one shared wall-clock deadline; evaluation waits for the package inventory the
 * upstream engines (osv-scanner `--all-packages`, Trivy `--list-all-pkgs`) already produce in the same
 * scan. Runtime and image inputs never lower coverage (§8.5): what the readers skip is evidence in the
 * engine note, not a coverage gap.
 */

import { lstat, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

import type { CoverageGap } from "../coverage-gaps.js";
import { OSV_SBOM_FILE_NAME, osvSbomInvocationSignature, runOsvScannerOnSbom, type OsvScanResult, type OsvSbomLocation, type OsvSbomResult } from "../engines/osv-scanner.js";
import type { TrivyReportPackage } from "../engines/trivy.js";
import { log } from "../logger.js";
import { packageEntryLine, readLockfileLines, type LockfileLines } from "../osv/package-line.js";
import type { OsvDbRecord } from "../osv/database.js";
import { OSV_SBOM_INVOCATION_COMPONENT, osvDatabaseComponent, synvoyaStaticComponentSignatures, type SynvoyaProducer } from "../provenance.js";
import type { EngineRunInfo, Finding } from "../types.js";
import { datasetActionAdvisories, loadActionsDb, matchActions, unpinnedActionsNote, withDatasetAdvisories, type ActionsDbLoad, type ActionsMatch } from "./actions-matcher.js";
import { SYNVOYA_MAX_CHECKED_FILES, SYNVOYA_MAX_COVERAGE_NOTES, SYNVOYA_READER_DEADLINE_MS } from "./constants.js";
import { loadSynvoyaDataset } from "./dataset.js";
import { evaluateSynvoya, packageAdvisoryFilter, type InventoryPackage, type PackageInventory, type UpstreamDbDates } from "./evaluate.js";
import { readActionReferences, type ActionsReaderResult } from "./readers/actions.js";
import { readImageTags } from "./readers/images.js";
import { readLibraries } from "./readers/libraries.js";
import { readProducts } from "./readers/products.js";
import { readRuntimePins } from "./readers/runtime.js";
import { declaredPackageInventory, isGoSbomInput, libraryInventory, parsePurl, writeCycloneDx, type DeclaredPackageInventory, type LibraryInventory, type SbomItem } from "./sbom.js";
import type { Declaration, ReaderResult, SynvoyaDataset } from "./types.js";

export interface SynvoyaScanOptions {
  /** Dataset directory; the bundled one by default. */
  datasetDir?: string;
  /** Evaluation clock; now by default. */
  now?: Date;
  /** Shared reader deadline; SYNVOYA_READER_DEADLINE_MS by default (which the internal env override can replace). Zero or less is already expired. */
  deadlineMs?: number;
  /** The scan's managed temp dir: the vendored-library SBOM and its osv-scanner run live below it. A private one when absent. */
  tmpDir?: string;
  /** The OSV GitHub Actions database (tests); the installed one and its install record by default. */
  actionsDb?: { zipPath?: string; readRecord?: () => Promise<OsvDbRecord | undefined> };
}

/** What the Actions matcher evaluated, for the `actions-unchecked` gap; absent when it did not run. */
export interface SynvoyaActionsCoverage {
  /** `${file}\0${uses}` of every reference the matcher evaluated. */
  evaluated: Set<string>;
  /** Every third-party `uses:` value the Actions reader saw (workflows and composite actions). */
  references: Array<{ file: string; reference: string }>;
}

export interface SynvoyaScanResult {
  findings: Finding[];
  /**
   * osv-scanner findings for vendored and CDN libraries and aliased Magento editions (engine `osv-scanner`,
   * producer `sbom:osv-scanner`), located at their declarations. The caller folds one an upstream engine
   * already reports in the same file.
   */
  sbomFindings: Finding[];
  /** `vendored-js` when exact vendored libraries could not be checked (osv-scanner or its npm database missing). */
  coverageGaps: CoverageGap[];
  /**
   * Set only when the GitHub Actions matcher ran (its database is installed and read): the caller then keeps in
   * the `actions-unchecked` gap only the references it did not evaluate. Absent, the gap stays as discovered.
   */
  actionsCoverage?: SynvoyaActionsCoverage;
  info: EngineRunInfo;
  /** Coverage notes for the scan (component `engine:synvoya`), deduplicated and capped; priority notes first. */
  notes: string[];
  /** Scan warnings: when the layer could not run, or the vendored-library SBOM check did not run or was partial. */
  warnings: string[];
  /**
   * What the readers parsed and skipped (skips are engine-note counts, never coverage gaps), and, per
   * producer, the files it fully checked this run. Every Synvoya finding (and every osv-scanner finding from
   * the vendored-library SBOM, as `synvoya:sbom:osv-scanner`) records its producer(s) as
   * `synvoya:<producer>` producer components; rescan confirms a prior finding fixed only when each of its
   * producers' sets lists its file. A reader's set holds the files it parsed completely with every
   * declaration resolvable (exact, floating or range); an inventory set holds that engine's lockfiles
   * (never one from a source outside the target). A set is omitted (so nothing it would hold can be
   * confirmed fixed) when its reader rejected, when any deadline skip occurred (every reader set and the SBOM
   * set: a walk cut short cannot name every file it missed), or when it exceeds SYNVOYA_MAX_CHECKED_FILES.
   * The SBOM set holds the files the library and product readers both fully read (neither skipped) with no
   * unresolved, floating or unaliased SBOM-kind declaration, and only when osv-scanner checked every component
   * from them completely (or there were none to check).
   */
  evidence: {
    parsed: string[];
    skipped: Array<{ file: string; reason: string }>;
    checked: Partial<Record<SynvoyaProducer, string[]>>;
  };
  componentSignatures: Record<string, string>;
}

/** Upstream engine output the inventory and DB dates are taken from; any of it may be absent. */
export interface SynvoyaUpstreamSources {
  trivy?: { ran: boolean; packages?: TrivyReportPackage[]; trivyDbDate?: string };
  /** Trivy ran its vulnerability scanner in this scan. */
  trivyVulnerabilityScan?: boolean;
  osv?: Pick<OsvScanResult, "info" | "coverage" | "packages">;
}

/**
 * The package inventory and upstream DB dates from what osv-scanner and Trivy already parsed in this scan.
 * A DB date is passed only for an engine that ran over that ecosystem; a missing date makes `covered`
 * entries run (the evaluator treats it as stale) and enrichment folds any duplicate into the upstream finding.
 * Line 0 means the engine gave no line; the scanner locates it for findings only.
 */
export function synvoyaUpstreamInputs(sources: SynvoyaUpstreamSources): { inventory: PackageInventory; dates: UpstreamDbDates } {
  // Deduplicated per engine only: a package both engines list stays twice, so its finding records both
  // producers and a rescan needs both to list the lockfile again.
  const byKey = new Map<string, InventoryPackage>();
  const add = (pkg: InventoryPackage): void => {
    const key = `${pkg.producer}\0${pkg.ecosystem.toLowerCase()}\0${pkg.name}\0${pkg.version}\0${pkg.file}`;
    if (!byKey.has(key)) byKey.set(key, pkg);
  };
  for (const { outside, ...pkg } of sources.osv?.packages ?? []) {
    add({ ...pkg, line: outside ? 1 : 0, ...(outside ? { outside } : {}), producer: "inventory:osv-scanner" });
  }
  const trivyRan = sources.trivy?.ran === true && sources.trivyVulnerabilityScan === true;
  if (trivyRan) for (const pkg of sources.trivy?.packages ?? []) add({ ...pkg, producer: "inventory:trivy" });

  const dates: UpstreamDbDates = {};
  if (trivyRan && sources.trivy?.trivyDbDate) dates.trivy = sources.trivy.trivyDbDate;
  if (sources.osv?.info.ran) {
    for (const entry of sources.osv.coverage) {
      if ((entry.state === "ran" || entry.state === "partial") && entry.database_version) {
        (dates.osv ??= {})[entry.ecosystem] = entry.database_version;
      }
    }
  }
  return { inventory: { packages: [...byKey.values()] }, dates };
}

const unique = (items: Iterable<string>): string[] => [...new Set(items)];

/** Priority notes are never dropped; the rest fill the cap, and an overflow is counted in a final note. */
export function capSynvoyaNotes(priority: readonly string[], others: readonly string[], cap = SYNVOYA_MAX_COVERAGE_NOTES): string[] {
  const kept = unique(priority);
  const keptSet = new Set(kept);
  const rest = unique(others).filter((note) => !keptSet.has(note));
  const room = Math.max(0, cap - kept.length);
  if (rest.length <= room) return [...kept, ...rest];
  const shown = Math.max(0, room - 1);
  return [...kept, ...rest.slice(0, shown), `… ${rest.length - shown} more Synvoya note(s) not shown.`];
}

function skippedSummary(skipped: ReadonlyArray<{ reason: string }>): string {
  const counts = new Map<string, number>();
  for (const entry of skipped) counts.set(entry.reason, (counts.get(entry.reason) ?? 0) + 1);
  return [...counts].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([reason, count]) => `${count} ${reason}`).join(", ");
}

/**
 * Gives every inventory package a real line before evaluation, so findings, messages and notes never say
 * line 0: a package some advisory targets is located at its own entry in its lockfile (else 1); any
 * other package is never reported and gets 1 without a read.
 */
async function locateInventory(target: string, dataset: SynvoyaDataset, inventory: PackageInventory): Promise<PackageInventory> {
  if (!inventory.packages.some((pkg) => pkg.line < 1)) return inventory;
  const targeted = packageAdvisoryFilter(dataset);
  const base = await lstat(target).then((info) => (info.isDirectory() ? target : dirname(target)), () => target);
  const cache = new Map<string, Promise<LockfileLines | undefined>>();
  const packages: InventoryPackage[] = [];
  for (const pkg of inventory.packages) {
    if (pkg.line >= 1) {
      packages.push(pkg);
      continue;
    }
    if (!targeted(pkg.ecosystem, pkg.name)) {
      packages.push({ ...pkg, line: 1 });
      continue;
    }
    let lines = cache.get(pkg.file);
    if (!lines) {
      lines = readLockfileLines(join(base, ...pkg.file.split("/")));
      cache.set(pkg.file, lines);
    }
    packages.push({ ...pkg, line: packageEntryLine(await lines, pkg.file, pkg.name) });
  }
  return { packages };
}

/**
 * Where the readers start. A directory is walked. A file is read alone, relative to the folder that gives
 * it its meaning to the readers: a workflow under `.github/workflows/`, `wp-includes/version.php` under
 * its WordPress root, anything else under its own folder (as the other engines report a file target).
 */
async function readerScope(target: string): Promise<{ root: string; only?: string }> {
  const isFile = await lstat(target).then((info) => !info.isDirectory(), () => false);
  if (!isFile) return { root: target };
  const name = basename(target);
  const parent = dirname(target);
  const grandparent = dirname(parent);
  if (basename(parent) === "workflows" && basename(grandparent) === ".github") {
    return { root: dirname(grandparent), only: `.github/workflows/${name}` };
  }
  if (name === "version.php" && basename(parent) === "wp-includes") return { root: grandparent, only: `wp-includes/${name}` };
  return { root: parent, only: name };
}

const READER_NAMES = ["runtime", "image", "product", "library"] as const;
const READER_PRODUCERS = ["runtime", "images", "products", "vendored"] as const;
const LIBRARY_READER = READER_PRODUCERS.indexOf("vendored");
const PRODUCT_READER = READER_PRODUCERS.indexOf("products");
const RUNTIME_READER = READER_PRODUCERS.indexOf("runtime");
const IMAGE_READER = READER_PRODUCERS.indexOf("images");

/** What osv-scanner checks a declaration as. */
type SbomKind = "library" | "edition" | "toolchain";
const SBOM_ECOSYSTEMS = ["npm", "Packagist", "Go"] as const;
type SbomEcosystem = (typeof SBOM_ECOSYSTEMS)[number];

/** One SBOM component's declaration, and what osv-scanner checks it as. */
interface SbomSubject {
  decl: Declaration;
  ecosystem: SbomEcosystem;
  kind: SbomKind;
  /** The package name the repository declares, when the component names its advisory package. */
  declaredName?: string;
}

/** Every component of the per-scan SBOM: exact vendored libraries, aliased Magento editions and Go toolchains. */
interface SbomInput {
  items: SbomItem[];
  byRef: Map<string, SbomSubject>;
}

function sbomInput(library: LibraryInventory, declared: DeclaredPackageInventory): SbomInput {
  const items: SbomItem[] = [...library.items];
  const byRef = new Map<string, SbomSubject>();
  for (const item of library.items) {
    const decl = library.byRef.get(item.ref);
    if (decl) byRef.set(item.ref, { decl, ecosystem: "npm", kind: "library" });
  }
  for (const pkg of declared.packages) {
    items.push({ purl: pkg.purl, ref: pkg.ref });
    const kind = pkg.ecosystem === "Go" ? "toolchain" : "edition";
    byRef.set(pkg.ref, { decl: pkg.decl, ecosystem: pkg.ecosystem, kind, ...(pkg.declaredName !== undefined ? { declaredName: pkg.declaredName } : {}) });
  }
  return { items, byRef };
}

/** The finding message's opening sentence: the declaration, never the SBOM. */
function sbomLead(subject: SbomSubject, name: string, version: string): string {
  const { decl } = subject;
  if (subject.kind === "toolchain") {
    return `${decl.file}:${decl.line} declares Go ${decl.resolved ?? decl.spec} (${decl.source}); osv-scanner checked the Go standard library (${name}) at that version.`;
  }
  if (subject.kind === "edition") {
    return `${decl.file}:${decl.line} locks Packagist package ${subject.declaredName ?? name} ${version}, ` +
      `which GitHub advisories list as ${name}; osv-scanner checked it under that name.`;
  }
  return `${decl.file}:${decl.line} ships npm package ${name}@${version} as a vendored or CDN-loaded library (${decl.source}).`;
}

/**
 * The vendored install a shipped library file belongs to: the path up to its first directory named for the
 * library (`public/libs/tinymce` for `public/libs/tinymce/plugins/link/plugin.min.js`; `tinymce-6.8.4` too),
 * else the file's own directory ("" at the repository root).
 */
export function vendoredRoot(file: string, name: string): string {
  const stem = name.slice(name.lastIndexOf("/") + 1).toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const named = new RegExp(`^${stem}(?:[-._@]v?\\d.*)?$`);
  const dirs = file.split("/").slice(0, -1);
  const at = dirs.findIndex((dir) => named.test(dir.toLowerCase()));
  return (at >= 0 ? dirs.slice(0, at + 1) : dirs).join("/");
}

/** How many other files of one vendored install a finding's message names. */
const VENDORED_EXAMPLES = 5;
const compare = (left: string, right: string): number => (left < right ? -1 : left > right ? 1 : 0);

/**
 * Where to report one package osv-scanner listed. A library shipped as files (banner or versioned file name) is
 * reported once per vendored root, at its shallowest file, naming up to 5 others: TinyMCE's banner is on every
 * plugin file, and one install is one exposure. Its fingerprint is keyed on the root (`fingerprintScope`), so
 * it stays stable as files of the install come and go. A CDN reference, a Magento edition or a Go toolchain is
 * reported at each declaration.
 */
function sbomLocations(subjects: readonly SbomSubject[], name: string, version: string): OsvSbomLocation[] {
  const single = (subject: SbomSubject, extra: Partial<OsvSbomLocation> = {}): OsvSbomLocation => ({
    file: subject.decl.file,
    line: subject.decl.line,
    lead: sbomLead(subject, name, version),
    ...(subject.declaredName !== undefined ? { declaredName: subject.declaredName } : {}),
    ...extra,
  });
  const locations: OsvSbomLocation[] = [];
  const installs = new Map<string, SbomSubject[]>();
  for (const subject of subjects) {
    if (subject.kind !== "library" || subject.decl.source === "cdn-url") {
      locations.push(single(subject));
      continue;
    }
    const root = vendoredRoot(subject.decl.file, name);
    const members = installs.get(root);
    if (members) members.push(subject);
    else installs.set(root, [subject]);
  }
  const depth = (file: string): number => file.split("/").length;
  for (const [root, members] of installs) {
    members.sort((left, right) =>
      depth(left.decl.file) - depth(right.decl.file) || compare(left.decl.file, right.decl.file) || left.decl.line - right.decl.line);
    const [first] = members as [SbomSubject, ...SbomSubject[]];
    const others: string[] = [];
    const seen = new Set([first.decl.file]);
    for (const member of members) {
      if (seen.has(member.decl.file)) continue;
      seen.add(member.decl.file);
      others.push(`${member.decl.file}:${member.decl.line}`);
    }
    const location = single(first, { fingerprintScope: root });
    if (others.length) {
      const shown = others.slice(0, VENDORED_EXAMPLES).join(", ");
      const rest = others.length - VENDORED_EXAMPLES;
      location.lead = `${location.lead.replace(/\.$/, "")}; ${others.length} more ${others.length === 1 ? "file" : "files"} ` +
        `${root ? `under ${root}/` : "at the repository root"} ship the same version: ${shown}${rest > 0 ? ` and ${rest} more` : ""}.`;
    }
    locations.push(location);
  }
  return locations.sort((left, right) => compare(left.file, right.file) || left.line - right.line);
}

/** What the SBOM check did; `skipped` when there was nothing to check. */
type SbomCheck = { state: "skipped" } | (OsvSbomResult & { omittedRefs: string[] });

/**
 * Write the SBOM components (exact vendored libraries, aliased Magento editions, Go toolchains) as a CycloneDX SBOM in the
 * scan's temp dir and check it with osv-scanner. Skipped entirely (no file, no process) when there is nothing
 * to check. Never throws.
 */
async function checkSbom(input: SbomInput, tmpDir: string | undefined): Promise<SbomCheck> {
  if (input.items.length === 0) return { state: "skipped" };
  let own: string | undefined;
  try {
    own = tmpDir === undefined ? await mkdtemp(join(tmpdir(), "ci-synvoya-sbom-")) : undefined;
    const workDir = join(tmpDir ?? own!, "synvoya-sbom");
    await mkdir(workDir, { recursive: true, mode: 0o700 });
    const sbomPath = join(workDir, OSV_SBOM_FILE_NAME);
    const written = await writeCycloneDx(input.items, sbomPath);
    const omitted = new Set(written.omittedRefs);
    // osv-scanner's result names each package by ecosystem, name and version (no bom-ref), so the written refs
    // are looked up by that key; one package may stand for several declarations.
    const byPackage = new Map<string, Array<{ subject: SbomSubject; name: string; version: string }>>();
    for (const item of input.items) {
      const purl = parsePurl(item.purl);
      const subject = input.byRef.get(item.ref);
      if (!purl || !subject || omitted.has(item.ref)) continue;
      const key = `${subject.ecosystem}\0${purl.name}\0${purl.version}`;
      const entry = { subject, name: purl.name, version: purl.version };
      const declared = byPackage.get(key);
      if (declared) declared.push(entry);
      else byPackage.set(key, [entry]);
    }
    const listed = [...byPackage.values()].map((entries) => entries[0]!);
    const result = await runOsvScannerOnSbom(sbomPath, workDir, {
      ecosystems: SBOM_ECOSYSTEMS.filter((ecosystem) => listed.some((entry) => entry.subject.ecosystem === ecosystem)),
      expected: listed.map((entry) => ({ ecosystem: entry.subject.ecosystem, name: entry.name, version: entry.version })),
      locate: (pkg) =>
        sbomLocations((byPackage.get(`${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`) ?? []).map(({ subject }) => subject), pkg.name, pkg.version),
    });
    return { ...result, omittedRefs: written.omittedRefs };
  } catch (error) {
    log.warn("synvoya: SBOM check failed", { cause: error instanceof Error ? error.message : String(error) });
    return { state: "failed", version: "unknown", reason: "the SBOM could not be written", missingDatabases: [], complete: false, findings: [], warnings: [], omittedRefs: [] };
  } finally {
    if (own !== undefined) await rm(own, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** "; osv-scanner checked 3 exact vendored libraries and 1 Magento edition; 1 … not checked" (empty without components). */
function sbomSummary(input: SbomInput, unchecked: ReadonlySet<string> | undefined): string {
  const count = (kind: SbomKind, checked: boolean): number =>
    [...input.byRef].filter(([ref, subject]) => subject.kind === kind && (unchecked === undefined ? !checked : unchecked.has(ref) !== checked)).length;
  const label = (kind: SbomKind, n: number): string =>
    kind === "library" ? `${n} exact vendored ${n === 1 ? "library" : "libraries"}`
      : kind === "edition" ? `${n} Magento edition${n === 1 ? "" : "s"}`
        : `${n} Go toolchain${n === 1 ? "" : "s"}`;
  const parts = (checked: boolean): string[] =>
    (["library", "edition", "toolchain"] as const).flatMap((kind) => {
      const n = count(kind, checked);
      return n > 0 ? [label(kind, n)] : [];
    });
  const checked = parts(true);
  const missed = parts(false);
  return `${checked.length ? `; osv-scanner checked ${checked.join(", ")}` : ""}${missed.length ? `; ${missed.join(", ")} not checked` : ""}`;
}

/** The refs osv-scanner did not check: all of them unless it ran, else those omitted from the SBOM or whose database is missing. */
function uncheckedRefs(input: SbomInput, sbom: SbomCheck): Set<string> {
  if (sbom.state === "skipped") return new Set();
  if (sbom.state !== "ran") return new Set(input.items.map((item) => item.ref));
  const missing = new Set<string>(sbom.missingDatabases);
  const refs = new Set(sbom.omittedRefs);
  for (const [ref, subject] of input.byRef) if (missing.has(subject.ecosystem)) refs.add(ref);
  return refs;
}

/** The `vendored-js` gap: exact vendored libraries no engine could check, one example per file. */
function vendoredGap(library: LibraryInventory): CoverageGap {
  const byFile = new Map<string, string>();
  for (const item of library.items) {
    const decl = library.byRef.get(item.ref);
    const purl = parsePurl(item.purl);
    if (decl && purl && !byFile.has(decl.file)) byFile.set(decl.file, `${decl.file} (${purl.name}@${purl.version})`);
  }
  const files = [...byFile.keys()].sort();
  return { id: "vendored-js", files: files.length, examples: files.slice(0, 5).map((file) => byFile.get(file)!) };
}

function unavailable(started: number, reason: string, version = "unknown"): SynvoyaScanResult {
  const note = `Synvoya gap advisories unavailable: ${reason}`;
  return {
    findings: [],
    info: { engine: "synvoya", version, available: false, ran: false, finding_count: 0, duration_ms: Date.now() - started, note },
    notes: [],
    warnings: [note],
    evidence: { parsed: [], skipped: [], checked: {} },
    componentSignatures: {},
    sbomFindings: [],
    coverageGaps: [],
  };
}

export async function runSynvoyaScan(
  target: string,
  inventory: Promise<PackageInventory> | PackageInventory,
  upstreamDbDates: Promise<UpstreamDbDates> | UpstreamDbDates,
  options: SynvoyaScanOptions = {},
): Promise<SynvoyaScanResult> {
  const started = Date.now();
  // Whatever happens below, a rejected input is never left unhandled.
  const inventoryReady = Promise.resolve(inventory);
  const datesReady = Promise.resolve(upstreamDbDates);
  inventoryReady.catch(() => undefined);
  datesReady.catch(() => undefined);

  const loaded = await loadSynvoyaDataset(options.datasetDir);
  if (!loaded.ok) return unavailable(started, loaded.reason);
  // Entries that need a later milestone's reader or matcher, or a platform no reader can see, never evaluate yet.
  const dataset = { ...loaded.dataset, advisories: loaded.dataset.advisories.filter((advisory) => advisory.requires === undefined) };

  // Awaited on every path out, so the SBOM run never outlives the scan's temp dir.
  let sbomTask: Promise<SbomCheck> | undefined;
  try {
    const scope = await readerScope(target);
    const deadlineMs = options.deadlineMs ?? SYNVOYA_READER_DEADLINE_MS;
    const controller = new AbortController();
    const timer = deadlineMs > 0 ? setTimeout(() => controller.abort(), deadlineMs) : undefined;
    timer?.unref?.();
    if (deadlineMs <= 0) controller.abort();
    let settled: Array<PromiseSettledResult<ReaderResult>>;
    let actionsSettled: PromiseSettledResult<ActionsReaderResult>;
    try {
      const options = { signal: controller.signal, ...(scope.only !== undefined ? { only: scope.only } : {}) };
      // Settled, not all: a reader that rejects never leaves the others running or discards what they read.
      [settled, [actionsSettled]] = await Promise.all([
        Promise.allSettled([
          readRuntimePins(scope.root, options),
          readImageTags(scope.root, dataset, options),
          readProducts(scope.root, options),
          readLibraries(scope.root, dataset.libraries, options),
        ]),
        Promise.allSettled([readActionReferences(scope.root, options)]),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
    const readers: ReaderResult[] = settled.map((outcome, index) => {
      if (outcome.status === "fulfilled") {
        const producer = READER_PRODUCERS[index]!;
        return { ...outcome.value, declarations: outcome.value.declarations.map((declaration) => ({ ...declaration, producer })) };
      }
      const name = READER_NAMES[index]!;
      log.warn(`synvoya ${name} reader failed`, { cause: outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason) });
      return {
        declarations: [],
        parsed: [],
        skipped: [{ file: ".", reason: "malformed" }],
        notes: [],
        priorityNotes: [`The Synvoya ${name} reader stopped unexpectedly; the files it reads were not checked.`],
      };
    });

    // The Actions reader feeds only the Actions matcher (never the dataset evaluator or the SBOM).
    let actionsReader: ActionsReaderResult;
    if (actionsSettled.status === "fulfilled") {
      actionsReader = { ...actionsSettled.value, declarations: actionsSettled.value.declarations.map((declaration) => ({ ...declaration, producer: "actions" as const })) };
    } else {
      log.warn("synvoya actions reader failed", { cause: actionsSettled.reason instanceof Error ? actionsSettled.reason.message : String(actionsSettled.reason) });
      actionsReader = {
        declarations: [], parsed: [], references: [], skipped: [{ file: ".", reason: "malformed" }], notes: [],
        priorityNotes: ["The Synvoya GitHub Actions reader stopped unexpectedly; the workflows and actions it reads were not checked."],
      };
    }

    const declarations = readers.flatMap((reader) => reader.declarations);
    const parsed = unique([...readers.flatMap((reader) => reader.parsed), ...actionsReader.parsed]).sort();
    const skipped = [...readers.flatMap((reader) => reader.skipped), ...actionsReader.skipped];
    const priority = [...readers.flatMap((reader) => reader.priorityNotes ?? []), ...(actionsReader.priorityNotes ?? [])];
    // A file target no reader reads: say so plainly; nothing about it is a checked file.
    const only = scope.only;
    if (only !== undefined && !parsed.includes(only) && !skipped.some((entry) => entry.file === only)) {
      priority.push(`Synvoya reads runtime, image, product and library declarations from directories; ${basename(target)} was not checked.`);
    }
    const deadlineSkips = skipped.filter((entry) => entry.reason === "deadline").length;

    // The exact vendored libraries, aliased Magento editions and Go toolchains go to osv-scanner now, alongside
    // the wait for the upstream inventory.
    const library = libraryInventory(declarations);
    const declared = declaredPackageInventory(declarations, dataset.aliases);
    const input = sbomInput(library, declared);
    sbomTask = checkSbom(input, options.tmpDir);
    const [received, dates] = await Promise.all([
      inventoryReady.catch((error: unknown) => {
        log.warn("synvoya: package inventory unavailable", { cause: error instanceof Error ? error.message : String(error) });
        return { packages: [] } as PackageInventory;
      }),
      datesReady.catch(() => ({}) as UpstreamDbDates),
    ]);
    const packages = await locateInventory(target, dataset, received);
    const now = options.now ?? new Date();
    const evaluation = evaluateSynvoya(dataset, declarations, packages, now, dates);
    // Third-party GitHub Actions against the installed OSV GitHub Actions database (never osv-scanner).
    const actionsDb: ActionsDbLoad = actionsReader.declarations.length > 0 ? await loadActionsDb(options.actionsDb) : { state: "missing" };
    // The dataset's own Actions advisories are judged with or without the database. Only a run over the database
    // is a coverage claim (`actions`); without it the dataset's findings and notes stand and nothing is checked.
    const datasetActions = datasetActionAdvisories(dataset.advisories);
    const matched: ActionsMatch | undefined = actionsReader.declarations.length === 0 ? undefined : matchActions(
      withDatasetAdvisories(actionsDb.state === "ready" ? actionsDb.db : undefined, datasetActions), actionsReader.declarations, now,
    );
    const actions: ActionsMatch | undefined = actionsDb.state === "ready" ? matched : undefined;
    const capChecked = (files: string[], kind: string): string[] | undefined => {
      if (files.length <= SYNVOYA_MAX_CHECKED_FILES) return files;
      priority.push(
        `Synvoya checked more than ${SYNVOYA_MAX_CHECKED_FILES} ${kind}; they are not recorded, so a rescan cannot confirm any of their Synvoya findings fixed.`,
      );
      return undefined;
    };
    const unjudgedBy = (producer: SynvoyaProducer): ReadonlySet<string> =>
      new Set(evaluation.unjudged.filter((entry) => entry.producer === producer).map((entry) => entry.file));
    const checked: Partial<Record<SynvoyaProducer, string[]>> = {};
    readers.forEach((reader, index) => {
      // Rejected reader, or any deadline skip (a cut walk cannot name every file it missed): no set.
      if (settled[index]!.status === "rejected" || deadlineSkips > 0) return;
      // A file holding anything the evaluator could not judge for this reader (unresolved, not comparable,
      // no release lines, no latest release on an end-of-life line) was not checked.
      const producer = READER_PRODUCERS[index]!;
      const readerUnjudged = new Set(reader.unjudged ?? []);
      const files = capChecked(
        unique(reader.parsed.filter((file) => !unjudgedBy(producer).has(file) && !readerUnjudged.has(file))).sort(),
        `${READER_NAMES[index]} declaration files`,
      );
      if (files) checked[READER_PRODUCERS[index]!] = files;
    });
    // The Actions producer re-checks a file only when its reader read it whole (no deadline skip anywhere) and
    // every reference in it got a definite answer from the matcher: a finding, or clean. A note (a moving tag
    // with a fixed release, an unlisted commit, a branch) or a reference the reader could not read leaves it out;
    // without the database only files with no third-party reference are checked.
    if (actionsSettled.status === "fulfilled" && deadlineSkips === 0) {
      const withReferences = new Set(actionsReader.declarations.map((decl) => decl.file));
      const unchecked = new Set<string>([...(actionsReader.unjudged ?? []), ...(actions ? actions.indefinite : withReferences)]);
      const files = capChecked(unique(actionsReader.parsed.filter((file) => !unchecked.has(file))).sort(), "GitHub Actions workflow and action files");
      if (files) checked.actions = files;
    }
    const sbom = await sbomTask;
    const warnings: string[] = [];
    // Field run 2026-11-05: a rerun lost findings to the deadline, so it is partial coverage, never only a note.
    if (deadlineSkips > 0) {
      warnings.push(
        `Synvoya coverage partial: the readers reached their ${Math.round(deadlineMs / 1000)} s deadline; ${deadlineSkips} file(s) or folder(s) ` +
          "were not read, so runtime, image, product, library and GitHub Actions declarations in them were not checked.",
      );
    }
    if (actionsDb.state === "failed") warnings.push(`Synvoya GitHub Actions check did not run: ${actionsDb.reason}`);
    else if (actionsDb.state === "ready" && actionsDb.warning) warnings.push(actionsDb.warning);
    const coverageGaps: CoverageGap[] = [];
    if (sbom.state === "failed") warnings.push(`Synvoya SBOM check did not run: ${sbom.reason ?? "osv-scanner failed"}`);
    else if (sbom.state === "ran") for (const warning of sbom.warnings) warnings.push(`Synvoya SBOM check partial: ${warning}`);
    const npmMissing = sbom.state === "unavailable" || (sbom.state === "ran" && sbom.missingDatabases.includes("npm"));
    if (npmMissing && library.items.length > 0) coverageGaps.push(vendoredGap(library));
    const unchecked = uncheckedRefs(input, sbom);
    const uncheckedFiles = new Set([...unchecked].flatMap((ref) => input.byRef.get(ref)?.decl.file ?? []));
    const omittedFiles = new Set(sbom.state === "skipped" ? [] : sbom.omittedRefs.flatMap((ref) => input.byRef.get(ref)?.decl.file ?? []));
    if (omittedFiles.size > 0) {
      priority.push(`${omittedFiles.size} file(s) did not fit the per-scan SBOM; osv-scanner did not check them.`);
    }
    // Editions and toolchains osv-scanner could not check are named (vendored libraries have the vendored-js
    // gap instead; a missing Go database needs no new gap id); a failed run already has its warning.
    for (const [kind, ecosystem, what] of [["edition", "Packagist", "Magento edition(s)"], ["toolchain", "Go", "Go toolchain declaration(s)"]] as const) {
      if (!(sbom.state === "unavailable" || (sbom.state === "ran" && sbom.missingDatabases.includes(ecosystem)))) continue;
      const files = [...input.byRef].filter(([ref, subject]) => subject.kind === kind && unchecked.has(ref)).map(([, subject]) => subject.decl.file);
      const reason = sbom.state === "unavailable" ? sbom.reason ?? "osv-scanner is not available" : `the OSV ${ecosystem} database is not installed`;
      if (files.length > 0) priority.push(`${files.length} ${what} were not checked by osv-scanner: ${reason} (${unique(files).sort().join(", ")}).`);
    }
    // The SBOM producer re-checks a file only when every reader that feeds the SBOM read it whole with nothing
    // unresolved, every SBOM-kind declaration in it (exact library, aliased edition, Go toolchain or image; other
    // producers' declarations never count) became a component (osv-scanner sees exact versions
    // only, under a name the advisories use), and osv-scanner completely checked every component in it (or it
    // had none). A file one feeding reader skipped is never checked, even if another read it.
    const feeding = [LIBRARY_READER, PRODUCT_READER, RUNTIME_READER, IMAGE_READER];
    if (feeding.every((index) => settled[index]!.status === "fulfilled") && deadlineSkips === 0 && (sbom.state === "skipped" || (sbom.state === "ran" && sbom.complete))) {
      const excluded = new Set<string>([
        ...feeding.flatMap((index) => [...readers[index]!.skipped.map((entry) => entry.file), ...(readers[index]!.unjudged ?? [])]),
        ...library.floatingFiles,
        ...declared.uncheckedFiles,
        ...uncheckedFiles,
      ]);
      // The runtime reader feeds the SBOM only through a go.mod `toolchain` line: a go.mod without one names no
      // toolchain (a removed line leaves the effective one unknown), so it is never SBOM-checked. Only SBOM-kind
      // declarations decide; the `go` minimum is the runtime producer's.
      const toolchainFiles = new Set(declarations.filter((decl) => decl.producer === "runtime" && isGoSbomInput(decl)).map((decl) => decl.file));
      const inputs = feeding.flatMap((index) => index === RUNTIME_READER ? readers[index]!.parsed.filter((file) => toolchainFiles.has(file)) : readers[index]!.parsed);
      const files = capChecked(unique(inputs).filter((file) => !excluded.has(file)).sort(), "SBOM input files");
      if (files) checked["sbom:osv-scanner"] = files;
    }
    for (const producer of ["inventory:osv-scanner", "inventory:trivy"] as const) {
      const files = capChecked(
        unique(packages.packages.filter((pkg) => pkg.producer === producer && !pkg.outside && !unjudgedBy(producer).has(pkg.file)).map((pkg) => pkg.file)).sort(),
        `${producer === "inventory:trivy" ? "Trivy" : "osv-scanner"} inventory lockfiles`,
      );
      if (files) checked[producer] = files;
    }

    const unpinned = unpinnedActionsNote(actionsReader.declarations);
    const notes = capSynvoyaNotes(priority, [
      ...readers.flatMap((reader) => reader.notes), ...library.notes, ...declared.notes, ...evaluation.notes,
      ...actionsReader.notes, ...(matched?.notes ?? []), ...(unpinned ? [unpinned] : []),
    ]);
    const skippedText = skipped.length ? `; ${skipped.length} input(s) skipped (${skippedSummary(skipped)})` : "";
    const sbomText = sbomSummary(input, sbom.state === "ran" ? unchecked : undefined);
    const actionsCount = actionsReader.declarations.length;
    const actionsText = actionsCount === 0 ? ""
      : actionsDb.state === "ready"
        ? `; ${actionsCount} GitHub Actions reference(s) checked against the OSV GitHub Actions database${actionsDb.db.date ? ` (${actionsDb.db.date})` : ""}`
        : `; ${actionsCount} GitHub Actions reference(s) not checked (${actionsDb.state === "failed" ? "its database could not be read" : "the OSV GitHub Actions database is not installed"})` +
          (datasetActions.size > 0 ? "; only Synvoya's own advisories for named actions were applied" : "");
    const findings = matched ? [...evaluation.findings, ...matched.findings] : evaluation.findings;
    const note =
      `Dataset ${dataset.version} (${dataset.date}): ${parsed.length} declaration file(s) read, ` +
      `${packages.packages.length} locked package(s) checked${sbomText}${actionsText}${skippedText}.`;
    const actionsSignature = actionsDb.state === "ready" ? actionsDb.db.signature : undefined;
    return {
      findings,
      info: {
        engine: "synvoya",
        version: dataset.version,
        available: true,
        ran: true,
        finding_count: findings.length,
        duration_ms: Date.now() - started,
        note,
      },
      notes,
      warnings,
      evidence: { parsed, skipped, checked },
      // The SBOM run's arguments are constant, so its invocation is signed even when no SBOM was needed.
      componentSignatures: {
        ...synvoyaStaticComponentSignatures(loaded.digest),
        [OSV_SBOM_INVOCATION_COMPONENT]: osvSbomInvocationSignature(),
        // The Actions database is signed only when its install record matches it: else no Actions finding can resolve.
        ...(actionsSignature ? { [osvDatabaseComponent("GitHub Actions")]: actionsSignature } : {}),
      },
      sbomFindings: sbom.state === "ran" ? sbom.findings : [],
      coverageGaps,
      ...(actions && actionsSettled.status === "fulfilled"
        ? { actionsCoverage: { evaluated: actions.evaluated, references: actionsReader.references.map(({ file, uses }) => ({ file, reference: uses })) } }
        : {}),
    };
  } catch (error) {
    // Never a silent zero: a failure is a run that did not complete, which lowers coverage.
    log.warn("synvoya scan failed", { cause: error instanceof Error ? error.message : String(error) });
    await sbomTask;
    const note = "Synvoya gap advisories did not run: an unexpected error stopped the gap layer.";
    return {
      findings: [],
      info: { engine: "synvoya", version: dataset.version, available: true, ran: false, finding_count: 0, duration_ms: Date.now() - started, note },
      notes: [],
      warnings: [note],
      evidence: { parsed: [], skipped: [], checked: {} },
      componentSignatures: {},
      sbomFindings: [],
      coverageGaps: [],
    };
  }
}
