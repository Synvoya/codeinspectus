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

import { lstat } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import type { OsvScanResult } from "../engines/osv-scanner.js";
import type { TrivyReportPackage } from "../engines/trivy.js";
import { log } from "../logger.js";
import { packageEntryLine, readLockfileLines, type LockfileLines } from "../osv/package-line.js";
import { synvoyaStaticComponentSignatures, type SynvoyaProducer } from "../provenance.js";
import type { EngineRunInfo, Finding } from "../types.js";
import { SYNVOYA_MAX_CHECKED_FILES, SYNVOYA_MAX_COVERAGE_NOTES, SYNVOYA_READER_DEADLINE_MS } from "./constants.js";
import { loadSynvoyaDataset } from "./dataset.js";
import { evaluateSynvoya, packageAdvisoryFilter, type InventoryPackage, type PackageInventory, type UpstreamDbDates } from "./evaluate.js";
import { readImageTags } from "./readers/images.js";
import { readProducts } from "./readers/products.js";
import { readRuntimePins } from "./readers/runtime.js";
import type { ReaderResult, SynvoyaDataset } from "./types.js";

export interface SynvoyaScanOptions {
  /** Dataset directory; the bundled one by default. */
  datasetDir?: string;
  /** Evaluation clock; now by default. */
  now?: Date;
  /** Shared reader deadline; SYNVOYA_READER_DEADLINE_MS by default (which the internal env override can replace). Zero or less is already expired. */
  deadlineMs?: number;
}

export interface SynvoyaScanResult {
  findings: Finding[];
  info: EngineRunInfo;
  /** Coverage notes for the scan (component `engine:synvoya`), deduplicated and capped; priority notes first. */
  notes: string[];
  /** Scan warnings: only when the layer could not run. */
  warnings: string[];
  /**
   * What the readers parsed and skipped (skips are engine-note counts, never coverage gaps), and, per
   * producer, the files it fully checked this run. Every Synvoya finding records its producer(s) as
   * `synvoya:<producer>` producer components; rescan confirms a prior finding fixed only when each of its
   * producers' sets lists its file. A reader's set holds the files it parsed completely with every
   * declaration resolvable (exact, floating or range); an inventory set holds that engine's lockfiles
   * (never one from a source outside the target). A set is omitted (so nothing it would hold can be
   * confirmed fixed) when its reader rejected, when any deadline skip occurred (all three reader sets: a
   * walk cut short cannot name every file it missed), or when it exceeds SYNVOYA_MAX_CHECKED_FILES.
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

const READER_NAMES = ["runtime", "image", "product"] as const;
const READER_PRODUCERS = ["runtime", "images", "products"] as const;

function unavailable(started: number, reason: string, version = "unknown"): SynvoyaScanResult {
  const note = `Synvoya gap advisories unavailable: ${reason}`;
  return {
    findings: [],
    info: { engine: "synvoya", version, available: false, ran: false, finding_count: 0, duration_ms: Date.now() - started, note },
    notes: [],
    warnings: [note],
    evidence: { parsed: [], skipped: [], checked: {} },
    componentSignatures: {},
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

  try {
    const scope = await readerScope(target);
    const deadlineMs = options.deadlineMs ?? SYNVOYA_READER_DEADLINE_MS;
    const controller = new AbortController();
    const timer = deadlineMs > 0 ? setTimeout(() => controller.abort(), deadlineMs) : undefined;
    timer?.unref?.();
    if (deadlineMs <= 0) controller.abort();
    let settled: Array<PromiseSettledResult<ReaderResult>>;
    try {
      const options = { signal: controller.signal, ...(scope.only !== undefined ? { only: scope.only } : {}) };
      // Settled, not all: a reader that rejects never leaves the others running or discards what they read.
      settled = await Promise.allSettled([readRuntimePins(scope.root, options), readImageTags(scope.root, dataset, options), readProducts(scope.root, options)]);
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

    const declarations = readers.flatMap((reader) => reader.declarations);
    const parsed = unique(readers.flatMap((reader) => reader.parsed)).sort();
    const skipped = readers.flatMap((reader) => reader.skipped);
    const priority = readers.flatMap((reader) => reader.priorityNotes ?? []);
    // A file target no reader reads: say so plainly; nothing about it is a checked file.
    const only = scope.only;
    if (only !== undefined && !parsed.includes(only) && !skipped.some((entry) => entry.file === only)) {
      priority.push(`Synvoya reads runtime, image and product declarations from directories; ${basename(target)} was not checked.`);
    }
    const deadlineSkips = skipped.filter((entry) => entry.reason === "deadline").length;
    if (deadlineSkips > 0) {
      priority.push(
        `Synvoya readers reached their ${Math.round(deadlineMs / 1000)} s deadline; ${deadlineSkips} file(s) or folder(s) were not read, ` +
          "so runtime, image and product declarations in them were not checked.",
      );
    }

    const [received, dates] = await Promise.all([
      inventoryReady.catch((error: unknown) => {
        log.warn("synvoya: package inventory unavailable", { cause: error instanceof Error ? error.message : String(error) });
        return { packages: [] } as PackageInventory;
      }),
      datesReady.catch(() => ({}) as UpstreamDbDates),
    ]);
    const packages = await locateInventory(target, dataset, received);
    const evaluation = evaluateSynvoya(dataset, declarations, packages, options.now ?? new Date(), dates);
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
    for (const producer of ["inventory:osv-scanner", "inventory:trivy"] as const) {
      const files = capChecked(
        unique(packages.packages.filter((pkg) => pkg.producer === producer && !pkg.outside && !unjudgedBy(producer).has(pkg.file)).map((pkg) => pkg.file)).sort(),
        `${producer === "inventory:trivy" ? "Trivy" : "osv-scanner"} inventory lockfiles`,
      );
      if (files) checked[producer] = files;
    }

    const notes = capSynvoyaNotes(priority, [...readers.flatMap((reader) => reader.notes), ...evaluation.notes]);
    const skippedText = skipped.length ? `; ${skipped.length} input(s) skipped (${skippedSummary(skipped)})` : "";
    const note =
      `Dataset ${dataset.version} (${dataset.date}): ${parsed.length} declaration file(s) read, ` +
      `${packages.packages.length} locked package(s) checked${skippedText}.`;
    return {
      findings: evaluation.findings,
      info: {
        engine: "synvoya",
        version: dataset.version,
        available: true,
        ran: true,
        finding_count: evaluation.findings.length,
        duration_ms: Date.now() - started,
        note,
      },
      notes,
      warnings: [],
      evidence: { parsed, skipped, checked },
      componentSignatures: synvoyaStaticComponentSignatures(loaded.digest),
    };
  } catch (error) {
    // Never a silent zero: a failure is a run that did not complete, which lowers coverage.
    log.warn("synvoya scan failed", { cause: error instanceof Error ? error.message : String(error) });
    const note = "Synvoya gap advisories did not run: an unexpected error stopped the gap layer.";
    return {
      findings: [],
      info: { engine: "synvoya", version: dataset.version, available: true, ran: false, finding_count: 0, duration_ms: Date.now() - started, note },
      notes: [],
      warnings: [note],
      evidence: { parsed: [], skipped: [], checked: {} },
      componentSignatures: {},
    };
  }
}
