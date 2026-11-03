/**
 * Synvoya gap-layer evaluator: what a repository declares (runtime pins, image tags, product versions)
 * and the engines' package inventory, judged against the bundled gap-advisory dataset.
 *
 * Pure and deterministic: no I/O and no clock. `now` and the upstream DB dates are parameters.
 *
 * A finding needs certainty from what is declared (design §8.4): an exact affected pin, or a floating /
 * range declaration whose every currently resolvable release line is affected or end-of-life. A floating
 * pin that can still resolve to a fixed release is an info hygiene note. Anything a version scheme cannot
 * compare is a note, never a finding: unknown is never treated as affected.
 */

import { synvoyaFindingComponents, synvoyaProducerComponent, type SynvoyaProducer } from "../provenance.js";
import type { Confidence, Finding, Severity } from "../types.js";
import { fingerprint as makeFingerprint } from "../util/hash.js";
import type { Declaration, EolEntry, OsvEvent, RuntimeId, SynvoyaAdvisory, SynvoyaDataset } from "./types.js";
import { compareVersions, EVENT_RANK, isAffected, schemeFor, type VersionScheme } from "./versions.js";

/** A resolved package the engines saw (from the osv-scanner and Trivy package lists). */
export interface InventoryPackage {
  ecosystem: string;
  name: string;
  version: string;
  /** Target-relative, forward slashes. */
  file: string;
  line: number;
  /** osv-scanner read it from a source outside the target: `file` is only a name and was never checked here. */
  outside?: true;
  /** The engine whose package list named it; the finding records it as `synvoya:<producer>`. */
  producer?: "inventory:osv-scanner" | "inventory:trivy";
}

export interface PackageInventory {
  packages: InventoryPackage[];
}

/** Upstream vulnerability-DB dates; `osv` is keyed by OSV ecosystem name. */
export interface UpstreamDbDates {
  trivy?: string;
  osv?: Record<string, string>;
}

export interface SynvoyaEvaluation {
  findings: Finding[];
  notes: string[];
  /**
   * Files (with the producer of the declaration or package) holding something a check reached but could not
   * judge: an unresolved declaration, a version a scheme could not compare, a declaration that could not be
   * resolved to release lines, or an end-of-life line with no latest release listed. A rescan cannot
   * confirm a fix from such a file. Deduplicated, in evaluation order.
   */
  unjudged: Array<{ file: string; producer?: SynvoyaProducer }>;
}

type Subject = Declaration["subject"];

const MAX_NOTES = 200;
const REBUILD_STEP = "Rebuild and redeploy every image or host that uses this runtime.";
const PROVISIONAL_SUFFIX = " (provisional — verify with the vendor)";
const DECLARED_CAVEAT = "This is the declared version, not proof of what is deployed.";
const MALWARE_STEPS = [
  "Remove the package from every manifest and lockfile and delete installed copies (dependency directories, caches and images built with it).",
  "Reinstall dependencies from a clean lockfile that does not contain the malicious version.",
  "Rotate every credential the install could reach: CI secrets, cloud, registry and API tokens, SSH keys and environment variables on every machine that installed it.",
];

const RUNTIME_LABELS: Record<RuntimeId, string> = {
  node: "Node.js",
  php: "PHP",
  python: "Python",
  ruby: "Ruby",
  go: "Go",
  dotnet: ".NET",
  java: "Java",
};

const PRODUCT_LABELS: Record<string, string> = {
  "adobe-commerce": "Adobe Commerce",
  "magento-open-source": "Magento Open Source",
  wordpress: "WordPress",
};

/** Release-cycle granularity per runtime: Node.js and Java by major, the rest by major.minor. */
const RUNTIME_CYCLE_PARTS: Record<RuntimeId, number> = {
  node: 1,
  php: 2,
  python: 2,
  ruby: 2,
  go: 2,
  dotnet: 2,
  java: 1,
};

// ---- subjects ----

function label(subject: Subject): string {
  if (subject.type === "runtime") return RUNTIME_LABELS[subject.runtime];
  if (subject.type === "package") return subject.name;
  return Object.hasOwn(PRODUCT_LABELS, subject.product) ? PRODUCT_LABELS[subject.product]! : subject.product;
}

/** The EOL-table product a subject's cycles are listed under. */
function eolProduct(subject: Subject): string | undefined {
  if (subject.type === "runtime") return subject.runtime;
  if (subject.type === "package") return undefined;
  return subject.product;
}

function subjectScheme(subject: Subject): VersionScheme {
  if (subject.type === "image-eol") return schemeFor({ type: "product", product: subject.product });
  return schemeFor(subject);
}

/** Ecosystems whose package names are case-insensitive. */
const CASE_INSENSITIVE_ECOSYSTEMS: ReadonlySet<string> = new Set(["npm", "nuget", "packagist"]);

/** npm, NuGet and Packagist names are case-insensitive; PyPI also folds `-_.` runs (PEP 503); others match exactly. */
export function packageKey(ecosystem: string, name: string): string {
  const eco = ecosystem.toLowerCase();
  const normalized =
    eco === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : CASE_INSENSITIVE_ECOSYSTEMS.has(eco) ? name.toLowerCase() : name;
  return `${eco}:${normalized}`;
}

/** The dataset's "<ecosystem>:<name>" alias map with both sides normalised like packageKey. */
function aliasTable(dataset: SynvoyaDataset): Map<string, string> {
  const split = (text: string): string | undefined => {
    const at = text.indexOf(":");
    return at > 0 ? packageKey(text.slice(0, at), text.slice(at + 1)) : undefined;
  };
  const table = new Map<string, string>();
  for (const [from, to] of Object.entries(dataset.aliases ?? {})) {
    const a = split(from);
    const b = split(to);
    if (a !== undefined && b !== undefined) table.set(a, b);
  }
  return table;
}

function subjectKey(subject: Subject, aliases: Map<string, string>): string {
  if (subject.type === "runtime") return `runtime:${subject.runtime}`;
  if (subject.type === "package") {
    const key = packageKey(subject.ecosystem, subject.name);
    return `package:${aliases.get(key) ?? key}`;
  }
  return `${subject.type}:${subject.product}`;
}

/** The advisory-index key a subject looks up: an EOL-only image also matches product advisories. */
function advisoryKey(subject: Subject, aliases: Map<string, string>): string {
  return subject.type === "image-eol" ? `product:${subject.product}` : subjectKey(subject, aliases);
}

function targetKey(target: SynvoyaAdvisory["target"], aliases: Map<string, string>): string {
  if (target.type === "runtime") return `runtime:${target.runtime}`;
  if (target.type === "product") return `product:${target.product}`;
  const key = packageKey(target.ecosystem, target.name);
  return `package:${aliases.get(key) ?? key}`;
}

/** Whether any advisory targets a package (dataset aliases applied): only then is its lockfile line worth finding. */
export function packageAdvisoryFilter(dataset: SynvoyaDataset): (ecosystem: string, name: string) => boolean {
  const aliases = aliasTable(dataset);
  const keys = new Set(dataset.advisories.filter((advisory) => advisory.target.type === "package").map((advisory) => targetKey(advisory.target, aliases)));
  return (ecosystem, name) => keys.has(subjectKey({ type: "package", ecosystem, name }, aliases));
}

// ---- cycles and dates ----

function leadingParts(subject: Subject, version: string): string[] | undefined {
  let text = version.trim().replace(/^v(?=\d)/i, "");
  const runtime = subject.type === "runtime" ? subject.runtime : undefined;
  if (runtime === "go") text = text.replace(/^go(?=\d)/, "");
  const match = /^\d+(?:\.\d+)*/.exec(text);
  if (!match) return undefined;
  let parts = match[0].split(".");
  // Java 1.8.0_401 is Java 8.
  if (runtime === "java" && parts[0] === "1" && parts.length >= 2) parts = parts.slice(1);
  return parts;
}

/**
 * The release cycle a version belongs to: a runtime's major (node, java) or major.minor (php, python,
 * ruby, go, dotnet); for a product or service, the longest cycle listed for it in the EOL table.
 * Undefined when the version is too short to name a cycle.
 */
export function cycleOf(subject: Subject, version: string, eolTable: readonly EolEntry[] = []): string | undefined {
  const parts = leadingParts(subject, version);
  if (!parts) return undefined;
  if (subject.type === "runtime") {
    const n = RUNTIME_CYCLE_PARTS[subject.runtime];
    return parts.length >= n ? parts.slice(0, n).join(".") : undefined;
  }
  const product = eolProduct(subject);
  if (product === undefined) return undefined;
  let best: string[] | undefined;
  for (const entry of eolTable) {
    if (entry.product !== product) continue;
    const cycle = entry.cycle.split(".");
    if (cycle.length <= parts.length && cycle.every((part, i) => part === parts[i]) && (!best || cycle.length > best.length)) best = cycle;
  }
  return best?.join(".");
}

/** Milliseconds for YYYY-MM-DD (UTC midnight) or a full ISO timestamp; NaN when unreadable. */
function parseDate(text: string | undefined): number {
  if (typeof text !== "string") return Number.NaN;
  return Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(text) ? `${text}T00:00:00Z` : text);
}

function isPast(date: string, now: Date): boolean {
  const at = parseDate(date);
  return !Number.isNaN(at) && at < now.getTime();
}

/** EOL-table entry of the cycle an exact version is on. */
function eolEntryFor(subject: Subject, version: string, table: readonly EolEntry[]): EolEntry | undefined {
  const product = eolProduct(subject);
  const cycle = cycleOf(subject, version, table);
  if (product === undefined || cycle === undefined) return undefined;
  return table.find((entry) => entry.product === product && (subject.type === "runtime" ? cycleOf(subject, entry.cycle) : entry.cycle) === cycle);
}

/**
 * `covered` entries run only while the covering engine's local DB is older than `covered_since`
 * (PRD §9.1 rule 2). An unknown or unreadable date counts as stale: the upstream engine may not have run,
 * and an upstream duplicate is folded into the upstream finding by the scan's enrichment step.
 */
function shouldRun(advisory: SynvoyaAdvisory, dates: UpstreamDbDates): boolean {
  if (advisory.status !== "covered") return true;
  const since = parseDate(advisory.covered_since);
  if (Number.isNaN(since)) return true;
  let db: string | undefined;
  if (advisory.covered_by === "trivy") db = dates.trivy;
  else if (advisory.covered_by === "osv-scanner" && advisory.target.type === "package") {
    const ecosystem = advisory.target.ecosystem.toLowerCase();
    for (const [name, date] of Object.entries(dates.osv ?? {})) if (name.toLowerCase() === ecosystem) db = date;
  }
  const at = parseDate(db);
  return Number.isNaN(at) || at < since;
}

// ---- version spans ----

class Incomparable extends Error {}

/** A version bound; `null` in a span is unbounded. */
interface Bound {
  v: string;
  inclusive: boolean;
}

interface Span {
  lo: Bound | null;
  hi: Bound | null;
}

const NUMERIC = /^\d{1,15}(?:\.\d{1,15})*$/;

function cmp(scheme: VersionScheme, a: string, b: string): number {
  const c = compareVersions(scheme, a, b);
  if (c === undefined) throw new Incomparable();
  return c;
}

/** Lower bound `a` starts at or before lower bound `b`. */
function loAtOrBefore(scheme: VersionScheme, a: Bound | null, b: Bound | null): boolean {
  if (a === null) return true;
  if (b === null) return false;
  const c = cmp(scheme, a.v, b.v);
  return c < 0 || (c === 0 && (a.inclusive || !b.inclusive));
}

/** Upper bound `a` ends at or after upper bound `b`. */
function hiAtOrAfter(scheme: VersionScheme, a: Bound | null, b: Bound | null): boolean {
  if (a === null) return true;
  if (b === null) return false;
  const c = cmp(scheme, a.v, b.v);
  return c > 0 || (c === 0 && (a.inclusive || !b.inclusive));
}

function intersect(scheme: VersionScheme, a: Span, b: Span): Span | undefined {
  const lo = loAtOrBefore(scheme, a.lo, b.lo) ? b.lo : a.lo;
  const hi = hiAtOrAfter(scheme, a.hi, b.hi) ? b.hi : a.hi;
  if (lo && hi) {
    const c = cmp(scheme, lo.v, hi.v);
    if (c > 0 || (c === 0 && !(lo.inclusive && hi.inclusive))) return undefined;
  }
  return { lo, hi };
}

const contains = (scheme: VersionScheme, outer: Span, inner: Span): boolean =>
  loAtOrBefore(scheme, outer.lo, inner.lo) && hiAtOrAfter(scheme, outer.hi, inner.hi);

/** "22" → "22.0.0": every scheme reads three components; semver needs them. */
function pad(version: string): string {
  if (!NUMERIC.test(version)) return version;
  const parts = version.split(".");
  while (parts.length < 3) parts.push("0");
  return parts.join(".");
}

/** "22" → "23.0.0", "8.3" → "8.4.0": the first release after the line. */
function bump(parts: string[]): string {
  const out = parts.map(Number);
  out[out.length - 1] = (out[out.length - 1] ?? 0) + 1;
  return pad(out.join("."));
}

/** Every version on a release line: [line.0, next line). */
function lineSpan(line: string): Span | undefined {
  if (!NUMERIC.test(line)) return undefined;
  return { lo: { v: pad(line), inclusive: true }, hi: { v: bump(line.split(".")), inclusive: false } };
}

interface ElementSpan {
  span: Span;
  /** The element has no `fixed` or `limit` event: the vendor ships no patch for it. */
  fixless: boolean;
}

/**
 * Whether the vendor patches this range: a `fixed` release, or a `limit` where the fix is a hotfix that
 * never changes the version string. Only a range with neither proves exposure from the version alone.
 */
function hasPatch(element: SynvoyaAdvisory["affected"][number]): boolean {
  return element.events.some((event) => "fixed" in event || "limit" in event);
}

/** One affected element as spans, mirroring isAffected's event walk and line filter. */
function elementSpans(scheme: VersionScheme, element: SynvoyaAdvisory["affected"][number]): ElementSpan[] {
  type Kind = "introduced" | "fixed" | "last_affected" | "limit";
  const events: Array<{ kind: Kind; at: string | null }> = [];
  for (const event of element.events as Array<OsvEvent & Record<string, unknown>>) {
    const entries = Object.entries(event ?? {});
    const [kind, value] = entries[0] ?? [];
    if (entries.length !== 1 || typeof value !== "string" || !["introduced", "fixed", "last_affected", "limit"].includes(kind ?? "")) {
      throw new Incomparable();
    }
    const at = kind === "introduced" && value.trim() === "0" ? null : value;
    if (at !== null) cmp(scheme, at, at);
    events.push({ kind: kind as Kind, at });
  }
  if (!events.some((e) => e.kind === "introduced")) throw new Incomparable();
  events.sort((a, b) => {
    if (a.at === null || b.at === null) return a.at === b.at ? 0 : a.at === null ? -1 : 1;
    return cmp(scheme, a.at, b.at) || (EVENT_RANK[a.kind] ?? 0) - (EVENT_RANK[b.kind] ?? 0);
  });
  // Grouped by version exactly like isAffected's walk (see EVENT_RANK in versions.ts).
  const spans: Span[] = [];
  let start: Bound | null | undefined;
  for (let i = 0; i < events.length; ) {
    let j = i + 1;
    const at = events[i]!.at;
    while (j < events.length && (at === null ? events[j]!.at === null : events[j]!.at !== null && cmp(scheme, at, events[j]!.at!) === 0)) j++;
    const kinds = new Set(events.slice(i, j).map((event) => event.kind));
    i = j;
    if (start !== undefined && at !== null && (kinds.has("fixed") || kinds.has("limit"))) {
      spans.push({ lo: start, hi: { v: at, inclusive: false } });
      start = undefined;
    }
    if (start !== undefined && kinds.has("last_affected") && kinds.has("introduced")) continue;
    if (start === undefined && kinds.has("introduced")) start = at === null ? null : { v: at, inclusive: true };
    if (start !== undefined && at !== null && kinds.has("last_affected")) {
      spans.push({ lo: start, hi: { v: at, inclusive: true } });
      start = undefined;
    }
  }
  if (start !== undefined) spans.push({ lo: start, hi: null });
  let clipped = spans;
  if (element.line !== undefined) {
    const line = lineSpan(element.line);
    if (!line) throw new Incomparable();
    clipped = spans.flatMap((span) => intersect(scheme, span, line) ?? []);
  }
  const fixless = !hasPatch(element);
  return clipped.map((span) => ({ span, fixless }));
}

/**
 * The span walk's answer for one version (true / false, or undefined when anything is incomparable).
 * Exported so a test can hold it equal to `isAffected` on the same inputs.
 */
export function spansAffect(scheme: VersionScheme, version: string, affected: SynvoyaAdvisory["affected"]): boolean | undefined {
  if (compareVersions(scheme, version, version) === undefined) return undefined;
  let unknown = false;
  for (const element of affected) {
    let spans: ElementSpan[];
    try {
      spans = elementSpans(scheme, element);
    } catch (error) {
      if (!(error instanceof Incomparable)) throw error;
      unknown = true;
      continue;
    }
    if (spans.some((s) => pointIn(scheme, version, s.span))) return true;
  }
  return unknown ? undefined : false;
}

/** Composer `~`, Ruby `~>` and PEP 440 `~=`: drop the last component and bump the new last. */
function pessimisticUpper(parts: string[]): string {
  return bump(parts.length > 1 ? parts.slice(0, -1) : parts);
}

/**
 * One comparator as a span. Where ecosystems disagree on a partial version (`>8.1`, `<=8.1`) the wider
 * reading is used: a wider set can only turn a finding into a note, never the reverse.
 */
function comparatorSpan(scheme: VersionScheme, token: string): Span | "ignore" | undefined {
  const match = /^(>=|<=|~>|~=|==|!=|>|<|=|\^|~)?v?(.+)$/.exec(token);
  if (!match) return undefined;
  const op = match[1] ?? "";
  const raw = match[2]!;
  if (op === "!=") return "ignore";
  if (/^[xX*]$/.test(raw)) return { lo: null, hi: null };
  const stripped = raw.replace(/(?:\.[xX*])+$/, "");
  const numeric = NUMERIC.test(stripped);
  if (!numeric && compareVersions(scheme, stripped, stripped) === undefined) return undefined;
  const parts = stripped.split(".");
  const partial = numeric && (stripped !== raw || parts.length < 3);
  const full = pad(stripped);
  const at = (inclusive: boolean): Bound => ({ v: full, inclusive });
  switch (op) {
    case ">=":
      return { lo: at(true), hi: null };
    case ">":
      return { lo: at(false), hi: null };
    case "<":
      return { lo: null, hi: at(false) };
    case "<=":
      return { lo: null, hi: partial ? { v: bump(parts), inclusive: false } : at(true) };
    case "":
    case "=":
    case "==":
      return partial ? lineSpan(stripped) : { lo: at(true), hi: at(true) };
    case "^": {
      if (!numeric) return undefined;
      let i = parts.findIndex((part) => Number(part) !== 0);
      if (i === -1) i = parts.length - 1;
      return { lo: at(true), hi: { v: bump(parts.slice(0, i + 1)), inclusive: false } };
    }
    case "~":
      if (!numeric) return undefined;
      if (scheme === "php" || scheme === "ruby") return { lo: at(true), hi: { v: pessimisticUpper(parts), inclusive: false } };
      return { lo: at(true), hi: { v: bump(parts.slice(0, Math.min(parts.length, 2))), inclusive: false } };
    case "~>":
    case "~=":
      if (!numeric) return undefined;
      return { lo: at(true), hi: { v: pessimisticUpper(parts), inclusive: false } };
    default:
      return undefined;
  }
}

/** A floating or range declaration as alternative spans (`||` / `|` separated); undefined when unreadable. */
function declaredSpans(scheme: VersionScheme, spec: string, precision: Declaration["precision"]): Span[] | undefined {
  if (precision === "floating") {
    const line = spec.trim().replace(/^v(?=\d)/i, "").replace(/(?:\.[xX*])+$/, "");
    const span = lineSpan(line);
    return span ? [span] : undefined;
  }
  if (spec.length > 256) return undefined;
  const spans: Span[] = [];
  for (const alternative of spec.split(/\|\|?/)) {
    const text = alternative.trim();
    if (text === "") return undefined;
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
    const tokens = hyphen
      ? [`>=${hyphen[1]}`, `<=${hyphen[2]}`]
      : text.replace(/(>=|<=|~>|~=|==|!=|>|<|=|\^|~)\s+/g, "$1").split(/[\s,]+/).filter(Boolean);
    let span: Span | undefined = { lo: null, hi: null };
    for (const token of tokens) {
      const next = comparatorSpan(scheme, token);
      if (next === undefined) return undefined;
      if (next === "ignore") continue;
      span = intersect(scheme, span, next);
      if (!span) break;
    }
    if (span) spans.push(span);
  }
  return spans.length > 0 ? spans : undefined;
}

interface Segment {
  span: Span;
  /** The EOL-table cycle this part of the declaration falls in, when the table lists one. */
  cycle?: EolEntry;
}

/**
 * The currently resolvable release lines of a floating / range declaration: each alternative cut by the
 * EOL-table cycles it meets, plus a cycle-less remainder segment for every part no listed cycle covers
 * (below the oldest, between listed cycles, above the newest). A remainder is never end-of-life: the
 * bundled table cannot know lines released after it shipped. An alternative that meets no listed cycle
 * is one segment of its own when it is bounded on both sides; an unbounded one cannot be enumerated
 * (undefined). Throws Incomparable.
 */
function resolvableSegments(scheme: VersionScheme, spans: Span[], cycles: readonly EolEntry[]): Segment[] | undefined {
  const lines = cycles
    .flatMap((cycle) => {
      const line = lineSpan(cycle.cycle);
      return line ? [{ cycle, line }] : [];
    })
    .sort((a, b) => cmp(scheme, a.line.lo!.v, b.line.lo!.v));
  const out: Segment[] = [];
  for (const span of spans) {
    const listed: Segment[] = [];
    const remainder: Span[] = [];
    // Walk the listed lines in order; `cursor` is the lower bound of the part not yet covered.
    let cursor: Bound | null = span.lo;
    for (const { cycle, line } of lines) {
      const part = intersect(scheme, span, line);
      if (!part) continue;
      listed.push({ span: part, cycle });
      const gap = intersect(scheme, span, { lo: cursor, hi: { v: line.lo!.v, inclusive: false } });
      if (gap) remainder.push(gap);
      const after: Bound = { v: line.hi!.v, inclusive: true };
      if (loAtOrBefore(scheme, cursor, after)) cursor = after;
    }
    if (listed.length === 0) {
      if (!span.lo || !span.hi) return undefined;
      out.push({ span });
      continue;
    }
    const tail = intersect(scheme, span, { lo: cursor, hi: null });
    if (tail) remainder.push(tail);
    out.push(...listed, ...remainder.map((part) => ({ span: part })));
  }
  return out.length > 0 ? out : undefined;
}

type Judgement =
  | { verdict: "finding"; eolFloor: boolean; proven: boolean; missingLatest: string[] }
  | { verdict: "note"; fixed: string[]; missingLatest: string[] }
  | { verdict: "none"; missingLatest: string[] };

function pointIn(scheme: VersionScheme, version: string, span: Span): boolean {
  try {
    return intersect(scheme, span, { lo: { v: version, inclusive: true }, hi: { v: version, inclusive: true } }) !== undefined;
  } catch {
    return false;
  }
}

function sortVersions(scheme: VersionScheme, versions: string[]): string[] {
  const unique = [...new Set(versions)];
  try {
    return unique.sort((a, b) => cmp(scheme, a, b));
  } catch {
    return unique.sort();
  }
}

/**
 * Floating / range: a finding only when the advisory reaches at least one resolvable line and every
 * resolvable line is certain to be affected (design §8.4): wholly inside an affected span (no fix on the
 * line, rule b), or end-of-life with its last release (EOL-table `latest`) affected. An end-of-life line
 * whose last release carries the fix is the EOL finding's job alone; one with no `latest` listed cannot be
 * judged (reported in `missingLatest`). Otherwise, when the advisory reaches a supported line, a hygiene
 * note naming the fixed release on those lines. Throws Incomparable.
 */
function judgeSegments(scheme: VersionScheme, advisory: SynvoyaAdvisory, segments: Segment[], now: Date): Judgement {
  const spans = advisory.affected.flatMap((element) => elementSpans(scheme, element));
  const missingLatest: string[] = [];
  let touched = false;
  let allBad = true;
  let allEol = true;
  let proven = true;
  for (const segment of segments) {
    const eol = segment.cycle !== undefined && isPast(segment.cycle.eol, now);
    const cover = spans.filter((s) => contains(scheme, s.span, segment.span));
    const reaches = cover.length > 0 || spans.some((s) => intersect(scheme, s.span, segment.span) !== undefined);
    if (reaches) touched = true;
    if (!eol) allEol = false;
    let bad: boolean;
    if (advisory.kind === "eol" && segment.cycle !== undefined) {
      // An eol-kind entry waits for the table's date on a listed cycle; elsewhere its ranges decide.
      bad = eol && reaches;
    } else if (cover.length > 0) {
      bad = true;
    } else if (eol && reaches && segment.cycle !== undefined) {
      const latest = segment.cycle.latest;
      if (latest === undefined) {
        missingLatest.push(segment.cycle.cycle);
        bad = false;
      } else {
        bad = pointIn(scheme, latest, segment.span) && spans.some((s) => pointIn(scheme, latest, s.span));
      }
    } else {
      bad = false;
    }
    if (!bad) allBad = false;
    if (!eol && !cover.some((s) => s.fixless)) proven = false;
  }
  if (!touched) return { verdict: "none", missingLatest };
  if (allBad) return { verdict: "finding", eolFloor: allEol, proven, missingLatest };
  // An eol-kind entry has no hygiene advice; an all-EOL declaration already has its EOL finding.
  if (advisory.kind === "eol" || allEol) return { verdict: "none", missingLatest };
  const fixedEvents = advisory.affected.flatMap((element) => element.events.flatMap((event) => ("fixed" in event ? [event.fixed] : [])));
  const onLines = (versions: string[]): string[] => versions.filter((v) => segments.some((segment) => pointIn(scheme, v, segment.span)));
  // Prefer fixed releases on the declared lines; fall back to the entry's list.
  const candidates = [onLines(fixedEvents), onLines(advisory.fixed), advisory.fixed];
  return { verdict: "note", fixed: sortVersions(scheme, candidates.find((list) => list.length > 0) ?? []), missingLatest };
}

// ---- findings ----

interface Origin {
  subject: Subject;
  key: string;
  /** What is shown: the declared spec, or the locked package version. */
  version: string;
  file: string;
  line: number;
  source: string;
  /** Inventory packages are locked, not declared. */
  locked: boolean;
  /** A runtime or container image: every fix needs a rebuild and redeploy. */
  rebuild: boolean;
  producer?: SynvoyaProducer;
}

function hotfixName(advisory: SynvoyaAdvisory): string {
  return (
    advisory.aliases.find((alias) => /^VULN-\d+$/i.test(alias)) ??
    advisory.aliases.find((alias) => /^APSB\d{2}-\d+$/i.test(alias)) ??
    advisory.aliases.find((alias) => /^WSO2-\d{4}-\d+$/i.test(alias)) ??
    `the vendor hotfix for ${advisory.aliases[0] ?? advisory.id}`
  );
}

function cweFor(advisory: SynvoyaAdvisory): string[] {
  if (advisory.kind === "malware") return ["CWE-506"];
  if (advisory.kind === "eol" || advisory.kind === "runtime") return ["CWE-1104"];
  return ["CWE-1395"];
}

const unique = (items: string[]): string[] => [...new Set(items)];

/** Repository-controlled text in titles, messages and notes is clamped. */
const MAX_SHOWN_CHARS = 64;
const clip = (text: string): string => (text.length > MAX_SHOWN_CHARS ? `${text.slice(0, MAX_SHOWN_CHARS)}…` : text);

function baseFinding(ruleId: string, origin: Origin): Pick<Finding, "id" | "fingerprint" | "engine" | "engines" | "engine_family" | "rule_id" | "location" | "frameworks" | "producer_components" | "finding_kind"> {
  const fingerprint = makeFingerprint(["synvoya", ruleId, origin.file, origin.key]);
  return {
    id: fingerprint,
    fingerprint,
    engine: "synvoya",
    engines: ["synvoya"],
    engine_family: "synvoya",
    rule_id: ruleId,
    location: { file: origin.file, start_line: origin.line, end_line: origin.line, snippet: origin.version },
    frameworks: [],
    producer_components: [...synvoyaFindingComponents(), ...(origin.producer ? [synvoyaProducerComponent(origin.producer)] : [])],
    finding_kind: "vulnerability",
  };
}

function advisoryFinding(
  advisory: SynvoyaAdvisory,
  origin: Origin,
  tier: { confidence: Confidence; basis: "exact" | "line" | "eol-floor"; proven: boolean },
): Finding {
  const subjectLabel = label(origin.subject);
  const verify = advisory.product_rule === "verify-hotfix" && !tier.proven;
  const malware = advisory.kind === "malware";
  const severity: Severity = malware ? "critical" : verify ? "medium" : advisory.severity;
  const confidence: Confidence = advisory.provisional ? "low" : tier.confidence;
  const pkg = origin.subject.type === "package" ? origin.subject : undefined;
  const fixedText = advisory.fixed.join(" or ");
  const exploited = advisory.exploited ? " and it is known to be exploited" : "";

  let title: string;
  if (verify) title = `Verify ${hotfixName(advisory)} is applied to ${subjectLabel} ${clip(origin.version)} (declared in ${origin.file})`;
  else if (origin.locked) title = `${advisory.title} (${subjectLabel}@${clip(origin.version)})`;
  else title = `${advisory.title} (${subjectLabel} ${clip(origin.version)} declared in ${origin.file})`;
  if (advisory.provisional) title += PROVISIONAL_SUFFIX;

  const where = `${origin.file}:${origin.line}`;
  let message: string;
  if (origin.locked) {
    message = malware
      ? `${where} locks ${subjectLabel}@${clip(origin.version)}, which ${advisory.id} lists as malicious. Installing it may already have run its code.`
      : `${where} locks ${subjectLabel}@${clip(origin.version)}. ${advisory.id} lists that version as affected${exploited}. This proves dependency presence, not vulnerable-code reachability.`;
  } else {
    const head = `${where} declares ${subjectLabel} ${clip(origin.version)} (${origin.source}).`;
    const why =
      tier.basis === "eol-floor"
        ? `Every release line it can resolve to is end-of-life and ${advisory.id} affects the newest release on it${exploited}.`
        : tier.basis === "exact"
          ? `${advisory.id} lists the declared version as affected${exploited}.`
          : `Every release it can resolve to today is inside ${advisory.id}'s affected range${exploited}.`;
    const hotfix = verify ? " The vendor fix is a hotfix that does not change the version string, so the declared version alone cannot show whether it is applied." : "";
    message = `${head} ${why}${hotfix} ${DECLARED_CAVEAT}`;
  }

  let summary: string;
  if (malware) summary = `Remove ${subjectLabel}, reinstall from a clean lockfile and rotate every credential the install could reach.`;
  else if (verify) summary = `Verify ${hotfixName(advisory)} is applied${fixedText ? `, or upgrade to ${fixedText}` : ""}.`;
  else if (advisory.no_fix_available) summary = pkg ? `No fixed release of ${pkg.name} exists; replace or remove the package.` : `No fixed release of ${subjectLabel} exists; move off it.`;
  else if (pkg) summary = fixedText ? `Upgrade ${pkg.name} to ${fixedText} or later, or remove the package.` : `Upgrade ${pkg.name} to a version not listed as affected, or remove the package.`;
  else summary = fixedText ? `Upgrade the declared ${subjectLabel} to ${fixedText} or later.` : `Move the declared ${subjectLabel} to a release that is not affected.`;
  if (origin.rebuild && !malware) summary = `${summary.replace(/\.$/, "")}, then rebuild and redeploy.`;

  const aliases = unique(advisory.aliases).sort();
  return {
    ...baseFinding(advisory.id, origin),
    title,
    severity,
    ...(aliases.length > 0 ? { vulnerability_aliases: aliases } : {}),
    cwe: cweFor(advisory),
    owasp_web: [malware ? "A08:2021" : "A06:2021"],
    message,
    remediation: {
      summary,
      steps: unique([...advisory.remediation_steps, ...(malware ? MALWARE_STEPS : []), ...(origin.rebuild ? [REBUILD_STEP] : [])]),
      references: unique(advisory.sources),
    },
    confidence,
    ...(pkg ? { package: { ecosystem: pkg.ecosystem, name: pkg.name, version: origin.version } } : {}),
  };
}

function eolFinding(origin: Origin, product: string, cycles: EolEntry[]): Finding {
  const subjectLabel = label(origin.subject);
  const names = cycles.map((c) => c.cycle);
  const last = cycles[cycles.length - 1]!;
  const ended = cycles.map((c) => `${c.cycle} on ${c.eol}${c.latest ? ` (last release ${c.latest})` : ""}`).join(", ");
  const summary = `Move ${subjectLabel} to a release line that still receives security fixes${origin.rebuild ? ", then rebuild and redeploy" : ""}.`;
  return {
    ...baseFinding(`SYN-EOL-${product}-${last.cycle}`, origin),
    title: `${subjectLabel} ${names.join("/")} is end-of-life (declared in ${origin.file})`,
    severity: origin.subject.type === "runtime" ? "high" : "medium",
    cwe: ["CWE-1104"],
    owasp_web: ["A06:2021"],
    message:
      `${origin.file}:${origin.line} declares ${subjectLabel} ${clip(origin.version)} (${origin.source}). ` +
      `${subjectLabel} ${ended.includes(",") ? "lines" : "line"} ${ended} reached end-of-life and no longer receive${cycles.length > 1 ? "" : "s"} security fixes. ${DECLARED_CAVEAT}`,
    remediation: {
      summary,
      steps: unique([summary, ...(origin.rebuild ? [REBUILD_STEP] : [])]),
      references: unique(cycles.map((c) => c.source)),
    },
    confidence: "high",
  };
}

// ---- evaluation ----

function isImageSource(source: string): boolean {
  return /\bFROM\b/.test(source) || /\bimage\b/i.test(source);
}

/**
 * Judge every declaration and inventory package against the dataset. One finding per (rule, file,
 * subject): when several declarations in a file hit the same rule, the first by line is kept.
 */
export function evaluateSynvoya(
  dataset: SynvoyaDataset,
  declarations: Declaration[],
  inventory: PackageInventory,
  now: Date,
  upstreamDbDates: UpstreamDbDates,
): SynvoyaEvaluation {
  const aliases = aliasTable(dataset);
  const index = new Map<string, SynvoyaAdvisory[]>();
  for (const advisory of dataset.advisories) {
    if (!shouldRun(advisory, upstreamDbDates)) continue;
    const key = targetKey(advisory.target, aliases);
    index.set(key, [...(index.get(key) ?? []), advisory]);
  }
  const table = dataset.eol ?? [];
  const found = new Map<string, Finding>();
  const notes = new Set<string>();
  const unjudged = new Map<string, { file: string; producer?: SynvoyaProducer }>();
  const unjudge = (file: string, producer: SynvoyaProducer | undefined): void => {
    const key = `${producer ?? ""}\0${file}`;
    if (!unjudged.has(key)) unjudged.set(key, { file, ...(producer ? { producer } : {}) });
  };
  const keep = (finding: Finding, origin: Origin): void => {
    const key = `${finding.rule_id}\0${origin.file}\0${origin.key}`;
    const kept = found.get(key);
    if (!kept) found.set(key, finding);
    // The same finding from another producer: both must re-check it before a rescan can call it fixed.
    else kept.producer_components = [...new Set([...(kept.producer_components ?? []), ...(finding.producer_components ?? [])])];
  };

  const ordered = [...declarations].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  for (const decl of ordered) {
    const subjectLabel = label(decl.subject);
    const advisories = index.get(advisoryKey(decl.subject, aliases)) ?? [];
    const product = eolProduct(decl.subject);
    const cycles = product === undefined ? [] : table.filter((entry) => entry.product === product);
    const where = `${decl.file}:${decl.line}`;
    const origin: Origin = {
      subject: decl.subject,
      key: subjectKey(decl.subject, aliases),
      version: decl.precision === "exact" ? (decl.resolved ?? decl.spec) : decl.spec,
      file: decl.file,
      line: decl.line,
      source: decl.source,
      locked: false,
      rebuild: decl.subject.type === "runtime" || decl.subject.type === "image-eol" || isImageSource(decl.source),
      ...(decl.producer ? { producer: decl.producer } : {}),
    };

    if (decl.precision === "unresolved") {
      unjudge(decl.file, decl.producer);
      if (!decl.noted && (advisories.length > 0 || cycles.length > 0)) {
        notes.add(`${where}: ${decl.source} declares ${subjectLabel} "${clip(decl.spec)}", which is not a resolvable version; Synvoya could not check it against its ${subjectLabel} advisories or end-of-life dates.`);
      }
      continue;
    }

    const scheme = subjectScheme(decl.subject);
    let eolAdvisoryHit = false;

    if (decl.precision === "exact") {
      const version = origin.version;
      for (const advisory of advisories) {
        if (advisory.kind === "eol") {
          const entry = eolEntryFor(decl.subject, version, table);
          if (entry && !isPast(entry.eol, now)) continue;
        }
        const affected = isAffected(schemeFor(advisory.target), version, advisory.affected);
        if (affected === undefined) {
          unjudge(decl.file, decl.producer);
          notes.add(`${where}: could not compare ${clip(version)} for ${subjectLabel} against ${advisory.id}; no finding is possible for it.`);
          continue;
        }
        if (!affected) continue;
        const proven = advisory.affected.some(
          (element) => !hasPatch(element) && isAffected(schemeFor(advisory.target), version, [element]) === true,
        );
        keep(advisoryFinding(advisory, origin, { confidence: "high", basis: "exact", proven }), origin);
        if (advisory.kind === "eol") eolAdvisoryHit = true;
      }
      const entry = product === undefined ? undefined : eolEntryFor(decl.subject, version, table);
      if (product !== undefined && entry && isPast(entry.eol, now) && !eolAdvisoryHit) {
        // The cycle comes from the leading digits; a finding still needs a version the scheme can read.
        if (compareVersions(scheme, version, version) === undefined) {
          unjudge(decl.file, decl.producer);
          notes.add(`${where}: could not compare ${clip(version)} for ${subjectLabel} against the end-of-life table; no finding is possible for it.`);
        } else {
          keep(eolFinding(origin, product, [entry]), origin);
        }
      }
      continue;
    }

    // floating / range
    let segments: Segment[] | undefined;
    try {
      const spans = declaredSpans(scheme, decl.spec, decl.precision);
      segments = spans && resolvableSegments(scheme, spans, cycles);
    } catch (error) {
      if (!(error instanceof Incomparable)) throw error;
      segments = undefined;
    }
    if (!segments) {
      if (advisories.length > 0 || cycles.length > 0) {
        unjudge(decl.file, decl.producer);
        notes.add(`${where}: could not resolve ${subjectLabel} "${clip(decl.spec)}" to release lines; no finding is possible for it.`);
      }
      continue;
    }
    for (const advisory of advisories) {
      let judgement: Judgement;
      try {
        judgement = judgeSegments(schemeFor(advisory.target), advisory, segments, now);
      } catch (error) {
        if (!(error instanceof Incomparable)) throw error;
        unjudge(decl.file, decl.producer);
        notes.add(`${where}: could not compare ${clip(decl.spec)} for ${subjectLabel} against ${advisory.id}; no finding is possible for it.`);
        continue;
      }
      if (judgement.missingLatest.length > 0) unjudge(decl.file, decl.producer);
      for (const cycle of judgement.missingLatest) {
        notes.add(`${where}: ${subjectLabel} ${cycle} is end-of-life and the end-of-life table lists no latest release for it, so Synvoya could not check whether ${advisory.id} affects the release ${clip(decl.spec)} resolves to; no finding is possible for it.`);
      }
      if (judgement.verdict === "finding") {
        const tier = judgement.eolFloor
          ? { confidence: "high" as const, basis: "eol-floor" as const, proven: judgement.proven }
          : { confidence: "medium" as const, basis: "line" as const, proven: judgement.proven };
        keep(advisoryFinding(advisory, origin, tier), origin);
        if (advisory.kind === "eol") eolAdvisoryHit = true;
      } else if (judgement.verdict === "note") {
        const target = judgement.fixed.length > 0 ? `≥ ${judgement.fixed.join(" or ")}` : "a release outside the affected range";
        notes.add(`${where}: ${decl.source} declares ${subjectLabel} ${clip(decl.spec)}, which can still resolve to a release affected by ${advisory.id}; pin ${subjectLabel} to ${target}.`);
      }
    }
    if (product !== undefined && !eolAdvisoryHit && segments.every((s) => s.cycle !== undefined && isPast(s.cycle.eol, now))) {
      const ended = [...new Map(segments.map((s) => [s.cycle!.cycle, s.cycle!])).values()];
      keep(eolFinding(origin, product, sortCycles(scheme, ended)), origin);
    }
  }

  const packages = [...inventory.packages].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  for (const pkg of packages) {
    const subject: Subject = { type: "package", ecosystem: pkg.ecosystem, name: pkg.name };
    const key = subjectKey(subject, aliases);
    const advisories = index.get(key) ?? [];
    const origin: Origin = {
      subject,
      key,
      version: pkg.version,
      file: pkg.file,
      line: pkg.line,
      source: pkg.file,
      locked: true,
      rebuild: false,
      ...(pkg.producer ? { producer: pkg.producer } : {}),
    };
    for (const advisory of advisories) {
      const affected = isAffected(schemeFor(advisory.target), pkg.version, advisory.affected);
      if (affected === undefined) {
        unjudge(pkg.file, pkg.producer);
        notes.add(`${pkg.file}:${pkg.line}: could not compare ${clip(pkg.version)} for ${clip(pkg.name)} against ${advisory.id}; no finding is possible for it.`);
        continue;
      }
      if (affected) keep(advisoryFinding(advisory, origin, { confidence: "high", basis: "exact", proven: true }), origin);
    }
  }

  const findings = [...found.values()].sort(
    (a, b) =>
      (a.location.file < b.location.file ? -1 : a.location.file > b.location.file ? 1 : 0) ||
      a.location.start_line - b.location.start_line ||
      (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0),
  );
  return { findings, notes: capNotes([...notes]), unjudged: [...unjudged.values()] };
}

function sortCycles(scheme: VersionScheme, cycles: EolEntry[]): EolEntry[] {
  try {
    return [...cycles].sort((a, b) => cmp(scheme, pad(a.cycle), pad(b.cycle)));
  } catch {
    return cycles;
  }
}

function capNotes(notes: string[]): string[] {
  if (notes.length <= MAX_NOTES) return notes;
  return [...notes.slice(0, MAX_NOTES - 1), `… ${notes.length - (MAX_NOTES - 1)} more`];
}
