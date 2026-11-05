/**
 * Version comparison and OSV-style range evaluation for the Synvoya gap layer.
 *
 * Every scheme is a small parser to a comparable tuple. Anything that cannot be parsed
 * in the scheme yields `undefined` ("unknown"); callers must never treat unknown as affected.
 */

import type { OsvEvent, SynvoyaAdvisory } from "./types.js";

export type VersionScheme = "semver" | "php" | "pep440" | "go" | "ruby" | "dotnet" | "java" | "maven" | "magento" | "generic";

type Token = number | string;

/** Compared as: epoch, then rel (zero-padded), then tail (lexicographic, a prefix is lower). */
interface Parsed {
  epoch: number;
  rel: number[];
  tail: Token[];
}

type Parser = (input: string) => Parsed | undefined;

/** Hostile-input bounds: longer strings and numbers beyond double precision are not comparable. */
const MAX_VERSION_LENGTH = 128;
const MAX_DIGITS = 15;

const BUILD = "(?:\\+[0-9A-Za-z.-]+)?";

function toInt(text: string | undefined): number | undefined {
  if (text === undefined || text === "") return 0;
  return text.length <= MAX_DIGITS && /^\d+$/.test(text) ? Number(text) : undefined;
}

function toInts(parts: string[]): number[] | undefined {
  const out: number[] = [];
  for (const part of parts) {
    if (part === "" || part.length > MAX_DIGITS || !/^\d+$/.test(part)) return undefined;
    out.push(Number(part));
  }
  return out;
}

/** Dot-separated identifiers where all-digit ones are numeric (semver/NuGet/Go prerelease). */
function identifiers(text: string, lower = false): Token[] | undefined {
  const out: Token[] = [];
  for (const raw of text.split(".")) {
    if (raw === "") return undefined;
    if (/^\d+$/.test(raw)) {
      const n = toInt(raw);
      if (n === undefined) return undefined;
      out.push(n);
    } else {
      out.push(lower ? raw.toLowerCase() : raw);
    }
  }
  return out;
}

/** Tail for schemes where a prerelease sorts below the release: [0, ...ids] < [1]. */
const preTail = (ids: Token[] | undefined): Token[] => (ids ? [0, ...ids] : [1]);

/** Regex match as a group accessor; a group that did not take part reads as "". */
function exec(re: RegExp, text: string): ((group: number) => string) | undefined {
  const m = re.exec(text);
  return m ? (group) => m[group] ?? "" : undefined;
}

const parseSemver: Parser = (s) => {
  const g = exec(new RegExp(`^v?(\\d+)\\.(\\d+)\\.(\\d+)(?:-([0-9A-Za-z.-]+))?${BUILD}$`), s);
  if (!g) return undefined;
  const rel = toInts([g(1), g(2), g(3)]);
  const ids = g(4) === "" ? undefined : identifiers(g(4));
  if (!rel || (g(4) !== "" && !ids)) return undefined;
  return { epoch: 0, rel, tail: preTail(ids) };
};

const PHP_RANK: Record<string, number> = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, rc: 3, pl: 5, p: 5 };
const PHP_NONE = 4;

const parsePhp: Parser = (s) => {
  const g = exec(/^v?(\d+(?:\.\d+)*)(?:[-_.+]?(dev|alpha|a|beta|b|rc|pl|p)[-_.]?(\d*))?$/i, s);
  if (!g) return undefined;
  const rel = toInts(g(1).split("."));
  const n = toInt(g(3));
  if (!rel || n === undefined) return undefined;
  return { epoch: 0, rel, tail: [PHP_RANK[g(2).toLowerCase()] ?? PHP_NONE, n] };
};

const PEP_PRE: Record<string, number> = { a: 1, alpha: 1, b: 2, beta: 2, c: 3, rc: 3, pre: 3, preview: 3 };
const PEP_NONE = 4;
const PEP_NO_DEV = Number.MAX_SAFE_INTEGER;

const parsePep440: Parser = (s) => {
  const g = exec(/^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(alpha|beta|preview|pre|rc|a|b|c)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i, s);
  if (!g) return undefined;
  const epoch = toInt(g(1));
  const rel = toInts(g(2).split("."));
  const preN = toInt(g(4));
  const hasPost = g(5) !== "" || g(6) !== "";
  const postN = toInt(g(5) || g(7));
  const hasDev = g(8) !== "";
  const devN = toInt(g(9));
  if (epoch === undefined || !rel || preN === undefined || postN === undefined || devN === undefined) return undefined;
  const hasPre = g(3) !== "";
  // A bare .devN sorts before every pre-release of the same release.
  const preRank = hasPre ? (PEP_PRE[g(3).toLowerCase()] ?? PEP_NONE) : !hasPost && hasDev ? 0 : PEP_NONE;
  return { epoch, rel, tail: [preRank, hasPre ? preN : 0, hasPost ? postN : -1, hasDev ? devN : PEP_NO_DEV] };
};

const parseGo: Parser = (s) => {
  const g = exec(new RegExp(`^(?:go|v)?(\\d+(?:\\.\\d+){0,2})(?:(alpha|beta|rc)(\\d+)|-([0-9A-Za-z.-]+))?${BUILD}$`), s);
  if (!g) return undefined;
  const rel = toInts(g(1).split("."));
  if (!rel) return undefined;
  let ids: Token[] | undefined;
  if (g(2) !== "") {
    const n = toInt(g(3));
    if (n === undefined) return undefined;
    ids = [g(2), n];
  } else if (g(4) !== "") {
    ids = identifiers(g(4));
    if (!ids) return undefined;
  }
  return { epoch: 0, rel, tail: preTail(ids) };
};

/** Gem::Version: split into numeric/alphabetic tokens; the numeric run is the release, any letters make it a prerelease from that point. */
const parseRuby: Parser = (s) => {
  if (!/^v?\d+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(s)) return undefined;
  const tokens = s.replace(/^v/, "").replace(/-/g, ".pre.").match(/\d+|[a-z]+/gi) ?? [];
  let split = 0;
  while (split < tokens.length && /^\d+$/.test(tokens[split] ?? "")) split++;
  const rel = toInts(tokens.slice(0, split));
  if (!rel) return undefined;
  const ids: Token[] = [];
  for (const part of tokens.slice(split)) {
    const id = /^\d+$/.test(part) ? toInt(part) : part.toLowerCase();
    if (id === undefined) return undefined;
    ids.push(id);
  }
  return { epoch: 0, rel, tail: preTail(ids.length > 0 ? ids : undefined) };
};

const parseDotnet: Parser = (s) => {
  const g = exec(new RegExp(`^v?(\\d+(?:\\.\\d+){0,3})(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?${BUILD}$`), s);
  if (!g) return undefined;
  const rel = toInts(g(1).split("."));
  const ids = g(2) === "" ? undefined : identifiers(g(2), true);
  if (!rel || (g(2) !== "" && !ids)) return undefined;
  return { epoch: 0, rel, tail: preTail(ids) };
};

/** JDK runtime versions only (Maven libraries use parseMaven). Only `-ea` is a pre-release; other qualifiers are not comparable. */
const parseJava: Parser = (s) => {
  const g = exec(/^(?:(\d+)u(\d+)|(\d+(?:\.\d+)*)(?:_(\d+))?)(?:-(ea))?(?:\+[0-9A-Za-z.-]+)?$/, s);
  if (!g) return undefined;
  let rel: number[] | undefined;
  if (g(1) !== "") {
    // 8u401: Java 8 update 401.
    rel = toInts([g(1), "0", "0", g(2)]);
  } else {
    rel = toInts(g(3).split("."));
    if (!rel) return undefined;
    // 1.8.0_401 is the same release: drop the legacy leading 1 and put the update in the fourth component.
    if (rel[0] === 1 && rel.length >= 2) rel = rel.slice(1);
    if (g(4) !== "") {
      const update = toInt(g(4));
      if (update === undefined) return undefined;
      while (rel.length < 3) rel.push(0);
      rel.push(update);
    }
  }
  return rel ? { epoch: 0, rel, tail: preTail(g(5) === "" ? undefined : ["ea"]) } : undefined;
};

/** Maven ComparableVersion subset: alpha < beta < milestone < rc < snapshot < release (= ga = final) < sp. */
const MAVEN_QUALIFIER: Record<string, number> = {
  alpha: -5, a: -5, beta: -4, b: -4, milestone: -3, m: -3, rc: -2, cr: -2, snapshot: -1,
  "": 0, ga: 0, final: 0, release: 0, sp: 1,
};

/**
 * Numeric '.'-separated segments are the release (missing = 0); everything after the first qualifier or '-'
 * is a list of (qualifier rank, number) pairs ended by a (0, 0) terminator, so a release outranks every
 * pre-release and trails every sp. Unknown qualifiers (e.g. "-jre") are not comparable.
 */
const parseMaven: Parser = (s) => {
  if (!/^[0-9a-z]+(?:[.-][0-9a-z]+)*$/i.test(s)) return undefined;
  const tokens = [...s.toLowerCase().matchAll(/([.-]?)(\d+|[a-z]+)/g)].map((m) => ({ sep: m[1] ?? "", text: m[2] ?? "" }));
  const rel: number[] = [];
  let i = 0;
  for (; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t || !/^\d+$/.test(t.text) || (i > 0 && t.sep !== ".")) break;
    const n = toInt(t.text);
    if (n === undefined) return undefined;
    rel.push(n);
  }
  const pairs: Array<[number, number]> = [];
  let pending: number | undefined;
  for (; i < tokens.length; i++) {
    const text = tokens[i]?.text ?? "";
    if (/^\d+$/.test(text)) {
      const n = toInt(text);
      if (n === undefined) return undefined;
      pairs.push([pending ?? 0, n]);
      pending = undefined;
    } else {
      const rank = MAVEN_QUALIFIER[text];
      if (rank === undefined) return undefined;
      if (pending !== undefined) pairs.push([pending, 0]);
      pending = rank;
    }
  }
  if (pending !== undefined) pairs.push([pending, 0]);
  while (pairs.length > 0 && pairs[pairs.length - 1]?.[0] === 0 && pairs[pairs.length - 1]?.[1] === 0) pairs.pop();
  // An interior (0, 0) pair (e.g. "1.0-final-alpha") would break the padding equivalence; do not guess.
  if (pairs.some(([rank, n]) => rank === 0 && n === 0)) return undefined;
  return { epoch: 0, rel, tail: [...pairs.flat(), 0, 0] };
};

const MAGENTO_PRE: Record<string, number> = { alpha: 0, beta: 1, rc: 2 };

/** 2.4.7 < 2.4.7-p1 < 2.4.7-p10 < 2.4.8; 2.4.8-beta1 < 2.4.8. */
const parseMagento: Parser = (s) => {
  const g = exec(/^v?(\d+(?:\.\d+)*)(?:-(?:p(\d+)|(alpha|beta|rc)(\d*)))?$/i, s);
  if (!g) return undefined;
  const rel = toInts(g(1).split("."));
  if (!rel) return undefined;
  if (g(3) !== "") {
    const n = toInt(g(4));
    if (n === undefined) return undefined;
    return { epoch: 0, rel, tail: [0, MAGENTO_PRE[g(3).toLowerCase()] ?? 0, n] };
  }
  const patch = g(2) === "" ? -1 : toInt(g(2));
  if (patch === undefined) return undefined;
  return { epoch: 0, rel, tail: [1, patch] };
};

const parseGeneric: Parser = (s) => {
  if (!/^\d+(?:\.\d+)*$/.test(s)) return undefined;
  const rel = toInts(s.split("."));
  return rel ? { epoch: 0, rel, tail: [] } : undefined;
};

const PARSERS: Record<VersionScheme, Parser> = {
  semver: parseSemver,
  php: parsePhp,
  pep440: parsePep440,
  go: parseGo,
  ruby: parseRuby,
  dotnet: parseDotnet,
  java: parseJava,
  maven: parseMaven,
  magento: parseMagento,
  generic: parseGeneric,
};

function parse(scheme: VersionScheme, input: string): Parsed | undefined {
  if (typeof input !== "string") return undefined;
  const text = input.trim();
  if (text === "" || text.length > MAX_VERSION_LENGTH) return undefined;
  return PARSERS[scheme](text);
}

function compareToken(a: Token, b: Token): number {
  if (typeof a === typeof b) return a < b ? -1 : a > b ? 1 : 0;
  return typeof a === "number" ? -1 : 1;
}

function compareParsed(a: Parsed, b: Parsed): number {
  if (a.epoch !== b.epoch) return a.epoch < b.epoch ? -1 : 1;
  const relLength = Math.max(a.rel.length, b.rel.length);
  for (let i = 0; i < relLength; i++) {
    const x = a.rel[i] ?? 0;
    const y = b.rel[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  const tailLength = Math.min(a.tail.length, b.tail.length);
  for (let i = 0; i < tailLength; i++) {
    const x = a.tail[i];
    const y = b.tail[i];
    if (x === undefined || y === undefined) continue;
    const c = compareToken(x, y);
    if (c !== 0) return c;
  }
  return a.tail.length === b.tail.length ? 0 : a.tail.length < b.tail.length ? -1 : 1;
}

/** -1 / 0 / 1, or undefined when either side is not a valid version in the scheme. */
export function compareVersions(scheme: VersionScheme, a: string, b: string): number | undefined {
  const pa = parse(scheme, a);
  const pb = parse(scheme, b);
  if (!pa || !pb) return undefined;
  return compareParsed(pa, pb);
}

type EventKind = "introduced" | "fixed" | "last_affected" | "limit";
const EVENT_KINDS: readonly EventKind[] = ["introduced", "fixed", "last_affected", "limit"];

/** `at` is null for `introduced: "0"` (the beginning of time). */
interface BoundEvent {
  kind: EventKind;
  at: Parsed | null;
}

function toBoundEvents(scheme: VersionScheme, events: OsvEvent[]): BoundEvent[] | undefined {
  // An element that never opens an interval is a malformed advisory: unknown, not "not affected".
  if (!Array.isArray(events) || events.length === 0) return undefined;
  const out: BoundEvent[] = [];
  for (const event of events) {
    const keys = Object.keys(event ?? {});
    const kind = EVENT_KINDS.find((k) => k === keys[0]);
    if (keys.length !== 1 || kind === undefined) return undefined;
    const value = (event as Record<string, unknown>)[kind];
    if (typeof value !== "string") return undefined;
    if (kind === "introduced" && value.trim() === "0") {
      out.push({ kind, at: null });
      continue;
    }
    const at = parse(scheme, value);
    if (!at) return undefined;
    out.push({ kind, at });
  }
  return out.some((e) => e.kind === "introduced") ? out : undefined;
}

/**
 * Order at one version: an exclusive end (fixed, limit) closes the open interval before anything else. The
 * order of `introduced` and `last_affected` at one version depends on whether an interval is open there:
 * none open, introduced X + last_affected X is exactly X (an OSV point range); one open, last_affected X +
 * introduced X joins two contiguous intervals, so the next stays affected. The walkers group events by
 * version and apply that rule; EVENT_RANK only orders the sort.
 */
export const EVENT_RANK: Readonly<Record<string, number>> = { fixed: 0, limit: 0, introduced: 1, last_affected: 2 };

/** Ascending by version; at the same version, by EVENT_RANK. */
function compareEvents(a: BoundEvent, b: BoundEvent): number {
  if (a.at === null || b.at === null) return a.at === b.at ? 0 : a.at === null ? -1 : 1;
  const c = compareParsed(a.at, b.at);
  if (c !== 0) return c;
  return (EVENT_RANK[a.kind] ?? 0) - (EVENT_RANK[b.kind] ?? 0);
}

const sameAt = (a: BoundEvent, b: BoundEvent): boolean =>
  a.at === null || b.at === null ? a.at === b.at : compareParsed(a.at, b.at) === 0;

function inEvents(version: Parsed, events: BoundEvent[]): boolean {
  const sorted = [...events].sort(compareEvents);
  let open = false;
  let affected = false;
  for (let i = 0; i < sorted.length; ) {
    let j = i + 1;
    while (j < sorted.length && sameAt(sorted[i]!, sorted[j]!)) j++;
    const group = sorted.slice(i, j);
    i = j;
    const at = group[0]!.at;
    const c = at === null ? 1 : compareParsed(version, at);
    const has = (kind: BoundEvent["kind"]): boolean => group.some((event) => event.kind === kind);
    if (open && (has("fixed") || has("limit"))) {
      open = false;
      if (c >= 0) affected = false;
    }
    // Contiguous intervals joined at this version: still open, and this version is affected either way.
    if (open && has("last_affected") && has("introduced")) continue;
    if (!open && has("introduced")) {
      open = true;
      if (c >= 0) affected = true;
    }
    if (open && has("last_affected")) {
      open = false;
      if (c > 0) affected = false;
    }
  }
  return affected;
}

/** Same leading numeric components as the line ("22", "8.3"); missing version components count as 0. */
function onLine(scheme: VersionScheme, line: string, version: Parsed): boolean | undefined {
  // A Java runtime line is normalised like a version: "1.8" and "8" are the same line.
  const parts = scheme === "java" ? parse(scheme, line)?.rel : toInts(line.trim().split("."));
  if (!parts) return undefined;
  return parts.every((n, i) => (version.rel[i] ?? 0) === n);
}

/**
 * true  — the version is inside an introduced..fixed (exclusive) / introduced..last_affected (inclusive) interval;
 * false — it is provably outside every interval, or on a release line the advisory does not list;
 * undefined — the version, a line or an event could not be parsed and no other element proved it affected.
 */
export function isAffected(
  scheme: VersionScheme,
  version: string,
  ranges: SynvoyaAdvisory["affected"],
): boolean | undefined {
  const parsed = parse(scheme, version);
  if (!parsed) return undefined;
  let unknown = false;
  for (const range of ranges) {
    if (range.line !== undefined) {
      const matches = onLine(scheme, range.line, parsed);
      if (matches === undefined) {
        unknown = true;
        continue;
      }
      if (!matches) continue;
    }
    const events = toBoundEvents(scheme, range.events);
    if (!events) {
      unknown = true;
      continue;
    }
    if (inEvents(parsed, events)) return true;
  }
  return unknown ? undefined : false;
}

const RUNTIME_SCHEMES: Record<string, VersionScheme> = {
  node: "semver",
  php: "php",
  python: "pep440",
  ruby: "ruby",
  go: "go",
  dotnet: "dotnet",
  java: "java",
};

const PRODUCT_SCHEMES: Record<string, VersionScheme> = {
  "adobe-commerce": "magento",
  "magento-open-source": "magento",
};

const ECOSYSTEM_SCHEMES: Record<string, VersionScheme> = {
  npm: "semver",
  packagist: "php",
  pypi: "pep440",
  rubygems: "ruby",
  go: "go",
  nuget: "dotnet",
  maven: "maven",
  // Action release tags are compared as semver once their leading `v` is removed.
  "github actions": "semver",
};

export function schemeFor(target: SynvoyaAdvisory["target"]): VersionScheme {
  if (target.type === "runtime") return RUNTIME_SCHEMES[target.runtime] ?? "generic";
  if (target.type === "product") return PRODUCT_SCHEMES[target.product] ?? "generic";
  return ECOSYSTEM_SCHEMES[target.ecosystem.toLowerCase()] ?? "generic";
}
