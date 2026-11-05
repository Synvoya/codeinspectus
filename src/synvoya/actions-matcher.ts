/**
 * Synvoya's matcher for third-party GitHub Actions references (design §10.1): osv-scanner 2.7.0 rejects
 * `pkg:githubactions` purls and panics on `pkg:github` ones, so Actions are never passed to it. The
 * matcher reads the OSV "GitHub Actions" `all.zip` that setup installed (GHSA records, CC-BY-4.0) in
 * process with the bounded zip reader in src/osv/database.ts, and judges each reference:
 *
 * - an x.y.z tag (leading `v` removed) by the record's ECOSYSTEM/SEMVER ranges and versions list;
 * - a major or major.minor tag (`v4`) by the M1 floating rule: a finding only when every release the tag
 *   can resolve to is affected, otherwise a "pin to ≥ X" note;
 * - a tag the record lists verbatim in `versions` (e.g. a compromised `v1`) as affected;
 * - a full commit SHA as affected only when a record lists that commit (GIT `introduced`/`last_affected`
 *   events or `versions`), as clean for that record when it is the record's fixing commit, otherwise a note;
 * - a branch or any other ref, of an action with advisories, as a note.
 *
 * An action with no record is clean whatever its ref. Unknown is never affected: anything that cannot be
 * compared is a note, the reference stays in the `actions-unchecked` gap, and its file is not re-checked.
 *
 * The bundled Synvoya dataset's own GitHub Actions advisories (`datasetActionAdvisories`) are judged by the same
 * rules, with or without the installed database. Where the database's record for the same action names the same
 * advisory (a shared id or alias) and both report the reference, the database's finding stands unchanged and gains
 * Synvoya's fix steps; the dataset's duplicate is dropped. Pure apart from loadActionsDb; no network, ever.
 */

import { lstat } from "node:fs/promises";

import { osvDbZipPath, readOsvDbRecord, readZipArchive, type OsvDbRecord, type ZipReadLimits } from "../osv/database.js";
import { synvoyaActionsDatasetFindingComponents, synvoyaActionsFindingComponents } from "../provenance.js";
import type { Finding, Severity } from "../types.js";
import { fingerprint as makeFingerprint } from "../util/hash.js";
import { judgeDeclaredVersion } from "./evaluate.js";
import type { ActionDeclaration } from "./readers/actions.js";
import type { OsvEvent, SynvoyaAdvisory } from "./types.js";

/** Scan-time bounds on the archive (about 100 KB, 57 records when measured on 2026-11-04). */
const ARCHIVE_LIMITS: ZipReadLimits = {
  maxArchiveBytes: 32 * 1024 * 1024,
  maxEntries: 50_000,
  maxEntryBytes: 2 * 1024 * 1024,
  maxTotalBytes: 128 * 1024 * 1024,
};
const MAX_NAME_CHARS = 300;
const MAX_REFERENCES = 8;
const MAX_SHOWN_CHARS = 120;
const MAX_NOTES = 200;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const SHA = /^[0-9a-f]{40}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const EVENT_KINDS = ["introduced", "fixed", "last_affected", "limit"] as const;

/** One record's data for one action name. */
export interface ActionAdvisory {
  id: string;
  summary: string;
  aliases: string[];
  severity: Severity;
  cwe: string[];
  references: string[];
  /** ECOSYSTEM/SEMVER ranges and listed x.y.z versions, as the M1 evaluator reads them. */
  advisory: SynvoyaAdvisory;
  /** The record has tag data (ranges or a versions list) for this name. */
  tagData: boolean;
  /** Listed versions, leading `v` removed, compared as written. */
  listed: Set<string>;
  /** Commits a GIT range opens or ends affected at, and commits listed in `versions`. */
  affectedCommits: Set<string>;
  /** Commits a GIT range is fixed (or limited) at. */
  fixingCommits: Set<string>;
  /** The record has a GIT range for this name. */
  commitData: boolean;
  /** Fixed releases as the record writes them (leading `v` removed), keyed by their normalised form. */
  fixedShown: Map<string, string>;
  /** The installed OSV database (`osv`) or the bundled Synvoya dataset (`dataset`). */
  origin: "osv" | "dataset";
  /** Dataset entries only: what the entry itself says to do, and that it is known to be exploited. */
  own?: { steps: string[]; exploited: boolean };
}

export interface ActionsDb {
  /** Lower-case action name (`owner/repo` or `owner/repo/path`) → its records. */
  advisories: Map<string, ActionAdvisory[]>;
  records: number;
  /** `sha256:` of the archive, only when its install record matches it. */
  signature?: string;
  /** The upstream snapshot date (YYYY-MM-DD) from the install record, when known. */
  date?: string;
}

export type ActionsDbLoad =
  | { state: "missing" }
  | { state: "failed"; reason: string }
  | { state: "ready"; db: ActionsDb; warning?: string };

const clip = (text: string, max = MAX_SHOWN_CHARS): string => (text.length > max ? `${text.slice(0, max)}…` : text);
const stripV = (version: string): string => version.trim().replace(/^v(?=\d)/i, "");

/** `v41` → `41.0.0`, `v4.4` → `4.4.0`: the semver scheme needs three components. */
function normalizeVersion(version: string): string {
  const stripped = stripV(version);
  if (/^\d{1,15}$/.test(stripped)) return `${stripped}.0.0`;
  if (/^\d{1,15}\.\d{1,15}$/.test(stripped)) return `${stripped}.0`;
  return stripped;
}

/** `https://github.com/owner/repo/path` and `github.com/owner/repo` name the action `owner/repo/path`. */
function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/^(?:https?:\/\/)?(?:www\.)?github\.com\//, "").replace(/\.git$/, "").replace(/\/+$/, "");
}

const SEVERITIES: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

class MalformedRecord extends Error {}

const isObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []);

/** One range's events as OSV events with versions normalised; an event it cannot read is kept raw (unknown). */
function rangeEvents(events: unknown): OsvEvent[] {
  if (!Array.isArray(events)) throw new MalformedRecord();
  return events.map((event): OsvEvent => {
    if (!isObject(event)) return event as OsvEvent;
    const keys = Object.keys(event);
    const kind = EVENT_KINDS.find((candidate) => candidate === keys[0]);
    const value = kind === undefined ? undefined : event[kind];
    if (keys.length !== 1 || kind === undefined || typeof value !== "string") return event as OsvEvent;
    const at = kind === "introduced" && value.trim() === "0" ? "0" : normalizeVersion(value);
    return { [kind]: at } as OsvEvent;
  });
}

/**
 * A range with an `introduced` but no upper event (fixed, last_affected, limit) read literally covers every later
 * release. GHSA writes the bound it knows in the entry's `last_known_affected_version_range`: `< X` closes the range
 * before X (a `limit`, so X is not named as a fix) and `<= X` at X. A bound that is present but not one of those two
 * forms makes the range unknown, never open-ended; with no bound the advisory names no fix and the range stays open.
 */
function boundedEvents(events: OsvEvent[], specific: unknown): OsvEvent[] {
  if (events.some((event) => isObject(event) && ("fixed" in event || "last_affected" in event || "limit" in event))) return events;
  if (!events.some((event) => isObject(event) && "introduced" in event)) return events;
  const bound = isObject(specific) ? specific.last_known_affected_version_range : undefined;
  if (bound === undefined) return events;
  const match = typeof bound === "string" ? /^\s*(<=?)\s*([vV]?\d[0-9A-Za-z.+-]{0,63})\s*$/.exec(bound) : null;
  if (!match) return [{ introduced: "unreadable last known affected version range" }];
  const at = normalizeVersion(match[2]!);
  return [...events, match[1] === "<" ? { limit: at } : { last_affected: at }];
}

function recordAdvisories(text: string): Array<[string, ActionAdvisory]> {
  let record: unknown;
  try {
    record = JSON.parse(text);
  } catch {
    throw new MalformedRecord();
  }
  if (!isObject(record) || typeof record.id !== "string" || !ID.test(record.id) || !Array.isArray(record.affected)) throw new MalformedRecord();
  if (typeof record.withdrawn === "string" && record.withdrawn !== "") return [];
  const id = record.id;
  const specific = isObject(record.database_specific) ? record.database_specific : {};
  const severity = SEVERITIES[String(specific.severity ?? "").toUpperCase()] ?? "medium";
  const cwe = strings(specific.cwe_ids).filter((value) => /^CWE-\d{1,6}$/.test(value));
  const references = strings((Array.isArray(record.references) ? record.references : []).map((ref) => (isObject(ref) ? ref.url : undefined)))
    .filter((url) => /^https:\/\/[^\s]{1,300}$/.test(url));
  const byName = new Map<string, ActionAdvisory>();
  for (const affected of record.affected) {
    if (!isObject(affected) || !isObject(affected.package)) throw new MalformedRecord();
    const { ecosystem, name } = affected.package;
    if (typeof name !== "string" || name.trim() === "" || name.length > MAX_NAME_CHARS) throw new MalformedRecord();
    if (ecosystem !== "GitHub Actions") continue;
    const key = normalizeName(name);
    let entry = byName.get(key);
    if (!entry) {
      entry = {
        id,
        summary: typeof record.summary === "string" && record.summary.trim() ? record.summary.trim() : id,
        aliases: strings(record.aliases).filter((alias) => ID.test(alias) && alias !== id),
        severity,
        cwe: cwe.length > 0 ? cwe : ["CWE-1395"],
        references,
        advisory: {
          id, slug: id, title: id, kind: "vulnerability", aliases: [], target: { type: "package", ecosystem: "GitHub Actions", name: key },
          affected: [], fixed: [], severity, exploited: false, remediation_steps: [], sources: [], status: "active", provisional: false,
        },
        tagData: false,
        listed: new Set(),
        affectedCommits: new Set(),
        fixingCommits: new Set(),
        commitData: false,
        fixedShown: new Map(),
        origin: "osv",
      };
      byName.set(key, entry);
    }
    if (affected.ranges !== undefined && !Array.isArray(affected.ranges)) throw new MalformedRecord();
    for (const range of (affected.ranges ?? []) as unknown[]) {
      if (!isObject(range)) throw new MalformedRecord();
      if (range.type === "GIT") {
        entry.commitData = true;
        for (const event of Array.isArray(range.events) ? range.events : []) {
          if (!isObject(event)) continue;
          for (const [kind, value] of Object.entries(event)) {
            if (typeof value !== "string" || !SHA.test(value.toLowerCase())) continue;
            (kind === "fixed" || kind === "limit" ? entry.fixingCommits : entry.affectedCommits).add(value.toLowerCase());
          }
        }
        continue;
      }
      // ECOSYSTEM and SEMVER ranges compare tags; any other range type is kept and reads as unknown.
      entry.tagData = true;
      if (range.type !== "ECOSYSTEM" && range.type !== "SEMVER") {
        entry.advisory.affected.push({ events: [{ introduced: "unsupported range type" }] });
        continue;
      }
      entry.advisory.affected.push({ events: boundedEvents(rangeEvents(range.events), affected.database_specific) });
      for (const raw of Array.isArray(range.events) ? range.events : []) {
        if (isObject(raw) && typeof raw.fixed === "string") entry.fixedShown.set(normalizeVersion(raw.fixed), stripV(raw.fixed));
      }
    }
    if (affected.versions !== undefined && !Array.isArray(affected.versions)) throw new MalformedRecord();
    for (const version of strings(affected.versions)) {
      const lower = version.trim().toLowerCase();
      if (SHA.test(lower)) {
        entry.affectedCommits.add(lower);
        continue;
      }
      // Only a listed tag is tag data: a commits-only list says nothing about any tag.
      entry.tagData = true;
      entry.listed.add(stripV(version));
      // A full x.y.z listed version is also one affected point for tag comparison; `1` (a major tag) is not 1.0.0.
      const normalized = stripV(version);
      if (SEMVER.test(normalized)) entry.advisory.affected.push({ events: [{ introduced: normalized }, { last_affected: normalized }] });
    }
  }
  for (const entry of byName.values()) entry.advisory.fixed = [...entry.fixedShown.keys()];
  return [...byName];
}

/**
 * The bundled dataset's GitHub Actions advisories as matcher advisories, by lower-case action name. The mutable-tag
 * class (`kind: "config"`, name `*`) has no version to compare and is not one. A `fixed` entry that is a full commit
 * SHA is a commit the advisory is fixed at (clean for it); versions are compared as the dataset writes them.
 */
export function datasetActionAdvisories(advisories: readonly SynvoyaAdvisory[]): Map<string, ActionAdvisory[]> {
  const out = new Map<string, ActionAdvisory[]>();
  for (const dataset of advisories) {
    if (dataset.target.type !== "package" || dataset.target.ecosystem !== "GitHub Actions" || dataset.kind === "config" || dataset.target.name === "*") continue;
    const key = normalizeName(dataset.target.name);
    const fixedShown = new Map<string, string>();
    const fixingCommits = new Set<string>();
    for (const fixed of dataset.fixed) {
      if (SHA.test(fixed.trim().toLowerCase())) fixingCommits.add(fixed.trim().toLowerCase());
      else fixedShown.set(normalizeVersion(fixed), stripV(fixed));
    }
    const affected = dataset.affected.map((element) => ({ ...element, events: rangeEvents(element.events) }));
    for (const element of affected) {
      for (const event of element.events) if (isObject(event) && typeof (event as { fixed?: unknown }).fixed === "string") fixedShown.set((event as { fixed: string }).fixed, stripV((event as { fixed: string }).fixed));
    }
    const entry: ActionAdvisory = {
      id: dataset.id,
      summary: dataset.title,
      aliases: dataset.aliases.filter((alias) => alias !== dataset.id),
      severity: dataset.severity,
      cwe: dataset.kind === "malware" ? ["CWE-506"] : ["CWE-1395"],
      references: dataset.sources.filter((url) => /^https:\/\/[^\s]{1,300}$/.test(url)),
      advisory: { ...dataset, target: { ...dataset.target, name: key }, affected, fixed: [...fixedShown.keys()] },
      tagData: true,
      listed: new Set(),
      affectedCommits: new Set(),
      fixingCommits,
      commitData: fixingCommits.size > 0,
      fixedShown,
      origin: "dataset",
      own: { steps: dataset.remediation_steps, exploited: dataset.exploited },
    };
    const list = out.get(key);
    if (list) list.push(entry);
    else out.set(key, [entry]);
  }
  return out;
}

/** The installed database's records and the dataset's advisories as one lookup (the dataset alone when no database is given). */
export function withDatasetAdvisories(db: ActionsDb | undefined, dataset: ReadonlyMap<string, ActionAdvisory[]>): ActionsDb {
  const advisories = new Map<string, ActionAdvisory[]>(db?.advisories);
  for (const [name, list] of dataset) advisories.set(name, [...(advisories.get(name) ?? []), ...list]);
  return { ...(db ?? { records: 0 }), advisories };
}

/** Every record of the archive, indexed by action name. Throws (naming the entry) on any record it cannot read. */
export function parseActionsRecords(entries: ReadonlyArray<{ name: string; data: Buffer }>): ActionsDb {
  const advisories = new Map<string, ActionAdvisory[]>();
  let records = 0;
  for (const entry of entries) {
    let parsed: Array<[string, ActionAdvisory]>;
    try {
      parsed = recordAdvisories(entry.data.toString("utf8"));
    } catch (error) {
      if (error instanceof MalformedRecord) throw new Error(`record ${clip(entry.name, 80)} is malformed`);
      throw error;
    }
    records++;
    for (const [name, advisory] of parsed) {
      const list = advisories.get(name);
      if (list) list.push(advisory);
      else advisories.set(name, [advisory]);
    }
  }
  return { advisories, records };
}

/**
 * The installed database: `missing` when no archive is installed, `failed` (with a reason) when it cannot be
 * read whole, else `ready`, signed only when the install record describes these exact bytes.
 */
export async function loadActionsDb(options: { zipPath?: string; readRecord?: () => Promise<OsvDbRecord | undefined> } = {}): Promise<ActionsDbLoad> {
  const zipPath = options.zipPath ?? osvDbZipPath("GitHub Actions");
  if (!(await lstat(zipPath).catch(() => undefined))) return { state: "missing" };
  let db: ActionsDb;
  let sha256: string;
  let bytes = 0;
  try {
    const archive = await readZipArchive(zipPath, ARCHIVE_LIMITS, (name) => /\.json$/i.test(name));
    sha256 = archive.sha256;
    bytes = (await lstat(zipPath)).size;
    db = parseActionsRecords(archive.entries);
  } catch (error) {
    return { state: "failed", reason: `the OSV GitHub Actions database could not be read (${error instanceof Error ? clip(error.message, 160) : "unknown error"})` };
  }
  const record = await (options.readRecord ?? (() => readOsvDbRecord("GitHub Actions")))().catch(() => undefined);
  const signed = record !== undefined && record.bytes === bytes && record.signature === sha256;
  const date = record?.last_modified?.slice(0, 10);
  return {
    state: "ready",
    db: { ...db, ...(signed ? { signature: sha256 } : {}), ...(date && /^\d{4}-\d{2}-\d{2}$/.test(date) ? { date } : {}) },
    ...(signed ? {} : {
      warning: "The OSV GitHub Actions database has no install record that matches it (an interrupted, manual or modified install), " +
        "so Synvoya's Actions results cannot be proven reproducible on rescan. Run `codeinspectus setup` to reinstall it.",
    }),
  };
}

export interface ActionsMatch {
  findings: Finding[];
  notes: string[];
  /** `${file}\0${uses}` of every reference the matcher could evaluate (it leaves the `actions-unchecked` gap). */
  evaluated: Set<string>;
  /** Files holding a reference without a definite answer (a note): never re-checked for a rescan. */
  indefinite: Set<string>;
}

type Outcome =
  | { kind: "finding"; basis: "exact" | "line" | "listed" | "commit" }
  | { kind: "clean" }
  | { kind: "note"; text: string }
  | { kind: "unevaluated"; text: string };

function fixedText(advisory: ActionAdvisory, fixed: readonly string[] = advisory.advisory.fixed): string {
  return fixed.map((version) => advisory.fixedShown.get(version) ?? version).join(" or ");
}

function judge(advisory: ActionAdvisory, decl: ActionDeclaration, where: string, shown: string, now: Date): Outcome {
  const { action } = decl;
  const display = clip(action.name + action.path);
  if (action.kind === "sha") {
    const sha = decl.spec;
    if (advisory.affectedCommits.has(sha)) return { kind: "finding", basis: "commit" };
    if (advisory.fixingCommits.has(sha)) return { kind: "clean" };
    const fix = fixedText(advisory);
    const why = advisory.commitData || advisory.affectedCommits.size > 0
      ? `${advisory.id} lists commits, but not this one`
      : `${advisory.id} has no commit list in its advisory data`;
    return {
      kind: "unevaluated",
      text: `${where}: ${display}@${sha.slice(0, 12)} is pinned to a commit; ${why}, so Synvoya could not tell whether that commit is affected${fix ? ` (fixed in ${fix})` : ""}.`,
    };
  }
  if (advisory.listed.has(stripV(action.ref))) return { kind: "finding", basis: "listed" };
  if (action.kind === "branch") {
    return {
      kind: "unevaluated",
      text: `${where}: ${shown} names a branch or other moving ref, so Synvoya could not check it against ${advisory.id}; pin it to the full commit SHA of a fixed release.`,
    };
  }
  // A record with tag data but no ranges or x.y.z points enumerates what is affected: anything else is clean.
  if (advisory.advisory.affected.length === 0) {
    return advisory.tagData
      ? { kind: "clean" }
      : { kind: "unevaluated", text: `${where}: ${advisory.id} names ${display} but lists no affected releases, so Synvoya could not check ${shown} against it.` };
  }
  const judgement = judgeDeclaredVersion(advisory.advisory, decl.spec, decl.precision === "exact" ? "exact" : "floating", now);
  if (judgement.verdict === "finding") return { kind: "finding", basis: judgement.basis };
  if (judgement.verdict === "none") return { kind: "clean" };
  if (judgement.verdict === "note") {
    const fix = fixedText(advisory, judgement.fixed);
    return {
      kind: "note",
      text: `${where}: ${shown} is a moving tag that can still resolve to a release affected by ${advisory.id}; pin ${display} to ${fix ? `≥ ${fix}` : "a release outside the affected range"} by its full commit SHA.`,
    };
  }
  return { kind: "unevaluated", text: `${where}: could not compare ${shown} against ${advisory.id}; no finding is possible for it.` };
}

function finding(advisory: ActionAdvisory, decl: ActionDeclaration, basis: "exact" | "line" | "listed" | "commit"): Finding {
  const { action } = decl;
  const name = action.name + action.path;
  const key = `github actions:${name.toLowerCase()}`;
  const fp = makeFingerprint(["synvoya", advisory.id, decl.file, key]);
  const shown = clip(`${name}@${action.ref}`);
  const why = {
    exact: `${advisory.id} lists that release as affected.`,
    line: `${advisory.id} affects every release the moving tag ${clip(action.ref)} can resolve to today.`,
    listed: `${advisory.id} lists ${clip(action.ref)} itself as affected.`,
    commit: `${advisory.id} lists that commit as affected.`,
  }[basis];
  const fix = fixedText(advisory);
  const summary = fix
    ? `Update ${clip(name)} to ${fix} or later, pinned by its full commit SHA.`
    : `No fixed release of ${clip(name)} is listed; remove or replace the action.`;
  const exploited = advisory.own?.exploited ? " It is known to be exploited." : "";
  const steps = [
    ...(advisory.own?.steps ?? []),
    "Pin the `uses:` reference to the full 40-character commit SHA of a fixed release, with the tag in a comment.",
    "If an affected version ran, review the workflow logs and rotate every secret the job could reach.",
  ];
  return {
    id: fp,
    fingerprint: fp,
    engine: "synvoya",
    engines: ["synvoya"],
    engine_family: "synvoya",
    rule_id: advisory.id,
    title: `${clip(advisory.summary)} (${shown} in ${decl.file})`,
    severity: advisory.severity,
    ...(advisory.aliases.length > 0 ? { vulnerability_aliases: [...new Set(advisory.aliases)].sort() } : {}),
    cwe: advisory.cwe,
    owasp_web: ["A06:2021"],
    location: { file: decl.file, start_line: decl.line, end_line: decl.line, snippet: shown },
    message:
      `${decl.file}:${decl.line} uses ${shown} (${decl.source}). ${why}${exploited} ` +
      "The workflow runs this action's code with the job's token and the secrets in reach.",
    remediation: {
      summary,
      steps: [...new Set(steps)],
      references: [...new Set([`https://osv.dev/vulnerability/${advisory.id}`, ...advisory.references.slice(0, MAX_REFERENCES)])],
    },
    frameworks: [],
    confidence: basis === "line" ? "medium" : "high",
    // A dataset advisory depends on the bundled dataset; a database record on the installed database.
    producer_components: advisory.origin === "dataset" ? synvoyaActionsDatasetFindingComponents() : synvoyaActionsFindingComponents(),
    finding_kind: "vulnerability",
    package: { ecosystem: "GitHub Actions", name, version: action.ref },
  };
}

const upper = (values: Iterable<string>): Set<string> => new Set([...values].map((value) => value.trim().toUpperCase()));

/** Whether two advisories are the same one: a shared id or alias (GHSA, CVE). */
function sharesAdvisory(a: ActionAdvisory, b: ActionAdvisory): boolean {
  const ids = upper([a.id, ...a.aliases]);
  return [...upper([b.id, ...b.aliases])].some((id) => ids.has(id));
}

/** Enrich, never merge: the database's finding keeps everything it had and gains the dataset entry's fix steps. */
function enrich(upstream: Finding, advisory: ActionAdvisory, own: Finding): void {
  upstream.remediation = {
    ...upstream.remediation,
    steps: [...new Set([...upstream.remediation.steps, `Synvoya ${advisory.id}: ${own.remediation.summary}`, ...own.remediation.steps])],
  };
}

/** Judge every reference. One finding per (advisory, file, action): the first by line. */
export function matchActions(db: ActionsDb, declarations: readonly ActionDeclaration[], now: Date): ActionsMatch {
  const found = new Map<string, Finding>();
  const notes = new Set<string>();
  const evaluated = new Set<string>();
  const indefinite = new Set<string>();
  const ordered = [...declarations].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  for (const decl of ordered) {
    const { action } = decl;
    const where = `${decl.file}:${decl.line}`;
    const shown = clip(`${action.name}${action.path}@${action.ref}`);
    const full = (action.name + action.path).toLowerCase();
    // A reusable workflow is not the action an owner/repo record names: only a record naming that exact path covers it.
    const reusable = /^\/\.github\/workflows\//i.test(action.path);
    const keys = new Set(reusable ? [full] : [action.name.toLowerCase(), full]);
    const advisories = [...keys].flatMap((key) => db.advisories.get(key) ?? []);
    let couldNot = false;
    if (reusable && advisories.length === 0 && (db.advisories.get(action.name.toLowerCase()) ?? []).length > 0) {
      couldNot = true;
      indefinite.add(decl.file);
      if (notes.size < MAX_NOTES) {
        notes.add(`${where}: ${shown} is a reusable workflow; the advisories for ${clip(action.name)} name the action, not this workflow, so Synvoya could not check it.`);
      }
    }
    // The database's records first: a dataset advisory naming the same advisory folds into their finding.
    const judged = advisories
      .map((advisory) => ({ advisory, outcome: judge(advisory, decl, where, shown, now) }))
      .sort((a, b) => Number(a.advisory.origin === "dataset") - Number(b.advisory.origin === "dataset"));
    // Of the database records naming the same advisory, the one that reports the reference (a finding, then a note) is the twin.
    const rank = (kind: Outcome["kind"]): number => (kind === "finding" ? 0 : kind === "note" || kind === "unevaluated" ? 1 : 2);
    const sibling = (advisory: ActionAdvisory) =>
      advisory.origin === "dataset"
        ? judged
          .filter((other) => other.advisory.origin === "osv" && sharesAdvisory(other.advisory, advisory))
          .sort((a, b) => rank(a.outcome.kind) - rank(b.outcome.kind))[0]
        : undefined;
    for (const { advisory, outcome } of judged) {
      const twin = sibling(advisory);
      if (outcome.kind === "finding") {
        const result = finding(advisory, decl, outcome.basis);
        const key = `${result.rule_id}\0${decl.file}\0${(action.name + action.path).toLowerCase()}`;
        const upstream = twin?.outcome.kind === "finding" ? found.get(`${twin.advisory.id}\0${decl.file}\0${(action.name + action.path).toLowerCase()}`) : undefined;
        if (upstream) enrich(upstream, advisory, result);
        else if (!found.has(key)) found.set(key, result);
      } else if (outcome.kind === "note" || outcome.kind === "unevaluated") {
        indefinite.add(decl.file);
        // The database's record already said the same thing about the same advisory: one note, not two.
        const repeated = twin !== undefined && (twin.outcome.kind === "note" || twin.outcome.kind === "unevaluated");
        if (!repeated && notes.size < MAX_NOTES) notes.add(outcome.text);
        if (outcome.kind === "unevaluated") couldNot = true;
      }
    }
    if (!couldNot) evaluated.add(`${decl.file}\0${action.uses}`);
  }
  const findings = [...found.values()].sort(
    (a, b) =>
      (a.location.file < b.location.file ? -1 : a.location.file > b.location.file ? 1 : 0) ||
      a.location.start_line - b.location.start_line ||
      (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0),
  );
  return { findings, notes: [...notes], evaluated, indefinite };
}

/**
 * The hygiene disclosure (design §4.3; the github-actions pack has no mutable-reference rule, and M2 adds no
 * finding class): one info note naming the third-party references not pinned to a full commit SHA.
 */
export function unpinnedActionsNote(declarations: readonly ActionDeclaration[]): string | undefined {
  const unpinned = declarations.filter((decl) => decl.action.kind !== "sha");
  if (unpinned.length === 0) return undefined;
  const examples = unpinned.slice(0, 5).map((decl) => `${decl.file}:${decl.line} ${clip(decl.action.name + decl.action.path + "@" + decl.action.ref, 80)}`);
  return `${unpinned.length} third-party GitHub Actions reference(s) are not pinned to a full commit SHA, so the code they run can change without a change here (tag poisoning): ` +
    `${examples.join(", ")}${unpinned.length > examples.length ? ", …" : ""}. Pin each to a 40-character commit SHA.`;
}
