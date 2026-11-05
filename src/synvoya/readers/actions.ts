/**
 * Third-party GitHub Actions references: `uses: owner/repo[/path]@ref` in workflow jobs and steps
 * (`.github/workflows/*.yml|yaml`, top level only, as GitHub reads them) and in composite action steps
 * (`action.yml|yaml` anywhere the walk reaches). Local `./` actions are the repository's own and are
 * ignored; `docker://` steps are seen (they stay in the `actions-unchecked` gap) but never declared.
 *
 * Read-only and bounded like the other readers (see walk.ts): YAML is composed one document at a time
 * with no alias expansion, references and documents are capped per file, references and notes per scan,
 * and bytes per scan. A file read only in part is `capped`, never parsed; one holding something the
 * reader could not turn into a reference (an alias, a merge key, an unreadable value) is `unjudged`.
 */

import { Composer, isAlias, isMap, isScalar, isSeq, LineCounter, Parser, type Document, type Node as YamlNode } from "yaml";

import type { Declaration, ReaderOptions, ReaderResult } from "../types.js";

import { yamlText } from "./runtime.js";
import { readCandidate, walkCandidates, type WalkMatcher } from "./walk.js";

/** What a `uses:` value names, as written. */
export interface ActionReference {
  /** `owner/repo` as written (case kept). */
  name: string;
  /** Sub-path inside the repository, with its leading `/`; "" when none. */
  path: string;
  ref: string;
  /** `semver` x.y.z tag, `floating` major or major.minor tag, full 40-hex `sha`, anything else `branch`. */
  kind: "semver" | "floating" | "sha" | "branch";
  /** The `uses:` value as written (clipped to MAX_USES_CHARS): the `actions-unchecked` gap's key. */
  uses: string;
}

export interface ActionDeclaration extends Declaration {
  subject: { type: "package"; ecosystem: "GitHub Actions"; name: string };
  action: ActionReference;
}

export interface ActionsReaderResult extends ReaderResult {
  declarations: ActionDeclaration[];
  /** Every third-party `uses:` value the reader saw (declared, docker or unreadable), in file order. */
  references: Array<{ file: string; line: number; uses: string }>;
}

const MATCHERS: readonly WalkMatcher[] = [
  { prefix: ".github/workflows/", suffix: ".yml" },
  { prefix: ".github/workflows/", suffix: ".yaml" },
  { basename: ["action.yml", "action.yaml"] },
];

const MAX_REFERENCES_PER_FILE = 256;
const MAX_REFERENCES_PER_SCAN = 2000;
const MAX_NOTES_PER_FILE = 64;
const MAX_NOTES_PER_SCAN = 2000;
const MAX_YAML_DOCUMENTS = 16;
const MAX_SCAN_BYTES = 64 * 1024 * 1024;
/** The gap discovery reads at most this many characters of a `uses:` value; keys match it. */
export const MAX_USES_CHARS = 300;
const MAX_SHOWN_CHARS = 120;

const USES = /^([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100})((?:\/[^@\s]{1,200})?)@([^@\s]{1,200})$/;
const SHA = /^[0-9a-f]{40}$/i;
const FLOATING = /^[vV]?(\d{1,9}(?:\.\d{1,9})?)$/;
const SEMVER = /^[vV]?(\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,64})?(?:\+[0-9A-Za-z.-]{1,64})?)$/;

class Malformed extends Error {}

interface Ctx {
  file: string;
  out: ActionDeclaration[];
  references: ActionsReaderResult["references"];
  notes: string[];
  full: boolean;
  capped?: boolean;
  unjudged?: boolean;
}

const clip = (text: string): string => (text.length > MAX_SHOWN_CHARS ? `${text.slice(0, MAX_SHOWN_CHARS)}…` : text);

function note(ctx: Ctx, text: string): void {
  if (ctx.notes.length < MAX_NOTES_PER_FILE) ctx.notes.push(text);
}

/** The declaration for one `uses:` value, or undefined (with a note) when it is not a reference. */
export function parseUses(uses: string): ActionReference | undefined {
  const match = USES.exec(uses);
  if (!match) return undefined;
  const [, owner, repo, path, ref] = match as unknown as [string, string, string, string, string];
  if (owner === "." || owner === ".." || repo === "." || repo === "..") return undefined;
  const kind: ActionReference["kind"] = SHA.test(ref) ? "sha" : SEMVER.test(ref) ? "semver" : FLOATING.test(ref) ? "floating" : "branch";
  return { name: `${owner}/${repo}`, path, ref, kind, uses };
}

function declare(ctx: Ctx, uses: string, line: number, source: string): void {
  if (ctx.full) return;
  if (uses === "" || uses.startsWith("./")) return;
  if (ctx.references.length >= MAX_REFERENCES_PER_FILE) {
    ctx.full = true;
    ctx.capped = true;
    ctx.notes.push(`${ctx.file}: more than ${MAX_REFERENCES_PER_FILE} action references; extra ignored`);
    return;
  }
  const key = uses.slice(0, MAX_USES_CHARS);
  ctx.references.push({ file: ctx.file, line, uses: key });
  if (uses.startsWith("docker://")) return;
  const action = uses.length > MAX_USES_CHARS ? undefined : parseUses(uses);
  if (!action) {
    ctx.unjudged = true;
    note(ctx, `${ctx.file}:${line}: \`uses: ${clip(uses)}\` is not an action reference Synvoya can read; it was not checked against advisories.`);
    return;
  }
  const exact = action.kind === "semver" ? SEMVER.exec(action.ref)![1]! : undefined;
  const spec =
    action.kind === "semver" ? exact!
      : action.kind === "floating" ? FLOATING.exec(action.ref)![1]!
        : action.kind === "sha" ? action.ref.toLowerCase()
          : action.ref;
  ctx.out.push({
    subject: { type: "package", ecosystem: "GitHub Actions", name: action.name },
    spec,
    ...(exact !== undefined ? { resolved: exact } : {}),
    precision: action.kind === "semver" ? "exact" : action.kind === "floating" ? "floating" : "unresolved",
    file: ctx.file,
    line,
    source,
    ...(action.kind === "sha" || action.kind === "branch" ? { noted: true as const } : {}),
    action,
  });
}

interface Yaml {
  text: string;
  lines: LineCounter;
}

const lineOf = (yaml: Yaml, node: unknown): number => {
  const start = (node as YamlNode | null | undefined)?.range?.[0];
  return start === undefined ? 1 : yaml.lines.linePos(start).line;
};

/** Documents one at a time (no alias expansion; `uniqueKeys` off, its check is quadratic). */
function* documents(ctx: Ctx, yaml: Yaml): Generator<Document.Parsed> {
  const composer = new Composer({ uniqueKeys: false, prettyErrors: false });
  const parser = new Parser(yaml.lines.addNewLine);
  let count = 0;
  for (const doc of composer.compose(parser.parse(yaml.text))) {
    if (++count > MAX_YAML_DOCUMENTS) {
      ctx.capped = true;
      note(ctx, `${ctx.file}: more than ${MAX_YAML_DOCUMENTS} YAML documents; extra ignored`);
      return;
    }
    if (doc.errors.length > 0) throw new Malformed();
    yield doc;
  }
}

/** A map entry as a node; an alias or a merge key where a reference could hide makes the file unjudged. */
function entry(ctx: Ctx, yaml: Yaml, map: unknown, key: string): unknown {
  if (isAlias(map)) {
    ctx.unjudged = true;
    note(ctx, `${ctx.file}:${lineOf(yaml, map)}: a YAML alias is not expanded, so any action reference in it was not checked.`);
    return undefined;
  }
  if (!isMap(map)) return undefined;
  if (map.items.some((pair) => isScalar(pair.key) && pair.key.value === "<<")) {
    ctx.unjudged = true;
    note(ctx, `${ctx.file}:${lineOf(yaml, map)}: a YAML merge key is not expanded, so any action reference in it was not checked.`);
  }
  const value = map.get(key, true);
  if (isAlias(value)) {
    ctx.unjudged = true;
    note(ctx, `${ctx.file}:${lineOf(yaml, value)}: a YAML alias is not expanded, so any action reference in it was not checked.`);
    return undefined;
  }
  return value;
}

function uses(ctx: Ctx, yaml: Yaml, owner: unknown, source: string): void {
  const node = entry(ctx, yaml, owner, "uses");
  if (node === undefined || node === null) return;
  const written = yamlText(node, yaml.text);
  if (written === undefined) {
    ctx.unjudged = true;
    note(ctx, `${ctx.file}:${lineOf(yaml, node)}: a \`uses:\` value that is not text was not checked.`);
    return;
  }
  declare(ctx, written.trim(), lineOf(yaml, node), source);
}

function steps(ctx: Ctx, yaml: Yaml, owner: unknown, source: string): void {
  const list = entry(ctx, yaml, owner, "steps");
  if (!isSeq(list)) return;
  for (const step of list.items) {
    if (ctx.full) return;
    if (isAlias(step)) {
      ctx.unjudged = true;
      note(ctx, `${ctx.file}:${lineOf(yaml, step)}: a YAML alias is not expanded, so any action reference in it was not checked.`);
      continue;
    }
    uses(ctx, yaml, step, source);
  }
}

function readFile(ctx: Ctx, yaml: Yaml, composite: boolean): void {
  for (const doc of documents(ctx, yaml)) {
    if (composite) {
      steps(ctx, yaml, entry(ctx, yaml, doc.contents, "runs"), "composite action step uses");
      continue;
    }
    const jobs = entry(ctx, yaml, doc.contents, "jobs");
    if (!isMap(jobs)) continue;
    for (const job of jobs.items) {
      if (ctx.full) return;
      if (isAlias(job.value)) {
        ctx.unjudged = true;
        note(ctx, `${ctx.file}:${lineOf(yaml, job.value)}: a YAML alias is not expanded, so any action reference in it was not checked.`);
        continue;
      }
      uses(ctx, yaml, job.value, "workflow job uses");
      steps(ctx, yaml, job.value, "workflow step uses");
    }
  }
}

const isWorkflow = (file: string): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(file);

export async function readActionReferences(target: string, options: ReaderOptions = {}): Promise<ActionsReaderResult> {
  const walked = await walkCandidates(target, MATCHERS, {}, { signal: options.signal, only: options.only });
  const result: ActionsReaderResult = {
    declarations: [],
    parsed: [],
    // GitHub reads only the top level of .github/workflows/; deeper files are not workflows.
    skipped: walked.skipped.filter((entry) => entry.reason !== "symlink" || isWorkflow(entry.file) || /(?:^|\/)action\.ya?ml$/.test(entry.file)),
    notes: [],
    references: [],
  };
  let consumed = 0;
  let declarationsFull = false;
  for (const file of walked.files) {
    const workflow = isWorkflow(file);
    if (!workflow && !/(?:^|\/)action\.ya?ml$/.test(file)) continue;
    if (options.signal?.aborted) {
      result.skipped.push({ file, reason: "deadline" });
      continue;
    }
    if (consumed >= MAX_SCAN_BYTES || declarationsFull) {
      result.skipped.push({ file, reason: "budget" });
      continue;
    }
    const text = await readCandidate(target, file);
    if (text === undefined) {
      result.skipped.push({ file, reason: "unreadable" });
      continue;
    }
    consumed += Buffer.byteLength(text);
    const ctx: Ctx = { file, out: [], references: [], notes: [], full: false };
    try {
      readFile(ctx, { text, lines: new LineCounter() }, !workflow);
    } catch {
      // Malformed content is reported; any unexpected failure is treated the same way, never thrown.
      result.skipped.push({ file, reason: "malformed" });
      continue;
    }
    // Appended in loops, never spread.
    let scanFull = false;
    for (const declaration of ctx.out) {
      if (result.declarations.length >= MAX_REFERENCES_PER_SCAN) {
        scanFull = true;
        const capNote = `${file}: more than ${MAX_REFERENCES_PER_SCAN} action references in this scan; the rest were not checked`;
        ctx.notes.push(capNote);
        (result.priorityNotes ??= []).push(capNote);
        break;
      }
      result.declarations.push(declaration);
    }
    for (const reference of ctx.references) if (result.references.length < MAX_REFERENCES_PER_SCAN * 2) result.references.push(reference);
    for (const message of ctx.notes) if (result.notes.length < MAX_NOTES_PER_SCAN) result.notes.push(message);
    if (ctx.unjudged) (result.unjudged ??= []).push(file);
    if (ctx.capped || scanFull) result.skipped.push({ file, reason: "capped" });
    else result.parsed.push(file);
    if (scanFull) declarationsFull = true;
  }
  return result;
}
