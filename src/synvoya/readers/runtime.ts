/**
 * Declared runtime versions: what a repository says it runs on, read from version-manager pin files,
 * package manifests and GitHub Actions setup steps. Read-only and bounded (see walk.ts); a file that
 * cannot be parsed is reported in `skipped`, never thrown.
 *
 * `spec` is the version text the evaluator parses, with wrapper tokens removed (`v`, `go`,
 * `python-`, `net`, a Java vendor tag, a Ruby patch level). `resolved` is set only for `exact`.
 */

import { parse as parseToml } from "smol-toml";
import { isMap, isScalar, isSeq, LineCounter, parseDocument, type Node as YamlNode } from "yaml";

import type { Declaration, ReaderOptions, ReaderResult, RuntimeId } from "../types.js";

import { readCandidate, walkCandidates, type WalkMatcher } from "./walk.js";

type Precision = Declaration["precision"];

const PIN_FILES = [
  ".nvmrc", ".node-version", ".tool-versions", "mise.toml", ".mise.toml", "package.json",
  "composer.json", "composer.lock", ".python-version", "runtime.txt",
  ".ruby-version", "Gemfile", "Gemfile.lock", "global.json", ".java-version", ".sdkmanrc", "pom.xml", "go.mod",
] as const;

const MATCHERS: readonly WalkMatcher[] = [
  { basename: PIN_FILES },
  { basename: "*.csproj" },
  { prefix: ".github/workflows/", suffix: ".yml" },
  { prefix: ".github/workflows/", suffix: ".yaml" },
];

/** Hostile-input bounds: a manifest inside the 1 MiB file cap must not buy unbounded work or output. */
const MAX_DECLARATIONS_PER_FILE = 64;
const MAX_DECLARATIONS_PER_SCAN = 2000;
const MAX_NOTES_PER_FILE = 64;
const MAX_NOTES_PER_SCAN = 2000;
const MAX_JSON_DEPTH = 64;
const MAX_MATRIX_VALUES_PER_KEY = 32;
const MAX_MATRIX_EXPANSIONS_PER_FILE = 256;

class Malformed extends Error {}

interface Ctx {
  file: string;
  out: Declaration[];
  notes: string[];
  /** The per-file declaration cap was hit; readers stop as soon as they see it. */
  full: boolean;
  /** Matrix values expanded so far in this file. */
  expansions: number;
  /** Something the reader saw could not be read into a declaration (an unresolved repository, property, ...). */
  unjudged?: boolean;
  /** Some of the file was not read (a per-file cap or bound): it is reported as skipped "capped", never parsed. */
  capped?: boolean;
}

function note(ctx: Ctx, text: string): void {
  if (ctx.notes.length < MAX_NOTES_PER_FILE) ctx.notes.push(text);
}

// ---- version classification ----

/** Wrapper tokens removed so every reader hands the evaluator a plain version or range. */
function normalize(runtime: RuntimeId, raw: string): string {
  let spec = raw.trim().replace(/^(["'])(.*)\1$/, "$2").trim().replace(/^v(?=\d)/, "");
  if (runtime === "go") spec = spec.replace(/^go(?=\d)/, "");
  else if (runtime === "python") spec = spec.replace(/^(?:cpython|python)-(?=\d)/i, "");
  else if (runtime === "ruby") spec = spec.replace(/^ruby-(?=\d)/i, "").replace(/(?<=\d)p\d+$/, "");
  else if (runtime === "java") {
    spec = spec.replace(/^(?:[a-z][a-z0-9]*-)+(?=\d)/i, "").replace(/\+\d+$/, "").replace(/-[a-z][a-z0-9.]*$/i, "");
  }
  return spec;
}

function classify(spec: string): { precision: Precision; resolved?: string } {
  if (!/\d/.test(spec) || spec.includes("${") || /^(?:lts|latest|stable|oldstable|nightly|current|system)\b/i.test(spec)) {
    return { precision: "unresolved" };
  }
  if (/[<>^~|]|\s/.test(spec)) return { precision: "range" };
  if (/^\d+(?:\.\d+)?(?:\.[xX*]){0,2}$/.test(spec)) return { precision: "floating" };
  if (/^\d+\.\d+\.\d+(?:[-+._A-Za-z][0-9A-Za-z.+_-]*)?$/.test(spec)) return { precision: "exact", resolved: spec };
  return { precision: "unresolved" };
}

function emit(
  ctx: Ctx,
  runtime: RuntimeId,
  raw: string,
  line: number,
  source: string,
  options: { majorOnlyIsRange?: boolean; lineOnly?: boolean } = {},
): void {
  if (ctx.full) return;
  if (ctx.out.length >= MAX_DECLARATIONS_PER_FILE) {
    ctx.full = true;
    ctx.capped = true;
    ctx.notes.push(`${ctx.file}: more than ${MAX_DECLARATIONS_PER_FILE} runtime declarations; extra ignored`);
    return;
  }
  let spec = normalize(runtime, raw);
  if (spec === "") return;
  let { precision, resolved } = classify(spec);
  // A Maven property that names a major (17, 1.8) is a language level, not a pinned build.
  if (options.majorOnlyIsRange && /^(?:1\.)?\d+$/.test(spec)) precision = "range";
  // A value that sets a resolution target (Composer platform PHP) names its release line, not the patch
  // release that is deployed: 8.2.0 floats on 8.2.
  if (options.lineOnly && precision === "exact") {
    spec = spec.split(".").slice(0, 2).join(".");
    precision = "floating";
    resolved = undefined;
  }
  if (precision === "unresolved") {
    note(ctx, `${ctx.file}:${line}: ${source} "${spec}" does not name a resolvable version; no runtime finding is possible for it.`);
  }
  ctx.out.push({
    subject: { type: "runtime", runtime },
    spec,
    ...(precision === "exact" && resolved !== undefined ? { resolved } : {}),
    precision,
    file: ctx.file,
    line,
    source,
  });
}

// ---- text helpers ----

function splitLines(text: string): string[] {
  return text.replace(/^﻿/, "").split(/\r?\n/);
}

/**
 * 1-based line of the first occurrence of each object key path (up to 4 deep, joined with NUL) in a
 * JSON document. Linear time and memory: nesting past MAX_JSON_DEPTH stops the scan as Malformed, and
 * a running path prefix is kept per frame instead of rebuilding it per key.
 */
function jsonKeyLines(text: string): Map<string, number> {
  const found = new Map<string, number>();
  /** `prefix` is the NUL-joined key path to this container, or undefined past the depth any lookup needs. */
  interface Frame { object: boolean; prefix: string | undefined; key?: string }
  const frames: Frame[] = [];
  let line = 1;
  for (let at = 0; at < text.length; at++) {
    const ch = text[at]!;
    if (ch === "\n") line++;
    else if (ch === "{" || ch === "[") {
      if (frames.length >= MAX_JSON_DEPTH) throw new Malformed();
      const top = frames[frames.length - 1];
      let prefix: string | undefined;
      if (top === undefined) prefix = "";
      else if (top.object && top.key !== undefined && top.prefix !== undefined && frames.length <= 4) {
        prefix = top.prefix === "" ? top.key : `${top.prefix}\0${top.key}`;
      }
      frames.push({ object: ch === "{", prefix });
    } else if (ch === "}" || ch === "]") frames.pop();
    else if (ch === '"') {
      let end = at + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === "\\" ? 2 : 1;
      let after = end + 1;
      while (after < text.length && /\s/.test(text[after]!)) after++;
      const top = frames[frames.length - 1];
      if (top?.object && text[after] === ":") {
        top.key = text.slice(at + 1, end);
        if (top.prefix !== undefined) {
          const path = top.prefix === "" ? top.key : `${top.prefix}\0${top.key}`;
          if (!found.has(path)) found.set(path, line);
        }
      }
      at = end;
    }
  }
  return found;
}

function parseJsonObject(text: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new Malformed();
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Malformed();
  return value as Record<string, unknown>;
}

function at(value: unknown, path: readonly string[]): unknown {
  let current = value;
  for (const key of path) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

/** Emit the string at each `[runtime, path, source, options?]` entry of a parsed JSON document. */
function emitJsonKeys(
  ctx: Ctx,
  text: string,
  entries: ReadonlyArray<readonly [RuntimeId, readonly string[], string, { lineOnly?: boolean }?]>,
): void {
  const root = parseJsonObject(text);
  const lines = jsonKeyLines(text);
  for (const [runtime, path, source, options] of entries) {
    const value = at(root, path);
    if (typeof value === "string") emit(ctx, runtime, value, lines.get(path.join("\0")) ?? 1, source, options);
  }
}

// ---- line-oriented readers ----

/** pyenv accepts several versions; a file longer than this is not one, so only its first line counts. */
const MAX_PYENV_LINES = 16;

const LINE_PIN_FILES: Record<string, { runtime: RuntimeId; all: boolean }> = {
  ".nvmrc": { runtime: "node", all: false },
  ".node-version": { runtime: "node", all: false },
  ".python-version": { runtime: "python", all: true },
  "runtime.txt": { runtime: "python", all: false },
  ".ruby-version": { runtime: "ruby", all: false },
  ".java-version": { runtime: "java", all: false },
};

function readLinePins(ctx: Ctx, name: string, text: string): void {
  const { runtime, all } = LINE_PIN_FILES[name]!;
  const lines = splitLines(text);
  const every = all && lines.length <= MAX_PYENV_LINES;
  for (let index = 0; index < lines.length && !ctx.full; index++) {
    const value = lines[index]!.replace(/#.*$/, "").trim();
    if (value === "") continue;
    emit(ctx, runtime, value, index + 1, name);
    if (!every) return;
  }
}

const ASDF_NAMES: Record<string, RuntimeId> = {
  nodejs: "node", node: "node", python: "python", ruby: "ruby", golang: "go", go: "go",
  java: "java", php: "php", dotnet: "dotnet", "dotnet-core": "dotnet",
};

function readToolVersions(ctx: Ctx, text: string): void {
  splitLines(text).forEach((raw, index) => {
    const [name, version] = raw.replace(/#.*$/, "").trim().split(/\s+/);
    const runtime = name === undefined ? undefined : ASDF_NAMES[name];
    if (runtime && version && version !== "system" && !version.startsWith("ref:") && !version.startsWith("path:")) {
      emit(ctx, runtime, version, index + 1, ".tool-versions");
    }
  });
}

function readSdkmanrc(ctx: Ctx, text: string): void {
  splitLines(text).forEach((raw, index) => {
    const match = /^\s*java\s*=\s*(\S+)/.exec(raw.replace(/#.*$/, ""));
    if (match) emit(ctx, "java", match[1]!, index + 1, ".sdkmanrc");
  });
}

function readGoMod(ctx: Ctx, text: string): void {
  splitLines(text).forEach((raw, index) => {
    const match = /^\s*(go|toolchain)\s+(\S+)/.exec(raw.replace(/\/\/.*$/, ""));
    if (!match) return;
    if (match[1] === "toolchain" && /^(?:default|local)$/.test(match[2]!)) return;
    // Since Go 1.21 the `go` line is the minimum Go the module needs, not the toolchain that builds it.
    const value = match[1] === "go" && /^\d/.test(match[2]!) ? `>=${match[2]!}` : match[2]!;
    emit(ctx, "go", value, index + 1, `go.mod ${match[1]}`);
  });
}

function readGemfile(ctx: Ctx, text: string): void {
  splitLines(text).forEach((raw, index) => {
    const match = /^\s*ruby\s+((?:["'][^"'\r\n]{1,100}["']\s*,?\s*){1,4})/.exec(raw);
    if (!match) return; // `ruby file: ".ruby-version"` is read from .ruby-version itself
    const parts = [...match[1]!.matchAll(/["']([^"']+)["']/g)].map((part) => part[1]!);
    emit(ctx, "ruby", parts.join(", "), index + 1, "Gemfile ruby");
  });
}

function readGemfileLock(ctx: Ctx, text: string): void {
  const lines = splitLines(text);
  const header = lines.findIndex((raw) => /^RUBY VERSION\s*$/.test(raw));
  if (header < 0) return;
  for (let index = header + 1; index < lines.length; index++) {
    if (lines[index]!.trim() === "") continue;
    const match = /^\s+ruby\s+(\S+)/.exec(lines[index]!);
    if (match) emit(ctx, "ruby", match[1]!, index + 1, "Gemfile.lock RUBY VERSION");
    return;
  }
}

function readPom(ctx: Ctx, text: string): void {
  splitLines(text).forEach((raw, index) => {
    for (const match of raw.matchAll(/<(java\.version|maven\.compiler\.release)>([^<]{1,100})<\/\1>/g)) {
      const value = match[2]!.trim();
      if (value.includes("${")) {
        ctx.unjudged = true;
        note(ctx, `${ctx.file}:${index + 1}: pom.xml ${match[1]} "${value}" refers to another property; not resolved.`);
        continue;
      }
      emit(ctx, "java", value, index + 1, `pom.xml ${match[1]}`, { majorOnlyIsRange: true });
    }
  });
}

function readCsproj(ctx: Ctx, text: string): void {
  splitLines(text).forEach((raw, index) => {
    for (const match of raw.matchAll(/<(TargetFrameworks?)(?:\s[^>]{0,200})?>([^<]{1,300})<\/\1>/g)) {
      for (const tfm of match[2]!.split(";").map((item) => item.trim()).filter(Boolean)) {
        const modern = /^net(\d+\.\d+)(?:-[a-z0-9.]+)?$/i.exec(tfm) ?? /^netcoreapp(\d+\.\d+)$/i.exec(tfm);
        if (modern) emit(ctx, "dotnet", modern[1]!, index + 1, `csproj ${match[1]}`);
        else note(ctx, `${ctx.file}:${index + 1}: ${tfm} is not a .NET (Core) runtime target; not read.`);
      }
    }
  });
}

// ---- mise.toml ----

const MISE_NAMES: Record<string, RuntimeId> = {
  node: "node", nodejs: "node", python: "python", ruby: "ruby", go: "go", golang: "go",
  java: "java", php: "php", dotnet: "dotnet",
};

function tomlToolLine(text: string, tool: string): number {
  let section = "";
  const lines = splitLines(text);
  for (let index = 0; index < lines.length; index++) {
    const header = /^\s*\[([^\][]+)\]\s*(?:#.*)?$/.exec(lines[index]!);
    if (header) {
      section = header[1]!.trim();
      if (section === `tools.${tool}`) return index + 1;
    } else if (section === "tools" && new RegExp(`^\\s*["']?${tool}["']?\\s*=`).test(lines[index]!)) return index + 1;
  }
  return 1;
}

function readMise(ctx: Ctx, text: string): void {
  let parsed: Record<string, unknown>;
  try {
    parsed = parseToml(text);
  } catch {
    throw new Malformed();
  }
  const tools = parsed.tools;
  if (tools === null || typeof tools !== "object" || Array.isArray(tools)) return;
  for (const [tool, value] of Object.entries(tools)) {
    const runtime = MISE_NAMES[tool];
    if (!runtime) continue;
    const line = tomlToolLine(text, tool);
    const items = Array.isArray(value) ? value : [value];
    for (const item of items) {
      const version = typeof item === "string" ? item : at(item, ["version"]);
      if (typeof version === "string") emit(ctx, runtime, version, line, "mise.toml [tools]");
    }
  }
}

// ---- GitHub Actions ----

const SETUP_ACTIONS: Record<string, readonly [RuntimeId, string]> = {
  "actions/setup-node": ["node", "node-version"],
  "shivammathur/setup-php": ["php", "php-version"],
  "actions/setup-python": ["python", "python-version"],
  "actions/setup-go": ["go", "go-version"],
  "actions/setup-java": ["java", "java-version"],
  "actions/setup-dotnet": ["dotnet", "dotnet-version"],
  "ruby/setup-ruby": ["ruby", "ruby-version"],
};

/** The value as written: `3.10` stays `3.10` (YAML would read the number 3.1). */
export function yamlText(node: unknown, text: string): string | undefined {
  if (!isScalar(node) || node.value === null || node.value === undefined) return undefined;
  if (node.type === "PLAIN" && node.range) return text.slice(node.range[0], node.range[1]).trim();
  return String(node.value);
}

function readWorkflow(ctx: Ctx, text: string): void {
  const lineCounter = new LineCounter();
  const doc = parseDocument(text, { lineCounter, prettyErrors: false });
  if (doc.errors.length > 0) throw new Malformed();
  const lineOf = (node: unknown): number => {
    const start = (node as YamlNode | null | undefined)?.range?.[0];
    return start === undefined ? 1 : lineCounter.linePos(start).line;
  };
  const jobs = doc.get("jobs", true);
  if (!isMap(jobs)) return;
  for (const job of jobs.items) {
    if (ctx.full) return;
    if (!isMap(job.value)) continue;
    const strategy = job.value.get("strategy", true);
    const matrix = isMap(strategy) ? strategy.get("matrix", true) : undefined;
    const matrixCache = new Map<string, string[]>();
    const steps = job.value.get("steps", true);
    if (!isSeq(steps)) continue;
    for (const step of steps.items) {
      if (ctx.full) return;
      if (!isMap(step)) continue;
      const uses = yamlText(step.get("uses", true), text);
      const setup = uses === undefined ? undefined : SETUP_ACTIONS[uses.split("@")[0]!.toLowerCase()];
      const withMap = step.get("with", true);
      if (!setup || !isMap(withMap)) continue;
      const [runtime, input] = setup;
      const valueNode = withMap.get(input, true);
      const written = yamlText(valueNode, text);
      if (written === undefined) continue;
      const line = lineOf(valueNode);
      const source = `${uses!.split("@")[0]} ${input}`;
      for (const entry of written.split(/\r?\n/)) {
        if (ctx.full) return;
        const trimmed = entry.trim();
        if (trimmed === "") continue;
        const reference = /^\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}$/.exec(trimmed);
        let values = [trimmed];
        if (reference) {
          const key = reference[1]!;
          let cached = matrixCache.get(key);
          if (cached === undefined) {
            cached = matrixValues(ctx, matrix, key, text);
            matrixCache.set(key, cached);
          }
          if (cached.length > 0) values = cached;
        }
        if (reference) {
          ctx.expansions += values.length;
          if (ctx.expansions > MAX_MATRIX_EXPANSIONS_PER_FILE) {
            ctx.notes.push(`${ctx.file}: matrix expansion exceeds ${MAX_MATRIX_EXPANSIONS_PER_FILE} values; extra ignored`);
            ctx.full = true;
            ctx.capped = true;
            return;
          }
        }
        for (const value of values) emit(ctx, runtime, value, line, source);
      }
    }
  }
}

/**
 * Values of `strategy.matrix.<key>` (a list) plus that key in each `include` entry, in order, distinct,
 * at most MAX_MATRIX_VALUES_PER_KEY (a note says when more were ignored).
 */
function matrixValues(ctx: Ctx, matrix: unknown, key: string, text: string): string[] {
  if (!isMap(matrix)) return [];
  const values = new Set<string>();
  let truncated = false;
  const add = (node: unknown): void => {
    const value = yamlText(node, text);
    if (value === undefined || values.has(value)) return;
    // A matrix value that is itself an expression could be any version: the file is not fully judged.
    if (value.includes("${{")) {
      ctx.unjudged = true;
      return;
    }
    if (values.size >= MAX_MATRIX_VALUES_PER_KEY) truncated = true;
    else values.add(value);
  };
  const listed = matrix.get(key, true);
  if (isSeq(listed)) {
    for (const item of listed.items) {
      add(item);
      if (truncated) break;
    }
  } else add(listed);
  const include = matrix.get("include", true);
  if (isSeq(include) && !truncated) {
    for (const entry of include.items) {
      if (isMap(entry)) add(entry.get(key, true));
      if (truncated) break;
    }
  }
  if (truncated) {
    ctx.capped = true;
    ctx.notes.push(`${ctx.file}: matrix.${key} has more than ${MAX_MATRIX_VALUES_PER_KEY} distinct values; extra ignored`);
  }
  return [...values];
}

// ---- dispatch ----

function readOne(ctx: Ctx, name: string, text: string): void {
  if (name in LINE_PIN_FILES) return readLinePins(ctx, name, text);
  switch (name) {
    case ".tool-versions": return readToolVersions(ctx, text);
    case ".sdkmanrc": return readSdkmanrc(ctx, text);
    case "go.mod": return readGoMod(ctx, text);
    case "Gemfile": return readGemfile(ctx, text);
    case "Gemfile.lock": return readGemfileLock(ctx, text);
    case "pom.xml": return readPom(ctx, text);
    case "mise.toml":
    case ".mise.toml": return readMise(ctx, text);
    case "package.json":
      return emitJsonKeys(ctx, text, [
        ["node", ["engines", "node"], "package.json engines.node"],
        ["node", ["volta", "node"], "package.json volta.node"],
      ]);
    case "composer.json":
      return emitJsonKeys(ctx, text, [
        ["php", ["require", "php"], "composer.json require.php"],
        ["php", ["config", "platform", "php"], "composer.json config.platform.php", { lineOnly: true }],
      ]);
    case "composer.lock":
      return emitJsonKeys(ctx, text, [
        ["php", ["platform", "php"], "composer.lock platform"],
        ["php", ["platform-overrides", "php"], "composer.lock platform-overrides", { lineOnly: true }],
      ]);
    case "global.json":
      return emitJsonKeys(ctx, text, [["dotnet", ["sdk", "version"], "global.json sdk.version"]]);
    default:
      if (name.endsWith(".csproj")) return readCsproj(ctx, text);
      return readWorkflow(ctx, text);
  }
}

export async function readRuntimePins(target: string, options: ReaderOptions = {}): Promise<ReaderResult> {
  const walked = await walkCandidates(target, MATCHERS, {}, { signal: options.signal, only: options.only });
  const result: ReaderResult = { declarations: [], parsed: [], skipped: [...walked.skipped], notes: [] };
  for (const file of walked.files) {
    if (options.signal?.aborted) {
      result.skipped.push({ file, reason: "deadline" });
      continue;
    }
    const text = await readCandidate(target, file);
    if (text === undefined) {
      result.skipped.push({ file, reason: "unreadable" });
      continue;
    }
    const ctx: Ctx = { file, out: [], notes: [], full: false, expansions: 0 };
    let scanFull = false;
    try {
      readOne(ctx, file.slice(file.lastIndexOf("/") + 1), text);
      // Appended in loops, never spread: the arrays are bounded, but a spread's argument limit is not ours to rely on.
      for (const declaration of ctx.out) {
        if (result.declarations.length >= MAX_DECLARATIONS_PER_SCAN) {
          scanFull = true;
          const capNote = `${file}: more than ${MAX_DECLARATIONS_PER_SCAN} runtime declarations; extra ignored`;
          ctx.notes.push(capNote);
          (result.priorityNotes ??= []).push(capNote);
          break;
        }
        result.declarations.push(declaration);
      }
      for (const message of ctx.notes) if (result.notes.length < MAX_NOTES_PER_SCAN) result.notes.push(message);
      if (ctx.unjudged) (result.unjudged ??= []).push(file);
      // A file read only in part is not a re-check of everything it declares.
      if (ctx.capped || scanFull) result.skipped.push({ file, reason: "capped" });
      else result.parsed.push(file);
    } catch {
      // Malformed content is reported; any unexpected failure is treated the same way, never thrown.
      result.skipped.push({ file, reason: "malformed" });
    }
    if (scanFull) break;
  }
  return result;
}
