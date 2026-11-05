/**
 * The JavaScript/TypeScript parser behind the native packs (design §10.9, CodeInspectus 4.0).
 *
 * `@babel/parser` reads the whole file. A file is accepted only when one reading parses with no error;
 * its token stream then comes from the parser's own tokenizer, so every regex/division, template,
 * JSX, comment, identifier-escape and TypeScript decision is the parser's, never a heuristic. The
 * stream is mapped to the token shape the native analyzers already consume, so findings that both
 * the old lexer and the parser produce keep their rule ids, lines and fingerprints.
 *
 * Fail closed: a parse error, a token or nesting bound, or two valid readings that disagree (script
 * versus module) leave the file unparsed, which loaders record as the gap `native-parse-errors`.
 */
import { AsyncLocalStorage } from "node:async_hooks";

import { parse as babelParse } from "@babel/parser";

import type { JsToken } from "./javascript.js";

/** A node of the parser's AST, typed loosely: walks visit child objects generically. */
export interface JsAstNode {
  type: string;
  start?: number | null;
  end?: number | null;
  [key: string]: unknown;
}

interface BabelTokenType {
  label: string;
  keyword?: string;
}

interface BabelToken {
  type: BabelTokenType | string;
  value?: unknown;
  start: number;
  end: number;
}

interface BabelFile {
  type: "File";
  program: JsAstNode;
  tokens?: BabelToken[];
  comments?: Array<{ type: string; start: number; end: number }>;
  errors?: Array<{ reasonCode?: string; message?: string }>;
}

type SourceType = "module" | "script";

export interface ParsedJavaScript {
  tokens: JsToken[];
  /** Source ranges `[start, end)` of every unbraced if/else/for/while/with body, flattened. */
  conditionalBodies: number[];
  issues: string[];
}

/** `.ts`, `.tsx`, `.mts`, `.cts` are TypeScript (Ruling 30: `.mts`/`.cts` too). */
const TYPESCRIPT_PATH = /\.(?:[cm]?ts|tsx)$/i;
/** TypeScript-only files: angle brackets are type assertions and generics, never JSX. */
const TYPESCRIPT_ONLY_PATH = /\.[cm]?ts$/i;
const MODULE_PATH = /\.m[jt]s$/i;
const SCRIPT_PATH = /\.c[jt]s$/i;

/** Syntax every reading accepts: shipped ECMAScript plus TypeScript's legacy decorators. */
const COMMON_PLUGINS = [
  "decorators-legacy",
  "decoratorAutoAccessors",
  "explicitResourceManagement",
  ["importAttributes", { deprecatedAssertSyntax: true }],
] as const;

/** A TypeScript declaration file (`.d.ts`, `.d.mts`, `.d.cts`): ambient declarations only. */
const DECLARATION_PATH = /\.d\.[cm]?ts$/i;

/**
 * Recoverable parser errors that never change how the file is tokenized or nested: strict-mode rules on
 * names and statements the parser checks after reading them. Node rejects such a file in strict code, so
 * reading it is harmless, and the analyzers still see every token. Any other error is a parse failure.
 */
const TOKEN_NEUTRAL_ERRORS = new Set([
  "StrictDelete",
  "StrictEvalArguments",
  "StrictEvalArgumentsBinding",
  "StrictFunction",
  "StrictNumericEscape",
  "StrictOctalLiteral",
  "StrictWith",
]);

function pluginSets(path: string): unknown[][] {
  if (DECLARATION_PATH.test(path)) return [[["typescript", { dts: true }], ...COMMON_PLUGINS]];
  if (TYPESCRIPT_ONLY_PATH.test(path)) return [["typescript", ...COMMON_PLUGINS]];
  if (TYPESCRIPT_PATH.test(path)) return [["typescript", "jsx", ...COMMON_PLUGINS]];
  // JavaScript: JSX is accepted everywhere (React Native and Next.js ship it in `.js`), and Flow only
  // when the plain reading fails, as Metro's Babel preset strips it.
  return [["jsx", ...COMMON_PLUGINS], ["jsx", "flow", ...COMMON_PLUGINS]];
}

function attempt(content: string, sourceType: SourceType, plugins: unknown[]): BabelFile | string {
  try {
    const file = babelParse(content, {
      sourceType,
      plugins: plugins as never,
      tokens: true,
      errorRecovery: true,
      // CommonJS wraps a script in a function: a top-level `return` is valid there.
      allowReturnOutsideFunction: sourceType !== "module",
      allowNewTargetOutsideFunction: sourceType !== "module",
      allowUndeclaredExports: true,
      createParenthesizedExpressions: false,
      // Comments stay in the token stream; attaching them to nodes is work no analyzer reads.
      attachComment: false,
    }) as unknown as BabelFile;
    const blocking = file.errors?.find((error) => !TOKEN_NEUTRAL_ERRORS.has(error.reasonCode ?? ""));
    if (blocking) return blocking.message ?? blocking.reasonCode ?? "syntax error";
    return file;
  } catch (error) {
    // A stack overflow on pathological nesting is a parse failure like any other (fail closed).
    if (error instanceof RangeError) return "nesting too deep for the parser";
    return error instanceof Error ? error.message : String(error);
  }
}

function sameTokens(left: BabelFile, right: BabelFile): boolean {
  const a = left.tokens ?? [];
  const b = right.tokens ?? [];
  if (a.length !== b.length) return false;
  for (let index = 0; index < a.length; index++) {
    const x = a[index]!;
    const y = b[index]!;
    if (x.start !== y.start || x.end !== y.end || label(x) !== label(y)) return false;
  }
  return true;
}

/**
 * Parse one file. A `.mjs`/`.mts` file is a module and a `.cjs`/`.cts` file a script. Any other file
 * (`.js`, `.jsx`, `.ts`, `.tsx`) runs as a script or, in a `"type": "module"` package, as a module,
 * which a single file cannot tell, so it is read under both goals: when both are valid they must
 * tokenize identically (an HTML-like comment is a comment only in a script; `await` is an operator only
 * in a module), else the file is refused; when one goal alone is valid, that reading is the one Node can
 * run. The parser's `unambiguous` mode is never used: it reads a script with module rules.
 */
function parseFile(path: string, content: string): BabelFile | string {
  const goals: SourceType[] = MODULE_PATH.test(path) ? ["module"]
    : SCRIPT_PATH.test(path) ? ["script"]
    : ["script", "module"];
  let firstFailure: string | undefined;
  for (const plugins of pluginSets(path)) {
    const readings: Array<{ goal: SourceType; file: BabelFile }> = [];
    for (const goal of goals) {
      const file = attempt(content, goal, plugins);
      if (typeof file === "string") firstFailure ??= file;
      else readings.push({ goal, file });
    }
    if (readings.length === 2 && !sameTokens(readings[0]!.file, readings[1]!.file)) {
      return "The file reads differently as a script and as a module.";
    }
    const reading = readings[0];
    if (!reading) continue;
    if (reading.goal === "module" && htmlCommentOpenerAsOperators(reading.file, content)) {
      return "An HTML-like comment opener (<!--) is read as operators in a module, which V8 rejects.";
    }
    return reading.file;
  }
  return firstFailure ?? "syntax error";
}

/**
 * A module reading that took `<!--` as the operators `<` `!` `--` (re-review R1). The parser accepts it,
 * but V8 rejects an HTML-like comment opener in a module, so the reading is not code Node runs. A `<!--`
 * inside a string, template, regex or comment is part of that token and never starts a `<` token.
 */
function htmlCommentOpenerAsOperators(file: BabelFile, content: string): boolean {
  return (file.tokens ?? []).some((token) =>
    token.end === token.start + 1 && typeof token.type !== "string" && content.startsWith("<!--", token.start)
  );
}

function label(token: BabelToken): string {
  return typeof token.type === "string" ? token.type : token.type.label;
}

/** Offsets of every LF: lines count LF only, as the rest of CodeInspectus and the old lexer do. */
function lineStarts(content: string): number[] {
  const starts = [0];
  for (let index = content.indexOf("\n"); index >= 0; index = content.indexOf("\n", index + 1)) starts.push(index + 1);
  return starts;
}

interface TemplateFrame {
  kind: "template";
  index: number;
  dynamic: boolean;
  cooked?: string | null;
}

interface SubstitutionFrame {
  kind: "substitution";
  braces: number;
}

const OPENING_BRACES = new Set(["{", "${", "{|", "#{"]);
const SKIPPED = new Set(["CommentLine", "CommentBlock", "#!...", "eof", "jsxText"]);

/**
 * Map the parser's tokens to the analyzers' token shape: keywords and names are identifiers (the
 * value is the decoded name, so `eval` is `eval`), a template literal is one `template` token
 * followed by the tokens of its substitutions (Ruling 26), JSX `</` and `/>` are single symbols and
 * JSX text is not code. Lines are LF-counted.
 */
function mapTokens(content: string, babelTokens: readonly BabelToken[]): JsToken[] {
  const starts = lineStarts(content);
  let lineIndex = 0;
  const lineAt = (offset: number): number => {
    while (lineIndex + 1 < starts.length && starts[lineIndex + 1]! <= offset) lineIndex++;
    return lineIndex + 1;
  };
  const tokens: JsToken[] = [];
  const frames: Array<TemplateFrame | SubstitutionFrame> = [];
  for (let index = 0; index < babelTokens.length; index++) {
    const token = babelTokens[index]!;
    const kind = label(token);
    if (SKIPPED.has(kind)) continue;
    const raw = content.slice(token.start, token.end);
    const line = lineAt(token.start);
    const frame = frames.at(-1);
    if (kind === "`") {
      if (frame?.kind === "template") {
        frames.pop();
        const placeholder = tokens[frame.index]!;
        placeholder.end = token.end;
        placeholder.value = content.slice(placeholder.start, token.end);
        placeholder.raw = placeholder.value;
        if (!frame.dynamic && typeof frame.cooked === "string") placeholder.staticValue = frame.cooked;
      } else {
        tokens.push({ kind: "template", value: raw, raw, start: token.start, end: token.end, line });
        frames.push({ kind: "template", index: tokens.length - 1, dynamic: false });
      }
      continue;
    }
    if (frame?.kind === "template") {
      if (kind === "template") frame.cooked = typeof token.value === "string" ? token.value : null;
      if (kind === "${") {
        frame.dynamic = true;
        frames.push({ kind: "substitution", braces: 0 });
      }
      continue;
    }
    if (frame?.kind === "substitution") {
      if (OPENING_BRACES.has(kind)) frame.braces++;
      if (kind === "}" || kind === "|}") {
        if (frame.braces === 0) {
          frames.pop();
          continue;
        }
        frame.braces--;
      }
    }
    if (kind === "name" || kind === "jsxName" || (typeof token.type !== "string" && token.type.keyword)) {
      const value = kind === "name" || kind === "jsxName" ? String(token.value) : raw;
      tokens.push({ kind: "identifier", value, raw, start: token.start, end: token.end, line });
    } else if (kind === "string") {
      tokens.push({
        kind: "string", value: raw, raw, start: token.start, end: token.end, line,
        ...(typeof token.value === "string" ? { staticValue: token.value } : {}),
      });
    } else if (kind === "num" || kind === "bigint" || kind === "decimal") {
      tokens.push({ kind: "number", value: raw, raw, start: token.start, end: token.end, line });
    } else if (kind === "regexp") {
      tokens.push({ kind: "regex", value: raw, raw, start: token.start, end: token.end, line });
    } else if (kind === "jsxTagStart") {
      const next = babelTokens[index + 1];
      if (next && label(next) === "/") {
        tokens.push({ kind: "symbol", value: "</", raw: "</", start: token.start, end: next.end, line, jsx: true });
        index++;
      } else {
        tokens.push({ kind: "symbol", value: "<", raw: "<", start: token.start, end: token.end, line, jsx: true });
      }
    } else if (kind === "jsxTagEnd") {
      const previous = tokens.at(-1);
      if (previous?.value === "/" && previous.kind === "symbol") {
        previous.value = "/>";
        previous.raw = "/>";
        previous.end = token.end;
      } else {
        tokens.push({ kind: "symbol", value: ">", raw: ">", start: token.start, end: token.end, line });
      }
    } else {
      tokens.push({ kind: "symbol", value: raw, raw, start: token.start, end: token.end, line });
    }
  }
  return tokens;
}

const UNICODE_SPACES = new Set([0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]);

/**
 * A cheap upper bound on the number of tokens the parser records (comments, JSX text and empty template
 * chunks included): one per identifier/number run and per punctuator character, plus room for the
 * zero-width tokens a backtick, `${`, `>` or `}` can produce. Linear, with no lexing decisions.
 */
export function tokenUpperBound(content: string): number {
  let count = 2;
  let inWord = false;
  let previous = 0;
  for (let index = 0; index < content.length; index++) {
    const code = content.charCodeAt(index);
    const space = code === 32 || (code >= 9 && code <= 13) || UNICODE_SPACES.has(code) || (code >= 0x2000 && code <= 0x200a);
    const word = !space && ((code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) ||
      code === 36 || code === 95 || code > 127);
    if (word) {
      if (!inWord) count++;
      inWord = true;
    } else {
      inWord = false;
      if (!space) {
        count++;
        if (code === 96) count += 2;
        if (code === 62 || code === 125) count++;
        if (code === 123 && previous === 36) count++;
      }
    }
    previous = code;
  }
  return count;
}

/** Bodies whose execution depends on a condition or loop: if/else, for/for-in/for-of, while, with. */
const CONDITIONAL_BODY_KEYS: Readonly<Record<string, readonly string[]>> = {
  IfStatement: ["consequent", "alternate"],
  ForStatement: ["body"],
  ForInStatement: ["body"],
  ForOfStatement: ["body"],
  WhileStatement: ["body"],
  WithStatement: ["body"],
};

function isNode(value: unknown): value is JsAstNode {
  return typeof value === "object" && value !== null && typeof (value as { type?: unknown }).type === "string";
}

/**
 * One iterative walk of the AST (an explicit stack, so no recursion depth limit): the source ranges of
 * every unbraced conditional or loop body.
 */
function conditionalBodies(program: JsAstNode): number[] {
  const ranges: number[] = [];
  const stack: unknown[] = [program];
  while (stack.length) {
    const value = stack.pop();
    if (Array.isArray(value)) {
      for (const item of value) stack.push(item);
      continue;
    }
    if (!isNode(value)) continue;
    const keys = CONDITIONAL_BODY_KEYS[value.type];
    if (keys) {
      for (const key of keys) {
        const body = value[key];
        if (isNode(body) && body.type !== "BlockStatement" && typeof body.start === "number" && typeof body.end === "number") {
          ranges.push(body.start, body.end);
        }
      }
    }
    for (const key in value) {
      if (key === "loc" || key === "leadingComments" || key === "trailingComments" || key === "innerComments" || key === "extra") continue;
      const child = value[key];
      if (typeof child === "object" && child !== null) stack.push(child);
    }
  }
  return ranges;
}

/** How the path selects the reading: declaration file, TypeScript, TSX, module, script, or JavaScript. */
function readingClass(path: string): string {
  return [DECLARATION_PATH, TYPESCRIPT_ONLY_PATH, TYPESCRIPT_PATH, MODULE_PATH, SCRIPT_PATH]
    .map((pattern) => (pattern.test(path) ? "1" : "0")).join("");
}

/**
 * Parses shared by the native analyzers of one scan, which run concurrently and read the same files.
 * The cache exists only inside `withJavaScriptParseCache` (one per native-pack execution) and is cleared
 * when that scan ends, so nothing outlives the scan. It is bounded by mapped tokens and source size;
 * the oldest entries go first. Keyed by reading class and content, the only inputs of a parse. Results
 * are never mutated by consumers.
 */
export const PARSE_CACHE_MAX_TOKENS = 250_000;
export const PARSE_CACHE_MAX_CHARS = 8 * 1024 * 1024;

export class JavaScriptParseCache {
  private readonly entries = new Map<string, Map<string, ParsedJavaScript>>();
  private readonly order: Array<[string, string]> = [];
  private head = 0;
  tokens = 0;
  chars = 0;

  get size(): number {
    return this.order.length - this.head;
  }

  get(reading: string, content: string): ParsedJavaScript | undefined {
    return this.entries.get(reading)?.get(content);
  }

  set(reading: string, content: string, parsed: ParsedJavaScript): void {
    const cost = parsed.tokens.length;
    if (cost > PARSE_CACHE_MAX_TOKENS || content.length > PARSE_CACHE_MAX_CHARS) return;
    let byContent = this.entries.get(reading);
    if (!byContent) this.entries.set(reading, byContent = new Map());
    if (byContent.has(content)) return;
    byContent.set(content, parsed);
    this.order.push([reading, content]);
    this.tokens += cost;
    this.chars += content.length;
    while (this.tokens > PARSE_CACHE_MAX_TOKENS || this.chars > PARSE_CACHE_MAX_CHARS) {
      const [oldReading, oldContent] = this.order[this.head++]!;
      const map = this.entries.get(oldReading)!;
      this.tokens -= map.get(oldContent)!.tokens.length;
      this.chars -= oldContent.length;
      map.delete(oldContent);
    }
    if (this.head > 1024 && this.head * 2 > this.order.length) {
      this.order.splice(0, this.head);
      this.head = 0;
    }
  }

  clear(): void {
    this.entries.clear();
    this.order.length = 0;
    this.head = 0;
    this.tokens = 0;
    this.chars = 0;
  }
}

const scanCache = new AsyncLocalStorage<JavaScriptParseCache>();

/** Run one scan's native analyzers with a parse cache that is cleared when they finish. */
export async function withJavaScriptParseCache<T>(run: () => Promise<T>, cache = new JavaScriptParseCache()): Promise<T> {
  try {
    return await scanCache.run(cache, run);
  } finally {
    cache.clear();
  }
}

/** The parse cache of the scan in progress, if any (tests). */
export function activeJavaScriptParseCache(): JavaScriptParseCache | undefined {
  return scanCache.getStore();
}

export function parseJavaScriptTokens(path: string, content: string, maxTokens: number): ParsedJavaScript {
  const cache = scanCache.getStore();
  const reading = `${readingClass(path)}:${maxTokens}`;
  const cached = cache?.get(reading, content);
  if (cached) return cached;
  const parsed = parseUncached(path, content, maxTokens);
  cache?.set(reading, content, parsed);
  return parsed;
}

function parseUncached(path: string, content: string, maxTokens: number): ParsedJavaScript {
  // Bounded work before the parser runs: the parser keeps every token and node it reads, so a file
  // that could hold far more tokens than the analyzers accept is refused unparsed (fail closed).
  if (tokenUpperBound(content) > 2 * maxTokens) {
    return { tokens: [], conditionalBodies: [], issues: [`JavaScript/TypeScript token bound exceeded (${maxTokens}).`] };
  }
  const file = parseFile(path, content);
  if (typeof file === "string") {
    return { tokens: [], conditionalBodies: [], issues: [`JavaScript/TypeScript parse error: ${file}`] };
  }
  // The parser's stream holds comments and the end-of-file marker too; the bound counts mapped tokens.
  const tokens = mapTokens(content, file.tokens ?? []);
  if (tokens.length > maxTokens) {
    return { tokens: [], conditionalBodies: [], issues: [`JavaScript/TypeScript token bound exceeded (${maxTokens}).`] };
  }
  return { tokens, conditionalBodies: conditionalBodies(file.program), issues: [] };
}
