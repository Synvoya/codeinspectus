/**
 * Bounded, non-executing Expo configuration analysis.
 *
 * Root and bounded nested Expo project configs are parsed when the directory
 * has an Expo package manifest or a statically provable Expo config shape.
 * Target code is never imported, evaluated, transpiled, or executed.
 */

import { lstat, open, opendir } from "node:fs/promises";
import type { Dirent, Stats } from "node:fs";
import { isIP } from "node:net";
import { basename, dirname, join, relative, resolve } from "node:path";

import { makeAiFinding } from "../../ai-checks/finding.js";
import type { Finding } from "../../types.js";
import type { NativeAnalyzerResult } from "../types.js";

export const EXPO_SECRET_PUBLIC_CONFIG_RULE_ID = "ci-expo-secret-in-public-config";
export const EXPO_UNSIGNED_CLEARTEXT_UPDATES_RULE_ID =
  "ci-expo-unsigned-cleartext-updates";

export const EXPO_CONFIG_RULE_IDS = [
  EXPO_SECRET_PUBLIC_CONFIG_RULE_ID,
  EXPO_UNSIGNED_CLEARTEXT_UPDATES_RULE_ID,
] as const;

const JSON_CONFIG_NAMES = ["app.config.json", "app.json"] as const;
const CODE_CONFIG_NAMES = [
  "app.config.cjs",
  "app.config.cts",
  "app.config.js",
  "app.config.mjs",
  "app.config.mts",
  "app.config.ts",
] as const;
const TYPESCRIPT_CONFIG_NAMES = new Set(["app.config.cts", "app.config.mts", "app.config.ts"]);
const CONFIG_NAMES = new Set<string>([...JSON_CONFIG_NAMES, ...CODE_CONFIG_NAMES]);
const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_TOKENS = 100_000;
const MAX_DEPTH = 64;
const MAX_PROPERTIES = 20_000;
const MAX_NOTES = 20;
const MAX_DISCOVERY_ENTRIES = 20_000;
const MAX_PROJECT_ROOTS = 500;
const MAX_DISCOVERY_DEPTH = 24;
const MAX_TOTAL_READ_FILES = 4_096;
const MAX_TOTAL_READ_BYTES = 4 * 1024 * 1024;
const MAX_TOTAL_TOKENS = 250_000;
const MAX_TOTAL_PROPERTIES = 25_000;
export interface ExpoDiscoveryBounds {
  maxEntries: number;
  maxProjectRoots: number;
  maxDepth: number;
  maxReadFiles: number;
  maxReadBytes: number;
  maxTokens: number;
  maxProperties: number;
}
const DEFAULT_DISCOVERY_BOUNDS: ExpoDiscoveryBounds = {
  maxEntries: MAX_DISCOVERY_ENTRIES,
  maxProjectRoots: MAX_PROJECT_ROOTS,
  maxDepth: MAX_DISCOVERY_DEPTH,
  maxReadFiles: MAX_TOTAL_READ_FILES,
  maxReadBytes: MAX_TOTAL_READ_BYTES,
  maxTokens: MAX_TOTAL_TOKENS,
  maxProperties: MAX_TOTAL_PROPERTIES,
};

function constrainedDiscoveryBounds(bounds: Partial<ExpoDiscoveryBounds>): ExpoDiscoveryBounds {
  const constrain = (value: number | undefined, maximum: number) =>
    Math.min(maximum, Math.max(
      1,
      typeof value === "number" && Number.isFinite(value) ? Math.floor(value) : maximum,
    ));
  return {
    maxEntries: constrain(bounds.maxEntries, MAX_DISCOVERY_ENTRIES),
    maxProjectRoots: constrain(bounds.maxProjectRoots, MAX_PROJECT_ROOTS),
    maxDepth: constrain(bounds.maxDepth, MAX_DISCOVERY_DEPTH),
    maxReadFiles: constrain(bounds.maxReadFiles, MAX_TOTAL_READ_FILES),
    maxReadBytes: constrain(bounds.maxReadBytes, MAX_TOTAL_READ_BYTES),
    maxTokens: constrain(bounds.maxTokens, MAX_TOTAL_TOKENS),
    maxProperties: constrain(bounds.maxProperties, MAX_TOTAL_PROPERTIES),
  };
}

interface ExpoReadBudget {
  filesRead: number;
  bytesRead: number;
  readonly maxFiles: number;
  readonly maxBytes: number;
  tokensParsed: number;
  propertiesParsed: number;
  readonly maxTokens: number;
  readonly maxProperties: number;
}
const IGNORED_DIRECTORIES = new Set([
  ".cache",
  ".dart_tool",
  ".git",
  ".gradle",
  ".next",
  ".nuxt",
  ".output",
  ".pub-cache",
  ".svelte-kit",
  "build",
  "cache",
  "caches",
  "coverage",
  "deriveddata",
  "dist",
  "node_modules",
  "out",
  "pods",
  "target",
  "vendor",
]);
const CORPUS_DIRECTORIES = new Set([
  "androidtest",
  "debug",
  "demo",
  "demos",
  "example",
  "examples",
  "integration_test",
  "profile",
  "sample",
  "samples",
  "test",
  "tests",
]);

type TokenKind = "identifier" | "number" | "string" | "symbol";

interface Token {
  kind: TokenKind;
  value: string;
  raw: string;
  start: number;
  end: number;
  line: number;
  interpolated?: boolean;
}

function symbolToken(token: Token | undefined, value: string): boolean {
  return token?.kind === "symbol" && token.value === value;
}

function identifierToken(token: Token | undefined, value: string): boolean {
  return token?.kind === "identifier" && token.value === value;
}

interface LexResult {
  tokens: Token[];
  issue?: string;
}

interface ExpoStringValue {
  kind: "string";
  value: string;
  line: number;
}

interface ExpoNumberValue {
  kind: "number";
  value: string;
  line: number;
}

interface ExpoBooleanValue {
  kind: "boolean";
  value: boolean;
  line: number;
}

interface ExpoNullValue {
  kind: "null";
  line: number;
}

interface ExpoEnvironmentValue {
  kind: "environment";
  name: string;
  line: number;
}

interface ExpoArrayValue {
  kind: "array";
  values: ExpoStaticValue[];
  line: number;
}

interface ExpoObjectProperty {
  key: string;
  line: number;
  value: ExpoStaticValue;
}

interface ExpoObjectValue {
  kind: "object";
  properties: ExpoObjectProperty[];
  line: number;
}

type ExpoStaticValue =
  | ExpoStringValue
  | ExpoNumberValue
  | ExpoBooleanValue
  | ExpoNullValue
  | ExpoEnvironmentValue
  | ExpoArrayValue
  | ExpoObjectValue;

export interface ExpoConfigDocument {
  path: string;
  root: ExpoObjectValue;
}

export interface ExpoConfigProject {
  target: string;
  root: string;
  /** Every independently parsed eligible Expo project, ordered by repository path. */
  documents?: ExpoConfigDocument[];
  /** Compatibility alias for the first document in a single- or multi-project scan. */
  document?: ExpoConfigDocument;
  /** Bounded, non-secret reasons that qualify or suppress static conclusions. */
  notes?: string[];
}

export type ExpoConfigInput = string | ExpoConfigProject | Promise<ExpoConfigProject>;

function decodeEscape(
  source: string,
  index: number,
): { value: string; consumed: number; issue?: string } {
  const character = source[index];
  if (character === undefined) return { value: "", consumed: 0 };
  const simple: Record<string, string> = {
    "'": "'",
    '"': '"',
    "\\": "\\",
    b: "\b",
    f: "\f",
    n: "\n",
    r: "\r",
    t: "\t",
    v: "\v",
    "0": "\0",
  };
  if (/^[1-9]$/.test(character) || (character === "0" && /[0-9]/.test(source[index + 1] ?? ""))) {
    return { value: "", consumed: 1, issue: "Unsupported legacy numeric string escape." };
  }
  if (simple[character] !== undefined) return { value: simple[character], consumed: 1 };
  if (character === "x" && /^[\da-f]{2}$/i.test(source.slice(index + 1, index + 3))) {
    return {
      value: String.fromCodePoint(Number.parseInt(source.slice(index + 1, index + 3), 16)),
      consumed: 3,
    };
  }
  if (character === "x") {
    return { value: "", consumed: 1, issue: "Invalid hexadecimal string escape." };
  }
  if (character === "u") {
    const braced = /^\{([\da-f]{1,6})\}/i.exec(source.slice(index + 1));
    if (braced) {
      const point = Number.parseInt(braced[1]!, 16);
      if (point <= 0x10ffff) {
        return { value: String.fromCodePoint(point), consumed: braced[0].length + 1 };
      }
    }
    const fixed = source.slice(index + 1, index + 5);
    if (/^[\da-f]{4}$/i.test(fixed)) {
      return { value: String.fromCodePoint(Number.parseInt(fixed, 16)), consumed: 5 };
    }
    return { value: "", consumed: 1, issue: "Invalid Unicode string escape." };
  }
  if (character === "\n") return { value: "", consumed: 1 };
  if (character === "\r" && source[index + 1] === "\n") {
    return { value: "", consumed: 2 };
  }
  return { value: character, consumed: 1 };
}

function lexString(
  source: string,
  start: number,
  initialLine: number,
): { token: Token; next: number; line: number; issue?: string } {
  const quote = source[start]!;
  let cursor = start + 1;
  let line = initialLine;
  let segmentStart = cursor;
  const valueParts: string[] = [];
  const valueThrough = (end: number): string => {
    if (end > segmentStart) valueParts.push(source.slice(segmentStart, end));
    return valueParts.join("");
  };
  let interpolated = false;
  while (cursor < source.length) {
    const character = source[cursor]!;
    if (character === quote) {
      const end = cursor + 1;
      const value = valueThrough(cursor);
      return {
        token: {
          kind: "string",
          value,
          raw: source.slice(start, end),
          start,
          end,
          line: initialLine,
          ...(interpolated ? { interpolated: true } : {}),
        },
        next: end,
        line,
      };
    }
    if (character === "\\") {
      if (cursor > segmentStart) valueParts.push(source.slice(segmentStart, cursor));
      const decoded = decodeEscape(source, cursor + 1);
      if (decoded.issue) {
        return {
          token: {
            kind: "string",
            value: valueParts.join(""),
            raw: source.slice(start, cursor + 2),
            start,
            end: cursor + 2,
            line: initialLine,
          },
          next: cursor + 2,
          line,
          issue: `${decoded.issue} At line ${line}.`,
        };
      }
      valueParts.push(decoded.value);
      const escaped = source.slice(cursor + 1, cursor + 1 + decoded.consumed);
      line += (escaped.match(/\n/g) ?? []).length;
      cursor += 1 + Math.max(decoded.consumed, 1);
      segmentStart = cursor;
      continue;
    }
    if (quote === "`" && character === "$" && source[cursor + 1] === "{") {
      interpolated = true;
    }
    if (character === "\n") {
      line++;
      if (quote !== "`") {
        return {
          token: {
            kind: "string",
            value: valueThrough(cursor),
            raw: source.slice(start, cursor),
            start,
            end: cursor,
            line: initialLine,
          },
          next: cursor,
          line,
          issue: `Unterminated string at line ${initialLine}.`,
        };
      }
    }
    cursor++;
  }
  return {
    token: {
      kind: "string",
      value: valueThrough(source.length),
      raw: source.slice(start),
      start,
      end: source.length,
      line: initialLine,
    },
    next: source.length,
    line,
    issue: `Unterminated string at line ${initialLine}.`,
  };
}

function validNumericLiteral(raw: string): boolean {
  // Numeric separators add lexer-context edge cases without contributing to
  // either Expo rule. Reject them conservatively instead of normalizing an
  // invalid literal into an apparently valid static config.
  if (raw.includes("_")) return false;
  if (/^0[xX][\da-fA-F]+$/.test(raw)) return true;
  if (/^0[bB][01]+$/.test(raw)) return true;
  if (/^0[oO][0-7]+$/.test(raw)) return true;
  return /^(?:0|[1-9]\d*)(?:\.\d*)?(?:[eE][+-]?\d+)?$/.test(raw);
}

function lexConfig(source: string, budget: ExpoReadBudget): LexResult {
  const tokens: Token[] = [];
  const appendToken = (token: Token): string | undefined => {
    if (tokens.length >= MAX_TOKENS) {
      return `Expo config exceeds the ${MAX_TOKENS.toLocaleString()}-token bound.`;
    }
    if (budget.tokensParsed >= budget.maxTokens) {
      return `Expo configs exceed the aggregate ${budget.maxTokens.toLocaleString()}-token bound.`;
    }
    tokens.push(token);
    budget.tokensParsed++;
    return undefined;
  };
  let cursor = 0;
  let line = 1;
  while (cursor < source.length) {
    const character = source[cursor]!;
    const next = source[cursor + 1];
    if (character === "\n") {
      line++;
      cursor++;
      continue;
    }
    if (/\s/.test(character)) {
      cursor++;
      continue;
    }
    if (source.startsWith("<!--", cursor) || source.startsWith("-->", cursor)) {
      return { tokens, issue: `Unsupported HTML-comment syntax at line ${line}.` };
    }
    if (character === "/" && next === "/") {
      cursor += 2;
      while (cursor < source.length && source[cursor] !== "\n") cursor++;
      continue;
    }
    if (character === "/" && next === "*") {
      const commentLine = line;
      cursor += 2;
      let closed = false;
      while (cursor < source.length) {
        if (source[cursor] === "\n") line++;
        if (source[cursor] === "*" && source[cursor + 1] === "/") {
          cursor += 2;
          closed = true;
          break;
        }
        cursor++;
      }
      if (!closed) return { tokens, issue: `Unterminated comment at line ${commentLine}.` };
      continue;
    }
    if (character === "/") {
      return {
        tokens,
        issue: `Unsupported regular-expression or division syntax at line ${line}.`,
      };
    }
    if (character === "'" || character === '"' || character === "`") {
      const parsed = lexString(source, cursor, line);
      const boundIssue = appendToken(parsed.token);
      if (boundIssue) return { tokens, issue: boundIssue };
      cursor = parsed.next;
      line = parsed.line;
      if (parsed.issue) return { tokens, issue: parsed.issue };
    } else if (/[A-Za-z_$]/.test(character)) {
      const start = cursor++;
      while (/[A-Za-z0-9_$]/.test(source[cursor] ?? "")) cursor++;
      const raw = source.slice(start, cursor);
      const boundIssue = appendToken({
        kind: "identifier", value: raw, raw, start, end: cursor, line,
      });
      if (boundIssue) return { tokens, issue: boundIssue };
    } else if (/[0-9]/.test(character)) {
      const start = cursor;
      const numeric = /^(?:0[xX][\da-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|\d[\d_]*(?:\.[\d_]*)?(?:[eE][+-]?[\d_]+)?)/
        .exec(source.slice(cursor))?.[0] ?? character;
      cursor += numeric.length;
      const raw = source.slice(start, cursor);
      if (!validNumericLiteral(raw)) {
        return { tokens, issue: `Invalid numeric literal at line ${line}.` };
      }
      const boundIssue = appendToken({ kind: "number", value: raw, raw, start, end: cursor, line });
      if (boundIssue) return { tokens, issue: boundIssue };
    } else {
      const symbol = ["...", "=>", "?.", "??", "&&", "||", "==", "!=", "<=", ">="]
        .find((candidate) => source.startsWith(candidate, cursor)) ?? character;
      const boundIssue = appendToken({
        kind: "symbol",
        value: symbol,
        raw: symbol,
        start: cursor,
        end: cursor + symbol.length,
        line,
      });
      if (boundIssue) return { tokens, issue: boundIssue };
      cursor += symbol.length;
    }
  }
  return { tokens };
}

function environmentReference(
  tokens: readonly Token[],
  start: number,
  typescriptConfig: boolean,
): { value: ExpoEnvironmentValue; next: number } | undefined {
  if (
    !identifierToken(tokens[start], "process") ||
    !symbolToken(tokens[start + 1], ".") ||
    !identifierToken(tokens[start + 2], "env")
  ) return undefined;
  const selector = tokens[start + 3];
  const name = symbolToken(selector, ".")
    ? tokens[start + 4]?.kind === "identifier" ? tokens[start + 4] : undefined
    : symbolToken(selector, "[") && tokens[start + 4]?.kind === "string" &&
        symbolToken(tokens[start + 5], "]")
      ? tokens[start + 4]
      : undefined;
  if (!name || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name.value)) return undefined;
  const baseNext = symbolToken(selector, ".") ? start + 5 : start + 6;
  let next = baseNext;
  if (!typescriptConfig) {
    return {
      value: { kind: "environment", name: name.value, line: tokens[start]!.line },
      next,
    };
  }
  while (true) {
    if (symbolToken(tokens[next], "!")) {
      next++;
      continue;
    }
    const asserted = skipTypeAssertion(tokens, next);
    if (asserted === next) break;
    next = asserted;
  }
  return {
    value: { kind: "environment", name: name.value, line: tokens[start]!.line },
    next,
  };
}

function declarationEquals(
  tokens: readonly Token[],
  nameIndex: number,
  before: number,
  typescriptConfig: boolean,
): number | undefined {
  let cursor = nameIndex + 1;
  if (symbolToken(tokens[cursor], "=")) return cursor;
  if (!typescriptConfig || !symbolToken(tokens[cursor], ":")) return undefined;
  cursor++;
  let curly = 0;
  let square = 0;
  let round = 0;
  let angle = 0;
  for (; cursor < before; cursor++) {
    const token = tokens[cursor]!;
    const topLevel = curly === 0 && square === 0 && round === 0 && angle === 0;
    if (topLevel && symbolToken(token, "=")) return cursor;
    if (topLevel && symbolToken(token, ";")) return undefined;
    if (symbolToken(token, "{")) curly++;
    else if (symbolToken(token, "}")) curly = Math.max(0, curly - 1);
    else if (symbolToken(token, "[")) square++;
    else if (symbolToken(token, "]")) square = Math.max(0, square - 1);
    else if (symbolToken(token, "(")) round++;
    else if (symbolToken(token, ")")) round = Math.max(0, round - 1);
    else if (symbolToken(token, "<")) angle++;
    else if (symbolToken(token, ">")) angle = Math.max(0, angle - 1);
  }
  return undefined;
}

function automaticSemicolonBoundary(referenceEnd: Token, following: Token | undefined): boolean {
  if (!following || following.line <= referenceEnd.line) return false;
  if (following.kind === "identifier") {
    return !["as", "in", "instanceof", "of", "satisfies"].includes(following.value);
  }
  return symbolToken(following, "{");
}

function topLevelEnvironmentAliases(
  tokens: readonly Token[],
  before: number,
  typescriptConfig: boolean,
): { aliases: Map<string, ExpoEnvironmentValue>; issues: string[] } {
  const aliases = new Map<string, ExpoEnvironmentValue>();
  const declarations = new Set<string>();
  const issues: string[] = [];
  let curly = 0;
  let square = 0;
  let round = 0;
  for (let index = 0; index < before; index++) {
    const token = tokens[index]!;
    const topLevel = curly === 0 && square === 0 && round === 0;
    if (topLevel && identifierToken(token, "const") && tokens[index + 1]?.kind === "identifier") {
      const name = tokens[index + 1]!.value;
      if (declarations.has(name)) {
        issues.push(`Duplicate top-level const declaration ${name} at line ${token.line}.`);
        aliases.delete(name);
      } else {
        declarations.add(name);
      }
      const equals = declarationEquals(tokens, index + 1, before, typescriptConfig);
      const reference = equals === undefined
        ? undefined
        : environmentReference(tokens, equals + 1, typescriptConfig);
      const following = reference && tokens[reference.next];
      const referenceEnd = reference ? tokens[reference.next - 1] : undefined;
      const asiBoundary = Boolean(referenceEnd && automaticSemicolonBoundary(referenceEnd, following));
      if (
        !issues.some((issue) => issue.includes(` ${name} `)) &&
        reference && (!following || symbolToken(following, ";") || asiBoundary)
      ) {
        aliases.set(name, reference.value);
      }
    }
    if (symbolToken(token, "{")) curly++;
    else if (symbolToken(token, "}")) curly = Math.max(0, curly - 1);
    else if (symbolToken(token, "[")) square++;
    else if (symbolToken(token, "]")) square = Math.max(0, square - 1);
    else if (symbolToken(token, "(")) round++;
    else if (symbolToken(token, ")")) round = Math.max(0, round - 1);
  }
  return { aliases, issues };
}

class StaticValueParser {
  private cursor: number;
  private readonly issues: string[] = [];
  private propertyCount = 0;

  constructor(
    private readonly tokens: readonly Token[],
    start: number,
    private readonly aliases: ReadonlyMap<string, ExpoEnvironmentValue>,
    private readonly codeConfig: boolean,
    private readonly typescriptConfig: boolean,
    private readonly budget: ExpoReadBudget,
  ) {
    this.cursor = start;
  }

  get next(): number {
    return this.cursor;
  }

  get problems(): readonly string[] {
    return this.issues;
  }

  private issue(message: string): void {
    if (this.issues.length < MAX_NOTES) this.issues.push(message);
  }

  private skipExpression(close: string): void {
    let curly = 0;
    let square = 0;
    let round = 0;
    while (this.cursor < this.tokens.length) {
      const token = this.tokens[this.cursor]!;
      if (curly === 0 && square === 0 && round === 0 &&
        (symbolToken(token, ",") || symbolToken(token, close))) return;
      if (symbolToken(token, "{")) curly++;
      else if (symbolToken(token, "}") && curly > 0) curly--;
      else if (symbolToken(token, "[")) square++;
      else if (symbolToken(token, "]") && square > 0) square--;
      else if (symbolToken(token, "(")) round++;
      else if (symbolToken(token, ")") && round > 0) round--;
      this.cursor++;
    }
  }

  parseValue(depth = 0): ExpoStaticValue | undefined {
    if (depth > MAX_DEPTH) {
      this.issue(`Expo config exceeds the ${MAX_DEPTH}-level structural depth bound.`);
      return undefined;
    }
    const token = this.tokens[this.cursor];
    if (!token) {
      this.issue("Expo config ended before a static value was complete.");
      return undefined;
    }
    if (symbolToken(token, "{")) return this.parseObject(depth + 1);
    if (symbolToken(token, "[")) return this.parseArray(depth + 1);
    if (symbolToken(token, "(") && this.codeConfig) {
      this.cursor++;
      const value = this.parseValue(depth + 1);
      if (!symbolToken(this.tokens[this.cursor], ")")) {
        this.issue(`Unsupported parenthesized Expo config expression at line ${token.line}.`);
        return undefined;
      }
      this.cursor++;
      return value;
    }
    if (token.kind === "string") {
      this.cursor++;
      if (token.interpolated) {
        this.issue(`Dynamic template expression in Expo config at line ${token.line}.`);
        return undefined;
      }
      if (!this.codeConfig) {
        try {
          const value: unknown = JSON.parse(token.raw);
          if (typeof value !== "string") throw new Error("not a string");
          return { kind: "string", value, line: token.line };
        } catch {
          this.issue(`Invalid JSON string in Expo config at line ${token.line}.`);
          return undefined;
        }
      }
      return { kind: "string", value: token.value, line: token.line };
    }
    if (token.kind === "number") {
      this.cursor++;
      if (!this.codeConfig && !/^(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(token.value)) {
        this.issue(`Invalid JSON number in Expo config at line ${token.line}.`);
        return undefined;
      }
      return { kind: "number", value: token.value, line: token.line };
    }
    if (symbolToken(token, "-") && this.tokens[this.cursor + 1]?.kind === "number") {
      const number = this.tokens[this.cursor + 1]!;
      this.cursor += 2;
      if (!/^(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(number.value)) {
        this.issue(`Invalid numeric Expo config value at line ${token.line}.`);
        return undefined;
      }
      return { kind: "number", value: `-${number.value}`, line: token.line };
    }
    if (identifierToken(token, "true") || identifierToken(token, "false")) {
      this.cursor++;
      return { kind: "boolean", value: token.value === "true", line: token.line };
    }
    if (identifierToken(token, "null")) {
      this.cursor++;
      return { kind: "null", line: token.line };
    }
    const environment = this.codeConfig
      ? environmentReference(this.tokens, this.cursor, this.typescriptConfig)
      : undefined;
    if (environment) {
      this.cursor = environment.next;
      return environment.value;
    }
    if (this.codeConfig && token.kind === "identifier") {
      const alias = this.aliases.get(token.value);
      if (alias) {
        this.cursor++;
        return { ...alias, line: token.line };
      }
    }
    this.issue(`Unresolved Expo config expression at line ${token.line}.`);
    this.cursor++;
    return undefined;
  }

  private parseArray(depth: number): ExpoArrayValue | undefined {
    const opening = this.tokens[this.cursor++]!;
    const values: ExpoStaticValue[] = [];
    let expectValue = true;
    while (this.cursor < this.tokens.length) {
      const token = this.tokens[this.cursor]!;
      if (symbolToken(token, "]")) {
        this.cursor++;
        return { kind: "array", values, line: opening.line };
      }
      if (!expectValue) {
        this.issue(`Malformed Expo config array at line ${token.line}.`);
        this.skipExpression("]");
      } else if (symbolToken(token, "...")) {
        this.issue(`Unsupported spread in Expo config at line ${token.line}.`);
        this.cursor++;
        this.skipExpression("]");
      } else {
        const value = this.parseValue(depth);
        if (value) values.push(value);
        if (!symbolToken(this.tokens[this.cursor], ",") &&
          !symbolToken(this.tokens[this.cursor], "]")) {
          this.issue(`Unsupported Expo config array expression at line ${token.line}.`);
          this.skipExpression("]");
        }
      }
      if (symbolToken(this.tokens[this.cursor], ",")) {
        this.cursor++;
        expectValue = true;
      } else {
        expectValue = false;
      }
    }
    this.issue(`Unterminated Expo config array at line ${opening.line}.`);
    return undefined;
  }

  private parseObject(depth: number): ExpoObjectValue | undefined {
    const opening = this.tokens[this.cursor++]!;
    const properties: ExpoObjectProperty[] = [];
    const keys = new Set<string>();
    let expectProperty = true;
    while (this.cursor < this.tokens.length) {
      const token = this.tokens[this.cursor]!;
      if (symbolToken(token, "}")) {
        this.cursor++;
        return { kind: "object", properties, line: opening.line };
      }
      if (!expectProperty) {
        this.issue(`Malformed Expo config object at line ${token.line}.`);
        this.skipExpression("}");
      } else if (symbolToken(token, "...")) {
        this.issue(`Unsupported spread in Expo config at line ${token.line}.`);
        this.cursor++;
        this.skipExpression("}");
      } else if (symbolToken(token, "[")) {
        this.issue(`Unsupported computed Expo config key at line ${token.line}.`);
        this.skipExpression("}");
      } else if (
        token.kind !== "identifier" && token.kind !== "string" && token.kind !== "number"
      ) {
        this.issue(`Malformed Expo config property at line ${token.line}.`);
        this.skipExpression("}");
      } else if (this.codeConfig && token.kind === "string" && token.raw.startsWith("`")) {
        this.issue(`Unsupported template-literal Expo config property at line ${token.line}.`);
        this.skipExpression("}");
      } else if (!this.codeConfig && token.kind !== "string") {
        this.issue(`JSON Expo config keys must use double-quoted strings at line ${token.line}.`);
        this.skipExpression("}");
      } else {
        this.cursor++;
        let key = token.value;
        if (!this.codeConfig) {
          try {
            const parsed: unknown = JSON.parse(token.raw);
            if (typeof parsed !== "string") throw new Error("not a string");
            key = parsed;
          } catch {
            this.issue(`Invalid JSON property string at line ${token.line}.`);
          }
        }
        if (keys.has(key)) this.issue(`Duplicate Expo config key ${key} at line ${token.line}.`);
        keys.add(key);
        if (this.propertyCount >= MAX_PROPERTIES) {
          this.issue(`Expo config exceeds the ${MAX_PROPERTIES.toLocaleString()}-property bound.`);
          return undefined;
        }
        if (this.budget.propertiesParsed >= this.budget.maxProperties) {
          this.issue(
            `Expo configs exceed the aggregate ${this.budget.maxProperties.toLocaleString()}-property bound.`,
          );
          return undefined;
        }
        this.propertyCount++;
        this.budget.propertiesParsed++;
        let value: ExpoStaticValue | undefined;
        if (symbolToken(this.tokens[this.cursor], ":")) {
          this.cursor++;
          value = this.parseValue(depth);
        } else if (token.kind === "identifier" && this.aliases.has(key)) {
          const alias = this.aliases.get(key)!;
          value = { ...alias, line: token.line };
        } else {
          this.issue(`Unsupported shorthand or method ${key} in Expo config at line ${token.line}.`);
        }
        if (value) properties.push({ key, line: token.line, value });
        if (!symbolToken(this.tokens[this.cursor], ",") &&
          !symbolToken(this.tokens[this.cursor], "}")) {
          this.issue(`Unsupported Expo config property expression at line ${token.line}.`);
          this.skipExpression("}");
        }
      }
      if (symbolToken(this.tokens[this.cursor], ",")) {
        this.cursor++;
        expectProperty = true;
      } else {
        expectProperty = false;
      }
    }
    this.issue(`Unterminated Expo config object at line ${opening.line}.`);
    return undefined;
  }
}

function skipTypeAssertion(tokens: readonly Token[], start: number): number {
  const assertion = tokens[start];
  if (!identifierToken(assertion, "as") && !identifierToken(assertion, "satisfies")) {
    return start;
  }
  let cursor = start + 1;
  const first = tokens[cursor];
  if (first?.kind !== "identifier") return start;
  if (first.value === "const") {
    return identifierToken(assertion, "as") ? cursor + 1 : start;
  }
  if (["import", "infer", "keyof", "new", "readonly", "typeof", "unique"].includes(first.value)) {
    return start;
  }
  cursor++;
  const unqualifiedRoot = ["false", "function", "null", "this", "true", "void"].includes(first.value);
  while (symbolToken(tokens[cursor], ".")) {
    if (unqualifiedRoot) return start;
    if (tokens[cursor + 1]?.kind !== "identifier") return start;
    cursor += 2;
  }
  while (symbolToken(tokens[cursor], "[")) {
    if (!symbolToken(tokens[cursor + 1], "]")) return start;
    cursor += 2;
  }
  return cursor;
}

function exportStarts(tokens: readonly Token[]): number[] {
  const starts: number[] = [];
  let curly = 0;
  let square = 0;
  let round = 0;
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (curly === 0 && square === 0 && round === 0) {
      if (identifierToken(token, "export") && identifierToken(tokens[index + 1], "default")) {
        starts.push(index + 2);
      }
      else if (
        identifierToken(token, "module") && symbolToken(tokens[index + 1], ".") &&
        identifierToken(tokens[index + 2], "exports") && symbolToken(tokens[index + 3], "=")
      ) starts.push(index + 4);
      else if (
        identifierToken(token, "exports") && symbolToken(tokens[index + 1], ".") &&
        identifierToken(tokens[index + 2], "default") && symbolToken(tokens[index + 3], "=")
      ) starts.push(index + 4);
    }
    if (symbolToken(token, "{")) curly++;
    else if (symbolToken(token, "}")) curly = Math.max(0, curly - 1);
    else if (symbolToken(token, "[")) square++;
    else if (symbolToken(token, "]")) square = Math.max(0, square - 1);
    else if (symbolToken(token, "(")) round++;
    else if (symbolToken(token, ")")) round = Math.max(0, round - 1);
  }
  return starts;
}

function parseStaticRoot(
  source: string,
  codeConfig: boolean,
  typescriptConfig: boolean,
  budget: ExpoReadBudget,
): {
  root?: ExpoObjectValue;
  issues: string[];
} {
  const lexed = lexConfig(source, budget);
  if (lexed.issue) return { issues: [lexed.issue] };
  const starts = codeConfig ? exportStarts(lexed.tokens) : [0];
  if (starts.length !== 1) {
    return {
      issues: [starts.length === 0
        ? "Expo code config has no direct static object export."
        : "Expo code config has multiple top-level exports and is ambiguous."],
    };
  }
  const aliasScan = codeConfig
    ? topLevelEnvironmentAliases(lexed.tokens, starts[0]!, typescriptConfig)
    : { aliases: new Map<string, ExpoEnvironmentValue>(), issues: [] };
  if (aliasScan.issues.length) return { issues: aliasScan.issues.slice(0, MAX_NOTES) };
  const parser = new StaticValueParser(
    lexed.tokens,
    starts[0]!,
    aliasScan.aliases,
    codeConfig,
    typescriptConfig,
    budget,
  );
  const parsed = parser.parseValue();
  let next = parser.next;
  if (typescriptConfig) next = skipTypeAssertion(lexed.tokens, next);
  const issues = [...parser.problems];
  if (symbolToken(lexed.tokens[next], ";")) next++;
  else if (codeConfig && next !== lexed.tokens.length) {
    issues.push(`Unsupported exported Expo config expression at line ${lexed.tokens[next]!.line}.`);
  }
  if (!codeConfig && next !== lexed.tokens.length) issues.push("Malformed trailing JSON config content.");
  if (!parsed || parsed.kind !== "object") {
    issues.push("Expo config root is not a static object.");
    return { issues: [...new Set(issues)].slice(0, MAX_NOTES) };
  }
  if (issues.length) return { issues: [...new Set(issues)].slice(0, MAX_NOTES) };
  return { root: parsed, issues: [] };
}

function notesCollector(): { add: (note: string) => void; finish: () => string[] } {
  const notes = new Set<string>();
  let omitted = 0;
  return {
    add(note) {
      if (notes.has(note)) return;
      if (notes.size < MAX_NOTES - 1) notes.add(note);
      else if (/\bbound\b/i.test(note)) {
        const replaceable = [...notes].find((existing) => !/\bbound\b/i.test(existing));
        if (replaceable) {
          notes.delete(replaceable);
          notes.add(note);
        }
        omitted++;
      } else omitted++;
    },
    finish() {
      return [
        ...notes,
        ...(omitted ? [`${omitted} additional Expo configuration limitations omitted.`] : []),
      ].sort();
    },
  };
}

function relativeConfigPath(root: string, path: string): string {
  const value = relative(root, path).replace(/\\/g, "/");
  return value && !value.startsWith("../") ? value : basename(path);
}

async function readRegularFileBounded(
  path: string,
  expected: Stats,
  budget: ExpoReadBudget,
): Promise<{
  content?: Buffer;
  tooLarge?: true;
  changed?: true;
  budgetExceeded?: true;
}> {
  if (budget.filesRead >= budget.maxFiles || budget.bytesRead >= budget.maxBytes) {
    return { budgetExceeded: true };
  }
  const handle = await open(path, "r");
  budget.filesRead++;
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.dev !== expected.dev ||
      opened.ino !== expected.ino
    ) {
      return { changed: true };
    }
    const remainingBytes = budget.maxBytes - budget.bytesRead;
    if (opened.size > remainingBytes) return { budgetExceeded: true };
    const chunks: Buffer[] = [];
    let total = 0;
    const readCap = Math.min(MAX_CONFIG_BYTES, remainingBytes);
    let reachedEof = false;
    while (total < readCap) {
      const capacity = Math.min(64 * 1024, readCap - total);
      if (capacity <= 0) break;
      const buffer = Buffer.allocUnsafe(capacity);
      const { bytesRead } = await handle.read(buffer, 0, capacity, null);
      if (bytesRead === 0) {
        reachedEof = true;
        break;
      }
      chunks.push(buffer.subarray(0, bytesRead));
      total += bytesRead;
      budget.bytesRead += bytesRead;
    }
    if (!reachedEof && total === readCap) {
      if (readCap < remainingBytes && readCap === MAX_CONFIG_BYTES) {
        const sentinel = Buffer.allocUnsafe(1);
        const { bytesRead } = await handle.read(sentinel, 0, 1, null);
        budget.bytesRead += bytesRead;
        if (bytesRead > 0) return { tooLarge: true };
      } else {
        return { budgetExceeded: true };
      }
    }
    return { content: Buffer.concat(chunks, total) };
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function readableConfig(
  path: string,
  root: string,
  addNote: (note: string) => void,
  budget: ExpoReadBudget,
): Promise<{ path: string; relativePath: string; source: string } | undefined> {
  const relativePath = relativeConfigPath(root, path);
  let metadata;
  try {
    metadata = await lstat(path);
  } catch {
    addNote(`Skipped unreadable Expo config ${relativePath}.`);
    return undefined;
  }
  try {
    if (metadata.isSymbolicLink()) {
      addNote(`Skipped symlinked Expo config ${relativePath}.`);
      return undefined;
    }
    if (!metadata.isFile()) return undefined;
    if (metadata.size > MAX_CONFIG_BYTES) {
      addNote(`Skipped oversized Expo config ${relativePath} (limit: 1 MiB).`);
      return undefined;
    }
    const loaded = await readRegularFileBounded(path, metadata, budget);
    if (loaded.budgetExceeded) {
      addNote(
        `Skipped Expo config ${relativePath} after the aggregate ${budget.maxFiles.toLocaleString()}-file/${budget.maxBytes.toLocaleString()}-byte read bound was reached.`,
      );
      return undefined;
    }
    if (loaded.changed) {
      addNote(`Skipped changed Expo config ${relativePath}.`);
      return undefined;
    }
    if (loaded.tooLarge) {
      addNote(`Skipped oversized Expo config ${relativePath} (limit: 1 MiB).`);
      return undefined;
    }
    const content = loaded.content;
    if (!content) return undefined;
    return { path, relativePath, source: content.toString("utf8") };
  } catch {
    addNote(`Skipped unreadable Expo config ${relativePath}.`);
    return undefined;
  }
}

async function packageDeclaresExpo(
  packagePath: string | undefined,
  scanRoot: string,
  addNote: (note: string) => void,
  budget: ExpoReadBudget,
): Promise<boolean> {
  if (!packagePath) return false;
  const relativePath = relativeConfigPath(scanRoot, packagePath);
  try {
    const metadata = await lstat(packagePath);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      addNote(`Skipped non-regular Expo package manifest ${relativePath}.`);
      return false;
    }
    if (metadata.size > MAX_CONFIG_BYTES) {
      addNote(`Skipped oversized Expo package manifest ${relativePath} (limit: 1 MiB).`);
      return false;
    }
    const loaded = await readRegularFileBounded(packagePath, metadata, budget);
    if (loaded.budgetExceeded) {
      addNote(
        `Skipped Expo package manifest ${relativePath} after the aggregate ${budget.maxFiles.toLocaleString()}-file/${budget.maxBytes.toLocaleString()}-byte read bound was reached.`,
      );
      return false;
    }
    if (loaded.tooLarge) {
      addNote(`Skipped oversized Expo package manifest ${relativePath} (limit: 1 MiB).`);
      return false;
    }
    if (loaded.changed || !loaded.content) {
      addNote(`Skipped changed or unreadable Expo package manifest ${relativePath}.`);
      return false;
    }
    const parsed: unknown = JSON.parse(loaded.content.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const manifest = parsed as Record<string, unknown>;
    return ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
      .some((field) => {
        const dependencies = manifest[field];
        return Boolean(
          dependencies && typeof dependencies === "object" && !Array.isArray(dependencies) &&
          Object.hasOwn(dependencies, "expo"),
        );
      });
  } catch {
    addNote(`Skipped malformed or unreadable Expo package manifest ${relativePath}.`);
    return false;
  }
}

function staticConfigProvesExpo(root: ExpoObjectValue): boolean {
  const expo = root.properties.find((entry) => entry.key === "expo")?.value;
  return expo?.kind === "object";
}

interface DiscoveredExpoRoot {
  candidates: Set<string>;
  unsafeCandidate: boolean;
  packagePath?: string;
  expectedDev?: number;
  expectedIno?: number;
}

function discoveredRoot(
  roots: Map<string, DiscoveredExpoRoot>,
  directory: string,
  identity?: { dev: number; ino: number },
): DiscoveredExpoRoot {
  const existing = roots.get(directory);
  if (existing) {
    if (identity) {
      existing.expectedDev = identity.dev;
      existing.expectedIno = identity.ino;
    }
    return existing;
  }
  const created: DiscoveredExpoRoot = {
    candidates: new Set(),
    unsafeCandidate: false,
    ...(identity ? { expectedDev: identity.dev, expectedIno: identity.ino } : {}),
  };
  roots.set(directory, created);
  return created;
}

function exhaustedBudgetNote(budget: ExpoReadBudget): string | undefined {
  if (budget.filesRead >= budget.maxFiles) {
    return `aggregate ${budget.maxFiles.toLocaleString()}-file read bound reached`;
  }
  if (budget.bytesRead >= budget.maxBytes) {
    return `aggregate ${budget.maxBytes.toLocaleString()}-byte read bound reached`;
  }
  if (budget.tokensParsed >= budget.maxTokens) {
    return `aggregate ${budget.maxTokens.toLocaleString()}-token parse bound reached`;
  }
  if (budget.propertiesParsed >= budget.maxProperties) {
    return `aggregate ${budget.maxProperties.toLocaleString()}-property parse bound reached`;
  }
  return undefined;
}

async function discoverExpoRoots(
  scanRoot: string,
  addNote: (note: string) => void,
  bounds: ExpoDiscoveryBounds,
): Promise<Array<{
  directory: string;
  candidates: string[];
  unsafeCandidate: boolean;
  packagePath?: string;
  expectedDev?: number;
  expectedIno?: number;
}>> {
  const roots = new Map<string, DiscoveredExpoRoot>();
  let entriesSeen = 0;
  let discoveryBoundReached = false;

  async function walk(directory: string, depth: number): Promise<void> {
    if (discoveryBoundReached) return;
    const remainingEntries = bounds.maxEntries - entriesSeen;
    if (remainingEntries <= 0) {
      discoveryBoundReached = true;
      return;
    }
    const entries: Dirent[] = [];
    let directoryIdentity: { dev: number; ino: number } | undefined;
    try {
      const expected = await lstat(directory);
      if (expected.isSymbolicLink() || !expected.isDirectory()) {
        addNote(`Skipped non-regular Expo discovery directory ${relativeConfigPath(scanRoot, directory)}.`);
        return;
      }
      const handle = await opendir(directory);
      try {
        const openedPath = await lstat(directory);
        if (
          openedPath.isSymbolicLink() || !openedPath.isDirectory() ||
          openedPath.dev !== expected.dev || openedPath.ino !== expected.ino
        ) {
          addNote(`Skipped changed Expo discovery directory ${relativeConfigPath(scanRoot, directory)}.`);
          return;
        }
        while (true) {
          const entry = await handle.read();
          if (!entry) break;
          entries.push(entry);
          if (entries.length > remainingEntries) {
            discoveryBoundReached = true;
            entriesSeen = bounds.maxEntries;
            return;
          }
        }
        const finalPath = await lstat(directory);
        if (
          finalPath.isSymbolicLink() || !finalPath.isDirectory() ||
          finalPath.dev !== expected.dev || finalPath.ino !== expected.ino
        ) {
          addNote(`Skipped changed Expo discovery directory ${relativeConfigPath(scanRoot, directory)}.`);
          return;
        }
        directoryIdentity = { dev: finalPath.dev, ino: finalPath.ino };
      } finally {
        await handle.close().catch(() => undefined);
      }
    } catch {
      addNote(`Skipped unreadable Expo discovery directory ${relativeConfigPath(scanRoot, directory)}.`);
      return;
    }
    entriesSeen += entries.length;
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const lowerName = entry.name.toLowerCase();
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(lowerName) || CORPUS_DIRECTORIES.has(lowerName)) continue;
        if (depth >= bounds.maxDepth) {
          addNote(
            `Skipped Expo discovery below ${relativeConfigPath(scanRoot, path)} (depth limit: ${bounds.maxDepth}).`,
          );
          continue;
        }
        await walk(path, depth + 1);
        continue;
      }
      if (entry.isFile()) {
        if (lowerName === "package.json") {
          discoveredRoot(roots, directory, directoryIdentity).packagePath = path;
        }
        if (CONFIG_NAMES.has(lowerName)) {
          discoveredRoot(roots, directory, directoryIdentity).candidates.add(path);
        }
        continue;
      }
      if (entry.isSymbolicLink()) {
        if (IGNORED_DIRECTORIES.has(lowerName) || CORPUS_DIRECTORIES.has(lowerName)) continue;
        addNote(`Skipped symlinked Expo discovery path ${relativeConfigPath(scanRoot, path)}.`);
        if (CONFIG_NAMES.has(lowerName)) {
          discoveredRoot(roots, directory, directoryIdentity).unsafeCandidate = true;
        }
      } else if (CONFIG_NAMES.has(lowerName)) {
        discoveredRoot(roots, directory, directoryIdentity).unsafeCandidate = true;
        addNote(`Skipped non-file Expo config ${relativeConfigPath(scanRoot, path)}.`);
      }
    }
  }

  await walk(scanRoot, 0);
  if (discoveryBoundReached) {
    addNote(
      `Skipped Expo discovery entries beyond the ${bounds.maxEntries.toLocaleString()}-entry bound.`,
    );
  }
  const eligible = [...roots.entries()]
    .filter(([directory, root]) =>
      (root.candidates.size > 0 || root.unsafeCandidate)
        ? directory === scanRoot || root.packagePath !== undefined
        : false
    )
    .sort(([left], [right]) => {
      const leftPath = relative(scanRoot, left).replace(/\\/g, "/") || ".";
      const rightPath = relative(scanRoot, right).replace(/\\/g, "/") || ".";
      return leftPath.localeCompare(rightPath);
    });
  if (eligible.length > bounds.maxProjectRoots) {
    addNote(
      `Skipped ${eligible.length - bounds.maxProjectRoots} Expo project root(s) beyond the ${bounds.maxProjectRoots}-root bound.`,
    );
  }
  return eligible.slice(0, bounds.maxProjectRoots).map(([directory, root]) => ({
    directory,
    candidates: [...root.candidates].sort((left, right) => left.localeCompare(right)),
    unsafeCandidate: root.unsafeCandidate,
    ...(root.packagePath ? { packagePath: root.packagePath } : {}),
    ...(root.expectedDev !== undefined ? { expectedDev: root.expectedDev } : {}),
    ...(root.expectedIno !== undefined ? { expectedIno: root.expectedIno } : {}),
  }));
}

async function projectRootIdentityMatches(
  projectRoot: string,
  expectedDev: number | undefined,
  expectedIno: number | undefined,
): Promise<boolean> {
  if (expectedDev === undefined || expectedIno === undefined) return true;
  try {
    const current = await lstat(projectRoot);
    return !current.isSymbolicLink() && current.isDirectory() &&
      current.dev === expectedDev && current.ino === expectedIno;
  } catch {
    return false;
  }
}

async function parseProjectRoot(
  scanRoot: string,
  projectRoot: string,
  candidatePaths: readonly string[],
  unsafeCandidate: boolean,
  packagePath: string | undefined,
  requireExpoQualification: boolean,
  addNote: (note: string) => void,
  budget: ExpoReadBudget,
  expectedDev?: number,
  expectedIno?: number,
): Promise<ExpoConfigDocument | undefined> {
  const rootLabel = relative(scanRoot, projectRoot).replace(/\\/g, "/") || ".";
  const exhausted = exhaustedBudgetNote(budget);
  if (exhausted) {
    addNote(`Skipped Expo conclusions for ${rootLabel}: ${exhausted}.`);
    return undefined;
  }
  if (!(await projectRootIdentityMatches(projectRoot, expectedDev, expectedIno))) {
    addNote(`Skipped Expo conclusions for ${rootLabel}: the discovered project root changed.`);
    return undefined;
  }
  if (unsafeCandidate) {
    addNote(`Skipped Expo conclusions for ${rootLabel}: a config candidate was not a regular file.`);
    return undefined;
  }
  let skippedCandidate = false;
  let candidates: Array<{ path: string; relativePath: string; source: string }> = [];
  for (const path of candidatePaths) {
    if (!(await projectRootIdentityMatches(projectRoot, expectedDev, expectedIno))) {
      addNote(`Skipped Expo conclusions for ${rootLabel}: the discovered project root changed.`);
      return undefined;
    }
    const loaded = await readableConfig(path, scanRoot, (note) => {
      skippedCandidate = true;
      addNote(note);
    }, budget);
    if (!(await projectRootIdentityMatches(projectRoot, expectedDev, expectedIno))) {
      addNote(`Skipped Expo conclusions for ${rootLabel}: the discovered project root changed.`);
      return undefined;
    }
    if (loaded) candidates.push(loaded);
  }
  if (skippedCandidate) {
    addNote(`Skipped Expo conclusions for ${rootLabel}: a config candidate could not be safely parsed.`);
    return undefined;
  }
  const codeCandidates = candidates.filter((candidate) =>
    CODE_CONFIG_NAMES.includes(
      basename(candidate.path).toLowerCase() as typeof CODE_CONFIG_NAMES[number],
    )
  );
  if (codeCandidates.length > 1) {
    addNote(
      `Skipped ambiguous Expo configuration for ${rootLabel}: multiple code configs (${codeCandidates.map((item) => item.relativePath).sort().join(", ")}).`,
    );
    return undefined;
  }
  if (codeCandidates.length === 1) candidates = codeCandidates;
  else {
    const jsonCandidates = candidates.filter((candidate) =>
      JSON_CONFIG_NAMES.includes(
        basename(candidate.path).toLowerCase() as typeof JSON_CONFIG_NAMES[number],
      )
    );
    if (jsonCandidates.length > 1) {
      addNote(
        `Skipped ambiguous Expo configuration for ${rootLabel}: both ${jsonCandidates.map((item) => item.relativePath).sort().join(" and ")} are present.`,
      );
      return undefined;
    }
    candidates = jsonCandidates;
  }
  const candidate = candidates[0];
  if (!candidate) return undefined;
  const configName = basename(candidate.path).toLowerCase();
  const codeConfig = CODE_CONFIG_NAMES.includes(
    configName as typeof CODE_CONFIG_NAMES[number],
  );
  const parsed = parseStaticRoot(
    candidate.source,
    codeConfig,
    TYPESCRIPT_CONFIG_NAMES.has(configName),
    budget,
  );
  if (!parsed.root) {
    for (const issue of parsed.issues) {
      addNote(`Skipped unresolved Expo config ${candidate.relativePath}: ${issue}`);
    }
    return undefined;
  }
  if (requireExpoQualification && !staticConfigProvesExpo(parsed.root)) {
    if (!(await projectRootIdentityMatches(projectRoot, expectedDev, expectedIno))) {
      addNote(`Skipped Expo conclusions for ${rootLabel}: the discovered project root changed.`);
      return undefined;
    }
    const declared = await packageDeclaresExpo(packagePath, scanRoot, addNote, budget);
    if (!(await projectRootIdentityMatches(projectRoot, expectedDev, expectedIno))) {
      addNote(`Skipped Expo conclusions for ${rootLabel}: the discovered project root changed.`);
      return undefined;
    }
    if (!declared) {
      addNote(`Skipped non-Expo app config at ${candidate.relativePath}.`);
      return undefined;
    }
  }
  return { path: candidate.relativePath, root: parsed.root };
}

function loadedProject(
  target: string,
  root: string,
  documents: ExpoConfigDocument[],
  notes: string[],
): ExpoConfigProject {
  return {
    target,
    root,
    ...(documents.length ? { documents, document: documents[0] } : {}),
    ...(notes.length ? { notes } : {}),
  };
}

async function loadUncached(
  target: string,
  discoveryBounds: ExpoDiscoveryBounds = DEFAULT_DISCOVERY_BOUNDS,
): Promise<ExpoConfigProject> {
  const absoluteTarget = resolve(target);
  const notes = notesCollector();
  const readBudget: ExpoReadBudget = {
    filesRead: 0,
    bytesRead: 0,
    tokensParsed: 0,
    propertiesParsed: 0,
    maxFiles: discoveryBounds.maxReadFiles,
    maxBytes: discoveryBounds.maxReadBytes,
    maxTokens: discoveryBounds.maxTokens,
    maxProperties: discoveryBounds.maxProperties,
  };
  const targetMetadata = await lstat(absoluteTarget).catch(() => undefined);
  if (!targetMetadata) {
    return {
      target: absoluteTarget,
      root: absoluteTarget,
      notes: ["Expo configuration target was unreadable."],
    };
  }
  if (targetMetadata.isSymbolicLink()) {
    return {
      target: absoluteTarget,
      root: dirname(absoluteTarget),
      notes: ["Skipped symlinked Expo configuration target."],
    };
  }

  if (targetMetadata.isFile()) {
    const root = dirname(absoluteTarget);
    if (!CONFIG_NAMES.has(basename(absoluteTarget).toLowerCase())) {
      return { target: absoluteTarget, root };
    }
    const document = await parseProjectRoot(
      root,
      root,
      [absoluteTarget],
      false,
      undefined,
      false,
      notes.add,
      readBudget,
    );
    return loadedProject(absoluteTarget, root, document ? [document] : [], notes.finish());
  }
  if (!targetMetadata.isDirectory()) return { target: absoluteTarget, root: absoluteTarget };

  const roots = await discoverExpoRoots(absoluteTarget, notes.add, discoveryBounds);
  const documents: ExpoConfigDocument[] = [];
  for (const root of roots) {
    const document = await parseProjectRoot(
      absoluteTarget,
      root.directory,
      root.candidates,
      root.unsafeCandidate,
      root.packagePath,
      true,
      notes.add,
      readBudget,
      root.expectedDev,
      root.expectedIno,
    );
    if (document) documents.push(document);
  }
  documents.sort((left, right) => left.path.localeCompare(right.path));
  return loadedProject(absoluteTarget, absoluteTarget, documents, notes.finish());
}

/** Load every bounded eligible Expo project config without evaluating target code. */
export function loadExpoConfig(
  target: string,
  discoveryBounds: Partial<ExpoDiscoveryBounds> = DEFAULT_DISCOVERY_BOUNDS,
): Promise<ExpoConfigProject> {
  return loadUncached(target, constrainedDiscoveryBounds(discoveryBounds));
}

/** One filesystem read/parse shared by the two independent Expo analyzers. */
export function createCachedExpoConfigLoader(target: string): () => Promise<ExpoConfigProject> {
  let cached: Promise<ExpoConfigProject> | undefined;
  return () => cached ??= loadUncached(target);
}

export function resolveExpoConfig(input: ExpoConfigInput): Promise<ExpoConfigProject> {
  if (typeof input === "string") return loadUncached(input);
  return Promise.resolve(input);
}

function property(object: ExpoObjectValue | undefined, key: string): ExpoObjectProperty | undefined {
  return object?.properties.find((candidate) => candidate.key === key);
}

function objectValue(value: ExpoStaticValue | undefined): ExpoObjectValue | undefined {
  return value?.kind === "object" ? value : undefined;
}

function effectiveRoot(document: ExpoConfigDocument): ExpoObjectValue {
  const wrapped = objectValue(property(document.root, "expo")?.value);
  return wrapped ?? document.root;
}

function projectDocuments(project: ExpoConfigProject): ExpoConfigDocument[] {
  return project.documents ?? (project.document ? [project.document] : []);
}

function boundedNotes(values: readonly string[]): string[] {
  const unique = [...new Set(values)].sort();
  if (unique.length <= MAX_NOTES) return unique;
  return [
    ...unique.slice(0, MAX_NOTES - 1),
    `${unique.length - MAX_NOTES + 1} additional Expo analyzer limitations omitted.`,
  ];
}

function publicPathExcluded(path: readonly string[]): boolean {
  if (path[0] === "hooks") return true;
  if (path[0] === "ios" && path[1] === "config") return true;
  if (path[0] === "android" && path[1] === "config") return true;
  return path[0] === "updates" &&
    (path[1] === "codeSigningCertificate" || path[1] === "codeSigningMetadata");
}

function sensitiveEnvironment(name: string): boolean {
  const normalized = name.toUpperCase();
  if (normalized.startsWith("EXPO_PUBLIC_")) return false;
  if (normalized === "MAPBOX_ACCESS_TOKEN") return false;
  if (
    /(?:^|_)SECRET(?:_|$)/.test(normalized) ||
    /(?:^|_)(?:PASSWORD|PASSWD)$/.test(normalized) ||
    /(?:^|_)(?:PRIVATE_KEY|SERVICE_ROLE(?:_KEY)?|SECRET_ACCESS_KEY|DATABASE_URL|DB_URL|CONNECTION_STRING|SIGNING_KEY|ENCRYPTION_KEY)(?:_|$)/
      .test(normalized)
  ) return true;
  return /(?:^|_)(?:ADMIN|API|AUTH|BEARER|BOT|CI|DEPLOY|EAS|EXPO|GITHUB|GITLAB|ID|NETLIFY|NPM|REFRESH|SERVER|SESSION|VERCEL|WEBHOOK|ACCESS)_TOKEN(?:_|$)/
    .test(normalized) ||
    /(?:^|_)(?:ANTHROPIC|OPENAI|RESEND|SENDGRID)_API_KEY$/.test(normalized);
}

interface EnvironmentPlacement {
  reference: ExpoEnvironmentValue;
  path: string[];
  line: number;
}

function environmentPlacements(
  value: ExpoStaticValue,
  path: string[] = [],
  line = value.line,
): EnvironmentPlacement[] {
  if (value.kind === "environment") return [{ reference: value, path, line }];
  if (value.kind === "object") {
    return value.properties.flatMap((entry) =>
      environmentPlacements(entry.value, [...path, entry.key], entry.line)
    );
  }
  if (value.kind === "array") {
    return value.values.flatMap((entry, index) =>
      environmentPlacements(entry, [...path, String(index)], entry.line)
    );
  }
  return [];
}

function secretFinding(document: ExpoConfigDocument, placement: EnvironmentPlacement): Finding {
  const displayPath = placement.path.map((segment) =>
    /^[A-Za-z_$][A-Za-z0-9_$-]{0,63}$/.test(segment) || /^\d+$/.test(segment)
      ? segment
      : "[field]"
  ).join(".") || "<root>";
  return makeAiFinding({
    ruleId: EXPO_SECRET_PUBLIC_CONFIG_RULE_ID,
    title: "Server-side secret is referenced from public Expo configuration",
    severity: "high",
    cwe: ["CWE-798", "CWE-312"],
    owasp_web: ["A02:2021"],
    file: document.path,
    startLine: placement.line,
    snippet: "Public Expo config reads a sensitive environment variable [VALUE REDACTED]",
    message:
      `The public Expo config path ${displayPath} reads a sensitive non-EXPO_PUBLIC environment variable. Expo application configuration is embedded in or otherwise readable from the client application unless the field is one of Expo's documented private config paths.`,
    remediation: {
      summary: "Remove server secrets from Expo client configuration.",
      steps: [
        "Remove the environment reference from the public Expo config path.",
        "Move the secret-dependent operation behind an authenticated server or trusted build-time boundary.",
        "Rotate the credential if a build containing this configuration was distributed.",
      ],
      references: [
        "CWE-798",
        "CWE-312",
        "https://docs.expo.dev/workflow/configuration/",
        "https://docs.expo.dev/guides/environment-variables/",
      ],
    },
    confidence: "high",
    isSecret: true,
  });
}

/** Find sensitive server environment references placed into public Expo config fields. */
export async function runExpoSecretInPublicConfig(
  input: ExpoConfigInput,
): Promise<NativeAnalyzerResult> {
  const project = await resolveExpoConfig(input);
  const findings = projectDocuments(project).flatMap((document) =>
    environmentPlacements(effectiveRoot(document))
      .filter((placement) =>
        !publicPathExcluded(placement.path) && sensitiveEnvironment(placement.reference.name)
      )
      .map((placement) => secretFinding(document, placement))
  );
  return { findings, ...(project.notes?.length ? { notes: project.notes } : {}) };
}

function reservedIpv4(host: string): boolean {
  const octets = host.split(".").map((value) => Number.parseInt(value, 10));
  if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    return true;
  }
  const [a, b, c] = octets as [number, number, number, number];
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && ((b === 0 && (c === 0 || c === 2)) || b === 168 || (b === 88 && c === 99))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113);
}

function ipv6Integer(host: string): bigint | undefined {
  const value = host.replace(/^\[|\]$/g, "").toLowerCase();
  const halves = value.split("::");
  if (halves.length > 2) return undefined;
  const words = (part: string): number[] | undefined => {
    if (!part) return [];
    const parsed: number[] = [];
    for (const word of part.split(":")) {
      if (!/^[\da-f]{1,4}$/.test(word)) return undefined;
      parsed.push(Number.parseInt(word, 16));
    }
    return parsed;
  };
  const left = words(halves[0] ?? "");
  const right = words(halves[1] ?? "");
  if (!left || !right) return undefined;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    return undefined;
  }
  const complete = halves.length === 2
    ? [...left, ...Array.from({ length: missing }, () => 0), ...right]
    : left;
  if (complete.length !== 8) return undefined;
  return complete.reduce((result, word) => (result << 16n) | BigInt(word), 0n);
}

function ipv6InCidr(host: string, base: string, prefixLength: number): boolean {
  const address = ipv6Integer(host);
  const network = ipv6Integer(base);
  if (address === undefined || network === undefined || prefixLength < 0 || prefixLength > 128) {
    return false;
  }
  if (prefixLength === 0) return true;
  const shift = BigInt(128 - prefixLength);
  return (address >> shift) === (network >> shift);
}

function globallyReachableIetfAssignment(host: string): boolean {
  return [
    ["2001:1::1", 128],
    ["2001:1::2", 128],
    ["2001:1::3", 128],
    ["2001:3::", 32],
    ["2001:4:112::", 48],
    ["2001:20::", 28],
    ["2001:30::", 28],
  ].some(([base, prefix]) => ipv6InCidr(host, base as string, prefix as number));
}

function reservedIpv6(host: string): boolean {
  const value = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (value === "::" || value === "::1") return true;
  const mappedHex = /^::ffff:([\da-f]{1,4}):([\da-f]{1,4})$/.exec(value);
  if (mappedHex) {
    const high = Number.parseInt(mappedHex[1]!, 16);
    const low = Number.parseInt(mappedHex[2]!, 16);
    return reservedIpv4([
      high >>> 8,
      high & 0xff,
      low >>> 8,
      low & 0xff,
    ].join("."));
  }
  const mapped = /(?:^|:)ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(value);
  if (mapped) return reservedIpv4(mapped[1]!);
  // Conservative snapshot of IANA's IPv6 Special-Purpose Address Registry.
  // Inside 2001::/23, only the registry's more-specific globally reachable
  // allocations qualify as production evidence.
  if (ipv6InCidr(value, "2001::", 23) && !globallyReachableIetfAssignment(value)) return true;
  if ([
    ["2001:db8::", 32],
    ["2002::", 16],
    ["3fff::", 20],
  ].some(([base, prefix]) => ipv6InCidr(value, base as string, prefix as number))) return true;
  // The rule deliberately limits public literal-IP conclusions to global
  // unicast space; local, multicast, and unallocated prefixes fail closed.
  return !ipv6InCidr(value, "2000::", 3);
}

function productionHttpUrl(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" || !parsed.hostname) return false;
  const host = parsed.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (isIP(host) === 4) return !reservedIpv4(host);
  if (isIP(host) === 6) return !reservedIpv6(host);
  if (!host.includes(".") || /\s/.test(host)) return false;
  if (["example.com", "example.org", "example.net"].some((name) => host === name || host.endsWith(`.${name}`))) {
    return false;
  }
  if (["localhost", "local", "test", "invalid", "example", "localdomain", "internal", "lan", "onion", "alt", "arpa"]
    .some((suffix) => host === suffix || host.endsWith(`.${suffix}`))) return false;
  return host.split(".").every((label) =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
  );
}

function unsignedUpdatesFinding(document: ExpoConfigDocument, url: ExpoStringValue): Finding {
  return makeAiFinding({
    ruleId: EXPO_UNSIGNED_CLEARTEXT_UPDATES_RULE_ID,
    title: "Expo production updates use unsigned cleartext transport",
    severity: "high",
    cwe: ["CWE-494", "CWE-319"],
    owasp_web: ["A08:2021", "A02:2021"],
    file: document.path,
    startLine: url.line,
    snippet: "updates.url uses http:// without a literal code-signing certificate",
    message:
      "Expo updates are enabled with a non-local production HTTP URL and no literal codeSigningCertificate. An attacker able to modify cleartext update traffic could replace application code.",
    remediation: {
      summary: "Require HTTPS and sign production Expo updates.",
      steps: [
        "Change updates.url to an HTTPS endpoint controlled by the application owner.",
        "Configure Expo update code signing with a trusted certificate and verify the runtime policy.",
        "Build and test a production artifact to confirm unsigned or cleartext updates are rejected.",
      ],
      references: [
        "CWE-494",
        "CWE-319",
        "https://docs.expo.dev/eas-update/code-signing/",
        "https://docs.expo.dev/versions/latest/config/app/#updates",
      ],
    },
    confidence: "high",
  });
}

function analyzeUnsignedCleartextDocument(document: ExpoConfigDocument): NativeAnalyzerResult {
  const updatesProperty = property(effectiveRoot(document), "updates");
  if (!updatesProperty) return { findings: [] };
  const updates = objectValue(updatesProperty.value);
  if (!updates) {
    return {
      findings: [],
      notes: [`Skipped unsigned-update conclusion in ${document.path}: updates is not a static object.`],
    };
  }
  const enabled = property(updates, "enabled")?.value;
  const url = property(updates, "url")?.value;
  const certificate = property(updates, "codeSigningCertificate")?.value;
  const dynamicRelevant = [enabled, url, certificate].some((value) => value?.kind === "environment");
  if (dynamicRelevant) {
    return {
      findings: [],
      notes: [`Skipped unsigned-update conclusion in ${document.path}: a relevant updates field is dynamic.`],
    };
  }
  if (enabled?.kind === "boolean" && enabled.value === false) return { findings: [] };
  if (enabled && (enabled.kind !== "boolean" || enabled.value !== true)) {
    return {
      findings: [],
      notes: [`Skipped unsigned-update conclusion in ${document.path}: updates.enabled is not a literal boolean.`],
    };
  }
  if (url && url.kind !== "string") {
    return {
      findings: [],
      notes: [`Skipped unsigned-update conclusion in ${document.path}: updates.url is not a literal string.`],
    };
  }
  if (!url || !productionHttpUrl(url.value)) return { findings: [] };
  if (certificate?.kind === "string" && certificate.value.trim()) return { findings: [] };
  if (certificate && certificate.kind !== "null" && certificate.kind !== "string") {
    return {
      findings: [],
      notes: [`Skipped unsigned-update conclusion in ${document.path}: codeSigningCertificate is not a literal string.`],
    };
  }
  return { findings: [unsignedUpdatesFinding(document, url)] };
}

/** Find explicit production HTTP Expo update endpoints without literal code signing. */
export async function runExpoUnsignedCleartextUpdates(
  input: ExpoConfigInput,
): Promise<NativeAnalyzerResult> {
  const project = await resolveExpoConfig(input);
  const results = projectDocuments(project).map(analyzeUnsignedCleartextDocument);
  const findings = results.flatMap((result) => result.findings);
  const notes = boundedNotes([
    ...(project.notes ?? []),
    ...results.flatMap((result) => [...(result.notes ?? [])]),
  ]);
  return { findings, ...(notes.length ? { notes } : {}) };
}
