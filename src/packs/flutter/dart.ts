/**
 * Small, first-party Dart lexical/structural layer for the Flutter pack.
 *
 * It deliberately stops short of a type-checking AST. Comments and string bodies are
 * atomic lexical regions, bracket pairs are balanced once, and the rules consume calls,
 * arguments, and assignments from tokens instead of matching raw source text.
 */

export type DartTokenKind = "identifier" | "string" | "number" | "symbol";

export interface DartToken {
  kind: DartTokenKind;
  value: string;
  raw: string;
  start: number;
  end: number;
  line: number;
  rawString?: boolean;
}

export interface DartDocument {
  path: string;
  content: string;
  tokens: DartToken[];
  /** Bidirectional token-index map for (), [], and {}. */
  pairs: ReadonlyMap<number, number>;
  balanced: boolean;
}

export interface DartExpression {
  start: number;
  end: number;
  tokens: readonly DartToken[];
}

export interface DartArgument extends DartExpression {
  name?: string;
}

export interface DartCall {
  name: string;
  receiver?: string;
  callee: string;
  tokenIndex: number;
  openIndex: number;
  closeIndex: number;
  line: number;
  arguments: DartArgument[];
}

export interface DartAssignment extends DartExpression {
  name: string;
  tokenIndex: number;
  line: number;
}

export interface DartDefinition {
  name: string;
  tokenIndex: number;
  line: number;
  declaredType?: string;
  expression?: DartExpression;
  /** Function/closure body that bounds a parameter definition. */
  visibilityScope?: number;
}

const IDENTIFIER_START = /[A-Za-z_$]/;
const IDENTIFIER_CONTINUE = /[A-Za-z0-9_$]/;
const DIGIT = /[0-9]/;
const MULTI_SYMBOLS = [
  "...",
  "?..",
  "??=",
  "<<=",
  ">>=",
  "=>",
  "==",
  "!=",
  "<=",
  ">=",
  "&&",
  "||",
  "??",
  "?.",
  "..",
  "++",
  "--",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "<<",
  ">>",
  "&=",
  "|=",
  "^=",
] as const;

function isIdentifierStart(char: string | undefined): boolean {
  return char !== undefined && IDENTIFIER_START.test(char);
}

function isIdentifierContinue(char: string | undefined): boolean {
  return char !== undefined && IDENTIFIER_CONTINUE.test(char);
}

function isDigit(char: string | undefined): boolean {
  return char !== undefined && DIGIT.test(char);
}

function readString(
  source: string,
  start: number,
  line: number,
): { token: DartToken; next: number; line: number } | undefined {
  const rawPrefix = (source[start] === "r" || source[start] === "R") &&
    (source[start + 1] === "'" || source[start + 1] === '"');
  const quoteIndex = rawPrefix ? start + 1 : start;
  const quote = source[quoteIndex];
  if (quote !== "'" && quote !== '"') return undefined;
  const triple = source.slice(quoteIndex, quoteIndex + 3) === quote.repeat(3);
  const delimiterLength = triple ? 3 : 1;
  const bodyStart = quoteIndex + delimiterLength;
  let cursor = bodyStart;
  let currentLine = line;

  while (cursor < source.length) {
    const char = source[cursor]!;
    if (char === "\n") currentLine++;
    if (!rawPrefix && char === "\\") {
      if (source[cursor + 1] === "\n") currentLine++;
      cursor += 2;
      continue;
    }
    if (triple) {
      if (source.slice(cursor, cursor + 3) === quote.repeat(3)) {
        const end = cursor + 3;
        return {
          token: {
            kind: "string",
            value: source.slice(bodyStart, cursor),
            raw: source.slice(start, end),
            start,
            end,
            line,
            rawString: rawPrefix,
          },
          next: end,
          line: currentLine,
        };
      }
    } else if (char === quote) {
      const end = cursor + 1;
      return {
        token: {
          kind: "string",
          value: source.slice(bodyStart, cursor),
          raw: source.slice(start, end),
          start,
          end,
          line,
          rawString: rawPrefix,
        },
        next: end,
        line: currentLine,
      };
    }
    cursor++;
  }

  return {
    token: {
      kind: "string",
      value: source.slice(bodyStart),
      raw: source.slice(start),
      start,
      end: source.length,
      line,
      rawString: rawPrefix,
    },
    next: source.length,
    line: currentLine,
  };
}

export function lexDart(source: string): DartToken[] {
  const tokens: DartToken[] = [];
  let cursor = 0;
  let line = 1;

  while (cursor < source.length) {
    const char = source[cursor]!;
    const next = source[cursor + 1];
    if (char === "\n") {
      line++;
      cursor++;
      continue;
    }
    if (/\s/.test(char)) {
      cursor++;
      continue;
    }

    if (char === "/" && next === "/") {
      cursor += 2;
      while (cursor < source.length && source[cursor] !== "\n") cursor++;
      continue;
    }
    if (char === "/" && next === "*") {
      cursor += 2;
      let depth = 1;
      while (cursor < source.length && depth > 0) {
        if (source[cursor] === "\n") line++;
        if (source[cursor] === "/" && source[cursor + 1] === "*") {
          depth++;
          cursor += 2;
        } else if (source[cursor] === "*" && source[cursor + 1] === "/") {
          depth--;
          cursor += 2;
        } else {
          cursor++;
        }
      }
      continue;
    }

    const string = readString(source, cursor, line);
    if (string) {
      tokens.push(string.token);
      cursor = string.next;
      line = string.line;
      continue;
    }

    if (isIdentifierStart(char)) {
      const start = cursor++;
      while (isIdentifierContinue(source[cursor])) cursor++;
      const raw = source.slice(start, cursor);
      tokens.push({ kind: "identifier", value: raw, raw, start, end: cursor, line });
      continue;
    }

    if (isDigit(char)) {
      const start = cursor++;
      while (isDigit(source[cursor]) || /[A-Fa-f_xX.]/.test(source[cursor] ?? "")) cursor++;
      const raw = source.slice(start, cursor);
      tokens.push({ kind: "number", value: raw, raw, start, end: cursor, line });
      continue;
    }

    const symbol = MULTI_SYMBOLS.find((candidate) => source.startsWith(candidate, cursor)) ?? char;
    tokens.push({
      kind: "symbol",
      value: symbol,
      raw: symbol,
      start: cursor,
      end: cursor + symbol.length,
      line,
    });
    cursor += symbol.length;
  }

  return tokens;
}

function balance(tokens: readonly DartToken[]): { pairs: Map<number, number>; balanced: boolean } {
  const pairs = new Map<number, number>();
  const stack: Array<{ value: string; index: number }> = [];
  const expected: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
  let valid = true;

  for (let index = 0; index < tokens.length; index++) {
    const value = tokens[index]!.value;
    if (value === "(" || value === "[" || value === "{") {
      stack.push({ value, index });
    } else if (value === ")" || value === "]" || value === "}") {
      const open = stack.pop();
      if (!open || open.value !== expected[value]) {
        valid = false;
        continue;
      }
      pairs.set(open.index, index);
      pairs.set(index, open.index);
    }
  }
  return { pairs, balanced: valid && stack.length === 0 };
}

export function parseDartSource(path: string, content: string): DartDocument {
  const tokens = lexDart(content);
  const { pairs, balanced } = balance(tokens);
  return { path, content, tokens, pairs, balanced };
}

function splitArguments(
  tokens: readonly DartToken[],
  start: number,
  end: number,
  pairs: ReadonlyMap<number, number>,
): DartArgument[] {
  const ranges: Array<[number, number]> = [];
  let partStart = start;
  let cursor = start;
  while (cursor < end) {
    const value = tokens[cursor]!.value;
    if (value === "(" || value === "[" || value === "{") {
      const close = pairs.get(cursor);
      if (close !== undefined && close < end) {
        cursor = close + 1;
        continue;
      }
    }
    if (value === ",") {
      if (cursor > partStart) ranges.push([partStart, cursor]);
      partStart = cursor + 1;
    }
    cursor++;
  }
  if (end > partStart) ranges.push([partStart, end]);

  return ranges.map(([rangeStart, rangeEnd]) => {
    let expressionStart = rangeStart;
    let name: string | undefined;
    if (
      tokens[rangeStart]?.kind === "identifier" &&
      tokens[rangeStart + 1]?.value === ":"
    ) {
      name = tokens[rangeStart]!.value;
      expressionStart += 2;
    }
    return {
      ...(name ? { name } : {}),
      start: expressionStart,
      end: rangeEnd,
      tokens: tokens.slice(expressionStart, rangeEnd),
    };
  });
}

function simpleCallee(tokens: readonly DartToken[], beforeOpen: number): {
  name: string;
  receiver?: string;
  callee: string;
  tokenIndex: number;
} | undefined {
  const nameToken = tokens[beforeOpen];
  if (!nameToken || nameToken.kind !== "identifier") return undefined;
  const segments = [nameToken.value];
  let start = beforeOpen;
  let cursor = beforeOpen - 1;
  while (cursor >= 1 && (tokens[cursor]?.value === "." || tokens[cursor]?.value === "?." || tokens[cursor]?.value === "..")) {
    let priorIndex = cursor - 1;
    if (tokens[priorIndex]?.value === "!") priorIndex--;
    if (tokens[priorIndex]?.kind !== "identifier") break;
    const prior = tokens[priorIndex]!.value;
    segments.unshift(prior);
    start = priorIndex;
    cursor = priorIndex - 1;
  }
  const receiver = segments.length > 1 ? segments[segments.length - 2] : undefined;
  return {
    name: nameToken.value,
    ...(receiver ? { receiver } : {}),
    callee: segments.join("."),
    tokenIndex: start,
  };
}

export function dartCalls(document: DartDocument): DartCall[] {
  const calls: DartCall[] = [];
  for (let openIndex = 0; openIndex < document.tokens.length; openIndex++) {
    if (document.tokens[openIndex]!.value !== "(") continue;
    const closeIndex = document.pairs.get(openIndex);
    if (closeIndex === undefined) continue;
    const callee = simpleCallee(document.tokens, openIndex - 1);
    if (!callee) continue;
    calls.push({
      ...callee,
      openIndex,
      closeIndex,
      line: document.tokens[callee.tokenIndex]!.line,
      arguments: splitArguments(document.tokens, openIndex + 1, closeIndex, document.pairs),
    });
  }
  return calls;
}

function expressionEnd(
  tokens: readonly DartToken[],
  start: number,
  pairs: ReadonlyMap<number, number>,
): number {
  let cursor = start;
  while (cursor < tokens.length) {
    const value = tokens[cursor]!.value;
    if (value === "(" || value === "[" || value === "{") {
      const close = pairs.get(cursor);
      if (close !== undefined) {
        cursor = close + 1;
        continue;
      }
    }
    if (value === ";" || value === "," || value === ")" || value === "]" || value === "}") {
      return cursor;
    }
    cursor++;
  }
  return cursor;
}

export function dartAssignments(document: DartDocument): DartAssignment[] {
  const assignments: DartAssignment[] = [];
  for (let equals = 1; equals < document.tokens.length - 1; equals++) {
    if (document.tokens[equals]!.value !== "=") continue;
    const lhs = document.tokens[equals - 1];
    if (!lhs || lhs.kind !== "identifier") continue;
    const beforeLhs = document.tokens[equals - 2]?.value;
    if (beforeLhs === "." || beforeLhs === "?." || beforeLhs === "..") continue;
    const end = expressionEnd(document.tokens, equals + 1, document.pairs);
    if (end <= equals + 1) continue;
    assignments.push({
      name: lhs.value,
      tokenIndex: equals - 1,
      line: lhs.line,
      start: equals + 1,
      end,
      tokens: document.tokens.slice(equals + 1, end),
    });
  }
  return assignments;
}

interface DartAnalysisIndex {
  scopePaths: number[][];
  parameterScopes: ReadonlyMap<number, number>;
  definitions: DartDefinition[];
  definitionsByName: ReadonlyMap<string, readonly DartDefinition[]>;
}

const ANALYSIS_INDEX = new WeakMap<DartDocument, DartAnalysisIndex>();

function buildScopePaths(document: DartDocument): number[][] {
  const paths: number[][] = [];
  const stack: number[] = [];
  for (let index = 0; index < document.tokens.length; index++) {
    const value = document.tokens[index]!.value;
    if (value === "}") {
      const open = document.pairs.get(index);
      if (open !== undefined && stack[stack.length - 1] === open) stack.pop();
    }
    paths[index] = [...stack];
    if (value === "{" && (document.pairs.get(index) ?? -1) > index) stack.push(index);
  }
  return paths;
}

function buildParameterScopes(document: DartDocument): ReadonlyMap<number, number> {
  const scopes = new Map<number, number>();
  for (let open = 0; open < document.tokens.length; open++) {
    if (document.tokens[open]!.value !== "(") continue;
    const close = document.pairs.get(open);
    if (close === undefined || close < open) continue;
    let cursor = close + 1;
    while (
      cursor < document.tokens.length &&
      ["async", "sync", "*"].includes(document.tokens[cursor]!.value)
    ) cursor++;
    if (document.tokens[cursor]?.value !== "{" || !document.pairs.has(cursor)) continue;
    for (let index = open + 1; index < close; index++) scopes.set(index, cursor);
  }
  return scopes;
}

/** Innermost-last lexical brace path for a token. Collection literals are conservative scopes. */
export function lexicalScopePath(document: DartDocument, tokenIndex: number): number[] {
  return analysisIndex(document).scopePaths[tokenIndex] ?? [];
}

export function definitionVisibleAt(
  document: DartDocument,
  definitionIndex: number,
  useIndex: number,
): boolean {
  if (definitionIndex >= useIndex) return false;
  const definitionPath = lexicalScopePath(document, definitionIndex);
  const usePath = lexicalScopePath(document, useIndex);
  return definitionPath.every((scope, index) => usePath[index] === scope);
}

/**
 * Assignment and typed declaration definitions. Typed parameters/declarations are retained
 * even without an initializer so they correctly shadow outer reaching definitions.
 */
function buildDefinitions(
  document: DartDocument,
  parameterScopes: ReadonlyMap<number, number>,
): DartDefinition[] {
  const byKey = new Map<string, DartDefinition>();
  for (const assignment of dartAssignments(document)) {
    byKey.set(`${assignment.tokenIndex}:${assignment.name}`, {
      name: assignment.name,
      tokenIndex: assignment.tokenIndex,
      line: assignment.line,
      expression: assignment,
    });
  }

  for (let index = 0; index < document.tokens.length - 1; index++) {
    const type = document.tokens[index];
    let nameIndex = index + 1;
    if (document.tokens[nameIndex]?.value === "?") nameIndex++;
    const name = document.tokens[nameIndex];
    const after = document.tokens[nameIndex + 1]?.value;
    if (
      type?.kind !== "identifier" ||
      name?.kind !== "identifier" ||
      !["=", ";", ",", ")", "}", ":"].includes(after ?? "")
    ) continue;
    const key = `${nameIndex}:${name.value}`;
    const existing = byKey.get(key);
    const visibilityScope = parameterScopes.get(nameIndex);
    byKey.set(key, {
      name: name.value,
      tokenIndex: nameIndex,
      line: name.line,
      declaredType: type.value,
      ...(existing?.expression ? { expression: existing.expression } : {}),
      ...(visibilityScope !== undefined ? { visibilityScope } : {}),
    });
  }
  return [...byKey.values()].sort((left, right) => left.tokenIndex - right.tokenIndex);
}

function analysisIndex(document: DartDocument): DartAnalysisIndex {
  const existing = ANALYSIS_INDEX.get(document);
  if (existing) return existing;
  const scopePaths = buildScopePaths(document);
  const parameterScopes = buildParameterScopes(document);
  const definitions = buildDefinitions(document, parameterScopes);
  const definitionsByName = new Map<string, DartDefinition[]>();
  for (const definition of definitions) {
    const owned = definitionsByName.get(definition.name) ?? [];
    owned.push(definition);
    definitionsByName.set(definition.name, owned);
  }
  const index = { scopePaths, parameterScopes, definitions, definitionsByName };
  ANALYSIS_INDEX.set(document, index);
  return index;
}

export function dartDefinitions(document: DartDocument): DartDefinition[] {
  return analysisIndex(document).definitions;
}

export function nearestReachingDefinition(
  document: DartDocument,
  name: string,
  useIndex: number,
): DartDefinition | undefined {
  let nearest: DartDefinition | undefined;
  let nearestDepth = -1;
  for (const definition of analysisIndex(document).definitionsByName.get(name) ?? []) {
    const visible = definition.visibilityScope !== undefined
      ? definition.tokenIndex < useIndex &&
        definition.visibilityScope < useIndex &&
        useIndex < (document.pairs.get(definition.visibilityScope) ?? definition.visibilityScope)
      : definitionVisibleAt(document, definition.tokenIndex, useIndex);
    if (!visible) continue;
    const depth = lexicalScopePath(
      document,
      definition.visibilityScope !== undefined ? definition.visibilityScope + 1 : definition.tokenIndex,
    ).length;
    if (
      !nearest ||
      depth > nearestDepth ||
      depth === nearestDepth && definition.tokenIndex > nearest.tokenIndex
    ) {
      nearest = definition;
      nearestDepth = depth;
    }
  }
  return nearest;
}

export function expressionUntilStatementEnd(
  document: DartDocument,
  start: number,
): DartExpression {
  const end = expressionEnd(document.tokens, start, document.pairs);
  return {
    start,
    end,
    tokens: document.tokens.slice(start, end),
  };
}

export function argumentFor(call: DartCall, name: string, positionalIndex = 0): DartArgument | undefined {
  return call.arguments.find((argument) => argument.name === name) ??
    call.arguments.filter((argument) => argument.name === undefined)[positionalIndex];
}

export function hasTokenSequence(tokens: readonly DartToken[], values: readonly string[]): boolean {
  if (values.length === 0) return true;
  outer: for (let index = 0; index <= tokens.length - values.length; index++) {
    for (let offset = 0; offset < values.length; offset++) {
      if (tokens[index + offset]!.value !== values[offset]) continue outer;
    }
    return true;
  }
  return false;
}

export function expressionReferences(expression: DartExpression, names: ReadonlySet<string>): boolean {
  for (const token of expression.tokens) {
    if (token.kind === "identifier" && names.has(token.value)) return true;
    if (token.kind === "string") {
      for (const identifier of interpolationIdentifiers(token)) {
        if (names.has(identifier)) return true;
      }
    }
  }
  return false;
}

export function interpolationIdentifiers(token: DartToken): string[] {
  if (token.kind !== "string" || token.rawString) return [];
  const identifiers: string[] = [];
  for (let index = 0; index < token.value.length; index++) {
    if (token.value[index] !== "$" || token.value[index - 1] === "\\") continue;
    let cursor = index + 1;
    if (token.value[cursor] === "{") cursor++;
    if (!isIdentifierStart(token.value[cursor])) continue;
    const start = cursor++;
    while (isIdentifierContinue(token.value[cursor])) cursor++;
    identifiers.push(token.value.slice(start, cursor));
  }
  return identifiers;
}

export function decodedString(token: DartToken): string {
  if (token.kind !== "string" || token.rawString) return token.value;
  return token.value
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\u\{([0-9A-Fa-f]+)\}/g, (_, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\([\\'"nrt$])/g, (_, escaped: string) => ({ n: "\n", r: "\r", t: "\t" }[escaped] ?? escaped));
}

export function sourceLine(document: DartDocument, line: number): string {
  return document.content.split(/\r?\n/)[line - 1]?.trim() ?? "";
}

export function expressionFromTokens(tokens: readonly DartToken[]): DartExpression {
  return { start: 0, end: tokens.length, tokens };
}
