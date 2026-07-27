/**
 * Bounded Python lexical structure used by the first-party Python packs.
 *
 * This is intentionally not a Python interpreter or type checker. It proves a
 * small set of imports, direct calls, keyword arguments, and assignments while
 * keeping comments and string contents out of the structural token stream.
 */

import { parser as pythonSyntaxParser } from "@lezer/python";

export const PYTHON_MAX_TOKENS_PER_FILE = 200_000;
export const PYTHON_MAX_NESTING = 64;
export const PYTHON_MAX_CST_NODES_PER_FILE = 200_000;
export const PYTHON_MAX_CST_DEPTH = 128;

export type PythonTokenKind = "identifier" | "number" | "string" | "symbol" | "newline";

export interface PythonToken {
  kind: PythonTokenKind;
  value: string;
  raw: string;
  line: number;
  column: number;
  index: number;
  pairIndex?: number;
  staticString?: string;
  dynamicString?: boolean;
}

export interface PythonDocument {
  path: string;
  tokens: PythonToken[];
  balanced: boolean;
  tokenLimitExceeded: boolean;
  nestingLimitExceeded: boolean;
  syntaxError: boolean;
  cstNodeLimitExceeded: boolean;
  cstDepthLimitExceeded: boolean;
  cstNodeCount: number;
  formatStringUnsupported: boolean;
  tabIndentationUnsupported: boolean;
}

export interface PythonExpression {
  tokens: readonly PythonToken[];
  start: number;
  end: number;
}

export interface PythonArgument {
  name?: string;
  expression: PythonExpression;
  spread: boolean;
}

export interface PythonCall {
  reference: string[];
  startIndex: number;
  tokenIndex: number;
  closeIndex: number;
  line: number;
  arguments: PythonArgument[];
}

export interface PythonStatement {
  tokens: readonly PythonToken[];
  start: number;
  end: number;
}

function identifierStart(character: string): boolean {
  return character === "_" || /[A-Za-z]/.test(character) || character.charCodeAt(0) > 127;
}

function identifierContinue(character: string): boolean {
  return identifierStart(character) || /[0-9]/.test(character);
}

interface StringOpening {
  prefix: string;
  quote: "'" | '"';
  quoteLength: 1 | 3;
  openingLength: number;
}

function stringOpening(source: string, index: number): StringOpening | undefined {
  const direct = source[index];
  if (direct === "'" || direct === '"') {
    const quoteLength = source.slice(index, index + 3) === direct.repeat(3) ? 3 : 1;
    return { prefix: "", quote: direct, quoteLength, openingLength: quoteLength };
  }
  let prefix = "";
  for (let length = 1; length <= 2; length++) {
    const candidate = source.slice(index, index + length);
    if (!/^[rRbBuUfF]+$/.test(candidate)) break;
    const quote = source[index + length];
    if (quote !== "'" && quote !== '"') continue;
    const normalized = candidate.toLowerCase();
    if (!["r", "b", "u", "f", "br", "rb", "fr", "rf"].includes(normalized)) continue;
    prefix = candidate;
    const quoteLength = source.slice(index + length, index + length + 3) === quote.repeat(3) ? 3 : 1;
    return {
      prefix,
      quote,
      quoteLength,
      openingLength: prefix.length + quoteLength,
    };
  }
  return undefined;
}

function pushToken(
  tokens: PythonToken[],
  token: Omit<PythonToken, "index">,
): PythonToken {
  const value: PythonToken = { ...token, index: tokens.length };
  tokens.push(value);
  return value;
}

function advancePosition(text: string, line: number, column: number): { line: number; column: number } {
  let nextLine = line;
  let nextColumn = column;
  for (let index = 0; index < text.length; index++) {
    const character = text[index] ?? "";
    if (character === "\r") {
      if (text[index + 1] === "\n") index++;
      nextLine++;
      nextColumn = 1;
    } else if (character === "\n") {
      nextLine++;
      nextColumn = 1;
    } else {
      nextColumn++;
    }
  }
  return { line: nextLine, column: nextColumn };
}

/** Tokenize Python without evaluating imports, annotations, decorators, or expressions. */
export function parsePythonSource(path: string, source: string): PythonDocument {
  const tokens: PythonToken[] = [];
  const delimiterStack: Array<{ value: string; token: PythonToken }> = [];
  // Correctly mixing Python tab stops with spaces requires a full indentation
  // stack. Fail closed on leading tabs instead of treating each tab as one
  // column and accidentally promoting a conditional binding to direct scope.
  const tabIndentationUnsupported = /^(?: *\t)/m.test(source);
  let balanced = !tabIndentationUnsupported;
  let tokenLimitExceeded = false;
  let nestingLimitExceeded = false;
  let formatStringUnsupported = false;
  let line = 1;
  let column = 1;

  const add = (token: Omit<PythonToken, "index">): PythonToken | undefined => {
    if (tokens.length >= PYTHON_MAX_TOKENS_PER_FILE) {
      tokenLimitExceeded = true;
      return undefined;
    }
    return pushToken(tokens, token);
  };

  for (let index = 0; index < source.length;) {
    const character = source[index] ?? "";
    const next = source[index + 1] ?? "";

    if (character === " " || character === "\t" || character === "\f") {
      index++;
      column++;
      continue;
    }
    if (character === "\\" && (next === "\n" || next === "\r")) {
      const length = next === "\r" && source[index + 2] === "\n" ? 3 : 2;
      index += length;
      line++;
      column = 1;
      continue;
    }
    if (character === "\r" || character === "\n") {
      const length = character === "\r" && next === "\n" ? 2 : 1;
      if (delimiterStack.length === 0 && tokens.at(-1)?.kind !== "newline") {
        if (!add({ kind: "newline", value: "\n", raw: source.slice(index, index + length), line, column })) break;
      }
      index += length;
      line++;
      column = 1;
      continue;
    }
    if (character === "#") {
      while (index < source.length && source[index] !== "\n" && source[index] !== "\r") {
        index++;
        column++;
      }
      continue;
    }

    const opening = stringOpening(source, index);
    if (opening) {
      const start = index;
      const startLine = line;
      const startColumn = column;
      const prefix = opening.prefix.toLowerCase();
      // PEP 701 permits nested strings that reuse the outer f-string quote.
      // The bounded lexer does not yet model replacement-field syntax, so
      // continuing here could expose literal contents as executable tokens.
      // Suppress the entire document until format-string ranges are modeled.
      if (prefix.includes("f")) {
        formatStringUnsupported = true;
        balanced = false;
        break;
      }
      const delimiter = opening.quote.repeat(opening.quoteLength);
      index += opening.openingLength;
      column += opening.openingLength;
      const contentStart = index;
      let closed = false;
      while (index < source.length) {
        if (source.startsWith(delimiter, index)) {
          const content = source.slice(contentStart, index);
          index += opening.quoteLength;
          column += opening.quoteLength;
          const raw = source.slice(start, index);
          const dynamicString = prefix.includes("f") || prefix.includes("b");
          const staticString = !dynamicString && (prefix.includes("r") || !content.includes("\\"))
            ? content
            : undefined;
          if (!add({
            kind: "string",
            value: staticString ?? "",
            raw,
            line: startLine,
            column: startColumn,
            ...(staticString !== undefined ? { staticString } : {}),
            ...(dynamicString ? { dynamicString: true } : {}),
          })) break;
          closed = true;
          break;
        }
        const current = source[index] ?? "";
        if (current === "\\" && source[index + 1] !== undefined) {
          const escaped = source.slice(index, index + 2);
          const position = advancePosition(escaped, line, column);
          line = position.line;
          column = position.column;
          index += 2;
          continue;
        }
        if (opening.quoteLength === 1 && (current === "\n" || current === "\r")) break;
        const position = advancePosition(current, line, column);
        line = position.line;
        column = position.column;
        index++;
      }
      if (tokenLimitExceeded) break;
      if (!closed) {
        balanced = false;
        break;
      }
      continue;
    }

    if (identifierStart(character)) {
      const start = index;
      const startColumn = column;
      index++;
      column++;
      while (index < source.length && identifierContinue(source[index] ?? "")) {
        index++;
        column++;
      }
      const raw = source.slice(start, index);
      if (!add({ kind: "identifier", value: raw, raw, line, column: startColumn })) break;
      continue;
    }

    if (/[0-9]/.test(character)) {
      const start = index;
      const startColumn = column;
      index++;
      column++;
      while (index < source.length && /[A-Za-z0-9_.]/.test(source[index] ?? "")) {
        index++;
        column++;
      }
      const raw = source.slice(start, index);
      if (!add({ kind: "number", value: raw, raw, line, column: startColumn })) break;
      continue;
    }

    const three = source.slice(index, index + 3);
    const two = source.slice(index, index + 2);
    const multi = ["**=", "//=", ">>=", "<<=", "..."].includes(three)
      ? three
      : ["==", "!=", "<=", ">=", ":=", "**", "//", "->", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ">>", "<<", "@="].includes(two)
        ? two
        : character;
    const token = add({ kind: "symbol", value: multi, raw: multi, line, column });
    if (!token) break;
    if (["(", "[", "{"].includes(multi)) {
      delimiterStack.push({ value: multi, token });
      if (delimiterStack.length > PYTHON_MAX_NESTING) nestingLimitExceeded = true;
    } else if ([")", "]", "}"].includes(multi)) {
      const expected = multi === ")" ? "(" : multi === "]" ? "[" : "{";
      const openingDelimiter = delimiterStack.pop();
      if (!openingDelimiter || openingDelimiter.value !== expected) {
        balanced = false;
      } else {
        token.pairIndex = openingDelimiter.token.index;
        openingDelimiter.token.pairIndex = token.index;
      }
    }
    index += multi.length;
    column += multi.length;
  }

  if (delimiterStack.length) balanced = false;
  if (tokenLimitExceeded || nestingLimitExceeded) balanced = false;
  let syntaxError = false;
  let cstNodeLimitExceeded = false;
  let cstDepthLimitExceeded = false;
  let cstNodeCount = 0;
  try {
    const cursor = pythonSyntaxParser.parse(source).cursor();
      let nodes = 0;
      let depth = 0;
      let finished = false;
      while (!finished) {
        nodes++;
        cstNodeCount = nodes;
        if (cursor.type.isError) syntaxError = true;
        if (nodes > PYTHON_MAX_CST_NODES_PER_FILE) cstNodeLimitExceeded = true;
        if (depth > PYTHON_MAX_CST_DEPTH) cstDepthLimitExceeded = true;
        if (cstNodeLimitExceeded || cstDepthLimitExceeded) break;
        if (cursor.firstChild()) {
          depth++;
          continue;
        }
        while (!cursor.nextSibling()) {
          if (!cursor.parent()) {
            finished = true;
            break;
          }
          depth--;
        }
      }
  } catch {
    syntaxError = true;
  }
  if (syntaxError || cstNodeLimitExceeded || cstDepthLimitExceeded) balanced = false;
  return {
    path,
    tokens,
    balanced,
    tokenLimitExceeded,
    nestingLimitExceeded,
    syntaxError,
    cstNodeLimitExceeded,
    cstDepthLimitExceeded,
    cstNodeCount,
    formatStringUnsupported,
    tabIndentationUnsupported,
  };
}

export function pythonSignificant(tokens: readonly PythonToken[]): PythonToken[] {
  return tokens.filter((token) => token.kind !== "newline");
}

function expressionFrom(tokens: readonly PythonToken[]): PythonExpression {
  const significant = pythonSignificant(tokens);
  return {
    tokens: significant,
    start: significant[0]?.index ?? -1,
    end: significant.at(-1)?.index ?? -1,
  };
}

export function splitPythonTopLevel(tokens: readonly PythonToken[]): PythonExpression[] {
  const output: PythonExpression[] = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index <= tokens.length; index++) {
    const token = tokens[index];
    if (token?.value === "(" || token?.value === "[" || token?.value === "{") depth++;
    else if (token?.value === ")" || token?.value === "]" || token?.value === "}") depth--;
    if (index === tokens.length || (token?.value === "," && depth === 0)) {
      const expression = expressionFrom(tokens.slice(start, index));
      if (expression.tokens.length) output.push(expression);
      start = index + 1;
    }
  }
  return output;
}

function referenceBefore(tokens: readonly PythonToken[], openIndex: number): { reference: string[]; start: number } | undefined {
  let cursor = openIndex - 1;
  while (tokens[cursor]?.kind === "newline") cursor--;
  if (tokens[cursor]?.kind !== "identifier") return undefined;
  const reference = [tokens[cursor]!.value];
  let start = cursor;
  cursor--;
  while (cursor >= 1) {
    while (tokens[cursor]?.kind === "newline") cursor--;
    if (tokens[cursor]?.value !== ".") break;
    cursor--;
    while (tokens[cursor]?.kind === "newline") cursor--;
    if (tokens[cursor]?.kind !== "identifier") return undefined;
    reference.unshift(tokens[cursor]!.value);
    start = cursor;
    cursor--;
  }
  return { reference, start };
}

function callArguments(tokens: readonly PythonToken[]): PythonArgument[] {
  return splitPythonTopLevel(tokens).map((expression) => {
    const values = expression.tokens;
    const spread = values[0]?.value === "*" || values[0]?.value === "**";
    if (
      values[0]?.kind === "identifier" &&
      values[1]?.value === "="
    ) {
      return {
        name: values[0].value,
        expression: expressionFrom(values.slice(2)),
        spread: false,
      };
    }
    return { expression, spread };
  });
}

/** Enumerate direct name/attribute calls. Chained call results are deliberately unsupported. */
export function pythonCalls(document: PythonDocument): PythonCall[] {
  const calls: PythonCall[] = [];
  if (!document.balanced) return calls;
  for (const token of document.tokens) {
    if (token.value !== "(" || token.pairIndex === undefined) continue;
    const reference = referenceBefore(document.tokens, token.index);
    if (!reference) continue;
    const before = document.tokens[reference.start - 1];
    if (before?.kind === "identifier" && ["def", "class"].includes(before.value)) continue;
    calls.push({
      reference: reference.reference,
      startIndex: reference.start,
      tokenIndex: token.index,
      closeIndex: token.pairIndex,
      line: document.tokens[reference.start]?.line ?? token.line,
      arguments: callArguments(document.tokens.slice(token.index + 1, token.pairIndex)),
    });
  }
  return calls;
}

/** Logical top-level-delimiter statements. Newlines inside brackets were removed by the lexer. */
export function pythonStatements(document: PythonDocument): PythonStatement[] {
  const statements: PythonStatement[] = [];
  let start = 0;
  for (let index = 0; index <= document.tokens.length; index++) {
    const token = document.tokens[index];
    if (index === document.tokens.length || token?.kind === "newline" || token?.value === ";") {
      const significant = pythonSignificant(document.tokens.slice(start, index));
      if (significant.length) {
        statements.push({
          tokens: significant,
          start: significant[0]!.index,
          end: significant.at(-1)!.index,
        });
      }
      start = index + 1;
    }
  }
  return statements;
}

export function pythonExpressionReference(expression: PythonExpression | undefined): string[] | undefined {
  if (!expression) return undefined;
  const tokens = pythonSignificant(expression.tokens);
  if (tokens.length % 2 === 0) return undefined;
  const reference: string[] = [];
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (index % 2 === 0) {
      if (token.kind !== "identifier") return undefined;
      reference.push(token.value);
    } else if (token.value !== ".") return undefined;
  }
  return reference;
}
