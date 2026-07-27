/**
 * Bounded, dependency-free JavaScript/TypeScript/JSX structural layer.
 *
 * This is deliberately smaller than a compiler AST. Comments, quoted strings,
 * templates, and regular-expression literals are atomic; brackets are paired;
 * consumers operate on imports, definitions, calls, and JSX props. Unsupported
 * or malformed shapes fail closed instead of falling back to source regexes.
 */

export type JsTokenKind = "identifier" | "string" | "template" | "number" | "regex" | "symbol";

export interface JsToken {
  kind: JsTokenKind;
  value: string;
  raw: string;
  start: number;
  end: number;
  line: number;
  staticValue?: string;
}

export interface JsDocument {
  path: string;
  content: string;
  tokens: JsToken[];
  pairs: ReadonlyMap<number, number>;
  balanced: boolean;
  lexicalIssues: string[];
  hasDynamicJsxSpread: boolean;
}

export interface JsExpression {
  start: number;
  end: number;
  tokens: readonly JsToken[];
}

export interface JsCall {
  callee: string;
  reference: string[];
  tokenIndex: number;
  openIndex: number;
  closeIndex: number;
  line: number;
  arguments: JsExpression[];
}

export interface JsMemberAssignment {
  reference: string[];
  rootIndex: number;
  tokenIndex: number;
  operator: string;
  scope: readonly number[];
  conditional: boolean;
  expression: JsExpression;
}

export interface JsxProp {
  name: string;
  tokenIndex: number;
  line: number;
  kind: "boolean" | "literal" | "expression" | "spread";
  expression: JsExpression;
}

export interface JsxElement {
  reference: string[];
  tokenIndex: number;
  closeIndex: number;
  line: number;
  props: JsxProp[];
  hasSpread: boolean;
}

export interface ImportOrigin {
  source: string;
  imported: string;
  namespace: boolean;
}

export interface JsDefinition {
  name: string;
  tokenIndex: number;
  scope: readonly number[];
  visibilityEnd: number;
  kind?: "import" | "parameter" | "declaration" | "assignment" | "function";
  hoisted?: boolean;
  expression?: JsExpression;
  origin?: ImportOrigin;
}

const IDENTIFIER_START = /[A-Za-z_$]/;
const IDENTIFIER_CONTINUE = /[A-Za-z0-9_$]/;
const DIGIT = /[0-9]/;
const MULTI_SYMBOLS = [
  "===", "!==", ">>>", "**=", "&&=", "||=", "??=", "...", "=>", "==", "!=",
  "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=",
  "%=", "**", "<<", ">>", "&=", "|=", "^=", "</", "/>",
] as const;
export const REACT_NATIVE_MAX_JS_TOKENS = 200_000;
export const REACT_NATIVE_MAX_JS_NESTING = 64;
const MAX_TEMPLATE_NESTING = 64;

function identifierStart(char: string | undefined): boolean {
  return char !== undefined && IDENTIFIER_START.test(char);
}

function identifierContinue(char: string | undefined): boolean {
  return char !== undefined && IDENTIFIER_CONTINUE.test(char);
}

function digit(char: string | undefined): boolean {
  return char !== undefined && DIGIT.test(char);
}

function readQuoted(
  source: string,
  start: number,
  line: number,
): { token: JsToken; next: number; line: number; terminated: boolean } {
  const quote = source[start]!;
  let cursor = start + 1;
  let currentLine = line;
  let value = "";
  while (cursor < source.length) {
    const char = source[cursor]!;
    if (char === "\\") {
      const escaped = source[cursor + 1];
      if (escaped === "\n") currentLine++;
      if (escaped !== undefined) value += source.slice(cursor, cursor + 2);
      cursor += 2;
      continue;
    }
    if (char === quote) {
      const end = cursor + 1;
      return {
        token: {
          kind: "string",
          value: source.slice(start, end),
          staticValue: decodeQuotedValue(value),
          raw: source.slice(start, end),
          start,
          end,
          line,
        },
        next: end,
        line: currentLine,
        terminated: true,
      };
    }
    if (char === "\n") {
      return {
        token: {
          kind: "string",
          value: source.slice(start),
          raw: source.slice(start),
          start,
          end: source.length,
          line,
        },
        next: source.length,
        line: currentLine + 1,
        terminated: false,
      };
    }
    value += char;
    cursor++;
  }
  return {
    token: {
      kind: "string",
      value: source.slice(start),
      raw: source.slice(start),
      start,
      end: source.length,
      line,
    },
    next: source.length,
    line: currentLine,
    terminated: false,
  };
}

function decodeQuotedValue(value: string): string {
  return value.replace(/\\(?:u\{([0-9A-Fa-f]+)\}|u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2})|([\\'"bfnrtv0]))/g,
    (_match, unicodePoint: string | undefined, unicode: string | undefined, hex: string | undefined, simple: string | undefined) => {
      const digits = unicodePoint ?? unicode ?? hex;
      if (digits) {
        const codePoint = Number.parseInt(digits, 16);
        return Number.isFinite(codePoint) ? String.fromCodePoint(codePoint) : "";
      }
      const escapes: Record<string, string> = {
        "\\": "\\", "'": "'", "\"": "\"", b: "\b", f: "\f", n: "\n",
        r: "\r", t: "\t", v: "\v", "0": "\0",
      };
      return escapes[simple ?? ""] ?? simple ?? "";
    });
}

function readTemplate(
  source: string,
  start: number,
  line: number,
  nesting = 0,
): { token: JsToken; next: number; line: number; terminated: boolean } {
  if (nesting > MAX_TEMPLATE_NESTING) {
    return {
      token: {
        kind: "template",
        value: source.slice(start),
        raw: source.slice(start),
        start,
        end: source.length,
        line,
      },
      next: source.length,
      line,
      terminated: false,
    };
  }
  let cursor = start + 1;
  let currentLine = line;
  let dynamic = false;
  let escaped = false;
  let interpolationDepth = 0;
  while (cursor < source.length) {
    const char = source[cursor]!;
    if (char === "\n") currentLine++;
    if (escaped) {
      escaped = false;
      cursor++;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      cursor++;
      continue;
    }
    if (interpolationDepth > 0 && (char === "'" || char === "\"")) {
      const quoted = readQuoted(source, cursor, currentLine);
      cursor = quoted.next;
      currentLine = quoted.line;
      continue;
    }
    if (interpolationDepth > 0 && char === "`") {
      const nested = readTemplate(source, cursor, currentLine, nesting + 1);
      cursor = nested.next;
      currentLine = nested.line;
      if (!nested.terminated) break;
      continue;
    }
    if (interpolationDepth > 0 && char === "/" && source[cursor + 1] === "/") {
      cursor += 2;
      while (cursor < source.length && source[cursor] !== "\n") cursor++;
      continue;
    }
    if (interpolationDepth > 0 && char === "/" && source[cursor + 1] === "*") {
      cursor += 2;
      while (cursor < source.length && !(source[cursor] === "*" && source[cursor + 1] === "/")) {
        if (source[cursor] === "\n") currentLine++;
        cursor++;
      }
      cursor = Math.min(source.length, cursor + 2);
      continue;
    }
    if (char === "$" && source[cursor + 1] === "{") {
      dynamic = true;
      interpolationDepth++;
      cursor += 2;
      continue;
    }
    if (interpolationDepth > 0 && char === "{") {
      interpolationDepth++;
      cursor++;
      continue;
    }
    if (interpolationDepth > 0 && char === "}") {
      interpolationDepth--;
      cursor++;
      continue;
    }
    if (char === "`" && interpolationDepth === 0) {
      const end = cursor + 1;
      const body = source.slice(start + 1, cursor);
      return {
        token: {
          kind: "template",
          value: source.slice(start, end),
          ...(dynamic ? {} : { staticValue: decodeQuotedValue(body) }),
          raw: source.slice(start, end),
          start,
          end,
          line,
        },
        next: end,
        line: currentLine,
        terminated: true,
      };
    }
    cursor++;
  }
  return {
    token: {
      kind: "template",
      value: source.slice(start),
      raw: source.slice(start),
      start,
      end: source.length,
      line,
    },
    next: source.length,
    line: currentLine,
    terminated: false,
  };
}

function canStartRegex(previous: JsToken | undefined): boolean {
  if (!previous) return true;
  if (previous.kind === "identifier" && ![
    "return", "throw", "case", "delete", "void", "typeof", "instanceof", "in", "of", "yield", "await",
  ].includes(previous.value)) return false;
  if (previous.kind === "number" || previous.kind === "string" || previous.kind === "template" || previous.kind === "regex") {
    return false;
  }
  return ![")", "]", "}", "++", "--"].includes(previous.value);
}

function readRegex(
  source: string,
  start: number,
  line: number,
): { token: JsToken; next: number; terminated: boolean } {
  let cursor = start + 1;
  let escaped = false;
  let characterClass = false;
  while (cursor < source.length && source[cursor] !== "\n") {
    const char = source[cursor]!;
    if (escaped) {
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (char === "[") {
      characterClass = true;
    } else if (char === "]") {
      characterClass = false;
    } else if (char === "/" && !characterClass) {
      cursor++;
      while (/[A-Za-z]/.test(source[cursor] ?? "")) cursor++;
      return {
        token: {
          kind: "regex",
          value: source.slice(start, cursor),
          raw: source.slice(start, cursor),
          start,
          end: cursor,
          line,
        },
        next: cursor,
        terminated: true,
      };
    }
    cursor++;
  }
  return {
    token: {
      kind: "symbol",
      value: "/",
      raw: "/",
      start,
      end: start + 1,
      line,
    },
    next: start + 1,
    terminated: false,
  };
}

export function lexJavaScript(
  source: string,
  maxTokens = REACT_NATIVE_MAX_JS_TOKENS,
): { tokens: JsToken[]; issues: string[] } {
  if (!Number.isSafeInteger(maxTokens) || maxTokens < 1) {
    throw new Error("Invalid JavaScript/TypeScript token bound.");
  }
  const tokens: JsToken[] = [];
  const issues: string[] = [];
  const appendToken = (token: JsToken): boolean => {
    if (tokens.length >= maxTokens) {
      issues.push(`JavaScript/TypeScript token bound exceeded (${maxTokens}).`);
      return false;
    }
    tokens.push(token);
    return true;
  };
  let cursor = 0;
  let line = 1;
  if (source.startsWith("#!")) {
    while (cursor < source.length && source[cursor] !== "\n") cursor++;
  }

  scan: while (cursor < source.length) {
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
      const startLine = line;
      cursor += 2;
      let terminated = false;
      while (cursor < source.length) {
        if (source[cursor] === "\n") line++;
        if (source[cursor] === "*" && source[cursor + 1] === "/") {
          cursor += 2;
          terminated = true;
          break;
        }
        cursor++;
      }
      if (!terminated) issues.push(`Unterminated block comment at line ${startLine}.`);
      continue;
    }
    if (char === "'" || char === "\"") {
      const result = readQuoted(source, cursor, line);
      if (!appendToken(result.token)) break scan;
      if (!result.terminated) issues.push(`Unterminated quoted string at line ${line}.`);
      cursor = result.next;
      line = result.line;
      continue;
    }
    if (char === "`") {
      const result = readTemplate(source, cursor, line);
      if (!appendToken(result.token)) break scan;
      if (!result.terminated) issues.push(`Unterminated template literal at line ${line}.`);
      cursor = result.next;
      line = result.line;
      continue;
    }
    if (char === "/" && next !== "=" && canStartRegex(tokens.at(-1))) {
      const result = readRegex(source, cursor, line);
      if (!appendToken(result.token)) break scan;
      if (!result.terminated) issues.push(`Unterminated regular-expression literal at line ${line}.`);
      cursor = result.next;
      continue;
    }
    if (identifierStart(char)) {
      const start = cursor++;
      while (identifierContinue(source[cursor])) cursor++;
      const raw = source.slice(start, cursor);
      if (!appendToken({ kind: "identifier", value: raw, raw, start, end: cursor, line })) break scan;
      continue;
    }
    if (digit(char)) {
      const start = cursor++;
      while (/[A-Fa-f0-9_xXobOB.eE+-]/.test(source[cursor] ?? "")) cursor++;
      const raw = source.slice(start, cursor);
      if (!appendToken({ kind: "number", value: raw, raw, start, end: cursor, line })) break scan;
      continue;
    }
    const symbol = MULTI_SYMBOLS.find((candidate) => source.startsWith(candidate, cursor)) ?? char;
    if (!appendToken({
      kind: "symbol",
      value: symbol,
      raw: symbol,
      start: cursor,
      end: cursor + symbol.length,
      line,
    })) break scan;
    cursor += symbol.length;
  }
  return { tokens, issues };
}

function balance(tokens: readonly JsToken[]): { pairs: Map<number, number>; balanced: boolean; maxDepth: number } {
  const pairs = new Map<number, number>();
  const stack: Array<{ token: string; index: number }> = [];
  const opening: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
  let valid = true;
  let maxDepth = 0;
  for (let index = 0; index < tokens.length; index++) {
    const value = tokens[index]!.value;
    if (value === "(" || value === "[" || value === "{") {
      stack.push({ token: value, index });
      maxDepth = Math.max(maxDepth, stack.length);
      if (maxDepth > REACT_NATIVE_MAX_JS_NESTING) {
        valid = false;
        break;
      }
    } else if (value === ")" || value === "]" || value === "}") {
      const candidate = stack.pop();
      if (!candidate || candidate.token !== opening[value]) {
        valid = false;
        continue;
      }
      pairs.set(candidate.index, index);
      pairs.set(index, candidate.index);
    }
  }
  return { pairs, balanced: valid && stack.length === 0, maxDepth };
}

export function parseJavaScriptSource(path: string, content: string): JsDocument {
  const { tokens, issues } = lexJavaScript(content);
  const paired = balance(tokens);
  if (paired.maxDepth > REACT_NATIVE_MAX_JS_NESTING) {
    issues.push(`JavaScript/TypeScript structural nesting bound exceeded (${REACT_NATIVE_MAX_JS_NESTING}).`);
  }
  const document: JsDocument = {
    path,
    content,
    tokens,
    pairs: paired.pairs,
    balanced: paired.balanced && issues.length === 0,
    lexicalIssues: issues,
    hasDynamicJsxSpread: false,
  };
  document.hasDynamicJsxSpread = jsxElements(document).some((element) => element.hasSpread);
  return document;
}

export function expression(tokens: readonly JsToken[], start = 0, end = tokens.length): JsExpression {
  return { start, end, tokens: tokens.slice(start, end) };
}

function splitTopLevel(
  document: JsDocument,
  start: number,
  end: number,
  separator = ",",
): JsExpression[] {
  const results: JsExpression[] = [];
  let partStart = start;
  let cursor = start;
  while (cursor < end) {
    const token = document.tokens[cursor]!;
    if (token.value === "(" || token.value === "[" || token.value === "{") {
      const close = document.pairs.get(cursor);
      if (close !== undefined && close < end) {
        cursor = close + 1;
        continue;
      }
    }
    if (token.value === separator) {
      if (cursor > partStart) results.push(expression(document.tokens, partStart, cursor));
      partStart = cursor + 1;
    }
    cursor++;
  }
  if (end > partStart) results.push(expression(document.tokens, partStart, end));
  return results.filter((item) => item.tokens.length > 0);
}

function referenceBefore(tokens: readonly JsToken[], index: number): { reference: string[]; start: number } | undefined {
  if (tokens[index]?.kind !== "identifier") return undefined;
  const parts = [tokens[index]!.value];
  let cursor = index - 1;
  let start = index;
  while (
    cursor >= 1 &&
    (tokens[cursor]!.value === "." || tokens[cursor]!.value === "?.") &&
    tokens[cursor - 1]!.kind === "identifier"
  ) {
    parts.unshift(tokens[cursor - 1]!.value);
    start = cursor - 1;
    cursor -= 2;
  }
  return { reference: parts, start };
}

const callsCache = new WeakMap<JsDocument, JsCall[]>();

export function jsCalls(document: JsDocument): JsCall[] {
  const cached = callsCache.get(document);
  if (cached) return cached;
  if (!document.balanced) {
    callsCache.set(document, []);
    return [];
  }
  const calls: JsCall[] = [];
  for (let openIndex = 1; openIndex < document.tokens.length; openIndex++) {
    if (document.tokens[openIndex]!.value !== "(") continue;
    const closeIndex = document.pairs.get(openIndex);
    if (closeIndex === undefined || closeIndex <= openIndex) continue;
    const calleeToken = document.tokens[openIndex - 1]!;
    const ref = referenceBefore(document.tokens, openIndex - 1);
    if (!ref || ["if", "for", "while", "switch", "catch", "with"].includes(calleeToken.value)) continue;
    calls.push({
      callee: calleeToken.value,
      reference: ref.reference,
      tokenIndex: openIndex - 1,
      openIndex,
      closeIndex,
      line: calleeToken.line,
      arguments: splitTopLevel(document, openIndex + 1, closeIndex),
    });
  }
  callsCache.set(document, calls);
  return calls;
}

const memberAssignmentCache = new WeakMap<JsDocument, JsMemberAssignment[]>();

function sameScope(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((open, index) => right[index] === open);
}

/** True when a token is governed by an unbraced branch/loop or short-circuit expression. */
export function isConditionallyExecuted(document: JsDocument, tokenIndex: number): boolean {
  const tokens = document.tokens;
  const targetScope = lexicalScopeAt(document, tokenIndex);
  const controls = new Set(["if", "for", "while", "with"]);
  for (let index = 0; index < tokenIndex; index++) {
    if (!controls.has(tokens[index]!.value) || tokens[index + 1]?.value !== "(") continue;
    if (!sameScope(lexicalScopeAt(document, index), targetScope)) continue;
    const close = document.pairs.get(index + 1);
    if (close === undefined || close >= tokenIndex) continue;
    const bodyStart = close + 1;
    if (tokens[bodyStart]?.value === "{") continue;
    const bodyEnd = statementExpressionEnd(document, bodyStart);
    if (tokenIndex >= bodyStart && tokenIndex < bodyEnd) return true;
  }
  for (let index = 0; index < tokenIndex; index++) {
    if (tokens[index]!.value !== "else" || !sameScope(lexicalScopeAt(document, index), targetScope)) continue;
    const bodyStart = index + 1;
    if (tokens[bodyStart]?.value === "{") continue;
    const bodyEnd = statementExpressionEnd(document, bodyStart);
    if (tokenIndex >= bodyStart && tokenIndex < bodyEnd) return true;
  }
  let statementStart = tokenIndex - 1;
  while (statementStart >= 0 && ![";", "{", "}"].includes(tokens[statementStart]!.value)) statementStart--;
  return tokens.slice(statementStart + 1, tokenIndex).some((token) =>
    ["&&", "||", "??", "?"].includes(token.value)
  );
}

export function jsMemberAssignments(document: JsDocument): JsMemberAssignment[] {
  const cached = memberAssignmentCache.get(document);
  if (cached) return cached;
  if (!document.balanced) {
    memberAssignmentCache.set(document, []);
    return [];
  }
  const assignments: JsMemberAssignment[] = [];
  const tokens = document.tokens;
  const assignmentOperators = new Set(["=", "+=", "-=", "*=", "/=", "%=", "&&=", "||=", "??="]);
  for (let equals = 1; equals < tokens.length - 1; equals++) {
    if (!assignmentOperators.has(tokens[equals]!.value)) continue;
    let reference: string[] | undefined;
    let rootIndex: number | undefined;
    if (tokens[equals - 1]?.kind === "identifier") {
      reference = [tokens[equals - 1]!.value];
      rootIndex = equals - 1;
      let cursor = equals - 2;
      while (
        cursor >= 1 && [".", "?."].includes(tokens[cursor]!.value) &&
        tokens[cursor - 1]?.kind === "identifier"
      ) {
        reference.unshift(tokens[cursor - 1]!.value);
        rootIndex = cursor - 1;
        cursor -= 2;
      }
    } else if (tokens[equals - 1]?.value === "]") {
      const open = document.pairs.get(equals - 1);
      const root = open === undefined ? undefined : referenceBefore(tokens, open - 1);
      if (open !== undefined && root) {
        const keyTokens = tokens.slice(open + 1, equals - 1);
        const property = keyTokens.length === 1 && keyTokens[0]?.staticValue !== undefined
          ? keyTokens[0].staticValue
          : "*";
        reference = [...root.reference, property];
        rootIndex = root.start;
      }
    }
    if (!reference || rootIndex === undefined) continue;
    if (reference.length < 2) continue;
    assignments.push({
      reference,
      rootIndex,
      tokenIndex: equals,
      operator: tokens[equals]!.value,
      scope: lexicalScopeAt(document, rootIndex),
      conditional: isConditionallyExecuted(document, equals),
      expression: expression(tokens, equals + 1, statementExpressionEnd(document, equals + 1)),
    });
  }
  memberAssignmentCache.set(document, assignments);
  return assignments;
}

export function referenceHasMutation(
  document: JsDocument,
  root: string,
  beforeIndex: number,
): boolean {
  const rootDefinition = nearestDefinition(document, root, beforeIndex);
  if (jsMemberAssignments(document).some((assignment) =>
    assignment.tokenIndex < beforeIndex &&
    (rootDefinition
      ? referenceTargetsDefinition(document, assignment.reference[0]!, assignment.rootIndex, rootDefinition)
      : assignment.reference[0] === root)
  )) return true;
  for (let index = 0; index < beforeIndex; index++) {
    const value = document.tokens[index]!.value;
    if (value !== "delete" && !["++", "--"].includes(value)) continue;
    const member = memberReferenceStartingAt(document, index + 1);
    if (
      member && member.reference.length > 1 &&
      (rootDefinition
        ? referenceTargetsDefinition(document, member.reference[0]!, index + 1, rootDefinition)
        : member.reference[0] === root)
    ) return true;
  }
  return jsCalls(document).some((call) => {
    if (
      call.closeIndex >= beforeIndex || call.reference.length !== 2 ||
      !["Object.assign", "Object.defineProperty", "Reflect.set"].includes(call.reference.join("."))
    ) return false;
    const targetExpression = call.arguments[0];
    const reference = targetExpression ? simpleReference(targetExpression) : undefined;
    return reference?.length === 1 && (rootDefinition
      ? referenceTargetsDefinition(document, reference[0]!, targetExpression!.start, rootDefinition)
      : reference[0] === root);
  });
}

function jsxReference(tokens: readonly JsToken[], index: number): { reference: string[]; end: number } | undefined {
  if (tokens[index]?.kind !== "identifier") return undefined;
  const reference = [tokens[index]!.value];
  let cursor = index + 1;
  while (tokens[cursor]?.value === "." && tokens[cursor + 1]?.kind === "identifier") {
    reference.push(tokens[cursor + 1]!.value);
    cursor += 2;
  }
  return { reference, end: cursor };
}

const jsxCache = new WeakMap<JsDocument, JsxElement[]>();

export function jsxElements(document: JsDocument): JsxElement[] {
  const cached = jsxCache.get(document);
  if (cached) return cached;
  if (!document.balanced) {
    jsxCache.set(document, []);
    return [];
  }
  const elements: JsxElement[] = [];
  const tokens = document.tokens;
  for (let index = 0; index < tokens.length - 1; index++) {
    if (tokens[index]!.value !== "<" || tokens[index + 1]?.kind !== "identifier") continue;
    const ref = jsxReference(tokens, index + 1);
    if (!ref || !/^[A-Z]/.test(ref.reference.at(-1) ?? "")) continue;
    let closeIndex = ref.end;
    while (closeIndex < tokens.length) {
      const value = tokens[closeIndex]!.value;
      if (value === "{" || value === "(" || value === "[") {
        const close = document.pairs.get(closeIndex);
        if (close === undefined) break;
        closeIndex = close + 1;
        continue;
      }
      if (value === ">" || value === "/>") break;
      if (value === ";") break;
      closeIndex++;
    }
    if (closeIndex >= tokens.length || ![">", "/>"].includes(tokens[closeIndex]!.value)) continue;

    const props: JsxProp[] = [];
    let hasSpread = false;
    let cursor = ref.end;
    while (cursor < closeIndex) {
      const token = tokens[cursor]!;
      if (token.value === "{") {
        const close = document.pairs.get(cursor);
        if (close === undefined || close > closeIndex) break;
        if (tokens[cursor + 1]?.value === "...") {
          hasSpread = true;
          props.push({
            name: "...",
            tokenIndex: cursor,
            line: token.line,
            kind: "spread",
            expression: expression(tokens, cursor + 2, close),
          });
        }
        cursor = close + 1;
        continue;
      }
      if (token.kind !== "identifier") {
        cursor++;
        continue;
      }
      const name = token.value;
      if (tokens[cursor + 1]?.value !== "=") {
        props.push({
          name,
          tokenIndex: cursor,
          line: token.line,
          kind: "boolean",
          expression: expression([{ ...token, kind: "identifier", value: "true", raw: "true" }]),
        });
        cursor++;
        continue;
      }
      const valueIndex = cursor + 2;
      const valueToken = tokens[valueIndex];
      if (!valueToken) break;
      if (valueToken.kind === "string" || valueToken.kind === "template") {
        props.push({
          name,
          tokenIndex: cursor,
          line: token.line,
          kind: "literal",
          expression: expression(tokens, valueIndex, valueIndex + 1),
        });
        cursor = valueIndex + 1;
        continue;
      }
      if (valueToken.value === "{") {
        const close = document.pairs.get(valueIndex);
        if (close === undefined || close > closeIndex) break;
        props.push({
          name,
          tokenIndex: cursor,
          line: token.line,
          kind: "expression",
          expression: expression(tokens, valueIndex + 1, close),
        });
        cursor = close + 1;
        continue;
      }
      // Invalid JSX value: retain it as dynamic so rules fail closed.
      props.push({
        name,
        tokenIndex: cursor,
        line: token.line,
        kind: "expression",
        expression: expression(tokens, valueIndex, Math.min(valueIndex + 1, closeIndex)),
      });
      cursor = valueIndex + 1;
    }
    elements.push({
      reference: ref.reference,
      tokenIndex: index + 1,
      closeIndex,
      line: tokens[index + 1]!.line,
      props,
      hasSpread,
    });
    index = closeIndex;
  }
  jsxCache.set(document, elements);
  return elements;
}

export function jsxProp(element: JsxElement, name: string): JsxProp | undefined {
  // React/JSX applies duplicate props in source order; the final explicit prop wins.
  return [...element.props].reverse().find((prop) => prop.name === name);
}

const scopePathCache = new WeakMap<JsDocument, readonly (readonly number[])[]>();

function scopePaths(document: JsDocument): readonly (readonly number[])[] {
  const cached = scopePathCache.get(document);
  if (cached) return cached;
  const paths: number[][] = [];
  const stack: number[] = [];
  for (let index = 0; index < document.tokens.length; index++) {
    const token = document.tokens[index]!;
    if (token.value === "}") {
      const open = document.pairs.get(index);
      const position = open === undefined ? -1 : stack.lastIndexOf(open);
      if (position >= 0) stack.splice(position);
    }
    paths[index] = [...stack];
    if (token.value === "{" && (document.pairs.get(index) ?? -1) > index) stack.push(index);
  }
  scopePathCache.set(document, paths);
  return paths;
}

export function lexicalScopeAt(document: JsDocument, tokenIndex: number): readonly number[] {
  return scopePaths(document)[tokenIndex] ?? [];
}

export function scopeIsVisibleAt(
  candidateScope: readonly number[],
  useScope: readonly number[],
): boolean {
  return candidateScope.length <= useScope.length &&
    candidateScope.every((open, index) => useScope[index] === open);
}

function scopeEnd(document: JsDocument, scope: readonly number[]): number {
  const open = scope.at(-1);
  return open === undefined ? document.tokens.length : document.pairs.get(open) ?? document.tokens.length;
}

function statementExpressionEnd(document: JsDocument, start: number): number {
  let cursor = start;
  let jsxDepth = 0;
  let jsxOpening = false;
  let jsxClosing = false;
  const statementStarters = new Set([
    "break", "class", "const", "continue", "debugger", "export", "function", "if",
    "import", "let", "return", "switch", "throw", "try", "var", "while",
  ]);
  while (cursor < document.tokens.length) {
    const value = document.tokens[cursor]!.value;
    if (
      value === "<" &&
      (document.tokens[cursor + 1]?.value === ">" ||
        document.tokens[cursor + 1]?.kind === "identifier" &&
        /^[A-Z]/.test(document.tokens[cursor + 1]!.value))
    ) {
      jsxOpening = true;
      jsxClosing = false;
    } else if (value === "</") {
      jsxOpening = true;
      jsxClosing = true;
    } else if (jsxOpening && value === "/>") {
      jsxOpening = false;
      jsxClosing = false;
    } else if (jsxOpening && value === ">") {
      jsxDepth = Math.max(0, jsxDepth + (jsxClosing ? -1 : 1));
      jsxOpening = false;
      jsxClosing = false;
    }
    if (value === "(" || value === "[" || value === "{") {
      const close = document.pairs.get(cursor);
      if (close !== undefined) {
        cursor = close + 1;
        continue;
      }
    }
    if (value === ";" || value === ",") return cursor;
    if (
      cursor > start && document.tokens[cursor]!.kind === "identifier" &&
      statementStarters.has(value) &&
      document.tokens[cursor]!.line > (document.tokens[cursor - 1]?.line ?? document.tokens[cursor]!.line)
    ) return cursor;
    if (
      cursor > start && document.tokens[cursor]!.kind === "identifier" &&
      !["as", "in", "instanceof", "of", "satisfies"].includes(value) &&
      !jsxOpening && jsxDepth === 0 &&
      document.tokens[cursor]!.line > (document.tokens[cursor - 1]?.line ?? document.tokens[cursor]!.line) &&
      (
        ["identifier", "string", "template", "number", "regex"].includes(document.tokens[cursor - 1]?.kind ?? "") ||
        [")", "]", "}", "/>"].includes(document.tokens[cursor - 1]?.value ?? "")
      )
    ) return cursor;
    cursor++;
  }
  return cursor;
}

function importDefinitions(document: JsDocument, scopes: readonly (readonly number[])[]): JsDefinition[] {
  const definitions: JsDefinition[] = [];
  const tokens = document.tokens;
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index]!.value !== "import") continue;
    const importScope = scopes[index] ?? [];
    if (tokens[index + 1]?.value === "type" || tokens[index + 1]?.value === "typeof") {
      continue;
    }
    let sourceTokenIndex = index + 1;
    let fromIndex = -1;
    if (tokens[sourceTokenIndex]?.kind !== "string") {
      while (sourceTokenIndex < tokens.length) {
        if (
          tokens[sourceTokenIndex]!.value === "from" &&
          tokens[sourceTokenIndex + 1]?.kind === "string"
        ) {
          fromIndex = sourceTokenIndex;
          sourceTokenIndex++;
          break;
        }
        if (tokens[sourceTokenIndex]!.value === "import" && sourceTokenIndex > index + 1) break;
        sourceTokenIndex++;
      }
    }
    const sourceToken = tokens[sourceTokenIndex];
    if (sourceToken?.kind !== "string" || sourceToken.staticValue === undefined) continue;
    const source = sourceToken.staticValue;
    const bindingEnd = fromIndex >= 0 ? fromIndex : sourceTokenIndex;
    let cursor = index + 1;
    if (tokens[cursor]?.kind === "identifier" && !["type", "typeof"].includes(tokens[cursor]!.value)) {
      definitions.push({
        name: tokens[cursor]!.value,
        tokenIndex: cursor,
        scope: importScope,
        visibilityEnd: document.tokens.length,
        kind: "import",
        origin: { source, imported: "default", namespace: false },
      });
      cursor++;
      if (tokens[cursor]?.value === ",") cursor++;
    } else if (["type", "typeof"].includes(tokens[cursor]?.value ?? "")) {
      cursor++;
    }
    if (tokens[cursor]?.value === "*" && tokens[cursor + 1]?.value === "as" && tokens[cursor + 2]?.kind === "identifier") {
      definitions.push({
        name: tokens[cursor + 2]!.value,
        tokenIndex: cursor + 2,
        scope: importScope,
        visibilityEnd: document.tokens.length,
        kind: "import",
        origin: { source, imported: "*", namespace: true },
      });
    }
    const brace = tokens.slice(cursor, bindingEnd).findIndex((token) => token.value === "{");
    if (brace >= 0) {
      const open = cursor + brace;
      const close = document.pairs.get(open) ?? bindingEnd;
      let member = open + 1;
      while (member < close) {
        if (tokens[member]?.kind !== "identifier") {
          member++;
          continue;
        }
        if (tokens[member]!.value === "type") {
          while (member < close && tokens[member]!.value !== ",") member++;
          member++;
          continue;
        }
        const imported = tokens[member]!.value;
        const localIndex = tokens[member + 1]?.value === "as" && tokens[member + 2]?.kind === "identifier"
          ? member + 2
          : member;
        definitions.push({
          name: tokens[localIndex]!.value,
          tokenIndex: localIndex,
          scope: importScope,
          visibilityEnd: document.tokens.length,
          kind: "import",
          origin: { source, imported, namespace: false },
        });
        member = localIndex + 1;
        while (member < close && tokens[member]!.value !== ",") member++;
        member++;
      }
    }
  }
  return definitions;
}

function requireOrigin(expressionValue: JsExpression, localName: string): ImportOrigin | undefined {
  const values = expressionValue.tokens;
  if (
    values[0]?.value !== "require" || values[1]?.value !== "(" ||
    values[2]?.kind !== "string" || values[2]?.staticValue === undefined || values[3]?.value !== ")"
  ) return undefined;
  const imported = values[4]?.value === "." && values[5]?.kind === "identifier"
    ? values[5]!.value
    : "default";
  return { source: values[2]!.staticValue, imported: imported || localName, namespace: imported === "default" && values.length === 4 };
}

function parameterNames(tokens: readonly JsToken[]): string[] {
  const names: string[] = [];
  let cursor = 0;
  while (cursor < tokens.length) {
    const token = tokens[cursor]!;
    if (token.value === "{" || token.value === "[") {
      const closing = token.value === "{" ? "}" : "]";
      cursor++;
      while (cursor < tokens.length && tokens[cursor]!.value !== closing) {
        if (
          tokens[cursor]!.kind === "identifier" &&
          !["type", "readonly"].includes(tokens[cursor]!.value) &&
          tokens[cursor - 1]?.value !== "."
        ) {
          const alias = tokens[cursor + 1]?.value === ":" && tokens[cursor + 2]?.kind === "identifier"
            ? tokens[cursor + 2]!.value
            : tokens[cursor]!.value;
          names.push(alias);
          while (cursor < tokens.length && ![",", closing].includes(tokens[cursor]!.value)) cursor++;
        } else cursor++;
      }
    } else if (token.kind === "identifier" && !["this", "readonly", "public", "private", "protected"].includes(token.value)) {
      names.push(token.value);
      while (cursor < tokens.length && tokens[cursor]!.value !== ",") cursor++;
    }
    cursor++;
  }
  return [...new Set(names)];
}

function objectBindingNames(tokens: readonly JsToken[]): Array<{ imported: string; local: string }> {
  const bindings: Array<{ imported: string; local: string }> = [];
  let cursor = tokens[0]?.value === "{" ? 1 : 0;
  while (cursor < tokens.length && tokens[cursor]!.value !== "}") {
    if (tokens[cursor]?.kind !== "identifier") {
      cursor++;
      continue;
    }
    const imported = tokens[cursor]!.value;
    const local = tokens[cursor + 1]?.value === ":" && tokens[cursor + 2]?.kind === "identifier"
      ? tokens[cursor + 2]!.value
      : imported;
    bindings.push({ imported, local });
    while (cursor < tokens.length && ![",", "}"].includes(tokens[cursor]!.value)) cursor++;
    if (tokens[cursor]?.value === ",") cursor++;
  }
  return bindings;
}

function parameterDefinitions(document: JsDocument, scopes: readonly (readonly number[])[]): JsDefinition[] {
  const definitions: JsDefinition[] = [];
  const tokens = document.tokens;
  for (let arrow = 0; arrow < tokens.length; arrow++) {
    if (tokens[arrow]!.value !== "=>") continue;
    let parameterTokens: readonly JsToken[] = [];
    if (tokens[arrow - 1]?.value === ")") {
      const open = document.pairs.get(arrow - 1);
      if (open !== undefined) parameterTokens = tokens.slice(open + 1, arrow - 1);
    } else if (tokens[arrow - 1]?.kind === "identifier") {
      parameterTokens = tokens.slice(arrow - 1, arrow);
    }
    const bodyStart = arrow + 1;
    const bodyOpen = tokens[bodyStart]?.value === "{" ? bodyStart : undefined;
    const visibilityEnd = bodyOpen === undefined
      ? statementExpressionEnd(document, bodyStart)
      : document.pairs.get(bodyOpen) ?? document.tokens.length;
    const scope = bodyOpen === undefined
      ? scopes[arrow] ?? []
      : [...(scopes[bodyOpen] ?? []), bodyOpen];
    for (const name of parameterNames(parameterTokens)) {
      definitions.push({ name, tokenIndex: bodyStart, scope, visibilityEnd, kind: "parameter" });
    }
  }
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index]!.value !== "function") continue;
    let open = index + 1;
    if (tokens[open]?.kind === "identifier") open++;
    while (open < tokens.length && tokens[open]!.value !== "(") open++;
    const close = document.pairs.get(open);
    if (close === undefined) continue;
    let bodyOpen = close + 1;
    while (bodyOpen < tokens.length && tokens[bodyOpen]!.value !== "{" && tokens[bodyOpen]!.value !== ";") {
      bodyOpen++;
    }
    if (tokens[bodyOpen]?.value !== "{") continue;
    const scope = [...(scopes[bodyOpen] ?? []), bodyOpen];
    const visibilityEnd = document.pairs.get(bodyOpen) ?? document.tokens.length;
    for (const name of parameterNames(tokens.slice(open + 1, close))) {
      definitions.push({ name, tokenIndex: bodyOpen, scope, visibilityEnd, kind: "parameter" });
    }
  }
  const methodControls = new Set(["if", "for", "while", "switch", "catch", "with"]);
  for (let open = 1; open < tokens.length; open++) {
    if (tokens[open]!.value !== "(" || tokens[open - 1]?.kind !== "identifier") continue;
    if (tokens[open - 2]?.value === "function" || methodControls.has(tokens[open - 1]!.value)) continue;
    const close = document.pairs.get(open);
    if (close === undefined) continue;
    let bodyOpen = close + 1;
    if (tokens[bodyOpen]?.value === ":") {
      bodyOpen++;
      while (bodyOpen < tokens.length && !["{", ";", "=>"].includes(tokens[bodyOpen]!.value)) bodyOpen++;
    }
    if (tokens[bodyOpen]?.value !== "{") continue;
    const scope = [...(scopes[bodyOpen] ?? []), bodyOpen];
    const visibilityEnd = document.pairs.get(bodyOpen) ?? document.tokens.length;
    for (const name of parameterNames(tokens.slice(open + 1, close))) {
      definitions.push({ name, tokenIndex: bodyOpen, scope, visibilityEnd, kind: "parameter" });
    }
  }
  return definitions;
}

const definitionCache = new WeakMap<JsDocument, JsDefinition[]>();
const definitionsByNameCache = new WeakMap<JsDocument, ReadonlyMap<string, readonly JsDefinition[]>>();

export function jsDefinitions(document: JsDocument): JsDefinition[] {
  const cached = definitionCache.get(document);
  if (cached) return cached;
  const scopes = scopePaths(document);
  const definitions = importDefinitions(document, scopes);
  const tokens = document.tokens;
  const jsxPropIndexes = new Set(jsxElements(document).flatMap((element) =>
    element.props.map((prop) => prop.tokenIndex)
  ));
  const parenthesized = new Set<number>();
  const parenStack: number[] = [];
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index]!.value === ")") parenStack.pop();
    if (parenStack.length) parenthesized.add(index);
    if (tokens[index]!.value === "(") parenStack.push(index);
  }
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (token.value === "function" && tokens[index + 1]?.kind === "identifier") {
      const nameIndex = index + 1;
      const previous = tokens[index - 1];
      const declaration = !previous || previous.kind === "symbol" && [";", "{", "}"].includes(previous.value) ||
        previous.kind === "identifier" && ["async", "default", "export"].includes(previous.value);
      let open = nameIndex + 1;
      while (open < tokens.length && tokens[open]!.value !== "(") open++;
      const close = document.pairs.get(open);
      let bodyOpen = close === undefined ? -1 : close + 1;
      while (bodyOpen >= 0 && bodyOpen < tokens.length && !["{", ";"].includes(tokens[bodyOpen]!.value)) bodyOpen++;
      const bodyClose = bodyOpen >= 0 ? document.pairs.get(bodyOpen) : undefined;
      const scope = declaration
        ? scopes[nameIndex] ?? []
        : bodyOpen >= 0 ? [...(scopes[bodyOpen] ?? []), bodyOpen] : scopes[nameIndex] ?? [];
      definitions.push({
        name: tokens[nameIndex]!.value,
        tokenIndex: nameIndex,
        scope,
        visibilityEnd: declaration ? scopeEnd(document, scope) : bodyClose ?? scopeEnd(document, scope),
        kind: "function",
        ...(declaration ? { hoisted: true } : {}),
      });
    }
    if (token.value === "class" && tokens[index + 1]?.kind === "identifier") {
      const nameIndex = index + 1;
      const scope = scopes[nameIndex] ?? [];
      definitions.push({
        name: tokens[nameIndex]!.value,
        tokenIndex: nameIndex,
        scope,
        visibilityEnd: scopeEnd(document, scope),
        kind: "function",
      });
    }
    if (!["const", "let", "var"].includes(token.value)) continue;
    let nameIndex = index + 1;
    if (tokens[nameIndex]?.value === "{") {
      const close = document.pairs.get(nameIndex);
      if (close === undefined) continue;
      let equals = close + 1;
      while (equals < tokens.length && !["=", ";", ","].includes(tokens[equals]!.value)) equals++;
      const initializer = tokens[equals]?.value === "="
        ? expression(tokens, equals + 1, statementExpressionEnd(document, equals + 1))
        : undefined;
      const required = initializer ? requireOrigin(initializer, "") : undefined;
      for (const binding of objectBindingNames(tokens.slice(nameIndex, close + 1))) {
        const name = binding.local;
        const nameTokenIndex = tokens.findIndex((candidate, candidateIndex) =>
          candidateIndex >= nameIndex && candidateIndex <= close && candidate.value === name
        );
        const scope = scopes[nameIndex] ?? [];
        definitions.push({
          name,
          tokenIndex: nameTokenIndex >= 0 ? nameTokenIndex : nameIndex,
          scope,
          visibilityEnd: scopeEnd(document, scope),
          kind: "declaration",
          ...(initializer ? { expression: initializer } : {}),
          ...(required ? {
            origin: { source: required.source, imported: binding.imported, namespace: false },
          } : {}),
        });
      }
      index = close;
      continue;
    }
    if (tokens[nameIndex]?.kind !== "identifier") continue;
    const name = tokens[nameIndex]!.value;
    const scope = scopes[nameIndex] ?? [];
    let equals: number | undefined;
    let declarationCursor = nameIndex + 1;
    while (declarationCursor < tokens.length && ![";", ","].includes(tokens[declarationCursor]!.value)) {
      if (tokens[declarationCursor]!.value === "=") {
        equals = declarationCursor;
        break;
      }
      if (["(", "[", "{"].includes(tokens[declarationCursor]!.value)) {
        const close = document.pairs.get(declarationCursor);
        if (close !== undefined) {
          declarationCursor = close + 1;
          continue;
        }
      }
      declarationCursor++;
    }
    const initializer = equals === undefined
      ? undefined
      : expression(tokens, equals + 1, statementExpressionEnd(document, equals + 1));
    const origin = initializer ? requireOrigin(initializer, name) : undefined;
    definitions.push({
      name,
      tokenIndex: nameIndex,
      scope,
      visibilityEnd: scopeEnd(document, scope),
      kind: "declaration",
      ...(initializer ? { expression: initializer } : {}),
      ...(origin ? { origin } : {}),
    });
  }
  // Reassignments participate in source ordering and can shadow an imported/aliased value.
  for (let index = 1; index < tokens.length - 1; index++) {
    if (
      tokens[index]!.value !== "=" || tokens[index - 1]?.kind !== "identifier" ||
      jsxPropIndexes.has(index - 1) ||
      parenthesized.has(index) ||
      ["const", "let", "var", ".", "?.", ":"].includes(tokens[index - 2]?.value ?? "")
    ) continue;
    const nameIndex = index - 1;
    const scope = scopes[nameIndex] ?? [];
    definitions.push({
      name: tokens[nameIndex]!.value,
      tokenIndex: nameIndex,
      scope,
      visibilityEnd: scopeEnd(document, scope),
      kind: "assignment",
      expression: expression(tokens, index + 1, statementExpressionEnd(document, index + 1)),
    });
  }
  definitions.push(...parameterDefinitions(document, scopes));
  definitions.sort((left, right) => left.tokenIndex - right.tokenIndex || left.scope.length - right.scope.length);
  definitionCache.set(document, definitions);
  const byName = new Map<string, JsDefinition[]>();
  for (const definition of definitions) {
    const values = byName.get(definition.name) ?? [];
    values.push(definition);
    byName.set(definition.name, values);
  }
  definitionsByNameCache.set(document, byName);
  return definitions;
}

function scopeVisible(definition: JsDefinition, useScope: readonly number[], useIndex: number): boolean {
  return (definition.hoisted || definition.tokenIndex <= useIndex) && useIndex <= definition.visibilityEnd &&
    scopeIsVisibleAt(definition.scope, useScope);
}

export function nearestDefinition(document: JsDocument, name: string, useIndex: number): JsDefinition | undefined {
  const useScope = scopePaths(document)[useIndex] ?? [];
  jsDefinitions(document);
  const candidates = definitionsByNameCache.get(document)?.get(name) ?? [];
  let winner: JsDefinition | undefined;
  for (const candidate of candidates) {
    if (!scopeVisible(candidate, useScope, useIndex)) continue;
    if (
      !winner || candidate.scope.length > winner.scope.length ||
      candidate.scope.length === winner.scope.length && candidate.tokenIndex > winner.tokenIndex
    ) winner = candidate;
  }
  return winner;
}

function simpleReference(expressionValue: JsExpression): string[] | undefined {
  const tokens = expressionValue.tokens;
  if (tokens.length === 0 || tokens[0]?.kind !== "identifier") return undefined;
  const reference = [tokens[0]!.value];
  let cursor = 1;
  while (cursor < tokens.length && [".", "?."].includes(tokens[cursor]!.value) && tokens[cursor + 1]?.kind === "identifier") {
    reference.push(tokens[cursor + 1]!.value);
    cursor += 2;
  }
  return cursor === tokens.length ? reference : undefined;
}

export function resolveImport(
  document: JsDocument,
  reference: readonly string[],
  useIndex: number,
  maxAliases = 3,
  seen = new Set<string>(),
): ImportOrigin | undefined {
  const root = reference[0];
  if (!root) return undefined;
  const definition = nearestDefinition(document, root, useIndex);
  if (!definition) return undefined;
  if (definition.origin) {
    if (definition.origin.namespace && reference.length > 1) {
      return { ...definition.origin, imported: reference[1]!, namespace: false };
    }
    if (reference.length === 1) return definition.origin;
    return undefined;
  }
  if (maxAliases <= 0 || !definition.expression) return undefined;
  const alias = simpleReference(definition.expression);
  if (!alias) return undefined;
  const key = `${definition.tokenIndex}:${definition.name}`;
  if (seen.has(key)) return undefined;
  seen.add(key);
  const resolved = resolveImport(document, alias, definition.tokenIndex, maxAliases - 1, seen);
  if (!resolved || reference.length === 1) return resolved;
  if (resolved.namespace) return { ...resolved, imported: reference[1]!, namespace: false };
  return undefined;
}

export function staticString(
  document: JsDocument,
  expressionValue: JsExpression | undefined,
  useIndex: number,
  depth = 0,
  seen = new Set<string>(),
): string | undefined {
  if (!expressionValue || depth > 4) return undefined;
  const tokens = expressionValue.tokens;
  if (tokens.length === 1 && (tokens[0]?.kind === "string" || tokens[0]?.kind === "template")) {
    return tokens[0]!.staticValue;
  }
  const ref = simpleReference(expressionValue);
  if (!ref || ref.length !== 1) return undefined;
  const definition = nearestDefinition(document, ref[0]!, useIndex);
  if (!definition?.expression) return undefined;
  const key = `${definition.tokenIndex}:${definition.name}`;
  if (seen.has(key)) return undefined;
  seen.add(key);
  return staticString(document, definition.expression, definition.tokenIndex, depth + 1, seen);
}

export function staticBoolean(
  document: JsDocument,
  expressionValue: JsExpression | undefined,
  useIndex: number,
): boolean | undefined {
  if (!expressionValue) return undefined;
  const tokens = expressionValue.tokens;
  if (tokens.length === 1 && tokens[0]?.value === "true") return true;
  if (tokens.length === 1 && tokens[0]?.value === "false") return false;
  const ref = simpleReference(expressionValue);
  if (!ref || ref.length !== 1) return undefined;
  const definition = nearestDefinition(document, ref[0]!, useIndex);
  if (!definition?.expression) return undefined;
  const values = definition.expression.tokens;
  if (values.length === 1 && values[0]?.value === "true") return true;
  if (values.length === 1 && values[0]?.value === "false") return false;
  return undefined;
}

function stripParens(document: JsDocument, expressionValue: JsExpression): JsExpression {
  let current = expressionValue;
  while (current.tokens[0]?.value === "(" && current.tokens.at(-1)?.value === ")") {
    const absoluteOpen = current.start;
    const absoluteClose = document.pairs.get(absoluteOpen);
    if (absoluteClose !== current.end - 1) break;
    current = expression(document.tokens, current.start + 1, current.end - 1);
  }
  return current;
}

type ObjectPropertyLookup =
  | { kind: "absent" }
  | { kind: "ambiguous" }
  | { kind: "value"; value: JsExpression };

function literalObjectProperty(
  document: JsDocument,
  input: JsExpression,
  name: string,
): ObjectPropertyLookup {
  const source = stripParens(document, input);
  if (source.tokens[0]?.value !== "{" || source.tokens.at(-1)?.value !== "}") {
    return { kind: "ambiguous" };
  }
  const parts = splitTopLevel(document, source.start + 1, source.end - 1);
  for (const part of [...parts].reverse()) {
    const tokens = part.tokens;
    if (tokens[0]?.value === "...") return { kind: "ambiguous" };
    if (tokens[0]?.value === "[") {
      const close = document.pairs.get(part.start);
      if (close === undefined || close >= part.end) return { kind: "ambiguous" };
      const keyTokens = document.tokens.slice(part.start + 1, close);
      if (keyTokens.length !== 1 || keyTokens[0]?.staticValue === undefined) {
        return { kind: "ambiguous" };
      }
      if (keyTokens[0].staticValue !== name) continue;
      if (document.tokens[close + 1]?.value !== ":") return { kind: "ambiguous" };
      return { kind: "value", value: expression(document.tokens, close + 2, part.end) };
    }
    const key = tokens[0]?.kind === "string" ? tokens[0]?.staticValue : tokens[0]?.value;
    if (key !== name) continue;
    if (tokens[1]?.value === ":") {
      return { kind: "value", value: expression(document.tokens, part.start + 2, part.end) };
    }
    if (tokens.length === 1 && tokens[0]?.kind === "identifier") return { kind: "value", value: part };
    return { kind: "ambiguous" };
  }
  return { kind: "absent" };
}

interface ObjectWrite {
  tokenIndex: number;
  scope: readonly number[];
  conditional: boolean;
  value?: JsExpression;
}

function referenceTargetsDefinition(
  document: JsDocument,
  name: string,
  useIndex: number,
  target: JsDefinition,
  depth = 0,
  seen = new Set<string>(),
): boolean {
  if (depth > 4) return false;
  const definition = nearestDefinition(document, name, useIndex);
  if (!definition) return false;
  if (definition.tokenIndex === target.tokenIndex && definition.name === target.name) return true;
  const alias = definition.expression ? simpleReference(definition.expression) : undefined;
  if (alias?.length !== 1) return false;
  const key = `${definition.tokenIndex}:${definition.name}`;
  if (seen.has(key)) return false;
  seen.add(key);
  return referenceTargetsDefinition(document, alias[0]!, definition.tokenIndex, target, depth + 1, seen);
}

function memberReferenceStartingAt(
  document: JsDocument,
  start: number,
): { reference: string[]; end: number } | undefined {
  const tokens = document.tokens;
  if (tokens[start]?.kind !== "identifier") return undefined;
  const reference = [tokens[start]!.value];
  let cursor = start + 1;
  while (cursor < tokens.length) {
    if ([".", "?."].includes(tokens[cursor]!.value) && tokens[cursor + 1]?.kind === "identifier") {
      reference.push(tokens[cursor + 1]!.value);
      cursor += 2;
      continue;
    }
    if (tokens[cursor]!.value === "[") {
      const close = document.pairs.get(cursor);
      if (close === undefined) return undefined;
      const keyTokens = tokens.slice(cursor + 1, close);
      reference.push(keyTokens.length === 1 && keyTokens[0]?.staticValue !== undefined
        ? keyTokens[0].staticValue
        : "*");
      cursor = close + 1;
      continue;
    }
    break;
  }
  return { reference, end: cursor };
}

function syntaxMutationWrites(
  document: JsDocument,
  definition: JsDefinition,
  property: string,
  useIndex: number,
): ObjectWrite[] {
  const writes: ObjectWrite[] = [];
  const tokens = document.tokens;
  for (let index = 0; index < useIndex; index++) {
    if (tokens[index]!.value === "delete") {
      const member = memberReferenceStartingAt(document, index + 1);
      if (
        member?.reference.length === 2 && [property, "*"].includes(member.reference[1] ?? "") &&
        referenceTargetsDefinition(document, member.reference[0]!, index + 1, definition)
      ) {
        writes.push({
          tokenIndex: index,
          scope: lexicalScopeAt(document, index),
          conditional: isConditionallyExecuted(document, index),
        });
      }
      continue;
    }
    if (["++", "--"].includes(tokens[index]!.value)) {
      const member = memberReferenceStartingAt(document, index + 1);
      if (
        member?.reference.length === 2 && [property, "*"].includes(member.reference[1] ?? "") &&
        referenceTargetsDefinition(document, member.reference[0]!, index + 1, definition)
      ) {
        writes.push({
          tokenIndex: index,
          scope: lexicalScopeAt(document, index),
          conditional: isConditionallyExecuted(document, index),
        });
      }
      continue;
    }
    if (tokens[index]!.kind !== "identifier") continue;
    const member = memberReferenceStartingAt(document, index);
    if (
      member?.reference.length !== 2 || ![property, "*"].includes(member.reference[1] ?? "") ||
      !["++", "--"].includes(tokens[member.end]?.value ?? "") ||
      !referenceTargetsDefinition(document, member.reference[0]!, index, definition)
    ) continue;
    writes.push({
      tokenIndex: member.end,
      scope: lexicalScopeAt(document, index),
      conditional: isConditionallyExecuted(document, member.end),
    });
  }
  return writes;
}

function objectApiWrites(
  document: JsDocument,
  definition: JsDefinition,
  property: string,
  useIndex: number,
): ObjectWrite[] {
  const writes: ObjectWrite[] = [];
  for (const call of jsCalls(document)) {
    if (call.closeIndex >= useIndex || call.reference.length !== 2) continue;
    const api = call.reference.join(".");
    if (!["Object.assign", "Object.defineProperty", "Reflect.set"].includes(api)) continue;
    const target = call.arguments[0];
    const targetRef = target ? simpleReference(target) : undefined;
    if (
      targetRef?.length !== 1 ||
      !referenceTargetsDefinition(document, targetRef[0]!, target!.start, definition)
    ) continue;
    let lookup: ObjectPropertyLookup;
    const globalName = call.reference[0]!;
    if (nearestDefinition(document, globalName, call.tokenIndex)) {
      lookup = { kind: "ambiguous" };
    } else if (api === "Object.assign") {
      lookup = { kind: "absent" };
      for (const source of call.arguments.slice(1)) {
        const candidate = literalObjectProperty(document, source, property);
        if (candidate.kind !== "absent") lookup = candidate;
      }
    } else {
      const propertyName = staticString(document, call.arguments[1], call.tokenIndex);
      if (propertyName !== undefined && propertyName !== property) continue;
      if (propertyName === undefined) {
        lookup = { kind: "ambiguous" };
      } else if (api === "Reflect.set") {
        lookup = call.arguments[2]
          ? { kind: "value", value: call.arguments[2] }
          : { kind: "ambiguous" };
      } else {
        const descriptor = call.arguments[2];
        lookup = descriptor
          ? literalObjectProperty(document, descriptor, "value")
          : { kind: "ambiguous" };
        if (lookup.kind === "absent") lookup = { kind: "ambiguous" };
      }
    }
    if (lookup.kind === "absent") continue;
    writes.push({
      tokenIndex: call.closeIndex,
      scope: lexicalScopeAt(document, call.tokenIndex),
      conditional: isConditionallyExecuted(document, call.tokenIndex),
      ...(lookup.kind === "value" ? { value: lookup.value } : {}),
    });
  }
  return writes;
}

export function objectProperty(
  document: JsDocument,
  input: JsExpression | undefined,
  name: string,
  useIndex: number,
  depth = 0,
): JsExpression | undefined {
  if (!input || depth > 4) return undefined;
  let source = stripParens(document, input);
  const ref = simpleReference(source);
  if (ref?.length === 1) {
    const definition = nearestDefinition(document, ref[0]!, useIndex);
    if (!definition?.expression) return undefined;
    const useScope = lexicalScopeAt(document, useIndex);
    const writes: ObjectWrite[] = jsMemberAssignments(document)
      .filter((assignment) =>
        assignment.reference.length === 2 &&
        [name, "*"].includes(assignment.reference[1] ?? "") && assignment.tokenIndex < useIndex &&
        referenceTargetsDefinition(document, assignment.reference[0]!, assignment.rootIndex, definition)
      )
      .map((assignment) => ({
        tokenIndex: assignment.tokenIndex,
        scope: assignment.scope,
        conditional: assignment.conditional,
        ...(assignment.reference[1] === name && assignment.operator === "=" ? { value: assignment.expression } : {}),
      }));
    writes.push(...syntaxMutationWrites(document, definition, name, useIndex));
    writes.push(...objectApiWrites(document, definition, name, useIndex));
    writes.sort((left, right) => right.tokenIndex - left.tokenIndex);
    const latest = writes[0];
    if (latest) {
      if (
        latest.conditional || !latest.value ||
        !scopeIsVisibleAt(latest.scope, useScope)
      ) return undefined;
      return latest.value;
    }
    return objectProperty(document, definition.expression, name, definition.tokenIndex, depth + 1);
  }
  const lookup = literalObjectProperty(document, source, name);
  return lookup.kind === "value" ? lookup.value : undefined;
}

export function arrayItems(document: JsDocument, input: JsExpression | undefined): JsExpression[] {
  if (!input) return [];
  const source = stripParens(document, input);
  if (source.tokens[0]?.value !== "[" || source.tokens.at(-1)?.value !== "]") return [];
  return splitTopLevel(document, source.start + 1, source.end - 1);
}

export function expressionIdentifiers(expressionValue: JsExpression | undefined): string[] {
  return (expressionValue?.tokens ?? [])
    .filter((token) => token.kind === "identifier")
    .map((token) => token.value);
}

export function expressionHasSequence(expressionValue: JsExpression | undefined, sequence: readonly string[]): boolean {
  const values = (expressionValue?.tokens ?? []).map((token) => token.value);
  outer: for (let index = 0; index <= values.length - sequence.length; index++) {
    for (let offset = 0; offset < sequence.length; offset++) {
      if (values[index + offset] !== sequence[offset]) continue outer;
    }
    return true;
  }
  return false;
}

export function expressionReferencesName(expressionValue: JsExpression | undefined, name: string): boolean {
  return (expressionValue?.tokens ?? []).some((token) => token.kind === "identifier" && token.value === name);
}

export function normalizedWord(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}
