import {
  dartAssignments,
  dartCalls,
  decodedString,
  expressionFromTokens,
  expressionReferences,
  interpolationIdentifiers,
  nearestReachingDefinition,
  type DartArgument,
  type DartCall,
  type DartDocument,
  type DartExpression,
  type DartToken,
} from "./dart.js";

export function normalizedWord(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

export function callExpression(document: DartDocument, call: DartCall): DartExpression {
  return expressionFromTokens(document.tokens.slice(call.openIndex + 1, call.closeIndex));
}

export function argumentExpression(argument: DartArgument | undefined): DartExpression {
  return expressionFromTokens(argument?.tokens ?? []);
}

export function identifiers(expression: DartExpression): string[] {
  const values: string[] = [];
  for (const token of expression.tokens) {
    if (token.kind === "identifier") values.push(token.value);
    if (token.kind === "string") values.push(...interpolationIdentifiers(token));
  }
  return values;
}

export function hasIdentifier(
  expression: DartExpression,
  predicate: (identifier: string) => boolean,
): boolean {
  return identifiers(expression).some(predicate);
}

export function expressionStrings(expression: DartExpression): string[] {
  return expression.tokens
    .filter((token) => token.kind === "string")
    .map(decodedString);
}

export function hasIdentifierSequence(expression: DartExpression, values: readonly string[]): boolean {
  const tokens = expression.tokens;
  outer: for (let index = 0; index <= tokens.length - values.length; index++) {
    for (let offset = 0; offset < values.length; offset++) {
      if (tokens[index + offset]!.value !== values[offset]) continue outer;
    }
    return true;
  }
  return false;
}

export function deriveTaintedNames(
  document: DartDocument,
  source: (expression: DartExpression) => boolean,
  initial: Iterable<string> = [],
): Set<string> {
  const tainted = new Set(initial);
  const assignments = dartAssignments(document);
  let changed = true;
  let pass = 0;
  while (changed && pass++ < 8) {
    changed = false;
    for (const assignment of assignments) {
      if (tainted.has(assignment.name)) continue;
      if (source(assignment) || expressionReferences(assignment, tainted)) {
        tainted.add(assignment.name);
        changed = true;
      }
    }
  }
  return tainted;
}

const SENSITIVE_WORDS = [
  "password",
  "passwd",
  "accesstoken",
  "refreshtoken",
  "authtoken",
  "authorization",
  "bearer",
  "jwt",
  "sessiontoken",
  "apikey",
  "privatekey",
  "servicerole",
  "clientsecret",
  "cookie",
  "credential",
  "credentials",
  "secret",
  "token",
] as const;
const NON_CREDENTIAL_TOKEN_CONTEXT = ["fcm", "device", "push", "notification", "messaging"];
const SAFE_VALUE_TRANSFORMS = new Set([
  "redact",
  "redacted",
  "mask",
  "masked",
  "hash",
  "hashed",
  "digest",
  "fingerprint",
  "scrub",
  "length",
  "isempty",
  "isnotempty",
]);

function sensitiveWord(value: string): string | undefined {
  const normalized = normalizedWord(value);
  if (
    /^(?:show|has|is|remember|save)(?:password|token|secret)$/.test(normalized) ||
    /(?:token|password|secret)(?:expiry|expires|expiration|status|type|length|hash|digest|fingerprint)$/.test(normalized)
  ) return undefined;
  return SENSITIVE_WORDS.find((candidate) => normalized === candidate || normalized.includes(candidate));
}

export function isSafeDerivedValue(expression: DartExpression): boolean {
  const sensitiveIndexes = expression.tokens
    .map((token, index) => token.kind === "identifier" && sensitiveWord(token.value) ? index : -1)
    .filter((index) => index >= 0);

  if (expression.tokens.length === 1 && expression.tokens[0]?.kind === "string") {
    const token = expression.tokens[0];
    if (token.rawString) return false;
    const interpolations = token.value.match(/\$[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|\$\{[^}]+\}/g) ?? [];
    const sensitive = interpolations.filter((value) => sensitiveWord(value));
    if (sensitive.length === 0) return false;
    return sensitive.every((value) => {
      const normalized = normalizedWord(value);
      return /(?:length|isempty|isnotempty)$/.test(normalized) ||
        /^(?:redact|mask|hash|digest|fingerprint|scrub)/.test(normalized.replace(/^\$\{?/, ""));
    });
  }

  if (sensitiveIndexes.length === 0) return false;
  return sensitiveIndexes.every((index) => {
    const normalized = normalizedWord(expression.tokens[index]!.value);
    if (/^(?:redacted|masked|hashed)/.test(normalized)) return true;
    if (
      (expression.tokens[index + 1]?.value === "." || expression.tokens[index + 1]?.value === "?.") &&
      SAFE_VALUE_TRANSFORMS.has(normalizedWord(expression.tokens[index + 2]?.value ?? ""))
    ) return true;
    const openStack: number[] = [];
    for (let cursor = 0; cursor < index; cursor++) {
      if (expression.tokens[cursor]?.value === "(") openStack.push(cursor);
      else if (expression.tokens[cursor]?.value === ")") openStack.pop();
    }
    for (let cursor = openStack.length - 1; cursor >= 0; cursor--) {
      const open = openStack[cursor]!;
      const functionName = normalizedWord(expression.tokens[open - 1]?.value ?? "");
      if (SAFE_VALUE_TRANSFORMS.has(functionName)) return true;
    }
    return false;
  });
}

export function sensitiveCredentialLabels(expression: DartExpression): string[] {
  if (isSafeDerivedValue(expression)) return [];
  const labels = new Set<string>();
  const names = identifiers(expression);
  const context = [
    ...names,
    ...expression.tokens.filter((token) => token.kind === "string").map((token) => token.value),
  ].map(normalizedWord).join(" ");
  for (const identifier of names) {
    const label = sensitiveWord(identifier);
    if (!label) continue;
    if (
      label === "token" &&
      NON_CREDENTIAL_TOKEN_CONTEXT.some((safe) => context.includes(safe))
    ) continue;
    labels.add(label);
  }

  for (let index = 1; index < expression.tokens.length - 1; index++) {
    const token = expression.tokens[index]!;
    if (
      token.kind !== "string" ||
      expression.tokens[index - 1]?.value !== "[" ||
      expression.tokens[index + 1]?.value !== "]"
    ) continue;
    const label = sensitiveWord(decodedString(token));
    if (label) labels.add(label);
  }

  for (const token of expression.tokens) {
    if (token.kind !== "string" || token.rawString || !token.value.includes("$")) continue;
    const normalized = normalizedWord(token.value);
    const label = SENSITIVE_WORDS.find((candidate) => normalized.includes(candidate));
    if (
      label &&
      !(label === "token" && NON_CREDENTIAL_TOKEN_CONTEXT.some((safe) => normalized.includes(safe)))
    ) labels.add(label);
  }
  return [...labels].sort();
}

function closureParameter(tokens: readonly DartToken[]): string | undefined {
  const open = tokens.findIndex((token) => token.value === "(");
  if (open < 0) return undefined;
  for (let index = open + 1; index < tokens.length && tokens[index]!.value !== ")"; index++) {
    const token = tokens[index]!;
    if (token.kind !== "identifier") continue;
    const next = tokens[index + 1]?.value;
    if (next === "," || next === ")" || tokens[index + 1]?.kind === undefined) return token.value;
  }
  return undefined;
}

export function deepLinkSeedNames(document: DartDocument): Set<string> {
  const seeds = new Set<string>();
  for (const call of dartCalls(document)) {
    const callee = normalizedWord(call.callee);
    const callbackLike = /(?:link|uri|route)/.test(callee) && /(?:listen|handler|callback|link)/.test(callee);
    for (const argument of call.arguments) {
      if (!callbackLike && !/(?:link|route|redirect|navigation)/i.test(argument.name ?? "")) continue;
      const parameter = closureParameter(argument.tokens);
      if (parameter) seeds.add(parameter);
    }
  }
  return seeds;
}

export interface ReachingSourceOptions {
  expressionSource: (expression: DartExpression) => boolean;
  unresolvedIdentifierSource?: (identifier: string) => boolean;
}

/** Resolve aliases through the nearest visible definition before each use. */
export function expressionReachesSource(
  document: DartDocument,
  expression: DartExpression,
  useIndex: number,
  options: ReachingSourceOptions,
  seen = new Set<string>(),
): boolean {
  if (options.expressionSource(expression)) return true;
  for (const identifier of identifiers(expression)) {
    const definition = nearestReachingDefinition(document, identifier, useIndex);
    if (!definition) {
      if (options.unresolvedIdentifierSource?.(identifier)) return true;
      continue;
    }
    const key = `${definition.tokenIndex}:${definition.name}`;
    if (seen.has(key) || !definition.expression) continue;
    seen.add(key);
    if (
      expressionReachesSource(
        document,
        definition.expression,
        definition.tokenIndex,
        options,
        seen,
      )
    ) return true;
  }
  return false;
}

export function isDeepLinkSource(expression: DartExpression): boolean {
  const words = identifiers(expression).map(normalizedWord);
  const joined = words.join(".");
  return words.some((word) =>
    /^(?:queryparameters|queryparametersall|routeinformation|defaultroutename|initiallink|initialuri|getinitiallink|getinitialuri|applinks|urilinkstream)$/.test(word)
  ) ||
    /(?:modalroute|gorouterstate|routesettings|windowlocation|settingsarguments|routeinformation)/.test(joined);
}

function positiveKDebugCondition(tokens: readonly DartToken[]): boolean {
  const values = tokens.map((token) => token.value);
  return values.length === 1 && values[0] === "kDebugMode" ||
    values.length === 3 &&
      (values[0] === "kDebugMode" && values[1] === "==" && values[2] === "true" ||
        values[0] === "true" && values[1] === "==" && values[2] === "kDebugMode");
}

export function isKDebugModeGuarded(document: DartDocument, tokenIndex: number): boolean {
  const tokens = document.tokens;
  for (let index = 0; index < tokenIndex; index++) {
    if (tokens[index]!.value !== "if" || tokens[index + 1]?.value !== "(") continue;
    const conditionClose = document.pairs.get(index + 1);
    if (conditionClose === undefined || conditionClose >= tokenIndex) continue;
    if (!positiveKDebugCondition(tokens.slice(index + 2, conditionClose))) continue;
    const bodyStart = conditionClose + 1;
    if (tokens[bodyStart]?.value === "{") {
      const bodyEnd = document.pairs.get(bodyStart);
      if (bodyEnd !== undefined && tokenIndex > bodyStart && tokenIndex < bodyEnd) return true;
    } else {
      let bodyEnd = bodyStart;
      while (bodyEnd < tokens.length && tokens[bodyEnd]!.value !== ";") bodyEnd++;
      if (tokenIndex >= bodyStart && tokenIndex <= bodyEnd) return true;
    }
  }
  return false;
}

function exactPropertyComparison(
  tokens: readonly DartToken[],
  names: ReadonlySet<string>,
  property: "scheme" | "host",
  operator: "==" | "!=",
  expected?: string,
): boolean {
  for (let index = 0; index <= tokens.length - 5; index++) {
    const forward =
      tokens[index]?.kind === "identifier" &&
      names.has(tokens[index]!.value) &&
      tokens[index + 1]?.value === "." &&
      tokens[index + 2]?.value === property &&
      tokens[index + 3]?.value === operator &&
      tokens[index + 4]?.kind === "string";
    const reverse =
      tokens[index]?.kind === "string" &&
      tokens[index + 1]?.value === operator &&
      tokens[index + 2]?.kind === "identifier" &&
      names.has(tokens[index + 2]!.value) &&
      tokens[index + 3]?.value === "." &&
      tokens[index + 4]?.value === property;
    if (!forward && !reverse) continue;
    const literal = forward ? tokens[index + 4]! : tokens[index]!;
    const value = decodedString(literal).toLowerCase();
    if (expected ? value === expected : /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return true;
  }
  return false;
}

function containsReturnOrThrow(tokens: readonly DartToken[]): boolean {
  return tokens.some((token) => token.value === "return" || token.value === "throw");
}

export function hasExactHttpsHostAllowlist(
  document: DartDocument,
  sinkTokenIndex: number,
  taintedNames: ReadonlySet<string>,
): boolean {
  const tokens = document.tokens;
  for (let index = 0; index < sinkTokenIndex; index++) {
    if (tokens[index]!.value !== "if" || tokens[index + 1]?.value !== "(") continue;
    const conditionClose = document.pairs.get(index + 1);
    if (conditionClose === undefined || conditionClose >= sinkTokenIndex) continue;
    const condition = tokens.slice(index + 2, conditionClose);
    const positive = condition.some((token) => token.value === "&&") &&
      exactPropertyComparison(condition, taintedNames, "scheme", "==", "https") &&
      exactPropertyComparison(condition, taintedNames, "host", "==");
    const reject = condition.some((token) => token.value === "||") &&
      exactPropertyComparison(condition, taintedNames, "scheme", "!=", "https") &&
      exactPropertyComparison(condition, taintedNames, "host", "!=");
    const bodyStart = conditionClose + 1;
    if (tokens[bodyStart]?.value === "{") {
      const bodyEnd = document.pairs.get(bodyStart);
      if (bodyEnd === undefined) continue;
      if (positive && sinkTokenIndex > bodyStart && sinkTokenIndex < bodyEnd) return true;
      if (reject && bodyEnd < sinkTokenIndex && containsReturnOrThrow(tokens.slice(bodyStart + 1, bodyEnd))) {
        return true;
      }
    } else {
      let bodyEnd = bodyStart;
      while (bodyEnd < tokens.length && tokens[bodyEnd]!.value !== ";") bodyEnd++;
      if (positive && sinkTokenIndex >= bodyStart && sinkTokenIndex <= bodyEnd) return true;
      if (reject && bodyEnd < sinkTokenIndex && containsReturnOrThrow(tokens.slice(bodyStart, bodyEnd))) {
        return true;
      }
    }
  }
  return false;
}

export function expressionReferencesAny(expression: DartExpression, names: Iterable<string>): boolean {
  return expressionReferences(expression, new Set(names));
}
