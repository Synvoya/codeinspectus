import {
  expression,
  expressionIdentifiers,
  expressionReferencesName,
  isConditionallyExecuted,
  jsCalls,
  jsDefinitions,
  lexicalScopeAt,
  nearestDefinition,
  objectProperty,
  referenceHasMutation,
  resolveImport,
  staticString,
  type JsCall,
  type JsDocument,
  type JsExpression,
  type JsToken,
  type JsxElement,
} from "./javascript.js";

export function isReactNativeWebView(document: JsDocument, element: JsxElement): boolean {
  const origin = resolveImport(document, element.reference, element.tokenIndex);
  return origin?.source === "react-native-webview" &&
    (origin.imported === "default" || origin.imported === "WebView");
}

export function isAsyncStorageReceiver(
  document: JsDocument,
  call: JsCall,
): boolean {
  if (call.reference.length < 2) return false;
  const receiver = call.reference.slice(0, -1);
  // The contract intentionally permits one source-ordered alias, not arbitrary
  // transitive value-flow through a storage-shaped object.
  const origin = resolveImport(document, receiver, call.tokenIndex, 1);
  return origin?.source === "@react-native-async-storage/async-storage" &&
      (origin.imported === "default" || origin.imported === "AsyncStorage") ||
    origin?.source === "react-native" && origin.imported === "AsyncStorage";
}

function declaredCallbackParameterNames(input: readonly JsToken[]): string[] {
  let prefix = [...input];
  if (prefix[0]?.value === "async") prefix = prefix.slice(1);
  if (prefix[0]?.value === "(" && prefix.at(-1)?.value === ")") prefix = prefix.slice(1, -1);
  if (prefix[0]?.value === "{") {
    const names: string[] = [];
    let depth = 0;
    for (let index = 1; index < prefix.length; index++) {
      const token = prefix[index]!;
      if (token.value === "{") depth++;
      if (token.value === "}") {
        if (depth === 0) break;
        depth--;
      }
      if (depth !== 0 || token.kind !== "identifier") continue;
      if (prefix[index - 1]?.value === ".") continue;
      const local = prefix[index + 1]?.value === ":" && prefix[index + 2]?.kind === "identifier"
        ? prefix[index + 2]!.value
        : token.value;
      names.push(local);
      while (index < prefix.length && ![",", "}"].includes(prefix[index]!.value)) index++;
      if (prefix[index]?.value === "}") break;
    }
    return [...new Set(names)];
  }
  const first = prefix.find((token) =>
    token.kind === "identifier" && !["async", "readonly", "public", "private", "protected"].includes(token.value)
  );
  return first ? [first.value] : [];
}

function callbackParameters(argument: JsExpression): string[] {
  const tokens = argument.tokens;
  const arrow = tokens.findIndex((token) => token.value === "=>");
  if (arrow >= 0) return declaredCallbackParameterNames(tokens.slice(0, arrow));
  const functionIndex = tokens.findIndex((token) => token.value === "function");
  if (functionIndex < 0) return [];
  const open = tokens.findIndex((token, index) => index > functionIndex && token.value === "(");
  if (open < 0) return [];
  let depth = 0;
  let close = -1;
  for (let index = open; index < tokens.length; index++) {
    if (tokens[index]!.value === "(") depth++;
    if (tokens[index]!.value === ")" && --depth === 0) {
      close = index;
      break;
    }
  }
  return close > open ? declaredCallbackParameterNames(tokens.slice(open + 1, close)) : [];
}

interface TaintSeed {
  name: string;
  tokenIndex: number;
  start: number;
  end: number;
}

const callbackSeedCache = new WeakMap<JsDocument, TaintSeed[]>();

function callOrigin(document: JsDocument, call: JsCall): ReturnType<typeof resolveImport> {
  if (call.reference.length < 2) return resolveImport(document, call.reference, call.tokenIndex);
  return resolveImport(document, call.reference.slice(0, -1), call.tokenIndex);
}

function isLinkingCall(document: JsDocument, call: JsCall): boolean {
  const origin = callOrigin(document, call);
  if (origin?.source === "react-native" && origin.imported === "Linking") return true;
  return origin?.source === "expo-linking" && [
    "*", "default", "Linking", "addEventListener", "getInitialURL", "useURL",
  ].includes(origin.imported);
}

function callbackTaintSeeds(document: JsDocument): TaintSeed[] {
  const cached = callbackSeedCache.get(document);
  if (cached) return cached;
  const seeds: TaintSeed[] = [];
  const addCallbackSeeds = (callback: JsExpression): void => {
    for (const name of callbackParameters(callback)) {
      const parameterDefinition = jsDefinitions(document).find((definition) =>
        definition.kind === "parameter" && definition.name === name &&
        definition.tokenIndex >= callback.start && definition.tokenIndex <= callback.end
      );
      seeds.push({
        name,
        tokenIndex: parameterDefinition?.tokenIndex ?? callback.start,
        start: callback.start,
        end: callback.end,
      });
    }
  };
  for (const call of jsCalls(document)) {
    if (call.callee === "addEventListener" && isLinkingCall(document, call)) {
      const eventName = staticString(document, call.arguments[0], call.tokenIndex);
      const callback = call.arguments[1];
      if (eventName === "url" && callback) addCallbackSeeds(callback);
      continue;
    }
    if (call.callee !== "then" || ![".", "?."].includes(document.tokens[call.tokenIndex - 1]?.value ?? "")) {
      continue;
    }
    const receiverClose = call.tokenIndex - 2;
    if (document.tokens[receiverClose]?.value !== ")") continue;
    const initialUrlCall = jsCalls(document).find((candidate) =>
      candidate.closeIndex === receiverClose && candidate.callee === "getInitialURL" &&
      isLinkingCall(document, candidate)
    );
    const callback = call.arguments[0];
    if (initialUrlCall && callback) addCallbackSeeds(callback);
  }
  callbackSeedCache.set(document, seeds);
  return seeds;
}

function expressionContainsProvenUseRoute(document: JsDocument, expressionValue: JsExpression): boolean {
  return jsCalls(document).some((call) => {
    if (call.tokenIndex < expressionValue.start || call.closeIndex >= expressionValue.end) return false;
    const origin = callOrigin(document, call);
    return origin?.imported === "useRoute" &&
      (origin.source === "@react-navigation/native" || origin.source.startsWith("@react-navigation/"));
  });
}

function provenRouteBinding(document: JsDocument, name: string, useIndex: number): boolean {
  const definition = nearestDefinition(document, name, useIndex);
  if (!definition) return false;
  if (definition.kind === "parameter") return true;
  return definition.expression ? expressionContainsProvenUseRoute(document, definition.expression) : false;
}

function directRouteSource(
  document: JsDocument,
  expressionValue: JsExpression,
  useIndex: number,
): boolean {
  const values = expressionValue.tokens.map((token) => token.value);
  for (let index = 0; index < values.length - 2; index++) {
    if (
      values[index] === "route" && [".", "?."].includes(values[index + 1] ?? "") &&
      values[index + 2] === "params" && provenRouteBinding(document, "route", useIndex)
    ) return true;
    if (
      values[index] === "route" && [".", "?."].includes(values[index + 1] ?? "") &&
      values[index + 2] === "params" && index >= 2 &&
      values[index - 1] === "." && expressionValue.tokens[index - 2]?.kind === "identifier" &&
      provenRouteBinding(document, values[index - 2]!, useIndex)
    ) return true;
  }
  return expressionContainsProvenUseRoute(document, expressionValue) && values.includes("params");
}

function hookOrLinkingSource(document: JsDocument, expressionValue: JsExpression): boolean {
  const start = expressionValue.start;
  const end = expressionValue.end;
  return jsCalls(document).some((call) => {
    if (call.tokenIndex < start || call.closeIndex >= end) return false;
    const origin = callOrigin(document, call);
    if (
      origin?.source === "expo-router" &&
      ["useLocalSearchParams", "useGlobalSearchParams"].includes(origin.imported)
    ) return true;
    if (
      ["getInitialURL", "useURL"].includes(call.callee) ||
      ["getInitialURL", "useURL"].includes(origin?.imported ?? "")
    ) {
      return isLinkingCall(document, call);
    }
    return false;
  });
}

function seedReachesUse(
  document: JsDocument,
  name: string,
  useIndex: number,
  seeds: readonly TaintSeed[],
): boolean {
  const seed = seeds
    .filter((candidate) => candidate.name === name && useIndex >= candidate.start && useIndex <= candidate.end)
    .sort((left, right) => right.tokenIndex - left.tokenIndex)[0];
  if (!seed) return false;
  const shadow = jsDefinitions(document)
    .filter((definition) => definition.name === name && definition.tokenIndex > seed.tokenIndex && definition.tokenIndex < useIndex)
    .sort((left, right) => right.tokenIndex - left.tokenIndex)[0];
  return !shadow;
}

function referenceIdentifiers(value: JsExpression): string[] {
  return value.tokens.flatMap((token, index) => {
    if (token.kind !== "identifier") return [];
    if ([".", "?."].includes(value.tokens[index - 1]?.value ?? "")) return [];
    if (value.tokens[index + 1]?.value === ":") return [];
    return [token.value];
  });
}

export function expressionReachesUntrustedNavigation(
  document: JsDocument,
  expressionValue: JsExpression | undefined,
  useIndex: number,
  seen = new Set<string>(),
  depth = 0,
): boolean {
  if (!expressionValue || depth > 8) return false;
  if (directRouteSource(document, expressionValue, useIndex) || hookOrLinkingSource(document, expressionValue)) return true;
  const seeds = callbackTaintSeeds(document);
  for (const identifier of referenceIdentifiers(expressionValue)) {
    if (seedReachesUse(document, identifier, useIndex, seeds)) return true;
    const definition = nearestDefinition(document, identifier, useIndex);
    if (!definition?.expression) continue;
    const key = `${definition.tokenIndex}:${definition.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (
      expressionReachesUntrustedNavigation(
        document,
        definition.expression,
        definition.tokenIndex,
        seen,
        depth + 1,
      )
    ) return true;
  }
  return false;
}

function knownSanitizerReference(document: JsDocument, call: JsCall): boolean {
  const origin = callOrigin(document, call);
  if (origin?.source === "dompurify" && ["default", "sanitize"].includes(origin.imported)) return true;
  if (origin?.source === "sanitize-html" && ["default", "sanitizeHtml"].includes(origin.imported)) return true;
  if (origin?.source === "xss" && ["default", "filterXSS"].includes(origin.imported)) return true;
  return call.reference.length === 2 && call.reference[0] === "DOMPurify" && call.callee === "sanitize" &&
    resolveImport(document, ["DOMPurify"], call.tokenIndex)?.source === "dompurify";
}

export function isSanitizedHtml(
  document: JsDocument,
  expressionValue: JsExpression | undefined,
  useIndex: number,
  seen = new Set<string>(),
): boolean {
  if (!expressionValue) return false;
  let start = expressionValue.start;
  let end = expressionValue.end;
  while (
    document.tokens[start]?.value === "(" && document.tokens[end - 1]?.value === ")" &&
    document.pairs.get(start) === end - 1
  ) {
    start++;
    end--;
  }
  if (jsCalls(document).some((call) => {
    const referenceStart = call.tokenIndex - Math.max(0, call.reference.length - 1) * 2;
    return referenceStart === start && call.closeIndex === end - 1 && knownSanitizerReference(document, call);
  })) return true;
  const identifiers = expressionIdentifiers(expressionValue);
  if (identifiers.length !== 1 || expressionValue.tokens.length !== 1) return false;
  const definition = nearestDefinition(document, identifiers[0]!, useIndex);
  if (!definition?.expression) return false;
  const key = `${definition.tokenIndex}:${definition.name}`;
  if (seen.has(key)) return false;
  seen.add(key);
  return isSanitizedHtml(document, definition.expression, definition.tokenIndex, seen);
}

function exactComparison(
  tokens: readonly JsToken[],
  properties: ReadonlySet<string>,
  expected: (value: string) => boolean,
  equality: ReadonlySet<string>,
): string | undefined {
  for (let index = 0; index < tokens.length - 4; index++) {
    const root = tokens[index];
    const property = tokens[index + 2];
    const operator = tokens[index + 3];
    const literal = tokens[index + 4];
    if (
      root?.kind === "identifier" && [".", "?."].includes(tokens[index + 1]?.value ?? "") &&
      property?.kind === "identifier" && properties.has(property.value) &&
      equality.has(operator?.value ?? "") && literal?.staticValue !== undefined && expected(literal.staticValue)
    ) return root.value;
    if (
      root?.staticValue !== undefined && expected(root.staticValue) &&
      equality.has(tokens[index + 1]?.value ?? "") && tokens[index + 2]?.kind === "identifier" &&
      [".", "?."].includes(tokens[index + 3]?.value ?? "") &&
      tokens[index + 4]?.kind === "identifier" && properties.has(tokens[index + 4]!.value)
    ) return tokens[index + 2]!.value;
  }
  return undefined;
}

function safeHost(host: string): boolean {
  return host.length > 0 && !host.includes("*") && !/[\s/@]/.test(host) && !host.includes("..");
}

function exactHttpsHostPredicate(tokens: readonly JsToken[], negative = false): string | undefined {
  const operators = new Set(negative ? ["!=="] : ["==="]);
  if (tokens.some((token) => token.value === "!")) return undefined;
  if (tokens.some((token) => [",", "=", "+=", "-=", "*=", "/=", "&&=", "||=", "??="].includes(token.value))) {
    return undefined;
  }
  if (
    tokens.filter((token) => token.value === (negative ? "!==" : "===")).length !== 2 ||
    tokens.some((token) => token.value === (negative ? "===" : "!=="))
  ) return undefined;
  const schemeRoot = exactComparison(
    tokens,
    new Set(["protocol", "scheme"]),
    (value) => value.toLowerCase() === "https" || value.toLowerCase() === "https:",
    operators,
  );
  const hostRoot = exactComparison(tokens, new Set(["hostname", "host"]), safeHost, operators);
  if (!schemeRoot || !hostRoot || schemeRoot !== hostRoot) return undefined;
  if (negative) {
    if (!tokens.some((token) => token.value === "||") || tokens.some((token) => token.value === "&&")) {
      return undefined;
    }
  } else if (
    !tokens.some((token) => token.value === "&&") || tokens.some((token) => token.value === "||")
  ) return undefined;
  return schemeRoot;
}

function expressionSignature(value: JsExpression): string {
  return value.tokens.map((token) =>
    token.staticValue === undefined ? `${token.kind}:${token.value}` : `${token.kind}:${token.staticValue}`
  ).join("|");
}

function simpleExpressionRoot(value: JsExpression): string | undefined {
  if (value.tokens[0]?.kind !== "identifier") return undefined;
  for (let index = 1; index < value.tokens.length; index += 2) {
    if (![".", "?."].includes(value.tokens[index]?.value ?? "") || value.tokens[index + 1]?.kind !== "identifier") {
      return undefined;
    }
  }
  return value.tokens[0].value;
}

function provenanceKeys(
  document: JsDocument,
  value: JsExpression,
  useIndex: number,
  depth = 0,
  seen = new Set<string>(),
): Set<string> {
  const keys = new Set([`expr:${expressionSignature(value)}`]);
  if (depth > 5 || value.tokens.length !== 1 || value.tokens[0]?.kind !== "identifier") return keys;
  const definition = nearestDefinition(document, value.tokens[0].value, useIndex);
  if (!definition?.expression) return keys;
  const definitionKey = `def:${definition.tokenIndex}:${definition.name}`;
  keys.add(definitionKey);
  if (seen.has(definitionKey)) return keys;
  seen.add(definitionKey);
  for (const key of provenanceKeys(document, definition.expression, definition.tokenIndex, depth + 1, seen)) {
    keys.add(key);
  }
  return keys;
}

function newUrlArgument(
  document: JsDocument,
  root: string,
  useIndex: number,
): JsExpression | undefined {
  const definition = nearestDefinition(document, root, useIndex);
  if (!definition?.expression) return undefined;
  return jsCalls(document).find((call) => {
    if (
      call.callee !== "URL" || call.tokenIndex < definition.expression!.start ||
      call.closeIndex >= definition.expression!.end
    ) return false;
    return document.tokens[call.tokenIndex - 1]?.value === "new" &&
      nearestDefinition(document, "URL", call.tokenIndex) === undefined;
  })?.arguments[0];
}

function guardRootBoundToSource(
  document: JsDocument,
  root: string,
  source: JsExpression,
  useIndex: number,
): boolean {
  if (referenceHasMutation(document, root, useIndex)) return false;
  if (simpleExpressionRoot(source) === root) return true;
  const argument = newUrlArgument(document, root, useIndex);
  if (!argument) return false;
  const sourceKeys = provenanceKeys(document, source, source.start);
  return [...provenanceKeys(document, argument, useIndex)].some((key) => sourceKeys.has(key));
}

function guardedByPositiveIf(
  document: JsDocument,
  source: JsExpression,
  sinkIndex: number,
): boolean {
  const tokens = document.tokens;
  for (let index = 0; index < sinkIndex - 1; index++) {
    if (tokens[index]!.value !== "if" || tokens[index + 1]?.value !== "(") continue;
    if (isConditionallyExecuted(document, index)) continue;
    const close = document.pairs.get(index + 1);
    if (close === undefined || close >= sinkIndex) continue;
    const root = exactHttpsHostPredicate(tokens.slice(index + 2, close));
    if (!root || !guardRootBoundToSource(document, root, source, sinkIndex)) continue;
    const bodyOpen = close + 1;
    if (tokens[bodyOpen]?.value !== "{") continue;
    const bodyClose = document.pairs.get(bodyOpen);
    if (bodyClose !== undefined && sinkIndex > bodyOpen && sinkIndex < bodyClose) return true;
  }
  return false;
}

function guardedByRejectBefore(
  document: JsDocument,
  source: JsExpression,
  sinkIndex: number,
): boolean {
  const tokens = document.tokens;
  const sinkScope = lexicalScopeAt(document, sinkIndex);
  for (let index = 0; index < sinkIndex - 1; index++) {
    if (tokens[index]!.value !== "if" || tokens[index + 1]?.value !== "(") continue;
    if (isConditionallyExecuted(document, index)) continue;
    const guardScope = lexicalScopeAt(document, index);
    if (
      guardScope.length !== sinkScope.length ||
      guardScope.some((open, scopeIndex) => sinkScope[scopeIndex] !== open)
    ) continue;
    const close = document.pairs.get(index + 1);
    if (close === undefined || close >= sinkIndex) continue;
    const root = exactHttpsHostPredicate(tokens.slice(index + 2, close), true);
    if (!root || !guardRootBoundToSource(document, root, source, sinkIndex)) continue;
    const bodyStart = close + 1;
    if (tokens[bodyStart]?.value === "{") {
      const bodyClose = document.pairs.get(bodyStart);
      const bodyScope = [...guardScope, bodyStart];
      if (bodyClose !== undefined && bodyClose < sinkIndex && tokens.slice(bodyStart + 1, bodyClose).some((token, offset) => {
        if (!["return", "throw", "continue"].includes(token.value)) return false;
        const tokenIndex = bodyStart + 1 + offset;
        if (isConditionallyExecuted(document, tokenIndex)) return false;
        const tokenScope = lexicalScopeAt(document, tokenIndex);
        return tokenScope.length === bodyScope.length &&
          tokenScope.every((open, scopeIndex) => bodyScope[scopeIndex] === open);
      })) return true;
    } else {
      let cursor = bodyStart;
      while (cursor < sinkIndex && tokens[cursor]!.value !== ";") cursor++;
      if (["return", "throw", "continue"].includes(tokens[bodyStart]?.value ?? "")) {
        return true;
      }
    }
  }
  return false;
}

export function hasExactHttpsHostGuard(
  document: JsDocument,
  source: JsExpression,
  sinkIndex: number,
): boolean {
  return guardedByPositiveIf(document, source, sinkIndex) ||
    guardedByRejectBefore(document, source, sinkIndex);
}

export function hasFixedHttpsOriginWhitelist(
  document: JsDocument,
  expressionValue: JsExpression | undefined,
  useIndex: number,
): boolean {
  if (!expressionValue) return false;
  const tokens = expressionValue.tokens;
  if (tokens[0]?.value !== "[" || tokens.at(-1)?.value !== "]") return false;
  const strings = tokens.filter((token) => token.kind === "string" || token.kind === "template");
  if (strings.length === 0 || strings.some((token) => token.staticValue === undefined)) return false;
  if (tokens.some((token) => token.kind === "identifier")) return false;
  return strings.every((token) => {
    try {
      const url = new URL(token.staticValue!);
      return url.protocol === "https:" && safeHost(url.hostname) && url.origin === token.staticValue;
    } catch {
      return false;
    }
  });
}

export function isSafeNavigationCallback(
  document: JsDocument,
  expressionValue: JsExpression | undefined,
  seen = new Set<string>(),
): boolean {
  if (!expressionValue) return false;
  const tokens = expressionValue.tokens;
  if (tokens.length === 1 && tokens[0]?.kind === "identifier") {
    const definition = nearestDefinition(document, tokens[0].value, expressionValue.start);
    if (!definition?.expression) return false;
    const key = `${definition.tokenIndex}:${definition.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return isSafeNavigationCallback(document, definition.expression, seen);
  }
  const arrow = tokens.findIndex((token) => token.value === "=>");
  const parameters = callbackParameters(expressionValue);
  if (parameters.length === 0) return false;
  let predicateStart: number;
  if (arrow >= 0) {
    predicateStart = arrow + 1;
  } else {
    const functionIndex = tokens.findIndex((token) => token.value === "function");
    if (functionIndex < 0) return false;
    const body = tokens.findIndex((token, index) => index > functionIndex && token.value === "{");
    if (body < 0) return false;
    predicateStart = body;
  }
  let predicateEnd = tokens.length;
  if (tokens[predicateStart]?.value === "{") {
    if (tokens.filter((token) => token.kind === "identifier" && token.value === "return").length !== 1) {
      return false;
    }
    let lastReturn = -1;
    for (let index = predicateStart + 1; index < tokens.length; index++) {
      if (tokens[index]!.value === "return") lastReturn = index;
    }
    if (lastReturn < 0) return false;
    predicateStart = lastReturn + 1;
    predicateEnd = predicateStart;
    while (predicateEnd < tokens.length && ![";", "}"].includes(tokens[predicateEnd]!.value)) predicateEnd++;
  }
  const predicate = tokens.slice(predicateStart, predicateEnd);
  if (predicate.some((token) => ["?", ":"].includes(token.value))) return false;
  const root = exactHttpsHostPredicate(predicate);
  if (!root) return false;
  const absoluteUse = expressionValue.start + predicateStart;
  if (referenceHasMutation(document, root, absoluteUse)) return false;
  if (parameters.includes(root)) return true;
  const argument = newUrlArgument(document, root, absoluteUse);
  if (!argument) return false;
  const argumentRoot = simpleExpressionRoot(argument);
  return argumentRoot !== undefined && parameters.includes(argumentRoot) &&
    !referenceHasMutation(document, argumentRoot, absoluteUse) &&
    argument.tokens.some((token) => token.kind === "identifier" && token.value === "url");
}

function privateOrReservedIpv4(host: string): boolean {
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
    parts[0] === 100 && (parts[1] ?? 0) >= 64 && (parts[1] ?? 0) <= 127 ||
    parts[0] === 169 && parts[1] === 254 ||
    parts[0] === 172 && (parts[1] ?? 0) >= 16 && (parts[1] ?? 0) <= 31 ||
    parts[0] === 192 && parts[1] === 168 ||
    parts[0] === 192 && parts[1] === 0 && parts[2] === 0 ||
    parts[0] === 192 && parts[1] === 0 && parts[2] === 2 ||
    parts[0] === 192 && parts[1] === 88 && parts[2] === 99 ||
    parts[0] === 198 && ((parts[1] ?? 0) === 18 || (parts[1] ?? 0) === 19) ||
    parts[0] === 198 && parts[1] === 51 && parts[2] === 100 ||
    parts[0] === 203 && parts[1] === 0 && parts[2] === 113 ||
    (parts[0] ?? 0) >= 224;
}

function embeddedIpv4(host: string): string | undefined {
  const lower = host.toLowerCase();
  const prefix = lower.startsWith("::ffff:") ? "::ffff:" : lower.startsWith("::") ? "::" : undefined;
  if (!prefix) return undefined;
  const tail = lower.slice(prefix.length);
  if (tail.includes(".")) return tail;
  const words = tail.split(":");
  if (words.length !== 2 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return undefined;
  const high = Number.parseInt(words[0]!, 16);
  const low = Number.parseInt(words[1]!, 16);
  return `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`;
}

export function isProductionHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (url.protocol !== "https:" || !host) return false;
    if (["localhost", "localhost.localdomain", "::", "::1"].includes(host)) return false;
    if (!host.includes(".") && !host.includes(":")) return false;
    if (/^(?:f[cd]|fe[89ab]|ff|2001:db8)/i.test(host)) return false;
    const mapped = embeddedIpv4(host);
    if (mapped && privateOrReservedIpv4(mapped)) return false;
    if (privateOrReservedIpv4(host)) return false;
    if (/\.(?:internal|local|localhost|example|example\.com|example\.org|example\.net|invalid|test)$/.test(host)) return false;
    if (/^(?:example|example\.com|example\.org|example\.net)$/.test(host)) return false;
    return true;
  } catch {
    return false;
  }
}

export function sourceProperty(
  document: JsDocument,
  sourceExpression: JsExpression | undefined,
  property: "uri" | "html" | "baseUrl",
  useIndex: number,
): JsExpression | undefined {
  return objectProperty(document, sourceExpression, property, useIndex);
}

export function sourceLiteral(
  document: JsDocument,
  sourceExpression: JsExpression | undefined,
  property: "uri" | "html" | "baseUrl",
  useIndex: number,
): string | undefined {
  const value = sourceProperty(document, sourceExpression, property, useIndex);
  return staticString(document, value, value?.start ?? useIndex);
}

export function likelyBridgePropName(name: string): boolean {
  return [
    "onMessage", "injectedJavaScript", "injectedJavaScriptBeforeContentLoaded",
    "injectedJavaScriptForMainFrameOnly",
  ].includes(name);
}

export function sensitiveContextWords(...values: Array<JsExpression | undefined>): string[] {
  return values.flatMap((value) => [
    ...expressionIdentifiers(value),
    ...(value?.tokens ?? []).flatMap((token) => token.staticValue === undefined ? [] : [token.staticValue]),
  ]).filter(Boolean);
}

export function expressionIsStaticEmptyOrBoolean(
  document: JsDocument,
  value: JsExpression | undefined,
  useIndex: number,
): boolean {
  if (!value) return true;
  const literal = staticString(document, value, useIndex);
  if (literal !== undefined) return literal.length === 0;
  return value.tokens.length === 1 && ["true", "false", "null", "undefined"].includes(value.tokens[0]!.value);
}

export function expressionIsSafeCredentialDerivative(
  document: JsDocument,
  value: JsExpression | undefined,
): boolean {
  if (!value) return true;
  const safe = new Set(["hash", "hashSync", "digest", "mask", "redact", "fingerprint", "scrub"]);
  const tokens = value.tokens;
  if (
    tokens[0]?.kind === "identifier" && safe.has(tokens[0].value) && tokens[1]?.value === "(" &&
    document.pairs.get(value.start + 1) === value.end - 1
  ) return true;
  if (tokens.length === 1 && tokens[0]?.kind === "identifier") {
    return /(?:Hash|Hashed|Digest|Fingerprint|Masked|Redacted|Length|Expiry|Expires|Expiration|Status|Type)$/.test(
      tokens[0].value,
    );
  }
  return tokens.length === 3 && tokens[0]?.kind === "identifier" &&
    [".", "?."].includes(tokens[1]?.value ?? "") &&
    ["length", "status", "type"].includes(tokens[2]?.value ?? "");
}

export function expressionForTokens(tokens: readonly JsToken[]): JsExpression {
  return expression(tokens);
}

export function expressionMentions(value: JsExpression | undefined, name: string): boolean {
  return expressionReferencesName(value, name);
}
