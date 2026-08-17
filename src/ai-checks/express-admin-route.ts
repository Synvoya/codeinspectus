/**
 * Conservative Express privileged-route boundary check.
 *
 * A finding requires a statically-proven Express app/router, an immediate literal path with an
 * `admin` segment, and a same-file handler whose body is visibly free of authentication or
 * authorization evidence. Ambiguous middleware, receivers, paths, and handlers stay silent.
 */

import type { Finding } from "../types.js";
import {
  isConditionallyExecuted,
  jsCalls,
  jsDefinitions,
  jsMemberAssignments,
  lexicalScopeAt,
  nearestDefinition,
  resolveImport,
  type JsCall,
  type JsDefinition,
  type JsDocument,
  type JsExpression,
  type JsToken,
} from "../packs/react-native/javascript.js";
import { loadJavaScriptBaselineProject } from "../packs/javascript-baseline/project.js";
import { makeAiFinding } from "./finding.js";

const RULE_ID = "ci-ai-express-admin-route-no-authz";
const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "all"]);
const STANDARD_EXPRESS_MIDDLEWARE = new Set(["json", "urlencoded", "static"]);
const PUBLIC_ADMIN_UTILITY_SEGMENTS = new Set(["login", "callback", "health", "status"]);
const RESPONSE_SINK_METHODS = new Set([
  "download", "end", "json", "jsonp", "redirect", "render", "send", "sendFile", "sendStatus",
]);
const DATABASE_ROOT = /^(?:db|database|knex|orm|prisma|sequelize|supabase|typeorm)$/i;
const DATABASE_OPERATION = /^(?:aggregate|count|create|createMany|delete|deleteMany|destroy|execute|find|findAll|findFirst|findMany|findOne|findUnique|insert|query|raw|remove|save|select|transaction|update|updateMany|upsert)$/i;
const ADMIN_OPERATION = /^(?:add|ban|create|delete|disable|enable|grant|invite|remove|reset|revoke|set|suspend|update)(?:Admin|Permission|Role|User|Users)$/i;
const UNRESOLVED_GUARD = /(?:admin|auth|acl|guard|jwt|permission|policy|principal|rbac|role|session)/i;
const MAX_NOTES = 24;
const MAX_FINDINGS = 512;
const MAX_CALLS_PER_FILE = 2_048;
const MAX_ROUTE_CANDIDATES_PER_FILE = 512;

function generatedOrVendoredSource(path: string): boolean {
  const lower = path.toLowerCase();
  if (/\.min\.(?:js|mjs|cjs)$/.test(lower)) return true;
  return lower.split("/").slice(0, -1).some((segment) =>
    [".next", "build", "dist", "generated", "vendor", "vendors"].includes(segment)
  );
}

export interface ExpressAdminRouteAnalysis {
  findings: Finding[];
  notes: string[];
}

interface HandlerBody {
  start: number;
  end: number;
  scopeOpen?: number;
  requestRoot?: string;
  responseRoot?: string;
}

interface MiddlewareIndex {
  globalUnknownBefore?: number;
  prefixes: Map<string, number>;
}

interface DocumentIndex {
  calls: readonly JsCall[];
  callBySpan: ReadonlyMap<string, JsCall>;
  middlewareByReceiver: ReadonlyMap<number, MiddlewareIndex>;
  guardedMounts: ReadonlySet<number>;
  unguardedMounts: ReadonlySet<number>;
  ambiguousMounts: ReadonlySet<number>;
  lines: readonly string[];
}

interface ExpressMountIndex {
  guarded: ReadonlySet<number>;
  unguarded: ReadonlySet<number>;
  ambiguous: ReadonlySet<number>;
}

interface LocalHelper {
  definition: JsDefinition;
  body: HandlerBody;
}

interface TokenSpan {
  start: number;
  end: number;
}

function referenceStart(call: JsCall): number {
  return call.tokenIndex - Math.max(0, call.reference.length - 1) * 2;
}

function callSpanKey(start: number, end: number): string {
  return `${start}:${end}`;
}

function wholeExpressionCall(
  index: Pick<DocumentIndex, "callBySpan">,
  value: JsExpression,
): JsCall | undefined {
  return index.callBySpan.get(callSpanKey(value.start, value.end));
}

function isExpressFactory(document: JsDocument, call: JsCall): boolean {
  if (call.reference.length === 1) {
    const origin = resolveImport(document, call.reference, call.tokenIndex);
    return origin?.source === "express" && ["default", "Router"].includes(origin.imported);
  }
  if (call.reference.length !== 2 || call.reference[1] !== "Router") return false;
  const direct = resolveImport(document, call.reference, call.tokenIndex);
  if (direct?.source === "express" && direct.imported === "Router") return true;
  const root = resolveImport(document, [call.reference[0]!], call.tokenIndex);
  return root?.source === "express" && ["default", "*"].includes(root.imported);
}

function expressReceiver(
  document: JsDocument,
  index: Pick<DocumentIndex, "callBySpan">,
  call: JsCall,
): JsDefinition | undefined {
  if (call.reference.length !== 2) return undefined;
  const definition = nearestDefinition(document, call.reference[0]!, call.tokenIndex);
  if (!definition?.expression || definition.origin) return undefined;
  const factory = wholeExpressionCall(index, definition.expression);
  return factory && isExpressFactory(document, factory) ? definition : undefined;
}

function immediateLiteral(value: JsExpression | undefined): string | undefined {
  const token = value?.tokens[0];
  return value?.tokens.length === 1 && token?.staticValue !== undefined
    ? token.staticValue
    : undefined;
}

function hasAdminSegment(path: string): boolean {
  return path.split("/").some((segment) => segment.toLowerCase() === "admin");
}

function isPublicAdminUtilityPath(path: string): boolean {
  const segments = path.split("/").filter(Boolean).map((segment) => segment.toLowerCase());
  const admin = segments.lastIndexOf("admin");
  return admin >= 0 && admin === segments.length - 2 &&
    PUBLIC_ADMIN_UTILITY_SEGMENTS.has(segments[admin + 1]!);
}

function simpleMiddlewarePrefix(prefix: string): string | undefined {
  if (prefix === "/") return prefix;
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+\/?$/.test(prefix)) return undefined;
  // Express routing is case-insensitive unless the application opts into a dynamic setting that
  // this bounded check cannot prove. Normalizing avoids disproving a middleware match unsafely.
  return prefix.replace(/\/+$/, "").toLowerCase();
}

function isStandardExpressMiddleware(
  document: JsDocument,
  index: Pick<DocumentIndex, "callBySpan">,
  value: JsExpression,
): boolean {
  const call = wholeExpressionCall(index, value);
  if (!call || !STANDARD_EXPRESS_MIDDLEWARE.has(call.callee)) return false;
  if (call.reference.length === 1) {
    const origin = resolveImport(document, call.reference, call.tokenIndex);
    return origin?.source === "express" && origin.imported === call.callee;
  }
  if (call.reference.length !== 2) return false;
  const root = resolveImport(document, [call.reference[0]!], call.tokenIndex);
  return root?.source === "express" && ["default", "*"].includes(root.imported);
}

function recordUnknownMiddleware(
  middleware: MiddlewareIndex,
  callIndex: number,
  prefix?: string,
): void {
  if (prefix === undefined) {
    middleware.globalUnknownBefore = Math.min(middleware.globalUnknownBefore ?? callIndex, callIndex);
    return;
  }
  middleware.prefixes.set(prefix, Math.min(middleware.prefixes.get(prefix) ?? callIndex, callIndex));
}

function buildMiddlewareIndex(
  document: JsDocument,
  callBySpan: ReadonlyMap<string, JsCall>,
  calls: readonly JsCall[],
): ReadonlyMap<number, MiddlewareIndex> {
  const result = new Map<number, MiddlewareIndex>();
  const partialIndex = { callBySpan };
  for (const call of calls) {
    if (call.reference.length !== 2 || call.reference[1] !== "use") continue;
    const receiver = expressReceiver(document, partialIndex, call);
    if (!receiver) continue;
    const middleware = result.get(receiver.tokenIndex) ?? { prefixes: new Map<string, number>() };
    result.set(receiver.tokenIndex, middleware);

    const literal = immediateLiteral(call.arguments[0]);
    const middlewareArgs = literal === undefined ? call.arguments : call.arguments.slice(1);
    if (
      middlewareArgs.length > 0 &&
      middlewareArgs.every((argument) => isStandardExpressMiddleware(document, partialIndex, argument))
    ) continue;
    if (literal === undefined) {
      recordUnknownMiddleware(middleware, call.tokenIndex);
      continue;
    }
    const prefix = simpleMiddlewarePrefix(literal);
    // Express path strings with parameters/wildcards/metacharacters are not safe to disprove.
    recordUnknownMiddleware(middleware, call.tokenIndex, prefix);
  }
  return result;
}

function directIdentifier(value: JsExpression | undefined): string | undefined {
  return value?.tokens.length === 1 && value.tokens[0]?.kind === "identifier"
    ? value.tokens[0].value
    : undefined;
}

function hasDirectReassignment(
  document: JsDocument,
  definition: JsDefinition,
  useIndex: number,
): boolean {
  for (let index = definition.tokenIndex + 1; index < useIndex; index++) {
    if (document.tokens[index]?.value !== definition.name) continue;
    if (!["=", "+=", "-=", "*=", "/=", "&&=", "||=", "??="].includes(
      document.tokens[index + 1]?.value ?? "",
    )) continue;
    return true;
  }
  return false;
}

function expressDefinitionFromExpression(
  document: JsDocument,
  index: Pick<DocumentIndex, "callBySpan">,
  value: JsExpression,
  useIndex: number,
  depth = 0,
  seen = new Set<number>(),
): { definition: JsDefinition; ambiguous: boolean } | undefined {
  const name = directIdentifier(value);
  if (!name || depth > 3) return undefined;
  const definition = nearestDefinition(document, name, useIndex);
  if (!definition?.expression || definition.origin || seen.has(definition.tokenIndex)) return undefined;
  const reassigned = definition.kind === "assignment" || hasDirectReassignment(document, definition, useIndex);
  const factory = wholeExpressionCall(index, definition.expression);
  if (factory && isExpressFactory(document, factory)) {
    return { definition, ambiguous: reassigned };
  }
  const alias = directIdentifier(definition.expression);
  if (!alias) {
    if (definition.kind !== "assignment") return undefined;
    seen.add(definition.tokenIndex);
    const prior = expressDefinitionFromExpression(
      document,
      index,
      value,
      definition.tokenIndex - 1,
      depth + 1,
      seen,
    );
    return prior ? { definition: prior.definition, ambiguous: true } : undefined;
  }
  seen.add(definition.tokenIndex);
  const resolved = expressDefinitionFromExpression(
    document,
    index,
    definition.expression,
    definition.tokenIndex,
    depth + 1,
    seen,
  );
  return resolved ? { definition: resolved.definition, ambiguous: reassigned || resolved.ambiguous } : undefined;
}

function buildGuardedMountIndex(
  document: JsDocument,
  callBySpan: ReadonlyMap<string, JsCall>,
  calls: readonly JsCall[],
): ExpressMountIndex {
  const guarded = new Set<number>();
  const unguarded = new Set<number>();
  const ambiguous = new Set<number>();
  const partialIndex = { callBySpan };
  for (const call of calls) {
    if (call.reference.length !== 2 || call.reference[1] !== "use") continue;
    if (!expressReceiver(document, partialIndex, call)) continue;
    const offset = immediateLiteral(call.arguments[0]) === undefined ? 0 : 1;
    const mounted = call.arguments.slice(offset).map((argument) =>
      expressDefinitionFromExpression(document, partialIndex, argument, call.tokenIndex)
    );
    for (let index = 0; index < mounted.length; index++) {
      const mountedReceiver = mounted[index];
      if (!mountedReceiver) continue;
      const hasUnknownGuard = call.arguments.slice(offset).some((argument, argumentIndex) =>
        argumentIndex !== index &&
        !expressDefinitionFromExpression(document, partialIndex, argument, call.tokenIndex) &&
        !isStandardExpressMiddleware(document, partialIndex, argument)
      );
      if (mountedReceiver.ambiguous) {
        ambiguous.add(mountedReceiver.definition.tokenIndex);
      } else if (hasUnknownGuard) {
        guarded.add(mountedReceiver.definition.tokenIndex);
      } else {
        unguarded.add(mountedReceiver.definition.tokenIndex);
      }
    }
  }
  return { guarded, unguarded, ambiguous };
}

function routePrefixes(path: string): string[] {
  const prefixes = ["/"];
  const segments = path.toLowerCase().split("/").filter(Boolean);
  let current = "";
  for (const segment of segments) {
    current += `/${segment}`;
    prefixes.push(current);
  }
  return prefixes;
}

/** Unresolved prior middleware may authenticate, authorize, or mount a guarded router. */
function hasUnknownPriorMiddleware(
  index: DocumentIndex,
  route: JsCall,
  receiver: JsDefinition,
  path: string,
): boolean {
  const middleware = index.middlewareByReceiver.get(receiver.tokenIndex);
  if (!middleware) return false;
  if ((middleware.globalUnknownBefore ?? Number.POSITIVE_INFINITY) < route.tokenIndex) return true;
  return routePrefixes(path).some((prefix) =>
    (middleware.prefixes.get(prefix) ?? Number.POSITIVE_INFINITY) < route.tokenIndex
  );
}

function functionBodyOpen(
  document: JsDocument,
  paramsClose: number,
  limit: number,
): number | undefined {
  const tokens = document.tokens;
  let cursor = paramsClose + 1;
  if (tokens[cursor]?.value !== ":") return tokens[cursor]?.value === "{" ? cursor : undefined;
  cursor++;
  const typeContinuationAfterBrace = new Set([
    "{", "[", "]", "|", "&", "?", ":", ",", ">", ">>", ">>>", "extends", "is",
  ]);
  while (cursor < limit) {
    const token = tokens[cursor]!;
    if (["(", "["].includes(token.value)) {
      const close = document.pairs.get(cursor);
      if (close === undefined || close >= limit) return undefined;
      cursor = close + 1;
      continue;
    }
    if (token.value === "{") {
      const close = document.pairs.get(cursor);
      if (close === undefined || close >= limit) return undefined;
      // A braced return type is followed by another part of the type or by the real function
      // body. The actual body is the first top-level brace whose close does not continue a type.
      if (typeContinuationAfterBrace.has(tokens[close + 1]?.value ?? "")) {
        cursor = close + 1;
        continue;
      }
      return cursor;
    }
    cursor++;
  }
  return undefined;
}

function handlerParameterRoots(
  document: JsDocument,
  start: number,
  end: number,
): Pick<HandlerBody, "requestRoot" | "responseRoot"> {
  const tokens = document.tokens;
  const names: Array<string | undefined> = [];
  let partStart = start;
  let angleDepth = 0;
  for (let cursor = start; cursor <= end; cursor++) {
    const token = tokens[cursor];
    if (cursor < end && token && ["(", "[", "{"].includes(token.value)) {
      const close = document.pairs.get(cursor);
      if (close !== undefined && close < end) {
        cursor = close;
        continue;
      }
    }
    if (token?.value === "<") {
      angleDepth++;
      continue;
    }
    if ([">", ">>", ">>>"].includes(token?.value ?? "")) {
      angleDepth = Math.max(0, angleDepth - (token?.value.length ?? 0));
      continue;
    }
    if (cursor !== end && (token?.value !== "," || angleDepth > 0)) continue;
    let root = partStart;
    if (tokens[root]?.value === "...") root++;
    names.push(tokens[root]?.kind === "identifier" ? tokens[root]!.value : undefined);
    partStart = cursor + 1;
  }
  return {
    ...(names[0] ? { requestRoot: names[0] } : {}),
    ...(names[1] ? { responseRoot: names[1] } : {}),
  };
}

function rootArrowBody(document: JsDocument, value: JsExpression): HandlerBody | undefined {
  const tokens = document.tokens;
  let cursor = value.start;
  if (tokens[cursor]?.value === "async") cursor++;
  let parameterStart: number;
  let parameterEnd: number;
  if (tokens[cursor]?.kind === "identifier") {
    parameterStart = cursor;
    parameterEnd = cursor + 1;
    cursor++;
  } else if (tokens[cursor]?.value === "(") {
    const close = document.pairs.get(cursor);
    if (close === undefined || close >= value.end) return undefined;
    parameterStart = cursor + 1;
    parameterEnd = close;
    cursor = close + 1;
  } else {
    return undefined;
  }

  let arrow: number | undefined;
  while (cursor < value.end) {
    const token = tokens[cursor]!;
    if (["(", "[", "{"].includes(token.value)) {
      const close = document.pairs.get(cursor);
      if (close === undefined || close >= value.end) return undefined;
      cursor = close + 1;
      continue;
    }
    if (token.value === "=>") arrow = cursor;
    cursor++;
  }
  if (arrow === undefined) return undefined;
  const roots = handlerParameterRoots(document, parameterStart, parameterEnd);
  const bodyStart = arrow + 1;
  if (tokens[bodyStart]?.value !== "{") {
    return bodyStart < value.end ? { start: bodyStart, end: value.end, ...roots } : undefined;
  }
  const close = document.pairs.get(bodyStart);
  return close === value.end - 1
    ? { start: bodyStart + 1, end: close, scopeOpen: bodyStart, ...roots }
    : undefined;
}

function rootFunctionExpressionBody(
  document: JsDocument,
  value: JsExpression,
): HandlerBody | undefined {
  const tokens = document.tokens;
  let cursor = value.start;
  if (tokens[cursor]?.value === "async") cursor++;
  if (tokens[cursor]?.value !== "function") return undefined;
  cursor++;
  if (tokens[cursor]?.kind === "identifier") cursor++;
  if (tokens[cursor]?.value !== "(") return undefined;
  const paramsClose = document.pairs.get(cursor);
  if (paramsClose === undefined || paramsClose >= value.end) return undefined;
  const bodyOpen = functionBodyOpen(document, paramsClose, value.end);
  const bodyClose = bodyOpen === undefined ? undefined : document.pairs.get(bodyOpen);
  const roots = handlerParameterRoots(document, cursor + 1, paramsClose);
  return bodyClose === value.end - 1
    ? { start: bodyOpen! + 1, end: bodyClose, scopeOpen: bodyOpen, ...roots }
    : undefined;
}

function bodyFromRootExpression(document: JsDocument, value: JsExpression): HandlerBody | undefined {
  return rootArrowBody(document, value) ?? rootFunctionExpressionBody(document, value);
}

function declaredFunctionBody(document: JsDocument, definition: JsDefinition): HandlerBody | undefined {
  if (definition.expression) return bodyFromRootExpression(document, definition.expression);
  if (definition.kind !== "function") return undefined;
  const tokens = document.tokens;
  if (tokens[definition.tokenIndex - 1]?.value !== "function") return undefined;
  const open = definition.tokenIndex + 1;
  if (tokens[open]?.value !== "(") return undefined;
  const paramsClose = document.pairs.get(open);
  if (paramsClose === undefined) return undefined;
  const bodyOpen = functionBodyOpen(document, paramsClose, Math.min(tokens.length, paramsClose + 512));
  const bodyClose = bodyOpen === undefined ? undefined : document.pairs.get(bodyOpen);
  const roots = handlerParameterRoots(document, open + 1, paramsClose);
  return bodyClose === undefined
    ? undefined
    : { start: bodyOpen! + 1, end: bodyClose, scopeOpen: bodyOpen, ...roots };
}

function handlerBody(document: JsDocument, value: JsExpression, useIndex: number): HandlerBody | undefined {
  const inline = bodyFromRootExpression(document, value);
  if (inline) return inline;
  if (value.tokens.length !== 1 || value.tokens[0]?.kind !== "identifier") return undefined;
  const definition = nearestDefinition(document, value.tokens[0]!.value, useIndex);
  if (!definition || definition.origin) return undefined;
  return declaredFunctionBody(document, definition);
}

function trimmedExpressionSpan(
  document: JsDocument,
  start: number,
  end: number,
): TokenSpan {
  let left = start;
  let right = end;
  while (
    document.tokens[left]?.value === "(" &&
    document.pairs.get(left) === right - 1
  ) {
    left++;
    right--;
  }
  return { start: left, end: right };
}

function memberReferenceAt(
  document: JsDocument,
  start: number,
  end: number,
): { reference: string[]; end: number } | undefined {
  const tokens = document.tokens;
  if (tokens[start]?.kind !== "identifier") return undefined;
  const reference = [tokens[start]!.value];
  let cursor = start + 1;
  while (
    cursor + 1 < end && [".", "?."].includes(tokens[cursor]?.value ?? "") &&
    tokens[cursor + 1]?.kind === "identifier"
  ) {
    reference.push(tokens[cursor + 1]!.value);
    cursor += 2;
  }
  return { reference, end: cursor };
}

function requestIdentityReference(reference: readonly string[], requestRoot: string): boolean {
  return reference[0] === requestRoot &&
    ["user", "auth", "session", "principal"].includes(reference[1] ?? "");
}

function topLevelClauses(
  document: JsDocument,
  start: number,
  end: number,
  operator: string,
): TokenSpan[] {
  const clauses: TokenSpan[] = [];
  let partStart = start;
  for (let cursor = start; cursor < end; cursor++) {
    const value = document.tokens[cursor]?.value;
    if (["(", "[", "{"].includes(value ?? "")) {
      const close = document.pairs.get(cursor);
      if (close !== undefined && close < end) {
        cursor = close;
        continue;
      }
    }
    if (value !== operator) continue;
    clauses.push({ start: partStart, end: cursor });
    partStart = cursor + 1;
  }
  clauses.push({ start: partStart, end });
  return clauses;
}

function exactAuthenticationAtom(
  document: JsDocument,
  start: number,
  end: number,
  requestRoot: string,
): boolean {
  const span = trimmedExpressionSpan(document, start, end);
  const tokens = document.tokens;
  if (tokens[span.start]?.value === "!") {
    const member = memberReferenceAt(document, span.start + 1, span.end);
    return member?.end === span.end && member.reference.length === 2 &&
      requestIdentityReference(member.reference, requestRoot);
  }
  const left = memberReferenceAt(document, span.start, span.end);
  if (
    left?.reference.length === 2 && requestIdentityReference(left.reference, requestRoot) &&
    ["==", "==="].includes(tokens[left.end]?.value ?? "") && left.end + 2 === span.end &&
    ["null", "undefined"].includes(tokens[left.end + 1]?.value ?? "")
  ) return true;
  if (!["null", "undefined"].includes(tokens[span.start]?.value ?? "")) return false;
  if (!["==", "==="].includes(tokens[span.start + 1]?.value ?? "")) return false;
  const right = memberReferenceAt(document, span.start + 2, span.end);
  return right?.end === span.end && right.reference.length === 2 &&
    requestIdentityReference(right.reference, requestRoot);
}

function isExactAuthenticationRejection(
  document: JsDocument,
  start: number,
  end: number,
  requestRoot: string | undefined,
): boolean {
  if (!requestRoot) return false;
  const span = trimmedExpressionSpan(document, start, end);
  return topLevelClauses(document, span.start, span.end, "||").some((clause) =>
    exactAuthenticationAtom(document, clause.start, clause.end, requestRoot)
  );
}

function exactAuthorizationAtom(
  document: JsDocument,
  start: number,
  end: number,
  requestRoot: string,
): boolean {
  const span = trimmedExpressionSpan(document, start, end);
  const tokens = document.tokens;
  const negated = tokens[span.start]?.value === "!";
  const member = memberReferenceAt(document, span.start + (negated ? 1 : 0), span.end);
  if (!member || !requestIdentityReference(member.reference, requestRoot)) return false;

  const privilegePath = member.reference.slice(2);
  if (negated) {
    if (member.end === span.end && privilegePath.length === 1 && /^(?:is_?admin)$/i.test(privilegePath[0]!)) {
      return true;
    }
    const method = privilegePath.at(-1);
    const privilegeField = privilegePath.at(-2);
    if (
      !method || !privilegeField ||
      !/^(?:includes|has|some|hasRole|hasPermission)$/i.test(method) ||
      !/^(?:role|roles|permission|permissions)$/i.test(privilegeField) ||
      tokens[member.end]?.value !== "(" || document.pairs.get(member.end) !== span.end - 1
    ) return false;
    const argument = tokens.slice(member.end + 1, span.end - 1);
    return argument.length === 1 && argument[0]?.staticValue !== undefined &&
      argument[0].staticValue.length > 0;
  }

  if (privilegePath.length !== 1) return false;
  const field = privilegePath[0]!;
  const operator = tokens[member.end]?.value;
  if (!["!==", "!="].includes(operator ?? "") || member.end + 2 !== span.end) return false;
  const deniedValue = tokens[member.end + 1];
  if (/^(?:role|roles)$/i.test(field)) return deniedValue?.staticValue?.toLowerCase() === "admin";
  if (/^(?:is_?admin)$/i.test(field)) return deniedValue?.value === "true";
  return false;
}

function isExactAuthorizationRejection(
  document: JsDocument,
  start: number,
  end: number,
  requestRoot: string | undefined,
): boolean {
  if (!requestRoot) return false;
  const span = trimmedExpressionSpan(document, start, end);
  return topLevelClauses(document, span.start, span.end, "||").some((clause) =>
    exactAuthorizationAtom(document, clause.start, clause.end, requestRoot)
  );
}

function denialStatement(document: JsDocument, after: number, handlerEnd: number): TokenSpan | undefined {
  const tokens = document.tokens;
  if (tokens[after]?.value === "{") {
    const close = document.pairs.get(after);
    return close !== undefined && close <= handlerEnd ? { start: after, end: close + 1 } : undefined;
  }
  const startLine = tokens[after]?.line;
  const scope = lexicalScopeAt(document, after);
  const statementStarters = new Set(["if", "return", "throw", "const", "let", "var", "for", "while", "switch", "try"]);
  let end = after;
  while (end < handlerEnd) {
    const token = tokens[end]!;
    if (["(", "[", "{"].includes(token.value)) {
      const close = document.pairs.get(end);
      if (close !== undefined && close < handlerEnd) {
        end = close + 1;
        continue;
      }
    }
    if (token.value === ";") return { start: after, end: end + 1 };
    if (
      end > after && startLine !== undefined && token.line > startLine &&
      sameScope(lexicalScopeAt(document, end), scope) && statementStarters.has(token.value)
    ) return { start: after, end };
    end++;
  }
  return end > after ? { start: after, end } : undefined;
}

function sameScope(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => right[index] === value);
}

function isDenial(
  document: JsDocument,
  span: TokenSpan,
  status: "401" | "403",
  errorWord: RegExp,
  responseRoot: string | undefined,
): boolean {
  const tokens = document.tokens;
  const braced = tokens[span.start]?.value === "{";
  const start = span.start + (braced ? 1 : 0);
  const end = span.end - (braced ? 1 : 0);
  const directScope = lexicalScopeAt(document, start);
  const directResponseStatus = (rangeStart: number, rangeEnd: number): boolean => {
    if (!responseRoot) return false;
    for (let index = rangeStart; index + 4 < rangeEnd; index++) {
      if (tokens[index]?.value !== responseRoot || !sameScope(lexicalScopeAt(document, index), directScope)) continue;
      const previous = tokens[index - 1]?.value;
      if (index !== rangeStart && ![";", "return", "{"].includes(previous ?? "")) continue;
      if (![".", "?."].includes(tokens[index + 1]?.value ?? "")) continue;
      const method = tokens[index + 2]?.value;
      if (
        method === "sendStatus" && tokens[index + 3]?.value === "(" &&
        tokens[index + 4]?.value === status && document.pairs.get(index + 3) === index + 5
      ) return true;
      if (
        method !== "status" || tokens[index + 3]?.value !== "(" ||
        tokens[index + 4]?.value !== status || document.pairs.get(index + 3) !== index + 5
      ) continue;
      const terminal = index + 6;
      if (
        [".", "?."].includes(tokens[terminal]?.value ?? "") &&
        RESPONSE_SINK_METHODS.has(tokens[terminal + 1]?.value ?? "") &&
        tokens[terminal + 2]?.value === "(" &&
        (document.pairs.get(terminal + 2) ?? rangeEnd) < rangeEnd
      ) return true;
    }
    return false;
  };
  for (let exit = start; exit < end; exit++) {
    if (!["return", "throw"].includes(tokens[exit]!.value)) continue;
    if (!sameScope(lexicalScopeAt(document, exit), directScope)) continue;
    let statementEnd = exit + 1;
    while (statementEnd < end) {
      const token = tokens[statementEnd]!;
      if (["(", "[", "{"].includes(token.value)) {
        const close = document.pairs.get(statementEnd);
        if (close !== undefined && close < end) {
          statementEnd = close + 1;
          continue;
        }
      }
      statementEnd++;
      if (token.value === ";") break;
    }
    const terminatingStatement = tokens.slice(exit, statementEnd);
    if (tokens[exit]!.value === "throw") {
      if (
        terminatingStatement.some((token) => token.value === status) ||
        terminatingStatement.some((token) =>
          (token.kind === "identifier" || token.staticValue !== undefined) && errorWord.test(token.value)
        )
      ) return true;
      continue;
    }
    if (directResponseStatus(exit, statementEnd)) return true;
    const bareReturn = tokens.slice(exit + 1, statementEnd).every((token) => token.value === ";");
    if (braced && bareReturn && directResponseStatus(start, exit)) return true;
  }
  return false;
}

function spanContains(span: TokenSpan, index: number): boolean {
  return index >= span.start && index < span.end;
}

function callsInRange(calls: readonly JsCall[], start: number, end: number): readonly JsCall[] {
  let low = 0;
  let high = calls.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (calls[middle]!.tokenIndex < start) low = middle + 1;
    else high = middle;
  }
  const result: JsCall[] = [];
  for (let index = low; index < calls.length && calls[index]!.tokenIndex < end; index++) {
    result.push(calls[index]!);
  }
  return result;
}

function directExpressionReference(value: JsExpression | undefined): string[] | undefined {
  const tokens = value?.tokens ?? [];
  if (tokens[0]?.kind !== "identifier") return undefined;
  const reference = [tokens[0].value];
  let cursor = 1;
  while (
    cursor + 1 < tokens.length && [".", "?."].includes(tokens[cursor]?.value ?? "") &&
    tokens[cursor + 1]?.kind === "identifier"
  ) {
    reference.push(tokens[cursor + 1]!.value);
    cursor += 2;
  }
  return cursor === tokens.length ? reference : undefined;
}

function referenceHasPrivilegedOrigin(
  document: JsDocument,
  reference: readonly string[],
  useIndex: number,
  depth = 0,
  seen = new Set<number>(),
): boolean {
  if (reference.some((part) => DATABASE_ROOT.test(part) || /^admin(?:Service|Client|Api)?$/i.test(part))) {
    return true;
  }
  if (depth >= 3 || !reference[0]) return false;
  const definition = nearestDefinition(document, reference[0], useIndex);
  if (!definition?.expression || definition.origin || seen.has(definition.tokenIndex)) return false;
  const alias = directExpressionReference(definition.expression);
  if (!alias) return false;
  seen.add(definition.tokenIndex);
  return referenceHasPrivilegedOrigin(document, alias, definition.tokenIndex, depth + 1, seen);
}

function isPrivilegedOperation(document: JsDocument, call: JsCall): boolean {
  const receiver = call.reference.slice(0, -1);
  if (DATABASE_OPERATION.test(call.callee) && referenceHasPrivilegedOrigin(document, receiver, call.tokenIndex)) {
    return true;
  }
  if (ADMIN_OPERATION.test(call.callee)) return true;
  return referenceHasPrivilegedOrigin(document, receiver, call.tokenIndex) &&
    /^(?:create|delete|disable|enable|grant|invite|remove|reset|revoke|set|suspend|update)/i.test(call.callee);
}

function isProtectedSink(
  document: JsDocument,
  call: JsCall,
  responseRoot: string | undefined,
): boolean {
  const [root] = call.reference;
  if (
    responseRoot !== undefined && root === responseRoot &&
    RESPONSE_SINK_METHODS.has(call.callee)
  ) return true;
  return isPrivilegedOperation(document, call);
}

function isUnresolvedGuardCall(call: JsCall): boolean {
  return call.reference.some((part) => UNRESOLVED_GUARD.test(part)) && !RESPONSE_SINK_METHODS.has(call.callee);
}

function localHelpers(document: JsDocument, body: HandlerBody): LocalHelper[] {
  const helpers: LocalHelper[] = [];
  const seen = new Set<number>();
  for (const definition of jsDefinitions(document)) {
    if (
      definition.tokenIndex < body.start || definition.tokenIndex >= body.end ||
      seen.has(definition.tokenIndex)
    ) continue;
    const helperBody = declaredFunctionBody(document, definition);
    if (!helperBody || helperBody.start < body.start || helperBody.end > body.end) continue;
    seen.add(definition.tokenIndex);
    helpers.push({ definition, body: helperBody });
  }
  return helpers;
}

function helperPrivilegedAtCall(
  document: JsDocument,
  index: DocumentIndex,
  body: HandlerBody,
  helpers: readonly LocalHelper[],
  call: JsCall,
): boolean {
  if (
    call.reference.length !== 1 || isConditionallyExecuted(document, call.tokenIndex) ||
    !sameScope(lexicalScopeAt(document, call.tokenIndex), lexicalScopeAt(document, body.start))
  ) return false;
  const definition = nearestDefinition(document, call.reference[0]!, call.tokenIndex);
  if (definition?.tokenIndex === call.tokenIndex) return false;
  const helper = helpers.find((candidate) =>
    candidate.definition.tokenIndex === definition?.tokenIndex
  );
  if (!helper) return false;
  const nestedSpans = helpers
    .filter((candidate) => candidate !== helper && spanContains(helper.body, candidate.body.start))
    .map((candidate) => candidate.body);
  return callsInRange(index.calls, helper.body.start, helper.body.end).some((candidate) =>
    !nestedSpans.some((span) => spanContains(span, candidate.tokenIndex)) &&
    isPrivilegedOperation(document, candidate)
  );
}

function plausibleUnsupportedGuard(
  document: JsDocument,
  start: number,
  end: number,
  requestRoot: string | undefined,
): boolean {
  const tokens = document.tokens.slice(start, end);
  if (tokens.some((token) => token.value === "&&")) return false;
  if (tokens[0]?.value === "!" && tokens[1]?.value === "!") return false;
  if (
    tokens.some((token, index) =>
      ["===", "=="].includes(token.value) &&
      tokens[index + 1]?.staticValue?.toLowerCase() === "admin"
    )
  ) return false;
  return tokens.some((token) => token.value === requestRoot) ||
    tokens.some((token) => token.kind === "identifier" && UNRESOLVED_GUARD.test(token.value));
}

function identityReference(
  reference: readonly string[] | undefined,
  requestRoot: string | undefined,
): boolean {
  if (!reference || !requestRoot || reference[0] !== requestRoot || reference.length < 2) return false;
  return ["user", "auth", "session", "principal", "*"].includes(reference[1] ?? "");
}

function requestIdentityMutationBefore(
  document: JsDocument,
  index: DocumentIndex,
  body: HandlerBody,
  beforeIndex: number,
): boolean {
  if (!body.requestRoot) return true;
  if (jsMemberAssignments(document).some((assignment) =>
    assignment.tokenIndex >= body.start && assignment.tokenIndex < beforeIndex &&
    identityReference(assignment.reference, body.requestRoot)
  )) return true;
  const assignmentOperators = new Set(["=", "+=", "-=", "*=", "/=", "%=", "&&=", "||=", "??="]);
  for (let start = body.start; start < beforeIndex; start++) {
    if (document.tokens[start]?.value !== body.requestRoot) continue;
    const reference = [body.requestRoot];
    let cursor = start + 1;
    while (cursor < beforeIndex) {
      if (
        [".", "?."].includes(document.tokens[cursor]?.value ?? "") &&
        document.tokens[cursor + 1]?.kind === "identifier"
      ) {
        reference.push(document.tokens[cursor + 1]!.value);
        cursor += 2;
        continue;
      }
      if (document.tokens[cursor]?.value === "[") {
        const close = document.pairs.get(cursor);
        if (close === undefined || close >= beforeIndex) break;
        const key = document.tokens.slice(cursor + 1, close);
        reference.push(key.length === 1 && key[0]?.staticValue !== undefined ? key[0].staticValue : "*");
        cursor = close + 1;
        continue;
      }
      break;
    }
    if (identityReference(reference, body.requestRoot) && assignmentOperators.has(document.tokens[cursor]?.value ?? "")) {
      return true;
    }
  }
  return callsInRange(index.calls, body.start, beforeIndex).some((call) => {
    const api = call.reference.join(".");
    if (api === "Object.assign") {
      return identityReference(directExpressionReference(call.arguments[0]), body.requestRoot) ||
        directExpressionReference(call.arguments[0])?.join(".") === body.requestRoot;
    }
    if (api !== "Reflect.set") return false;
    const target = directExpressionReference(call.arguments[0]);
    if (identityReference(target, body.requestRoot)) return true;
    if (target?.length !== 1 || target[0] !== body.requestRoot) return false;
    const property = immediateLiteral(call.arguments[1]);
    return property === undefined || ["user", "auth", "session", "principal"].includes(property);
  });
}

function handlerGuardState(
  document: JsDocument,
  index: DocumentIndex,
  body: HandlerBody,
): "guarded" | "naked" | "unknown" {
  const tokens = document.tokens;
  const bodyScope = lexicalScopeAt(document, body.start);
  let authentication: TokenSpan | undefined;
  let authorization: TokenSpan | undefined;
  const unsupportedGuards: TokenSpan[] = [];
  for (let tokenIndex = body.start; tokenIndex < body.end; tokenIndex++) {
    if (tokens[tokenIndex]!.value !== "if" || tokens[tokenIndex + 1]?.value !== "(") continue;
    if (!sameScope(lexicalScopeAt(document, tokenIndex), bodyScope)) continue;
    if (isConditionallyExecuted(document, tokenIndex)) continue;
    const conditionEnd = document.pairs.get(tokenIndex + 1);
    if (conditionEnd === undefined || conditionEnd >= body.end) continue;
    const denial = denialStatement(document, conditionEnd + 1, body.end);
    if (!denial) continue;
    const rejectsUnauthenticated =
      isDenial(document, denial, "401", /unauth(?:orized|enticated)/i, body.responseRoot);
    const rejectsUnauthorized =
      isDenial(document, denial, "403", /forbidden|permission/i, body.responseRoot);
    const authenticationGrammar =
      isExactAuthenticationRejection(document, tokenIndex + 2, conditionEnd, body.requestRoot);
    const authorizationGrammar =
      isExactAuthorizationRejection(document, tokenIndex + 2, conditionEnd, body.requestRoot);
    const identityMutated = requestIdentityMutationBefore(document, index, body, tokenIndex);
    const exactAuthentication = authenticationGrammar && !identityMutated;
    const exactAuthorization = authorizationGrammar && !identityMutated;
    if (exactAuthentication && rejectsUnauthenticated) {
      authentication ??= { start: tokenIndex, end: denial.end };
    }

    if (exactAuthorization && rejectsUnauthorized) {
      authorization ??= { start: tokenIndex, end: denial.end };
    }
    if (
      !authenticationGrammar && !authorizationGrammar &&
      (rejectsUnauthenticated || rejectsUnauthorized) &&
      plausibleUnsupportedGuard(document, tokenIndex + 2, conditionEnd, body.requestRoot)
    ) unsupportedGuards.push({ start: tokenIndex, end: denial.end });
  }
  const recognizedGuards = [authentication, authorization].filter(
    (guard): guard is TokenSpan => guard !== undefined,
  );
  const helpers = localHelpers(document, body);
  const nestedFunctions = helpers.map((helper) => helper.body);
  const handlerCalls = callsInRange(index.calls, body.start, body.end).filter((call) =>
    !nestedFunctions.some((span) => spanContains(span, call.tokenIndex))
  );
  const protectedSinkIndices = handlerCalls
    .filter((call) => {
      const privileged = isPrivilegedOperation(document, call) ||
        helperPrivilegedAtCall(document, index, body, helpers, call);
      if (privileged) return true;
      return !recognizedGuards.some((guard) => spanContains(guard, call.tokenIndex)) &&
        isProtectedSink(document, call, body.responseRoot);
    })
    .map((call) => call.tokenIndex);
  if (authentication && authorization) {
    const completedAt = Math.max(authentication.end, authorization.end);
    if (protectedSinkIndices.some((tokenIndex) => tokenIndex < completedAt)) return "naked";
    return "guarded";
  }
  const firstProtectedSink = protectedSinkIndices[0] ?? body.end;
  if (unsupportedGuards.some((guard) => guard.end <= firstProtectedSink)) return "unknown";
  const unresolvedDominatingGuard = handlerCalls.some((call) =>
    call.tokenIndex < firstProtectedSink &&
    sameScope(lexicalScopeAt(document, call.tokenIndex), bodyScope) &&
    !isConditionallyExecuted(document, call.tokenIndex) &&
    !recognizedGuards.some((guard) => spanContains(guard, call.tokenIndex)) &&
    isUnresolvedGuardCall(call)
  );
  return unresolvedDominatingGuard ? "unknown" : "naked";
}

function handlerHasPrivilegedOperation(
  document: JsDocument,
  index: DocumentIndex,
  body: HandlerBody,
): boolean {
  const helpers = localHelpers(document, body);
  const nestedFunctions = helpers.map((helper) => helper.body);
  return callsInRange(index.calls, body.start, body.end).some((call) =>
    !nestedFunctions.some((span) => spanContains(span, call.tokenIndex)) &&
    (isPrivilegedOperation(document, call) || helperPrivilegedAtCall(document, index, body, helpers, call))
  );
}

function buildDocumentIndex(document: JsDocument, calls: readonly JsCall[]): DocumentIndex {
  const callBySpan = new Map<string, JsCall>();
  for (const call of calls) {
    callBySpan.set(callSpanKey(referenceStart(call), call.closeIndex + 1), call);
  }
  const mounts = buildGuardedMountIndex(document, callBySpan, calls);
  return {
    calls,
    callBySpan,
    middlewareByReceiver: buildMiddlewareIndex(document, callBySpan, calls),
    guardedMounts: mounts.guarded,
    unguardedMounts: mounts.unguarded,
    ambiguousMounts: mounts.ambiguous,
    lines: document.content.split(/\r?\n/),
  };
}

function finding(document: JsDocument, index: DocumentIndex, route: JsCall): Finding {
  return makeAiFinding({
    ruleId: RULE_ID,
    title: "Express admin route has no visible server-side access-control boundary",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-862", "CWE-863"],
    owasp_web: ["A01:2021"],
    owasp_api: ["API5:2023"],
    file: document.path,
    startLine: route.line,
    snippet: index.lines[route.line - 1] ?? "",
    message:
      "This statically-proven Express admin route has a direct handler with no visible authentication or server-side role/permission boundary. Ambiguous middleware and handlers are intentionally not reported.",
    remediation: {
      summary: "Authenticate the caller and deny requests without a server-controlled admin role or permission.",
      steps: [
        "Apply reviewed authentication middleware before the route or reject missing/invalid identity inside the handler.",
        "Check a server-controlled role or permission and return 403 for insufficient privilege.",
        "Test direct unauthenticated and authenticated non-admin requests against the server endpoint.",
      ],
      references: [
        "CWE-862",
        "CWE-863",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
      ],
    },
  });
}

function boundedNotes(notes: ReadonlySet<string>, omittedFindings: number): string[] {
  const sorted = [...notes].sort();
  if (omittedFindings === 0) {
    if (sorted.length <= MAX_NOTES) return sorted;
    const visible = sorted.slice(0, MAX_NOTES - 1);
    visible.push(`${sorted.length - visible.length} additional Express admin-route analysis notes omitted.`);
    return visible;
  }
  const findingNote =
    `Express admin-route analysis omitted ${omittedFindings} finding(s) after the ${MAX_FINDINGS}-finding bound.`;
  if (sorted.length < MAX_NOTES) return [...sorted, findingNote];
  const visible = sorted.slice(0, MAX_NOTES - 2);
  visible.push(`${sorted.length - visible.length} additional Express admin-route analysis notes omitted.`);
  visible.push(findingNote);
  return visible;
}

export async function runExpressAdminRouteAnalysis(target: string): Promise<ExpressAdminRouteAnalysis> {
  const project = await loadJavaScriptBaselineProject(target);
  const findings: Finding[] = [];
  let omittedFindings = 0;
  const notes = new Set(project.limitations ?? []);
  for (const document of project.files) {
    // Route ownership and middleware provenance cannot be recovered reliably from generated or
    // third-party bundles. Excluding them also prevents a minified asset from consuming the
    // per-file call budget intended for application route source.
    if (generatedOrVendoredSource(document.path)) continue;
    const calls = jsCalls(document);
    if (calls.length > MAX_CALLS_PER_FILE) {
      notes.add(
        `Skipped Express admin-route analysis for ${document.path}: ${calls.length} calls exceed the ${MAX_CALLS_PER_FILE}-call file bound.`,
      );
      continue;
    }
    const index = buildDocumentIndex(document, calls);
    const routes = calls.filter((call) =>
      call.reference.length === 2 && ROUTE_METHODS.has(call.reference[1] ?? "") &&
      call.arguments.length >= 1 && hasAdminSegment(immediateLiteral(call.arguments[0]) ?? "")
    );
    const boundedRoutes = routes.slice(0, MAX_ROUTE_CANDIDATES_PER_FILE);
    if (routes.length > boundedRoutes.length) {
      notes.add(
        `Express admin-route analysis skipped ${routes.length - boundedRoutes.length} route candidate(s) in ${document.path} after the ${MAX_ROUTE_CANDIDATES_PER_FILE}-route file bound.`,
      );
    }
    let middlewareUnknown = 0;
    let routeMiddlewareUnknown = 0;
    let mountedGuardUnknown = 0;
    let ambiguousMountUnknown = 0;
    let handlerUnknown = 0;
    let inHandlerGuardUnknown = 0;
    let publicUtilityUnknown = 0;
    for (const route of boundedRoutes) {
      if (route.arguments.length < 2) continue;
      const path = immediateLiteral(route.arguments[0]);
      if (path === undefined) continue;
      const receiver = expressReceiver(document, index, route);
      if (!receiver) continue;
      const routeMiddleware = route.arguments.slice(1, -1);
      if (routeMiddleware.some((argument) =>
        !isStandardExpressMiddleware(document, index, argument)
      )) {
        routeMiddlewareUnknown++;
        continue;
      }
      if (hasUnknownPriorMiddleware(index, route, receiver, path)) {
        middlewareUnknown++;
        continue;
      }
      const hasExactUnguardedMount = index.unguardedMounts.has(receiver.tokenIndex);
      if (!hasExactUnguardedMount && index.ambiguousMounts.has(receiver.tokenIndex)) {
        ambiguousMountUnknown++;
        continue;
      }
      if (!hasExactUnguardedMount && index.guardedMounts.has(receiver.tokenIndex)) {
        mountedGuardUnknown++;
        continue;
      }
      const body = handlerBody(document, route.arguments.at(-1)!, route.tokenIndex);
      if (!body) {
        handlerUnknown++;
        continue;
      }
      if (isPublicAdminUtilityPath(path) && !handlerHasPrivilegedOperation(document, index, body)) {
        publicUtilityUnknown++;
        continue;
      }
      const guardState = handlerGuardState(document, index, body);
      if (guardState === "unknown") {
        inHandlerGuardUnknown++;
        continue;
      }
      if (guardState !== "naked") continue;
      if (findings.length < MAX_FINDINGS) findings.push(finding(document, index, route));
      else omittedFindings++;
    }
    if (middlewareUnknown > 0) {
      notes.add(
        `Express admin-route analysis left ${middlewareUnknown} candidate(s) in ${document.path} unresolved because prior app/router.use middleware could not be proven irrelevant.`,
      );
    }
    if (routeMiddlewareUnknown > 0) {
      notes.add(
        `Express admin-route analysis left ${routeMiddlewareUnknown} candidate(s) in ${document.path} unresolved because route middleware could not be proven to be non-security Express middleware.`,
      );
    }
    if (mountedGuardUnknown > 0) {
      notes.add(
        `Express admin-route analysis left ${mountedGuardUnknown} candidate(s) in ${document.path} unresolved because the router is mounted behind unresolved middleware.`,
      );
    }
    if (ambiguousMountUnknown > 0) {
      notes.add(
        `Express admin-route analysis left ${ambiguousMountUnknown} candidate(s) in ${document.path} unresolved because a guarded router mount alias was reassigned or otherwise ambiguous.`,
      );
    }
    if (handlerUnknown > 0) {
      notes.add(
        `Express admin-route analysis left ${handlerUnknown} candidate(s) in ${document.path} unresolved because the final route handler body was not statically available.`,
      );
    }
    if (inHandlerGuardUnknown > 0) {
      notes.add(
        `Express admin-route analysis left ${inHandlerGuardUnknown} candidate(s) in ${document.path} unresolved because a plausible in-handler access-control guard was outside the exact proof grammar.`,
      );
    }
    if (publicUtilityUnknown > 0) {
      notes.add(
        `Express admin-route analysis left ${publicUtilityUnknown} public-looking login/callback/health/status candidate(s) in ${document.path} unresolved.`,
      );
    }
  }
  findings.sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    left.location.start_line - right.location.start_line
  );
  return {
    findings,
    notes: boundedNotes(notes, omittedFindings),
  };
}

export async function runExpressAdminRouteCheck(target: string): Promise<Finding[]> {
  return (await runExpressAdminRouteAnalysis(target)).findings;
}
