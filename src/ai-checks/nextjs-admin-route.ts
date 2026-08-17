/**
 * Conservative Next.js admin API route guard check.
 *
 * The detector is deliberately handler-scoped. It parses each App Router verb independently and
 * resolves Pages Router default exports to a local function/arrow. Comments, strings, unrelated
 * handlers, and dead helpers cannot supply guard evidence. A handler may use one directly-invoked
 * local guard helper; cross-file custom wrapper semantics remain unknown and are reported as a
 * coverage note rather than guessed.
 */
import type { Finding } from "../types.js";
import {
  isConditionallyExecuted,
  jsCalls,
  jsMemberAssignments,
  lexicalScopeAt,
  nearestDefinition,
  objectProperty,
  parseJavaScriptSource,
  resolveImport,
  staticString,
  type JsCall,
  type JsDocument,
  type JsExpression,
  type JsToken,
} from "../packs/react-native/javascript.js";
import { makeAiFinding } from "./finding.js";
import { collectFiles, lineText } from "./walk.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
const RULE_ID = "ci-ai-nextjs-admin-route-no-authz";
const APP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const PAGES_ADMIN_RE = /(?:^|\/)(?:src\/)?pages\/api\/admin(?:\/[^/]+)*\.(?:[cm]?[jt]sx?)$/;
const APP_ADMIN_RE = /(?:^|\/)(?:src\/)?app\/api\/admin(?:\/[^/]+)*\/route\.(?:[cm]?[jt]sx?)$/;
const MAX_NOTES = 50;
const MAX_ROUTE_FUNCTIONS = 2_048;
const MAX_ROUTE_CALLS = 10_000;
const MAX_AUTHZ_ALIAS_PATTERN_TOKENS = 2_048;

const PRIVILEGED_ACTION = /^(?:load|list|find|fetch|read|create|add|insert|update|change|set|delete|remove|destroy|grant|revoke|ban|invite|refund|charge|cancel|manage|admin|impersonate)/i;
const PRIVILEGED_TARGET = /(?:admin|user|account|role|permission|billing|audit|report|invite|workspace|tenant|organization|member|payment|refund|subscription|secret|credential)/i;
const NON_PRIVILEGED_NAMES = /^(?:auth|getUser|getSession|getServerSession|getToken|currentUser|verifyIdToken|verifySessionCookie|createClient|redirect|notFound|unauthorized|json|status|send|end|includes|has|some|indexOf|log|warn|error|info)$/i;
const GUARDISH_NAME = /^(?:(?:with|require|ensure|assert|check|verify|validate|authorize|authenticate|guard|protect|secure)(?:Auth|Admin|Role|Permission|Session|User)|auth|withAuth|middleware)$/;
const IDENTITY_NAME = /(?:user(?:Id)?|session|token|principal|account|claims|identity|auth)/i;
const ERROR_NAME = /^(?:error|err|authError|sessionError)$/i;
const SERVER_FIELD = /^(?:role|roles|permission|permissions|isAdmin|is_admin|claims)$/;
const USER_METADATA = new Set(["user_metadata", "raw_user_meta_data"]);
const SERVER_METADATA = new Set(["app_metadata", "raw_app_meta_data"]);
const PRIVILEGED_LITERAL = /^(?:admin|administrator|superadmin|super_admin|superuser|owner|root|staff|moderator|sysadmin)$/i;
const MUTATION_OPERATORS = new Set([
  "=", "+=", "-=", "*=", "/=", "%=", "**=", "&&=", "||=", "??=", "++", "--",
]);

interface FunctionSpan {
  name?: string;
  start: number;
  end: number;
  bodyStart: number;
  bodyEnd: number;
  line: number;
  params: string[];
  async: boolean;
}

interface Handler {
  label: string;
  exportIndex: number;
  fn: FunctionSpan;
  preauthenticated: boolean;
}

interface GuardEvidence {
  authenticated: boolean;
  authorized: boolean;
  authIndex?: number;
  authzIndex?: number;
}

interface IdentityEvidence {
  names: Set<string>;
  errors: Set<string>;
  bindings: Map<string, number>;
  mutations: Map<string, number>;
  requestRoots: Set<string>;
  lookups: number[];
  verifiedAt?: number;
}

interface IfStatement {
  index: number;
  conditionStart: number;
  conditionEnd: number;
  consequentStart: number;
  consequentEnd: number;
  termination?: "return" | "throw" | "navigation";
  returnsFalsy: boolean;
}

interface AuthzAlias {
  index: number;
  bindingIndex: number;
  kind: "boolean" | "role" | "roles" | "permission" | "permissions" | "isAdmin";
}

interface ProviderContext {
  owner: FunctionSpan;
  functions: readonly FunctionSpan[];
  calls: readonly JsCall[];
}

export interface NextjsAdminRouteAnalysis {
  findings: Finding[];
  notes: string[];
}

function isAdminRoute(path: string): "pages" | "app" | undefined {
  if (APP_ADMIN_RE.test(path)) return "app";
  if (PAGES_ADMIN_RE.test(path)) return "pages";
  return undefined;
}

function topLevelTokens(document: JsDocument): ReadonlySet<number> {
  const indexes = new Set<number>();
  let depth = 0;
  for (let index = 0; index < document.tokens.length; index++) {
    const value = document.tokens[index]!.value;
    if (value === "}") depth = Math.max(0, depth - 1);
    if (depth === 0) indexes.add(index);
    if (value === "{") depth++;
  }
  return indexes;
}

function nextValue(tokens: readonly JsToken[], start: number, value: string, limit = tokens.length): number | undefined {
  for (let index = start; index < limit; index++) {
    if (tokens[index]?.value === value) return index;
  }
  return undefined;
}

function statementEnd(document: JsDocument, start: number, limit = document.tokens.length): number {
  for (let index = start; index < limit; index++) {
    const value = document.tokens[index]!.value;
    if (["(", "[", "{"].includes(value)) {
      const close = document.pairs.get(index);
      if (close !== undefined && close < limit) {
        index = close;
        continue;
      }
    }
    if (value === ";" || value === "}") return index;
  }
  return limit;
}

function parameterNames(document: JsDocument, start: number, end: number): string[] {
  const names: string[] = [];
  let partStart = start;
  const addPart = (from: number, to: number) => {
    const candidate = document.tokens.slice(from, to).find((token) =>
      token.kind === "identifier" && !["public", "private", "readonly"].includes(token.value)
    );
    if (candidate && !names.includes(candidate.value)) names.push(candidate.value);
  };
  for (let index = start; index < end; index++) {
    const value = document.tokens[index]!.value;
    if (["(", "[", "{"].includes(value)) {
      const close = document.pairs.get(index);
      if (close !== undefined && close < end) {
        index = close;
        continue;
      }
    }
    if (value === ",") {
      addPart(partStart, index);
      partStart = index + 1;
    }
  }
  addPart(partStart, end);
  return names;
}

function declaredNameBefore(document: JsDocument, index: number): string | undefined {
  let equals: number | undefined;
  const floor = Math.max(0, index - 80);
  for (let cursor = index - 1; cursor >= floor; cursor--) {
    const value = document.tokens[cursor]!.value;
    if ([";", "{", "}"].includes(value)) break;
    if (value === "=") {
      equals = cursor;
      break;
    }
  }
  if (equals === undefined) return undefined;
  for (let cursor = equals - 1; cursor >= floor; cursor--) {
    const token = document.tokens[cursor]!;
    if (token.kind === "identifier" && document.tokens[cursor - 1]?.value !== ".") return token.value;
    if ([";", "{", "}"].includes(token.value)) break;
  }
  return undefined;
}

function functionBodyAfter(document: JsDocument, closeParen: number): { open: number; close: number } | undefined {
  let cursor = closeParen + 1;
  const limit = Math.min(document.tokens.length, closeParen + 80);
  while (cursor < limit) {
    if (document.tokens[cursor]?.value !== "{") {
      cursor++;
      continue;
    }
    const close = document.pairs.get(cursor);
    if (close === undefined) return undefined;
    const after = document.tokens[close + 1]?.value;
    // A braced TypeScript return type may precede the real function body.
    if (after && [">", "|", "&", "[", "]", "?", "{"].includes(after)) {
      cursor = close + 1;
      continue;
    }
    return { open: cursor, close };
  }
  return undefined;
}

function parseFunctions(document: JsDocument): FunctionSpan[] {
  const functions: FunctionSpan[] = [];
  const seen = new Set<string>();
  const add = (fn: FunctionSpan) => {
    const key = `${fn.start}:${fn.end}`;
    if (!seen.has(key)) {
      seen.add(key);
      functions.push(fn);
    }
  };
  const tokens = document.tokens;

  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index]!.value !== "function") continue;
    const named = tokens[index + 1]?.kind === "identifier";
    const name = named ? tokens[index + 1]!.value : declaredNameBefore(document, index);
    const open = nextValue(tokens, index + (named ? 2 : 1), "(", Math.min(tokens.length, index + 80));
    if (open === undefined) continue;
    const close = document.pairs.get(open);
    if (close === undefined) continue;
    const body = functionBodyAfter(document, close);
    if (!body) continue;
    add({
      ...(name ? { name } : {}),
      start: index,
      end: body.close + 1,
      bodyStart: body.open + 1,
      bodyEnd: body.close,
      line: tokens[index]!.line,
      params: parameterNames(document, open + 1, close),
      async: tokens[index - 1]?.value === "async",
    });
  }

  for (let arrow = 0; arrow < tokens.length; arrow++) {
    if (tokens[arrow]!.value !== "=>") continue;
    let params: string[] = [];
    if (tokens[arrow - 1]?.value === ")") {
      const open = document.pairs.get(arrow - 1);
      if (open !== undefined) params = parameterNames(document, open + 1, arrow - 1);
    } else if (tokens[arrow - 1]?.kind === "identifier") {
      params = [tokens[arrow - 1]!.value];
    }
    const name = declaredNameBefore(document, arrow);
    const body = arrow + 1;
    if (tokens[body]?.value === "{") {
      const close = document.pairs.get(body);
      if (close === undefined) continue;
      add({
        ...(name ? { name } : {}),
        start: arrow,
        end: close + 1,
        bodyStart: body + 1,
        bodyEnd: close,
        line: tokens[arrow]!.line,
        params,
        async: tokens[arrow - 1]?.value === "async" ||
          (tokens[arrow - 1]?.value === ")" &&
            document.pairs.get(arrow - 1) !== undefined &&
            tokens[(document.pairs.get(arrow - 1) ?? 0) - 1]?.value === "async"),
      });
    } else {
      const end = statementEnd(document, body);
      add({
        ...(name ? { name } : {}),
        start: arrow,
        end,
        bodyStart: body,
        bodyEnd: end,
        line: tokens[arrow]!.line,
        params,
        async: tokens[arrow - 1]?.value === "async" ||
          (tokens[arrow - 1]?.value === ")" &&
            document.pairs.get(arrow - 1) !== undefined &&
            tokens[(document.pairs.get(arrow - 1) ?? 0) - 1]?.value === "async"),
      });
    }
  }
  return functions.sort((left, right) => left.start - right.start || left.end - right.end);
}

function functionNamed(functions: readonly FunctionSpan[], name: string, useIndex: number): FunctionSpan | undefined {
  return [...functions]
    .filter((fn) => fn.name === name && fn.start < useIndex)
    .sort((left, right) => right.start - left.start)[0] ??
    functions.find((fn) => fn.name === name);
}

function functionInside(functions: readonly FunctionSpan[], start: number, end: number): FunctionSpan | undefined {
  return functions.find((fn) => fn.start >= start && fn.start < end);
}

function callReferenceBefore(document: JsDocument, open: number): string[] {
  const reference: string[] = [];
  let cursor = open - 1;
  if (document.tokens[cursor]?.kind !== "identifier") return reference;
  reference.unshift(document.tokens[cursor]!.value);
  cursor--;
  while (
    cursor >= 1 && [".", "?."].includes(document.tokens[cursor]!.value) &&
    document.tokens[cursor - 1]?.kind === "identifier"
  ) {
    reference.unshift(document.tokens[cursor - 1]!.value);
    cursor -= 2;
  }
  return reference;
}

function officialWrapper(document: JsDocument, reference: readonly string[], useIndex: number): boolean {
  const origin = resolveImport(document, reference, useIndex);
  if (origin) {
    if (packageSource(origin.source, "@auth0/nextjs-auth0") && origin.imported === "withApiAuthRequired") {
      return true;
    }
    if (origin.source === "next-auth/middleware" && origin.imported === "withAuth") return true;
  }
  return false;
}

interface ExportResolution {
  fn?: FunctionSpan;
  preauthenticated: boolean;
  unknownWrapper?: string;
}

function resolveExportValue(
  document: JsDocument,
  functions: readonly FunctionSpan[],
  start: number,
  end: number,
): ExportResolution {
  const direct = functionInside(functions, start, end);
  const first = document.tokens[start];
  if (direct && (first?.value === "async" || first?.value === "function" || first?.value === "(" || first?.kind === "identifier")) {
    const wrapped = document.tokens.slice(start, direct.start).some((token, offset) => {
      if (token.value !== "(") return false;
      const open = start + offset;
      const close = document.pairs.get(open);
      return close !== undefined && close >= direct.end;
    });
    if (wrapped) {
      // The function is an argument to a wrapper; handled below.
    } else {
      return { fn: direct, preauthenticated: false };
    }
  }
  if (first?.kind === "identifier" && !document.tokens.slice(start + 1, end).some((token) => token.value === "(")) {
    return { fn: functionNamed(functions, first.value, start), preauthenticated: false };
  }
  const open = document.tokens.slice(start, end).findIndex((token) => token.value === "(");
  if (open < 0) return { preauthenticated: false };
  const absoluteOpen = start + open;
  const close = document.pairs.get(absoluteOpen);
  if (close === undefined || close > end) return { preauthenticated: false };
  const reference = callReferenceBefore(document, absoluteOpen);
  const nested = functionInside(functions, absoluteOpen + 1, close);
  let fn = nested;
  if (!fn) {
    const argument = document.tokens.slice(absoluteOpen + 1, close).find((token) => token.kind === "identifier");
    if (argument) fn = functionNamed(functions, argument.value, absoluteOpen);
  }
  if (officialWrapper(document, reference, absoluteOpen)) return { fn, preauthenticated: true };
  return { fn, preauthenticated: false, unknownWrapper: reference.join(".") || "custom wrapper" };
}

function appHandlers(
  document: JsDocument,
  functions: readonly FunctionSpan[],
  note: (message: string) => void,
): Handler[] {
  const handlers: Handler[] = [];
  const seen = new Set<string>();
  const tokens = document.tokens;
  const add = (label: string, exportIndex: number, resolution: ExportResolution) => {
    if (resolution.unknownWrapper) {
      note(`${label} uses ${resolution.unknownWrapper}; custom wrapper semantics were not verified.`);
      return;
    }
    if (!resolution.fn) return;
    const key = `${label}:${resolution.fn.start}`;
    if (seen.has(key)) return;
    seen.add(key);
    handlers.push({
      label,
      exportIndex,
      fn: resolution.fn,
      preauthenticated: resolution.preauthenticated,
    });
  };

  const topLevel = topLevelTokens(document);

  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index]!.value !== "export" || !topLevel.has(index)) continue;
    let cursor = index + 1;
    if (tokens[cursor]?.value === "async") cursor++;
    if (tokens[cursor]?.value === "function") {
      const name = tokens[cursor + 1]?.value;
      if (name && APP_METHODS.has(name)) {
        const fn = functions.find((candidate) => candidate.start === cursor);
        if (fn) add(name, cursor + 1, { fn, preauthenticated: false });
      }
      continue;
    }
    if (["const", "let", "var"].includes(tokens[cursor]?.value ?? "")) {
      const nameIndex = cursor + 1;
      const name = tokens[nameIndex]?.value;
      if (!name || !APP_METHODS.has(name)) continue;
      const equals = nextValue(tokens, nameIndex + 1, "=", statementEnd(document, nameIndex + 1));
      if (equals === undefined) continue;
      add(name, nameIndex, resolveExportValue(document, functions, equals + 1, statementEnd(document, equals + 1)));
      continue;
    }
    if (tokens[cursor]?.value === "{") {
      const close = document.pairs.get(cursor);
      if (close === undefined) continue;
      let partStart = cursor + 1;
      for (let partEnd = partStart; partEnd <= close; partEnd++) {
        if (partEnd < close && tokens[partEnd]?.value !== ",") continue;
        const part = tokens.slice(partStart, partEnd);
        const asIndex = part.findIndex((token) => token.value === "as");
        const local = part[0]?.value;
        const exported = asIndex >= 0 ? part[asIndex + 1]?.value : local;
        if (local && exported && APP_METHODS.has(exported)) {
          const fn = functionNamed(functions, local, index);
          const exportedIndex = partStart + (asIndex >= 0 ? asIndex + 1 : 0);
          if (fn) add(exported, exportedIndex, { fn, preauthenticated: false });
        }
        partStart = partEnd + 1;
      }
    }
  }
  return handlers;
}

function pagesHandlers(
  document: JsDocument,
  functions: readonly FunctionSpan[],
  note: (message: string) => void,
): Handler[] {
  const tokens = document.tokens;
  const topLevel = topLevelTokens(document);
  for (let index = 0; index < tokens.length - 2; index++) {
    if (tokens[index]!.value !== "export" || tokens[index + 1]?.value !== "default" || !topLevel.has(index)) continue;
    const start = index + 2;
    const end = statementEnd(document, start);
    const resolution = resolveExportValue(document, functions, start, end);
    if (resolution.unknownWrapper) {
      note(`default uses ${resolution.unknownWrapper}; custom wrapper semantics were not verified.`);
      return [];
    }
    if (!resolution.fn) return [];
    return [{
      label: "default",
      exportIndex: index + 1,
      fn: resolution.fn,
      preauthenticated: resolution.preauthenticated,
    }];
  }
  return [];
}

function inNestedFunction(index: number, owner: FunctionSpan, functions: readonly FunctionSpan[]): boolean {
  return functions.some((fn) =>
    fn !== owner && fn.start >= owner.bodyStart && fn.end <= owner.bodyEnd && index >= fn.start && index < fn.end
  );
}

function callsIn(document: JsDocument, owner: FunctionSpan, functions: readonly FunctionSpan[]): JsCall[] {
  return jsCalls(document).filter((call) =>
    callRootIndex(call) >= owner.bodyStart && call.closeIndex <= owner.bodyEnd &&
    !inNestedFunction(call.tokenIndex, owner, functions)
  );
}

function callRootIndex(call: JsCall): number {
  return call.tokenIndex - Math.max(0, call.reference.length - 1) * 2;
}

function isAwaitedCall(document: JsDocument, call: JsCall): boolean {
  const root = callRootIndex(call);
  return document.tokens[root - 1]?.value === "await";
}

function exactExpressionRange(document: JsDocument, expression: JsExpression): TokenRange {
  let range = { start: expression.start, end: expression.end };
  while (
    document.tokens[range.start]?.value === "(" &&
    document.pairs.get(range.start) === range.end - 1
  ) range = { start: range.start + 1, end: range.end - 1 };
  return range;
}

function exactReferenceInRange(document: JsDocument, input: TokenRange): string[] | undefined {
  const range = stripOuterParens(document, input);
  const root = document.tokens[range.start];
  if (root?.kind !== "identifier") return undefined;
  const parts = [root.value];
  let cursor = range.start + 1;
  while (cursor < range.end) {
    if (
      [".", "?."].includes(document.tokens[cursor]?.value ?? "") &&
      document.tokens[cursor + 1]?.kind === "identifier"
    ) {
      parts.push(document.tokens[cursor + 1]!.value);
      cursor += 2;
      continue;
    }
    if (document.tokens[cursor]?.value === "[") {
      const close = document.pairs.get(cursor);
      if (close === undefined || close >= range.end) return undefined;
      const key = close === cursor + 2 ? document.tokens[cursor + 1]?.staticValue : undefined;
      parts.push(key ?? "*");
      cursor = close + 1;
      continue;
    }
    return undefined;
  }
  return parts;
}

function unshadowedIntrinsicCall(document: JsDocument, call: JsCall, reference: string): boolean {
  if (call.reference.join(".") !== reference) return false;
  const root = call.reference[0]!;
  return nearestDefinition(document, root, callRootIndex(call)) === undefined;
}

function providerMutationInScope(index: number, context: ProviderContext): boolean {
  return !context.functions.some((fn) =>
    fn !== context.owner && index >= fn.bodyStart && index < fn.bodyEnd
  );
}

function memberAssignmentReferenceBefore(
  document: JsDocument,
  equals: number,
): { reference: string[]; rootIndex: number } | undefined {
  const tokens = document.tokens;
  const floor = Math.max(0, equals - 32);
  let rootIndex: number | undefined;
  for (let index = equals - 1; index >= floor; index--) {
    if ([";", "{", "}", "=", "=>"].includes(tokens[index]!.value)) break;
    if (
      tokens[index]!.kind === "identifier" &&
      ![".", "?."].includes(tokens[index - 1]?.value ?? "") &&
      tokens[index - 1]?.value !== "["
    ) {
      rootIndex = index;
      break;
    }
  }
  if (rootIndex === undefined) return undefined;
  const reference = exactReferenceInRange(document, { start: rootIndex, end: equals });
  return reference && reference.length > 1 ? { reference, rootIndex } : undefined;
}

type SupabaseAuthAliasState = "same" | "unrelated" | "ambiguous";

function mergeAliasStates(
  left: SupabaseAuthAliasState,
  right: SupabaseAuthAliasState,
): SupabaseAuthAliasState {
  return left === right ? left : "ambiguous";
}

function supabaseAuthAliasState(
  document: JsDocument,
  root: string,
  definitionIndex: number,
  alias: string,
  useIndex: number,
  depth = 0,
  seen = new Set<number>(),
): SupabaseAuthAliasState {
  if (depth > 3) return "ambiguous";
  const definition = nearestDefinition(document, alias, useIndex);
  if (!definition?.expression) return "unrelated";
  if (seen.has(definition.tokenIndex)) return "ambiguous";
  seen.add(definition.tokenIndex);
  const reference = exactReferenceInRange(document, definition.expression);
  if (
    reference?.length === 2 &&
    reference[0] === root && reference[1] === "auth" &&
    nearestDefinition(document, root, definition.expression.start)?.tokenIndex === definitionIndex
  ) return "same";
  let current: SupabaseAuthAliasState = "unrelated";
  if (reference?.length === 1) {
    current = supabaseAuthAliasState(
      document,
      root,
      definitionIndex,
      reference[0]!,
      definition.tokenIndex,
      depth + 1,
      seen,
    );
  } else if ((definition.expression.tokens ?? []).some((token) => token.value === root)) {
    current = "ambiguous";
  }
  const tokens = document.tokens;
  const property = tokens[definition.tokenIndex - 1]?.value === ":"
    ? tokens[definition.tokenIndex - 2]?.value
    : tokens[definition.tokenIndex]?.value;
  if (
    property === "auth" && reference?.length === 1 && reference[0] === root &&
    nearestDefinition(document, root, definition.expression.start)?.tokenIndex === definitionIndex
  ) current = "same";
  if (!isConditionallyExecuted(document, definition.tokenIndex)) return current;
  const previous = supabaseAuthAliasState(
    document,
    root,
    definitionIndex,
    alias,
    definition.tokenIndex - 1,
    depth + 1,
    new Set(seen),
  );
  return mergeAliasStates(previous, current);
}

function descriptorObjectMayDefineGetUser(
  document: JsDocument,
  input: JsExpression | undefined,
  useIndex: number,
): boolean {
  if (!input) return true;
  const range = stripOuterParens(document, { start: input.start, end: input.end });
  if (
    document.tokens[range.start]?.value !== "{" ||
    document.pairs.get(range.start) !== range.end - 1
  ) return true;
  if (objectProperty(document, input, "getUser", useIndex) !== undefined) return true;
  for (let index = range.start + 1; index < range.end - 1; index++) {
    const value = document.tokens[index]!.value;
    if (value === "...") return true;
    if (value === "[") {
      const close = document.pairs.get(index);
      if (close === undefined || close >= range.end) return true;
      const key = close === index + 2 ? document.tokens[index + 1]?.staticValue : undefined;
      if (key === undefined || key === "getUser") return true;
      index = close;
      continue;
    }
    if (["(", "{"].includes(value)) {
      const close = document.pairs.get(index);
      if (close !== undefined && close < range.end) index = close;
    }
  }
  return false;
}

function referenceMayBeSupabaseAuth(
  document: JsDocument,
  reference: readonly string[],
  root: string,
  definitionIndex: number,
  useIndex: number,
): boolean {
  if (
    reference.length === 2 && reference[0] === root && reference[1] === "auth" &&
    nearestDefinition(document, root, useIndex)?.tokenIndex === definitionIndex
  ) return true;
  return reference.length === 1 && supabaseAuthAliasState(
    document,
    root,
    definitionIndex,
    reference[0]!,
    useIndex,
  ) !== "unrelated";
}

function helperMutatesSupabaseAuth(
  document: JsDocument,
  helper: FunctionSpan,
  invocationIndex: number,
  callArguments: readonly JsExpression[],
  root: string,
  definitionIndex: number,
  functions: readonly FunctionSpan[],
  allowHelperEdge = true,
): boolean {
  const parameterReference = (name: string): string[] | undefined => {
    const parameter = helper.params.indexOf(name);
    if (parameter < 0) return undefined;
    const argument = callArguments[parameter];
    return argument ? exactReferenceInRange(document, argument) : undefined;
  };
  const targetMayAlias = (name: string): boolean => {
    const mapped = parameterReference(name);
    if (mapped) return referenceMayBeSupabaseAuth(document, mapped, root, definitionIndex, invocationIndex);
    return supabaseAuthAliasState(document, root, definitionIndex, name, invocationIndex) !== "unrelated";
  };
  for (const assignment of jsMemberAssignments(document)) {
    if (
      assignment.rootIndex < helper.bodyStart || assignment.rootIndex >= helper.bodyEnd ||
      inNestedFunction(assignment.rootIndex, helper, functions)
    ) continue;
    const [target, member, leaf] = assignment.reference;
    if (
      target === root && ["auth", "*"].includes(member ?? "") &&
      [undefined, "getUser", "*"].includes(leaf) &&
      nearestDefinition(document, root, invocationIndex)?.tokenIndex === definitionIndex
    ) return true;
    if (leaf === undefined && ["getUser", "*"].includes(member ?? "") && targetMayAlias(target!)) return true;
  }
  for (const call of callsIn(document, helper, functions)) {
    const intrinsic = call.reference.join(".");
    if (![
      "Object.assign",
      "Reflect.set",
      "Object.defineProperty",
      "Object.defineProperties",
      "Reflect.defineProperty",
    ].includes(intrinsic) || !unshadowedIntrinsicCall(document, call, intrinsic)) continue;
    const target = call.arguments[0] ? exactReferenceInRange(document, call.arguments[0]!) : undefined;
    if (!target) continue;
    const aliases = referenceMayBeSupabaseAuth(document, target, root, definitionIndex, invocationIndex) ||
      (target.length === 1 && targetMayAlias(target[0]!));
    if (!aliases) continue;
    if (intrinsic === "Object.assign") return true;
    if (intrinsic === "Object.defineProperties") {
      if (descriptorObjectMayDefineGetUser(document, call.arguments[1], call.tokenIndex)) return true;
      continue;
    }
    const property = staticString(document, call.arguments[1], call.tokenIndex);
    if (property === "getUser" || property === undefined) return true;
  }
  if (allowHelperEdge) {
    const flow = directFlow(document, helper);
    for (const call of callsIn(document, helper, functions)) {
      const callStart = callRootIndex(call);
      if (
        call.reference.length !== 1 || !flow.has(callStart) ||
        isConditionallyExecuted(document, callStart)
      ) continue;
      for (const nested of localHelpersForCall(document, call.reference[0]!, callStart, functions)) {
        if (nested === helper) continue;
        const forwardedArguments = call.arguments.map((argument) => {
          const reference = exactReferenceInRange(document, argument);
          if (reference?.length !== 1) return argument;
          const parameter = helper.params.indexOf(reference[0]!);
          return parameter >= 0 ? callArguments[parameter] ?? argument : argument;
        });
        if (helperMutatesSupabaseAuth(
          document,
          nested,
          invocationIndex,
          forwardedArguments,
          root,
          definitionIndex,
          functions,
          false,
        )) return true;
      }
    }
  }
  return false;
}

function immediateInvocationIndex(document: JsDocument, fn: FunctionSpan): number | undefined {
  let cursor = fn.end;
  let wrappers = 0;
  while (document.tokens[cursor]?.value === ")") {
    const open = document.pairs.get(cursor);
    if (open === undefined || open >= fn.start || ++wrappers > 4) return undefined;
    cursor++;
  }
  return wrappers > 0 && document.tokens[cursor]?.value === "(" && document.pairs.has(cursor)
    ? cursor
    : undefined;
}

function localHelpersForCall(
  document: JsDocument,
  name: string,
  useIndex: number,
  functions: readonly FunctionSpan[],
  aliasDepth = 0,
  seen = new Set<number>(),
): FunctionSpan[] {
  const definition = nearestDefinition(document, name, useIndex);
  if (!definition || seen.has(definition.tokenIndex)) return [];
  seen.add(definition.tokenIndex);
  if (definition.kind === "function") {
    const fn = functionNamed(functions, name, useIndex);
    return fn ? [fn] : [];
  }
  let current: FunctionSpan[] = [];
  if (aliasDepth < 1 && definition.expression) {
    const reference = exactReferenceInRange(document, definition.expression);
    if (reference?.length === 1) {
      current = localHelpersForCall(
        document,
        reference[0]!,
        definition.tokenIndex,
        functions,
        aliasDepth + 1,
        new Set(seen),
      );
    }
  }
  if (current.length === 0) {
    const arrow = functions.find((fn) => fn.name === name && fn.start < useIndex);
    if (arrow) current = [arrow];
  }
  if (!isConditionallyExecuted(document, definition.tokenIndex)) return current;
  const previous = localHelpersForCall(
    document,
    name,
    definition.tokenIndex - 1,
    functions,
    aliasDepth,
    new Set(seen),
  );
  return [...new Set([...previous, ...current])];
}

function projectedHelperMutation(
  document: JsDocument,
  root: string,
  definitionIndex: number,
  useIndex: number,
  context: ProviderContext,
): boolean {
  const flow = directFlow(document, context.owner);
  for (const call of context.calls) {
    const callStart = callRootIndex(call);
    if (
      callStart <= definitionIndex || callStart >= useIndex ||
      call.reference.length !== 1 || !flow.has(callStart) || isConditionallyExecuted(document, callStart)
    ) continue;
    for (const helper of localHelpersForCall(document, call.reference[0]!, callStart, context.functions)) {
      if (helper === context.owner) continue;
      if (helperMutatesSupabaseAuth(
        document,
        helper,
        callStart,
        call.arguments,
        root,
        definitionIndex,
        context.functions,
      )) return true;
    }
  }
  for (let index = context.owner.bodyStart; index + 3 < useIndex; index++) {
    if (
      document.tokens[index]?.kind !== "identifier" ||
      document.tokens[index + 1]?.value !== "?." ||
      document.tokens[index + 2]?.value !== "(" ||
      !flow.has(index) || isConditionallyExecuted(document, index)
    ) continue;
    const close = document.pairs.get(index + 2);
    if (close === undefined || close >= useIndex || close !== index + 3) continue;
    for (const helper of localHelpersForCall(document, document.tokens[index]!.value, index, context.functions)) {
      if (helper === context.owner) continue;
      if (helperMutatesSupabaseAuth(
        document,
        helper,
        index,
        [],
        root,
        definitionIndex,
        context.functions,
      )) return true;
    }
  }
  for (const fn of context.functions) {
    if (fn === context.owner || fn.start < context.owner.bodyStart || fn.end > context.owner.bodyEnd) continue;
    const invocation = immediateInvocationIndex(document, fn);
    if (
      invocation === undefined || invocation <= definitionIndex || invocation >= useIndex ||
      !flow.has(invocation) || isConditionallyExecuted(document, invocation)
    ) continue;
    if (helperMutatesSupabaseAuth(
      document,
      fn,
      invocation,
      [],
      root,
      definitionIndex,
      context.functions,
    )) return true;
  }
  return false;
}

function supabaseAuthMethodMutated(
  document: JsDocument,
  root: string,
  definitionIndex: number,
  useIndex: number,
  context: ProviderContext,
): boolean {
  for (const assignment of jsMemberAssignments(document)) {
    if (
      assignment.tokenIndex <= definitionIndex ||
      assignment.tokenIndex >= useIndex ||
      !providerMutationInScope(assignment.rootIndex, context) ||
      assignment.reference[0] !== root ||
      !["auth", "*"].includes(assignment.reference[1] ?? "") ||
      ![undefined, "getUser", "*"].includes(assignment.reference[2])
    ) continue;
    if (nearestDefinition(document, root, assignment.rootIndex)?.tokenIndex === definitionIndex) return true;
  }
  for (let equals = definitionIndex + 1; equals < useIndex; equals++) {
    if (document.tokens[equals]?.value !== "=") continue;
    const assignment = memberAssignmentReferenceBefore(document, equals);
    if (!assignment || !providerMutationInScope(assignment.rootIndex, context)) continue;
    const [assignmentRoot, member, leaf] = assignment.reference;
    if (
      assignmentRoot === root &&
      ["auth", "*"].includes(member ?? "") &&
      [undefined, "getUser", "*"].includes(leaf) &&
      nearestDefinition(document, root, assignment.rootIndex)?.tokenIndex === definitionIndex
    ) return true;
    if (
      leaf === undefined &&
      ["getUser", "*"].includes(member ?? "") &&
      supabaseAuthAliasState(document, root, definitionIndex, assignmentRoot!, assignment.rootIndex) !== "unrelated"
    ) return true;
  }
  for (const call of jsCalls(document)) {
    const callStart = callRootIndex(call);
    if (
      callStart <= definitionIndex ||
      callStart >= useIndex ||
      !providerMutationInScope(callStart, context) ||
      ![
        "Object.assign",
        "Reflect.set",
        "Object.defineProperty",
        "Object.defineProperties",
        "Reflect.defineProperty",
      ].some((intrinsic) => unshadowedIntrinsicCall(document, call, intrinsic))
    ) continue;
    const target = call.arguments[0] ? exactReferenceInRange(document, call.arguments[0]!) : undefined;
    const directTarget = target?.length === 2 && target[0] === root &&
      ["auth", "*"].includes(target[1] ?? "") &&
      nearestDefinition(document, root, call.arguments[0]!.start)?.tokenIndex === definitionIndex;
    const aliasTarget = target?.length === 1 && supabaseAuthAliasState(
      document,
      root,
      definitionIndex,
      target[0]!,
      call.arguments[0]!.start,
    ) !== "unrelated";
    if (!directTarget && !aliasTarget) continue;
    const intrinsic = call.reference.join(".");
    if (intrinsic === "Object.assign") return true;
    if (intrinsic === "Object.defineProperties") {
      if (descriptorObjectMayDefineGetUser(document, call.arguments[1], call.tokenIndex)) return true;
      continue;
    }
    const property = staticString(document, call.arguments[1], call.tokenIndex);
    if (property === "getUser" || property === undefined) return true;
  }
  return projectedHelperMutation(document, root, definitionIndex, useIndex, context);
}

function isImportProvenSupabaseClient(
  document: JsDocument,
  root: string,
  useIndex: number,
  context: ProviderContext,
  stabilityEnd = useIndex,
  depth = 0,
  seen = new Set<number>(),
): boolean {
  if (depth > 3) return false;
  const definition = nearestDefinition(document, root, useIndex);
  if (!definition?.expression || seen.has(definition.tokenIndex)) return false;
  seen.add(definition.tokenIndex);
  if (supabaseAuthMethodMutated(document, root, definition.tokenIndex, stabilityEnd, context)) return false;
  const range = exactExpressionRange(document, definition.expression);
  const wholeCall = jsCalls(document).find((candidate) =>
    callRootIndex(candidate) === range.start && candidate.closeIndex === range.end - 1
  );
  if (wholeCall) {
    const candidate = wholeCall;
    const origin = resolveImport(document, candidate.reference, candidate.tokenIndex);
    return origin?.source === "@supabase/supabase-js" && origin.imported === "createClient";
  }
  const alias = document.tokens[range.start];
  return range.end === range.start + 1 && alias?.kind === "identifier" &&
    isImportProvenSupabaseClient(
      document,
      alias.value,
      definition.tokenIndex,
      context,
      stabilityEnd,
      depth + 1,
      seen,
    );
}

interface OfficialIdentityCall {
  kind: "lookup" | "verifier";
  provider: "next-auth" | "auth0" | "clerk" | "firebase" | "supabase";
}

function packageSource(source: string, packageName: string): boolean {
  return source === packageName || source.startsWith(`${packageName}/`);
}

function officialIdentityKind(
  document: JsDocument,
  call: JsCall,
  context: ProviderContext,
): OfficialIdentityCall | undefined {
  if (!isAwaitedCall(document, call)) return undefined;
  const joined = call.reference.join(".");
  if (
    /(?:^|\.)auth\.getUser$/.test(joined) &&
    call.reference.length >= 3 &&
    isImportProvenSupabaseClient(document, call.reference[0]!, call.tokenIndex, context)
  ) return { kind: "lookup", provider: "supabase" };
  const origin = resolveImport(document, call.reference, call.tokenIndex);
  const imported = origin?.imported ?? call.reference.at(-1) ?? "";
  const source = origin?.source ?? "";
  if (origin && source === "next-auth" && ["getServerSession", "getSession", "auth"].includes(imported)) {
    return { kind: "lookup", provider: "next-auth" };
  }
  if (origin && source === "next-auth/jwt" && imported === "getToken") {
    return { kind: "lookup", provider: "next-auth" };
  }
  if (origin && packageSource(source, "@auth0/nextjs-auth0") && ["getSession", "getAccessToken"].includes(imported)) {
    return { kind: "lookup", provider: "auth0" };
  }
  if (origin && source === "@clerk/nextjs/server" && ["auth", "currentUser"].includes(imported)) {
    return { kind: "lookup", provider: "clerk" };
  }
  if (["verifyIdToken", "verifySessionCookie"].includes(imported) && origin && packageSource(source, "firebase-admin")) {
    return { kind: "verifier", provider: "firebase" };
  }
  return undefined;
}

function providerCallIsUnconditional(document: JsDocument, owner: FunctionSpan, call: JsCall): boolean {
  const root = callRootIndex(call);
  return directFlow(document, owner).has(root) && !isConditionallyExecuted(document, root);
}

function staticTypeAssertionTail(document: JsDocument, start: number, end: number): boolean {
  if (!["as", "satisfies"].includes(document.tokens[start]?.value ?? "") || start + 1 >= end) return false;
  for (let index = start + 1; index < end; index++) {
    const token = document.tokens[index]!;
    if (["(", "[", "{"].includes(token.value)) {
      const close = document.pairs.get(index);
      if (close === undefined || close >= end) return false;
      index = close;
      continue;
    }
    if (
      token.kind === "identifier" ||
      token.staticValue !== undefined ||
      [".", "|", "&", "<", ">", "as", "satisfies", "const", "readonly", "keyof", "typeof"].includes(token.value)
    ) continue;
    return false;
  }
  return true;
}

function exactProviderResultAssignment(
  document: JsDocument,
  owner: FunctionSpan,
  call: JsCall,
  equals: number,
): boolean {
  if (!providerCallIsUnconditional(document, owner, call)) return false;
  const range = stripOuterParens(document, {
    start: equals + 1,
    end: statementEnd(document, equals + 1, owner.bodyEnd),
  });
  const root = callRootIndex(call);
  if (document.tokens[range.start]?.value !== "await" || range.start + 1 !== root) return false;
  let cursor = call.closeIndex + 1;
  if (document.tokens[cursor]?.value === "!") cursor++;
  if (cursor === range.end) return true;
  return staticTypeAssertionTail(document, cursor, range.end);
}

function assignmentBindings(
  document: JsDocument,
  call: JsCall,
  owner: FunctionSpan,
): { identities: string[]; errors: string[] } {
  const floor = owner.bodyStart;
  let equals: number | undefined;
  for (let index = call.tokenIndex - 1; index >= floor; index--) {
    const value = document.tokens[index]!.value;
    if ([";", "return", "{"].includes(value)) break;
    if (value === "=") {
      equals = index;
      break;
    }
  }
  if (equals === undefined) return { identities: [], errors: [] };
  if (!exactProviderResultAssignment(document, owner, call, equals)) return { identities: [], errors: [] };
  let start = equals - 1;
  while (start >= floor && !["const", "let", "var", ";"].includes(document.tokens[start]!.value)) {
    if (document.tokens[start]!.value === "}") {
      const open = document.pairs.get(start);
      if (open !== undefined && open >= floor) {
        start = open - 1;
        continue;
      }
    }
    start--;
  }
  if (!["const", "let", "var"].includes(document.tokens[start]?.value ?? "")) start++;
  else start++;
  const identifiers = document.tokens.slice(start, equals)
    .filter((token) => token.kind === "identifier")
    .map((token) => token.value)
    .filter((name) => name !== "await");
  const errors = identifiers.filter((name) => ERROR_NAME.test(name));
  let identities = identifiers.filter((name) => IDENTITY_NAME.test(name) && !ERROR_NAME.test(name));
  if (identities.length === 0) {
    const simple = identifiers.filter((name) => !errors.includes(name));
    if (simple.length === 1) identities = simple;
  }
  return { identities: [...new Set(identities)], errors: [...new Set(errors)] };
}

function mutatesIdentityReference(document: JsDocument, index: number, root: string): boolean {
  const tokens = document.tokens;
  if (tokens[index]?.value !== root || [".", "?."].includes(tokens[index - 1]?.value ?? "")) return false;
  let cursor = index + 1;
  while (cursor < tokens.length) {
    if (
      [".", "?."].includes(tokens[cursor]?.value ?? "") &&
      tokens[cursor + 1]?.kind === "identifier"
    ) {
      cursor += 2;
      continue;
    }
    if (tokens[cursor]?.value === "[") {
      const close = document.pairs.get(cursor);
      if (close === undefined) return false;
      cursor = close + 1;
      continue;
    }
    break;
  }
  return MUTATION_OPERATORS.has(tokens[cursor]?.value ?? "") ||
    MUTATION_OPERATORS.has(tokens[index - 1]?.value ?? "");
}

function intrinsicIdentityMutationTarget(document: JsDocument, call: JsCall): string[] | undefined {
  const isObjectAssign = unshadowedIntrinsicCall(document, call, "Object.assign") && call.arguments.length >= 2;
  const isReflectSet = unshadowedIntrinsicCall(document, call, "Reflect.set") && call.arguments.length >= 3;
  if (!isObjectAssign && !isReflectSet) return undefined;
  return call.arguments[0] ? exactReferenceInRange(document, call.arguments[0]!) : undefined;
}

function recordIdentityMutations(
  document: JsDocument,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
  calls: readonly JsCall[],
  evidence: IdentityEvidence,
): void {
  const record = (root: string, index: number) => {
    const binding = evidence.bindings.get(root);
    if (binding === undefined || index <= binding) return;
    const prior = evidence.mutations.get(root);
    if (prior === undefined || index < prior) evidence.mutations.set(root, index);
  };
  for (let index = owner.bodyStart; index < owner.bodyEnd; index++) {
    const root = document.tokens[index]?.value;
    if (!root || !evidence.bindings.has(root)) continue;
    if (inNestedFunction(index, owner, functions)) continue;
    if (mutatesIdentityReference(document, index, root)) record(root, index);
  }
  for (const call of calls) {
    const target = intrinsicIdentityMutationTarget(document, call);
    const root = target?.[0];
    if (root) record(root, callRootIndex(call));
  }
}

function identityEvidence(
  document: JsDocument,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
  preauthenticated: boolean,
): IdentityEvidence {
  const evidence: IdentityEvidence = {
    names: new Set(),
    errors: new Set(),
    bindings: new Map(),
    mutations: new Map(),
    requestRoots: new Set(),
    lookups: [],
  };
  if (preauthenticated && owner.params[0]) evidence.requestRoots.add(owner.params[0]);
  const calls = callsIn(document, owner, functions);
  const context: ProviderContext = { owner, functions, calls };
  for (const call of calls) {
    const identityCall = officialIdentityKind(document, call, context);
    if (!identityCall) continue;
    if (identityCall.kind === "verifier" && !providerCallIsUnconditional(document, owner, call)) continue;
    const bindings = assignmentBindings(document, call, owner);
    if (identityCall.kind === "lookup" && bindings.identities.length === 0 && bindings.errors.length === 0) {
      continue;
    }
    for (const name of bindings.identities) {
      evidence.names.add(name);
      evidence.bindings.set(name, call.tokenIndex);
    }
    for (const name of bindings.errors) {
      evidence.errors.add(name);
      evidence.bindings.set(name, call.tokenIndex);
    }
    if (identityCall.kind === "verifier") {
      evidence.verifiedAt = evidence.verifiedAt === undefined
        ? call.tokenIndex
        : Math.min(evidence.verifiedAt, call.tokenIndex);
      continue;
    }
    evidence.lookups.push(call.tokenIndex);
  }
  recordIdentityMutations(document, owner, functions, calls, evidence);
  return evidence;
}

interface DirectFlow {
  has(index: number): boolean;
}

function directFlow(document: JsDocument, owner: FunctionSpan): DirectFlow {
  const direct = new Set<number>();
  let depth = 0;
  for (let index = owner.bodyStart; index < owner.bodyEnd; index++) {
    const value = document.tokens[index]!.value;
    if (value === "}") depth = Math.max(0, depth - 1);
    if (depth === 0) direct.add(index);
    if (value === "{") depth++;
  }
  const forbidden: Array<{ start: number; end: number }> = [];
  for (const index of direct) {
    const value = document.tokens[index]!.value;
    if (["if", "for", "while", "with"].includes(value) && document.tokens[index + 1]?.value === "(") {
      const close = document.pairs.get(index + 1);
      if (close !== undefined && document.tokens[close + 1]?.value !== "{") {
        forbidden.push({ start: close + 1, end: statementEnd(document, close + 1, owner.bodyEnd) + 1 });
      }
    } else if (value === "else" && document.tokens[index + 1]?.value !== "{") {
      forbidden.push({ start: index + 1, end: statementEnd(document, index + 1, owner.bodyEnd) + 1 });
    }
  }
  return {
    has(index: number): boolean {
      return direct.has(index) && !forbidden.some((range) => index >= range.start && index < range.end);
    },
  };
}

function directTermination(
  document: JsDocument,
  start: number,
  end: number,
): { kind?: IfStatement["termination"]; returnsFalsy: boolean } {
  let cursor = start;
  const braced = document.tokens[cursor]?.value === "{";
  const limit = braced ? document.pairs.get(cursor) ?? end : end;
  if (braced) cursor++;
  const directScope = lexicalScopeAt(document, cursor);
  const directlyExecuted = (index: number): boolean => {
    const scope = lexicalScopeAt(document, index);
    const sameScope = scope.length === directScope.length &&
      scope.every((open, scopeIndex) => directScope[scopeIndex] === open);
    // The unbraced consequent itself is conditional on the guard being evaluated; nested
    // unbraced control flow inside that consequent is not an unconditional terminating denial.
    const nestedConditional = isConditionallyExecuted(document, index) && !(index === start && !braced);
    return sameScope && !nestedConditional;
  };
  for (; cursor < limit; cursor++) {
    const token = document.tokens[cursor]!;
    if (token.value === "return" && directlyExecuted(cursor)) {
      const next = document.tokens[cursor + 1];
      return {
        kind: "return",
        returnsFalsy: !next || next.value === ";" || ["false", "null", "undefined"].includes(next.value),
      };
    }
    if (token.value === "throw" && directlyExecuted(cursor)) return { kind: "throw", returnsFalsy: false };
    if (token.value === "{" || token.value === "(" || token.value === "[") {
      const close = document.pairs.get(cursor);
      if (close !== undefined && close < limit) {
        cursor = close;
        continue;
      }
    }
    if (
      token.kind === "identifier" &&
      ["redirect", "notFound", "unauthorized"].includes(token.value) &&
      document.tokens[cursor + 1]?.value === "(" &&
      directlyExecuted(cursor)
    ) {
      const origin = resolveImport(document, [token.value], cursor);
      if (origin?.source === "next/navigation") return { kind: "navigation", returnsFalsy: false };
    }
  }
  return { returnsFalsy: false };
}

function ifStatements(
  document: JsDocument,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
): IfStatement[] {
  const statements: IfStatement[] = [];
  const flow = directFlow(document, owner);
  for (let index = owner.bodyStart; index < owner.bodyEnd; index++) {
    if (
      document.tokens[index]!.value !== "if" ||
      inNestedFunction(index, owner, functions) ||
      !flow.has(index)
    ) continue;
    const open = index + 1;
    if (document.tokens[open]?.value !== "(") continue;
    const close = document.pairs.get(open);
    if (close === undefined || close >= owner.bodyEnd) continue;
    const consequentStart = close + 1;
    const consequentEnd = document.tokens[consequentStart]?.value === "{"
      ? (document.pairs.get(consequentStart) ?? statementEnd(document, consequentStart, owner.bodyEnd)) + 1
      : statementEnd(document, consequentStart, owner.bodyEnd) + 1;
    const termination = directTermination(document, consequentStart, consequentEnd);
    statements.push({
      index,
      conditionStart: open + 1,
      conditionEnd: close,
      consequentStart,
      consequentEnd,
      ...(termination.kind ? { termination: termination.kind } : {}),
      returnsFalsy: termination.returnsFalsy,
    });
  }
  return statements;
}

interface TokenRange {
  start: number;
  end: number;
}

function stripOuterParens(document: JsDocument, input: TokenRange): TokenRange {
  let range = input;
  while (
    document.tokens[range.start]?.value === "(" &&
    document.pairs.get(range.start) === range.end - 1
  ) range = { start: range.start + 1, end: range.end - 1 };
  return range;
}

function exactOrAtoms(document: JsDocument, input: TokenRange): TokenRange[] | undefined {
  const range = stripOuterParens(document, input);
  const separators: number[] = [];
  for (let index = range.start; index < range.end; index++) {
    const value = document.tokens[index]!.value;
    if (["(", "[", "{"].includes(value)) {
      const close = document.pairs.get(index);
      if (close !== undefined && close < range.end) {
        index = close;
        continue;
      }
    }
    if (value === "&&") return undefined;
    if (value === "||") separators.push(index);
  }
  if (!separators.length) return [range];
  const output: TokenRange[] = [];
  let start = range.start;
  for (const separator of [...separators, range.end]) {
    const nested = exactOrAtoms(document, { start, end: separator });
    if (!nested) return undefined;
    output.push(...nested);
    start = separator + 1;
  }
  return output;
}

function referenceAt(document: JsDocument, start: number, end: number): { parts: string[]; end: number } | undefined {
  if (document.tokens[start]?.kind !== "identifier") return undefined;
  const parts = [document.tokens[start]!.value];
  let cursor = start + 1;
  while (
    cursor + 1 < end &&
    [".", "?."].includes(document.tokens[cursor]!.value) &&
    document.tokens[cursor + 1]?.kind === "identifier"
  ) {
    parts.push(document.tokens[cursor + 1]!.value);
    cursor += 2;
  }
  return { parts, end: cursor };
}

function currentIdentityBinding(
  document: JsDocument,
  root: string,
  identity: IdentityEvidence,
  useIndex: number,
): boolean {
  const binding = identity.bindings.get(root);
  if (binding === undefined || binding >= useIndex) return false;
  const mutation = identity.mutations.get(root);
  if (mutation !== undefined && mutation < useIndex) return false;
  const definition = nearestDefinition(document, root, useIndex);
  // The shared definition index intentionally does not model nested object destructuring; the
  // provider call index still proves that binding unless a later visible definition supersedes it.
  if (!definition) return true;
  return Boolean(
    definition.expression &&
    binding >= definition.expression.start &&
    binding <= definition.expression.end
  );
}

function identityPresenceReference(
  document: JsDocument,
  parts: readonly string[],
  identity: IdentityEvidence,
  useIndex: number,
): boolean {
  const root = parts[0];
  const last = parts.at(-1) ?? "";
  if (
    !root ||
    !identity.names.has(root) ||
    !currentIdentityBinding(document, root, identity, useIndex)
  ) return false;
  if (SERVER_FIELD.test(last) || SERVER_METADATA.has(last) || USER_METADATA.has(last) || /error/i.test(last)) {
    return false;
  }
  return true;
}

function identityDenialAtom(
  document: JsDocument,
  input: TokenRange,
  identity: IdentityEvidence,
  useIndex: number,
): "identity" | "error" | undefined {
  let range = stripOuterParens(document, input);
  const tokens = document.tokens;
  if (tokens[range.start]?.value === "!") {
    range = stripOuterParens(document, { start: range.start + 1, end: range.end });
    const ref = referenceAt(document, range.start, range.end);
    if (!ref || ref.end !== range.end) return undefined;
    if (identityPresenceReference(document, ref.parts, identity, useIndex)) return "identity";
    if (
      (identity.errors.has(ref.parts[0]!) || ref.parts.at(-1) === "error") &&
      currentIdentityBinding(document, ref.parts[0]!, identity, useIndex)
    ) return "error";
    return undefined;
  }
  const direct = referenceAt(document, range.start, range.end);
  if (direct?.end === range.end) {
    if (
      (identity.errors.has(direct.parts[0]!) ||
        (identity.names.has(direct.parts[0]!) && direct.parts.at(-1) === "error")) &&
      currentIdentityBinding(document, direct.parts[0]!, identity, useIndex)
    ) return "error";
    return undefined;
  }
  for (let comparator = range.start; comparator < range.end; comparator++) {
    if (!["==", "==="].includes(tokens[comparator]!.value)) continue;
    const left = stripOuterParens(document, { start: range.start, end: comparator });
    const right = stripOuterParens(document, { start: comparator + 1, end: range.end });
    const leftRef = referenceAt(document, left.start, left.end);
    const rightRef = referenceAt(document, right.start, right.end);
    const leftAbsent = left.end === left.start + 1 && ["null", "undefined", "false"].includes(tokens[left.start]!.value);
    const rightAbsent = right.end === right.start + 1 && ["null", "undefined", "false"].includes(tokens[right.start]!.value);
    if (leftRef?.end === left.end && rightAbsent && identityPresenceReference(document, leftRef.parts, identity, useIndex)) return "identity";
    if (rightRef?.end === right.end && leftAbsent && identityPresenceReference(document, rightRef.parts, identity, useIndex)) return "identity";
  }
  return undefined;
}

function negativeIdentityCondition(
  document: JsDocument,
  statement: IfStatement,
  identity: IdentityEvidence,
): boolean {
  const atoms = exactOrAtoms(document, {
    start: statement.conditionStart,
    end: statement.conditionEnd,
  });
  if (!atoms?.length) return false;
  const classified = atoms.map((atom) => identityDenialAtom(document, atom, identity, statement.index));
  return classified.every(Boolean) && classified.includes("identity");
}

function trustedAuthzReference(
  document: JsDocument,
  parts: readonly string[],
  identity: IdentityEvidence,
  useIndex: number,
): AuthzAlias["kind"] | undefined {
  const root = parts[0];
  if (!root || parts.some((part) => USER_METADATA.has(part))) return undefined;
  if (identity.requestRoots.has(root) && !["user", "auth", "session"].includes(parts[1] ?? "")) {
    return undefined;
  }
  if (!identity.names.has(root) && !identity.requestRoots.has(root)) return undefined;
  if (
    identity.names.has(root) &&
    !currentIdentityBinding(document, root, identity, useIndex)
  ) return undefined;
  const field = parts.at(-1) ?? "";
  if (field === "isAdmin" || field === "is_admin") return "isAdmin";
  if (["role", "roles", "permission", "permissions"].includes(field)) {
    return field as AuthzAlias["kind"];
  }
  return undefined;
}

function staticPrivilege(kind: AuthzAlias["kind"], value: string): boolean {
  if (kind === "role" || kind === "roles") {
    return PRIVILEGED_LITERAL.test(value) || /(?:^|[:._-])admin$/i.test(value);
  }
  if (kind === "permission" || kind === "permissions") {
    return /(?:^|[:._-])(?:manage|write|delete|update|create|admin)(?:$|[:._-])/i.test(value);
  }
  return false;
}

function trustedMembership(
  document: JsDocument,
  range: TokenRange,
  identity: IdentityEvidence,
  useIndex: number,
): boolean {
  const ref = referenceAt(document, range.start, range.end);
  if (!ref || !["includes", "has"].includes(ref.parts.at(-1) ?? "")) return false;
  const kind = trustedAuthzReference(document, ref.parts.slice(0, -1), identity, useIndex);
  if (!kind || !["roles", "permissions"].includes(kind)) return false;
  if (document.tokens[ref.end]?.value !== "(") return false;
  const close = document.pairs.get(ref.end);
  if (close === undefined || close !== range.end - 1) return false;
  const argument = document.tokens[ref.end + 1];
  if (argument?.staticValue === undefined || ref.end + 2 !== close) return false;
  return staticPrivilege(kind, argument.staticValue);
}

function authzAliases(
  document: JsDocument,
  owner: FunctionSpan,
  identity: IdentityEvidence,
): Map<string, AuthzAlias> {
  const aliases = new Map<string, AuthzAlias>();
  const flow = directFlow(document, owner);
  const tokens = document.tokens;
  for (let equals = owner.bodyStart + 2; equals < owner.bodyEnd; equals++) {
    if (tokens[equals]!.value !== "=" || !flow.has(equals)) continue;
    const declaration = tokens[equals - 2]?.value;
    const name = tokens[equals - 1];
    if (!["const", "let", "var"].includes(declaration ?? "") || name?.kind !== "identifier") continue;
    const end = statementEnd(document, equals + 1, owner.bodyEnd);
    const rhs = stripOuterParens(document, { start: equals + 1, end });
    const ref = referenceAt(document, rhs.start, rhs.end);
    if (ref?.end === rhs.end) {
      const kind = trustedAuthzReference(document, ref.parts, identity, equals);
      if (kind) aliases.set(name.value, { index: equals, bindingIndex: equals - 1, kind });
    } else if (trustedMembership(document, rhs, identity, equals)) {
      aliases.set(name.value, { index: equals, bindingIndex: equals - 1, kind: "boolean" });
    }
  }
  return aliases;
}

function authzAliasIsCurrent(
  document: JsDocument,
  name: string,
  alias: AuthzAlias,
  useIndex: number,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
): boolean {
  if (nearestDefinition(document, name, useIndex)?.tokenIndex !== alias.bindingIndex) return false;
  const destructuringMutation = (index: number): boolean => {
    let inspected = 0;
    for (let open = index - 1; open > alias.index; open--) {
      inspected++;
      // Fail closed if a syntactically valid route still exceeds this local proof budget.
      if (inspected > MAX_AUTHZ_ALIAS_PATTERN_TOKENS) return true;
      if (!["[", "{"].includes(document.tokens[open]?.value ?? "")) continue;
      const close = document.pairs.get(open);
      if (close === undefined || close < index || close >= useIndex) continue;
      const after = document.tokens[close + 1]?.value;
      if (after === "=" || ["of", "in"].includes(after ?? "")) return true;
    }
    return false;
  };
  for (let index = alias.index + 1; index < useIndex; index++) {
    if (document.tokens[index]?.value !== name) continue;
    if (nearestDefinition(document, name, index)?.tokenIndex !== alias.bindingIndex) continue;
    if (mutatesIdentityReference(document, index, name)) return false;
    if (destructuringMutation(index)) return false;
    if (
      document.tokens[index - 1]?.value === "(" &&
      ["of", "in"].includes(document.tokens[index + 1]?.value ?? "")
    ) return false;
  }
  return true;
}

function authzDenialAtom(
  document: JsDocument,
  input: TokenRange,
  statementIndex: number,
  identity: IdentityEvidence,
  aliases: ReadonlyMap<string, AuthzAlias>,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
): boolean {
  let range = stripOuterParens(document, input);
  const tokens = document.tokens;
  if (tokens[range.start]?.value === "!") {
    range = stripOuterParens(document, { start: range.start + 1, end: range.end });
    if (trustedMembership(document, range, identity, statementIndex)) return true;
    const ref = referenceAt(document, range.start, range.end);
    if (!ref || ref.end !== range.end) return false;
    const alias = ref.parts.length === 1 ? aliases.get(ref.parts[0]!) : undefined;
    if (
      alias &&
      alias.index < statementIndex &&
      authzAliasIsCurrent(document, ref.parts[0]!, alias, statementIndex, owner, functions) &&
      ["boolean", "isAdmin"].includes(alias.kind)
    ) return true;
    return trustedAuthzReference(document, ref.parts, identity, statementIndex) === "isAdmin";
  }
  for (let comparator = range.start; comparator < range.end; comparator++) {
    const operator = tokens[comparator]!.value;
    if (!["!=", "!==", "==", "==="].includes(operator)) continue;
    const left = stripOuterParens(document, { start: range.start, end: comparator });
    const right = stripOuterParens(document, { start: comparator + 1, end: range.end });
    const leftRef = referenceAt(document, left.start, left.end);
    const rightRef = referenceAt(document, right.start, right.end);
    const check = (ref: ReturnType<typeof referenceAt>, refRange: TokenRange, literalRange: TokenRange): boolean => {
      if (!ref || ref.end !== refRange.end || literalRange.end !== literalRange.start + 1) return false;
      const literal = tokens[literalRange.start]!;
      const alias = ref.parts.length === 1 ? aliases.get(ref.parts[0]!) : undefined;
      const kind = alias && alias.index < statementIndex &&
        authzAliasIsCurrent(document, ref.parts[0]!, alias, statementIndex, owner, functions)
        ? alias.kind
        : trustedAuthzReference(document, ref.parts, identity, statementIndex);
      if (!kind) return false;
      if ((kind === "boolean" || kind === "isAdmin") && ["==", "==="].includes(operator)) {
        return literal.value === "false";
      }
      if ((kind === "boolean" || kind === "isAdmin") && ["!=", "!=="].includes(operator)) {
        return literal.value === "true";
      }
      return ["!=", "!=="].includes(operator) &&
        literal.staticValue !== undefined && staticPrivilege(kind, literal.staticValue);
    };
    if (check(leftRef, left, right) || check(rightRef, right, left)) return true;
  }
  return false;
}

function serverControlledCondition(
  document: JsDocument,
  statement: IfStatement,
  identity: IdentityEvidence,
  aliases: ReadonlyMap<string, AuthzAlias>,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
): boolean {
  const atoms = exactOrAtoms(document, {
    start: statement.conditionStart,
    end: statement.conditionEnd,
  });
  return Boolean(atoms?.length) && atoms!.every((atom) =>
    authzDenialAtom(document, atom, statement.index, identity, aliases, owner, functions)
  );
}

function directAwaitedStandaloneCall(
  document: JsDocument,
  owner: FunctionSpan,
  call: JsCall,
): boolean {
  if (!isAwaitedCall(document, call)) return false;
  const root = callRootIndex(call);
  if (!directFlow(document, owner).has(root)) return false;
  const start = statementStart(document, owner, root);
  const prefix = document.tokens.slice(start, root).map((token) => token.value);
  if (prefix.length !== 1 || prefix[0] !== "await") return false;
  const after = document.tokens[call.closeIndex + 1]?.value;
  return after === ";" || call.closeIndex + 1 >= owner.bodyEnd;
}

function clerkProtectEvidence(
  document: JsDocument,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
): GuardEvidence | undefined {
  for (const call of callsIn(document, owner, functions)) {
    if (
      call.reference.length !== 2 ||
      call.reference[1] !== "protect" ||
      !directAwaitedStandaloneCall(document, owner, call)
    ) continue;
    const origin = resolveImport(document, [call.reference[0]!], call.tokenIndex);
    if (origin?.source !== "@clerk/nextjs/server" || origin.imported !== "auth") continue;
    const options = call.arguments[0];
    const role = options ? objectProperty(document, options, "role", call.tokenIndex) : undefined;
    const permission = options ? objectProperty(document, options, "permission", call.tokenIndex) : undefined;
    const roleValue = staticString(document, role, call.tokenIndex);
    const permissionValue = staticString(document, permission, call.tokenIndex);
    const authorized = Boolean(
      roleValue && staticPrivilege("role", roleValue) ||
      permissionValue && staticPrivilege("permission", permissionValue)
    );
    return {
      authenticated: true,
      authorized,
      authIndex: call.tokenIndex,
      ...(authorized ? { authzIndex: call.tokenIndex } : {}),
    };
  }
  return undefined;
}

type GuardMode = "handler" | "helper-strong" | "helper-return";

function acceptedTermination(statement: IfStatement, mode: GuardMode): boolean {
  if (!statement.termination) return false;
  if (mode === "handler") return true;
  if (mode === "helper-strong") return ["throw", "navigation"].includes(statement.termination);
  return ["throw", "navigation"].includes(statement.termination) ||
    (statement.termination === "return" && statement.returnsFalsy);
}

function guardEvidence(
  document: JsDocument,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
  preauthenticated: boolean,
  mode: GuardMode = "handler",
): GuardEvidence {
  const identity = identityEvidence(document, owner, functions, preauthenticated);
  const flow = directFlow(document, owner);
  const statements = ifStatements(document, owner, functions);
  const aliases = authzAliases(document, owner, identity);
  let authIndex = identity.verifiedAt !== undefined && flow.has(identity.verifiedAt)
    ? identity.verifiedAt
    : undefined;
  let authzIndex: number | undefined;
  for (const statement of statements) {
    if (!acceptedTermination(statement, mode)) continue;
    if (authIndex === undefined && negativeIdentityCondition(document, statement, identity)) authIndex = statement.index;
    if (
      authzIndex === undefined &&
      serverControlledCondition(document, statement, identity, aliases, owner, functions)
    ) authzIndex = statement.index;
  }
  const protect = mode === "handler" ? clerkProtectEvidence(document, owner, functions) : undefined;
  if (protect?.authenticated && authIndex === undefined) authIndex = protect.authIndex;
  if (protect?.authorized && authzIndex === undefined) authzIndex = protect.authzIndex;
  return {
    authenticated: preauthenticated || authIndex !== undefined,
    authorized: authzIndex !== undefined,
    ...(preauthenticated ? { authIndex: owner.bodyStart } : authIndex !== undefined ? { authIndex } : {}),
    ...(authzIndex !== undefined ? { authzIndex } : {}),
  };
}

interface PrivilegedBoundary {
  boundary?: number;
  unsupported?: string;
}

function isReturnedCall(document: JsDocument, call: JsCall): boolean {
  let cursor = callRootIndex(call) - 1;
  if (document.tokens[cursor]?.value === "await") cursor--;
  return document.tokens[cursor]?.value === "return";
}

function isClerkProtectCall(document: JsDocument, call: JsCall): boolean {
  if (call.reference.length !== 2 || call.reference[1] !== "protect") return false;
  const origin = resolveImport(document, [call.reference[0]!], call.tokenIndex);
  return origin?.source === "@clerk/nextjs/server" && origin.imported === "auth";
}

function privilegedBoundary(
  document: JsDocument,
  owner: FunctionSpan,
  functions: readonly FunctionSpan[],
): PrivilegedBoundary {
  const calls = callsIn(document, owner, functions);
  const context: ProviderContext = { owner, functions, calls };
  let unsupported: string | undefined;
  for (const call of calls) {
    const name = call.reference.at(-1) ?? "";
    const joined = call.reference.join(".");
    if (
      officialIdentityKind(document, call, context) ||
      isClerkProtectCall(document, call) ||
      NON_PRIVILEGED_NAMES.test(name)
    ) continue;
    if (/^(?:console|logger)\./.test(joined)) continue;
    if (call.reference.length === 1 && GUARDISH_NAME.test(name) && functionNamed(functions, name, call.tokenIndex)) continue;
    if (/^(?:db|database|prisma|prismaClient|adminDb|supabase|supabaseAdmin)\./.test(joined)) {
      return { boundary: call.tokenIndex };
    }
    if (PRIVILEGED_ACTION.test(name) && PRIVILEGED_TARGET.test(name)) {
      return { boundary: call.tokenIndex };
    }
    if (!unsupported && (isAwaitedCall(document, call) || isReturnedCall(document, call))) {
      unsupported = joined || name;
    }
  }
  return { ...(unsupported ? { unsupported } : {}) };
}

function statementStart(document: JsDocument, owner: FunctionSpan, index: number): number {
  for (let cursor = index - 1; cursor >= owner.bodyStart; cursor--) {
    if ([";", "}"].includes(document.tokens[cursor]!.value)) return cursor + 1;
  }
  return owner.bodyStart;
}

function directStandaloneCall(
  document: JsDocument,
  owner: FunctionSpan,
  call: JsCall,
): boolean {
  if (call.reference.length !== 1 || !directFlow(document, owner).has(call.tokenIndex)) return false;
  const start = statementStart(document, owner, call.tokenIndex);
  const prefix = document.tokens.slice(start, call.tokenIndex).map((token) => token.value);
  if (prefix.length > 1 || prefix.some((value) => value !== "await")) return false;
  const after = document.tokens[call.closeIndex + 1]?.value;
  return after === ";" || call.closeIndex + 1 >= owner.bodyEnd;
}

function negativeCallAtom(document: JsDocument, input: TokenRange, call: JsCall): boolean {
  let range = stripOuterParens(document, input);
  if (document.tokens[range.start]?.value !== "!") return false;
  range = stripOuterParens(document, { start: range.start + 1, end: range.end });
  if (document.tokens[range.start]?.value === "await") range = { start: range.start + 1, end: range.end };
  range = stripOuterParens(document, range);
  return callRootIndex(call) === range.start && call.closeIndex === range.end - 1;
}

function callerChecksCall(
  document: JsDocument,
  handler: FunctionSpan,
  functions: readonly FunctionSpan[],
  call: JsCall,
): boolean {
  for (const statement of ifStatements(document, handler, functions)) {
    if (!statement.termination || call.tokenIndex < statement.conditionStart || call.closeIndex > statement.conditionEnd) continue;
    const atoms = exactOrAtoms(document, {
      start: statement.conditionStart,
      end: statement.conditionEnd,
    });
    if (atoms?.length === 1 && negativeCallAtom(document, atoms[0]!, call)) return true;
  }
  return false;
}

function mergeLocalHelperEvidence(
  document: JsDocument,
  handler: FunctionSpan,
  functions: readonly FunctionSpan[],
  boundary: number,
  initial: GuardEvidence,
): GuardEvidence {
  let evidence = initial;
  for (const call of callsIn(document, handler, functions)) {
    if (call.tokenIndex >= boundary || call.reference.length !== 1) continue;
    const fn = functionNamed(functions, call.reference[0]!, call.tokenIndex);
    if (!fn || fn === handler || (fn.start >= handler.bodyStart && fn.end <= handler.bodyEnd)) continue;
    const standalone = directStandaloneCall(document, handler, call) && (!fn.async || isAwaitedCall(document, call));
    const checked = callerChecksCall(document, handler, functions, call) && (!fn.async || isAwaitedCall(document, call));
    if (!standalone && !checked) continue;
    const helperEvidence = guardEvidence(
      document,
      fn,
      functions,
      false,
      standalone ? "helper-strong" : "helper-return",
    );
    evidence = {
      authenticated: evidence.authenticated || helperEvidence.authenticated,
      authorized: evidence.authorized || helperEvidence.authorized,
      ...(evidence.authIndex !== undefined
        ? { authIndex: evidence.authIndex }
        : helperEvidence.authenticated ? { authIndex: call.tokenIndex } : {}),
      ...(evidence.authzIndex !== undefined
        ? { authzIndex: evidence.authzIndex }
        : helperEvidence.authorized ? { authzIndex: call.tokenIndex } : {}),
    };
    if (evidence.authenticated && evidence.authorized) break;
  }
  return evidence;
}

function unknownGuardCall(
  document: JsDocument,
  handler: FunctionSpan,
  functions: readonly FunctionSpan[],
  boundary: number,
): string | undefined {
  const calls = callsIn(document, handler, functions);
  const context: ProviderContext = { owner: handler, functions, calls };
  for (const call of calls) {
    if (call.tokenIndex >= boundary) continue;
    const name = call.reference.at(-1) ?? "";
    if (!GUARDISH_NAME.test(name) || officialIdentityKind(document, call, context)) continue;
    if (call.reference.length === 1 && functionNamed(functions, name, call.tokenIndex)) continue;
    const origin = resolveImport(document, call.reference, call.tokenIndex);
    if (!origin) continue;
    if (
      name === "auth" &&
      isAwaitedCall(document, call) &&
      directFlow(document, handler).has(call.tokenIndex)
    ) return call.reference.join(".");
    if (!directStandaloneCall(document, handler, call) && !callerChecksCall(document, handler, functions, call)) {
      continue;
    }
    return call.reference.join(".");
  }
  return undefined;
}

function missingBoundary(evidence: GuardEvidence, boundary: number): string | undefined {
  const authenticated = evidence.authenticated && evidence.authIndex !== undefined && evidence.authIndex < boundary;
  const authorized = evidence.authorized && evidence.authzIndex !== undefined && evidence.authzIndex < boundary;
  if (authenticated && authorized) return undefined;
  if (!authenticated && !authorized) return "authentication and authorization";
  return authenticated ? "authorization" : "authentication";
}

function boundedNotes(notes: readonly string[]): string[] {
  const unique = [...new Set(notes)];
  if (unique.length <= MAX_NOTES) return unique;
  return [...unique.slice(0, MAX_NOTES), `${unique.length - MAX_NOTES} additional Next.js admin-route coverage notes omitted.`];
}

export async function runNextjsAdminRouteAnalysis(target: string): Promise<NextjsAdminRouteAnalysis> {
  const findings: Finding[] = [];
  const notes: string[] = [];
  for (const file of await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false })) {
    const kind = isAdminRoute(file.rel);
    if (!kind) continue;
    const document = parseJavaScriptSource(file.rel, file.content);
    if (!document.balanced) {
      const reason = document.lexicalIssues[0] ?? "unbalanced JavaScript/TypeScript structure";
      notes.push(`${file.rel}: Next.js admin-route analysis skipped: ${reason}`);
      continue;
    }
    const functions = parseFunctions(document);
    const callCount = jsCalls(document).length;
    if (functions.length > MAX_ROUTE_FUNCTIONS || callCount > MAX_ROUTE_CALLS) {
      const reason = functions.length > MAX_ROUTE_FUNCTIONS
        ? `function bound exceeded (${MAX_ROUTE_FUNCTIONS})`
        : `call bound exceeded (${MAX_ROUTE_CALLS})`;
      notes.push(`${file.rel}: Next.js admin-route analysis skipped: ${reason}`);
      continue;
    }
    const fileNote = (message: string) => notes.push(`${file.rel}: ${message}`);
    const handlers = kind === "app"
      ? appHandlers(document, functions, fileNote)
      : pagesHandlers(document, functions, fileNote);

    for (const handler of handlers) {
      const privileged = privilegedBoundary(document, handler.fn, functions);
      const boundary = privileged.boundary;
      if (boundary === undefined) {
        if (privileged.unsupported) {
          fileNote(`${handler.label} calls ${privileged.unsupported}; privileged-operation semantics were not verified.`);
        }
        continue;
      }
      let evidence = guardEvidence(document, handler.fn, functions, handler.preauthenticated);
      evidence = mergeLocalHelperEvidence(document, handler.fn, functions, boundary, evidence);
      const unknownGuard = unknownGuardCall(document, handler.fn, functions, boundary);
      if (unknownGuard) {
        fileNote(`${handler.label} calls ${unknownGuard}; custom guard semantics were not verified.`);
        continue;
      }
      const missing = missingBoundary(evidence, boundary);
      if (!missing) continue;
      const token = document.tokens[handler.exportIndex] ?? document.tokens[handler.fn.start]!;
      findings.push(
        makeAiFinding({
          ruleId: RULE_ID,
          title: "Next.js admin API route lacks a visible authentication/authorization boundary",
          severity: "high",
          confidence: "medium",
          cwe: ["CWE-862", "CWE-863", "CWE-306"],
          owasp_web: ["A01:2021"],
          owasp_api: ["API5:2023"],
          file: file.rel,
          startLine: token.line,
          snippet: lineText(file.content, token.line),
          message:
            `The ${handler.label} handler in this conventional Next.js admin API route has no recognized in-handler ${missing} boundary before its privileged operation. ` +
            "Identity lookup alone is not authentication: missing or invalid identity must terminate. Authorization must use server-controlled claims and terminate the denied path; Supabase user_metadata is client-writable and is not authorization evidence.",
          remediation: {
            summary:
              "Authenticate the caller and enforce a server-controlled role or permission decision before any privileged operation.",
            steps: [
              "Resolve the authenticated user from a server-side session or verified token and terminate missing/invalid identity paths.",
              "Check a server-controlled role or permission (for Supabase, use app_metadata rather than user_metadata) and terminate unauthorized paths.",
              "Keep the guard adjacent to the handler or in one reviewed directly-invoked helper, then test unauthenticated and insufficient-role requests.",
            ],
            references: [
              "CWE-862",
              "CWE-863",
              "CWE-306",
              "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
              "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
            ],
          },
        }),
      );
    }
  }
  return { findings, notes: boundedNotes(notes) };
}

/** Compatibility wrapper for existing pack registration. */
export async function runNextjsAdminRouteCheck(target: string): Promise<Finding[]> {
  return (await runNextjsAdminRouteAnalysis(target)).findings;
}
