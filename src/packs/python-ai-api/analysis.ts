import {
  pythonArgumentReference,
  pythonCallOrigin,
  pythonHasSpreadArgument,
  pythonImports,
  pythonKeywordArgument,
  pythonPositionalArguments,
  pythonReferenceOrigin,
  pythonStaticBoolean,
  pythonStaticString,
  pythonStaticStringList,
  type PythonImportBinding,
} from "../python/analysis.js";
import {
  pythonCalls,
  pythonExpressionReference,
  pythonSignificant,
  pythonStatements,
  splitPythonTopLevel,
  type PythonArgument,
  type PythonCall,
  type PythonDocument,
  type PythonExpression,
  type PythonToken,
} from "../python/python.js";

export interface PythonStatementContext {
  tokens: readonly PythonToken[];
  start: number;
  end: number;
  line: number;
  column: number;
  blockPath: readonly number[];
}

export interface PythonParameter {
  name: string;
  annotation: PythonExpression;
  defaultValue: PythonExpression;
}

export interface PythonFunctionScope {
  id: number;
  name: string;
  start: number;
  end: number;
  line: number;
  column: number;
  parameters: readonly PythonParameter[];
  decorators: readonly PythonStatementContext[];
}

export interface PythonLocalAssignment {
  name?: string;
  target: PythonExpression;
  expression: PythonExpression;
  tokenIndex: number;
  line: number;
  column: number;
  scopeId?: number;
  blockPath: readonly number[];
}

export interface PythonAnalysisContext {
  document: PythonDocument;
  calls: readonly PythonCall[];
  imports: readonly PythonImportBinding[];
  statements: readonly PythonStatementContext[];
  functions: readonly PythonFunctionScope[];
  assignments: readonly PythonLocalAssignment[];
}

function expression(tokens: readonly PythonToken[]): PythonExpression {
  const values = pythonSignificant(tokens);
  return {
    tokens: values,
    start: values[0]?.index ?? -1,
    end: values.at(-1)?.index ?? -1,
  };
}

export function expressionFromTokens(tokens: readonly PythonToken[]): PythonExpression {
  return expression(tokens);
}

export function unwrapPythonExpression(value: PythonExpression | undefined): PythonExpression {
  let tokens = pythonSignificant(value?.tokens ?? []);
  while (tokens[0]?.value === "(" && tokens[0].pairIndex === tokens.at(-1)?.index) {
    tokens = tokens.slice(1, -1);
  }
  while (tokens[0]?.value === "await") tokens = tokens.slice(1);
  return expression(tokens);
}

function topLevelOperator(tokens: readonly PythonToken[], operator: string): number {
  let depth = 0;
  for (let index = 0; index < tokens.length; index++) {
    const value = tokens[index]!.value;
    if (["(", "[", "{"].includes(value)) depth++;
    else if ([")", "]", "}"].includes(value)) depth--;
    else if (depth === 0 && value === operator) return index;
  }
  return -1;
}

function parameterFrom(item: PythonExpression): PythonParameter | undefined {
  let tokens = pythonSignificant(item.tokens);
  while (["*", "**"].includes(tokens[0]?.value ?? "")) tokens = tokens.slice(1);
  if (tokens.length === 1 && tokens[0]?.value === "/") return undefined;
  const name = tokens.find((token) => token.kind === "identifier");
  if (!name) return undefined;
  const equals = topLevelOperator(tokens, "=");
  const defaultValue = expression(equals >= 0 ? tokens.slice(equals + 1) : []);
  const declaration = equals >= 0 ? tokens.slice(0, equals) : tokens;
  const colon = topLevelOperator(declaration, ":");
  return {
    name: name.value,
    annotation: expression(colon >= 0 ? declaration.slice(colon + 1) : []),
    defaultValue,
  };
}

function functionHeader(statement: PythonStatementContext): {
  name: string;
  parameters: PythonParameter[];
} | undefined {
  const tokens = statement.tokens;
  const defIndex = tokens[0]?.value === "def"
    ? 0
    : tokens[0]?.value === "async" && tokens[1]?.value === "def"
      ? 1
      : -1;
  if (defIndex < 0 || tokens[defIndex + 1]?.kind !== "identifier") return undefined;
  const open = tokens.find((token, index) => index > defIndex + 1 && token.value === "(");
  if (!open?.pairIndex) return undefined;
  const inner = tokens.filter((token) => token.index > open.index && token.index < open.pairIndex!);
  return {
    name: tokens[defIndex + 1]!.value,
    parameters: splitPythonTopLevel(inner)
      .map(parameterFrom)
      .filter((value): value is PythonParameter => Boolean(value)),
  };
}

function decoratorStatements(
  statements: readonly PythonStatementContext[],
  headerIndex: number,
): PythonStatementContext[] {
  const header = statements[headerIndex];
  if (!header) return [];
  const output: PythonStatementContext[] = [];
  let expectedLine = header.line;
  for (let index = headerIndex - 1; index >= 0; index--) {
    const candidate = statements[index]!;
    const lastLine = candidate.tokens.at(-1)?.line ?? candidate.line;
    if (
      candidate.tokens[0]?.value !== "@" ||
      candidate.column !== header.column ||
      lastLine + 1 !== expectedLine
    ) break;
    output.unshift(candidate);
    expectedLine = candidate.line;
  }
  return output;
}

function buildFunctions(statements: readonly PythonStatementContext[], tokenEnd: number): PythonFunctionScope[] {
  const functions: PythonFunctionScope[] = [];
  for (let index = 0; index < statements.length; index++) {
    const statement = statements[index]!;
    const header = functionHeader(statement);
    if (!header) continue;
    const nextBoundary = statements.slice(index + 1).find((candidate) => candidate.column <= statement.column);
    functions.push({
      id: functions.length,
      name: header.name,
      start: statement.start,
      end: (nextBoundary?.start ?? tokenEnd + 1) - 1,
      line: statement.line,
      column: statement.column,
      parameters: header.parameters,
      decorators: decoratorStatements(statements, index),
    });
  }
  return functions;
}

export function functionAt(
  context: Pick<PythonAnalysisContext, "functions">,
  tokenIndex: number,
): PythonFunctionScope | undefined {
  return context.functions
    .filter((scope) => tokenIndex > scope.start && tokenIndex <= scope.end)
    .sort((left, right) => right.column - left.column || right.start - left.start)[0];
}

function assignmentTargetName(tokens: readonly PythonToken[]): string | undefined {
  const values = pythonSignificant(tokens);
  if (values.length === 1 && values[0]?.kind === "identifier") return values[0].value;
  if (values[0]?.kind !== "identifier") return undefined;
  const colon = topLevelOperator(values, ":");
  return colon > 0 ? values[0].value : undefined;
}

function buildAssignments(
  statements: readonly PythonStatementContext[],
  functions: readonly PythonFunctionScope[],
): PythonLocalAssignment[] {
  const output: PythonLocalAssignment[] = [];
  for (const statement of statements) {
    const operator = topLevelOperator(statement.tokens, "=");
    if (operator <= 0) continue;
    const target = expression(statement.tokens.slice(0, operator));
    const assigned = expression(statement.tokens.slice(operator + 1));
    if (!target.tokens.length || !assigned.tokens.length) continue;
    const scope = functionAt({ functions }, statement.start);
    output.push({
      name: assignmentTargetName(target.tokens),
      target,
      expression: assigned,
      tokenIndex: statement.start,
      line: statement.line,
      column: statement.column,
      ...(scope ? { scopeId: scope.id } : {}),
      blockPath: statement.blockPath,
    });
  }
  return output;
}

export function analyzePythonDocument(document: PythonDocument): PythonAnalysisContext {
  if (!document.balanced) {
    return {
      document,
      calls: [],
      imports: [],
      statements: [],
      functions: [],
      assignments: [],
    };
  }
  const statements = pythonStatements(document).map((statement): PythonStatementContext => ({
    tokens: statement.tokens,
    start: statement.start,
    end: statement.end,
    line: statement.tokens[0]?.line ?? 1,
    column: statement.tokens[0]?.column ?? 1,
    blockPath: [],
  }));
  const blockStack: PythonStatementContext[] = [];
  for (const statement of statements) {
    while (blockStack.length && statement.column <= blockStack.at(-1)!.column) blockStack.pop();
    statement.blockPath = blockStack.map((block) => block.start);
    let depth = 0;
    let colon = -1;
    for (let index = 0; index < statement.tokens.length; index++) {
      const value = statement.tokens[index]!.value;
      if (["(", "[", "{"].includes(value)) depth++;
      else if ([")", "]", "}"].includes(value)) depth--;
      else if (depth === 0 && value === ":") colon = index;
    }
    if (colon === statement.tokens.length - 1) blockStack.push(statement);
  }
  const functions = buildFunctions(statements, document.tokens.at(-1)?.index ?? -1);
  return {
    document,
    calls: pythonCalls(document),
    imports: pythonImports(document),
    statements,
    functions,
    assignments: buildAssignments(statements, functions),
  };
}

export function statementAt(
  context: Pick<PythonAnalysisContext, "statements">,
  tokenIndex: number,
): PythonStatementContext | undefined {
  return context.statements.find((statement) => tokenIndex >= statement.start && tokenIndex <= statement.end);
}

function pathPrefix(left: readonly number[], right: readonly number[]): boolean {
  return left.length <= right.length && left.every((block, index) => right[index] === block);
}

function assignmentScopeCandidates(
  context: PythonAnalysisContext,
  name: string,
  useIndex: number,
): { assignments: PythonLocalAssignment[]; usePath: readonly number[] } {
  const scope = functionAt(context, useIndex);
  const local = context.assignments.filter((assignment) =>
    assignment.name === name && assignment.scopeId === scope?.id
  );
  if (!scope || local.length) {
    return {
      assignments: local.filter((assignment) => assignment.tokenIndex < useIndex),
      usePath: statementAt(context, useIndex)?.blockPath ?? [],
    };
  }
  return {
    assignments: context.assignments.filter((assignment) =>
      assignment.name === name && assignment.scopeId === undefined && assignment.tokenIndex < useIndex
    ),
    // A function reads module globals after module-level control flow has
    // completed, not from inside the function definition's indentation path.
    usePath: [],
  };
}

/** Possible source-ordered reaching definitions, including completed branches. */
export function reachingAssignments(
  context: PythonAnalysisContext,
  name: string,
  useIndex: number,
): PythonLocalAssignment[] {
  const scoped = assignmentScopeCandidates(context, name, useIndex);
  const ordered = [...scoped.assignments].sort((left, right) => left.tokenIndex - right.tokenIndex);
  const dominating = ordered.filter((assignment) => pathPrefix(assignment.blockPath, scoped.usePath));
  const baseline = dominating.at(-1);
  const afterBaseline = ordered.filter((assignment) =>
    assignment.tokenIndex >= (baseline?.tokenIndex ?? -1) &&
    (assignment === baseline || pathPrefix(scoped.usePath, assignment.blockPath))
  );
  return afterBaseline.sort((left, right) => right.tokenIndex - left.tokenIndex);
}

function assignmentDominatesUse(
  context: PythonAnalysisContext,
  assignment: PythonLocalAssignment,
  useIndex: number,
): boolean {
  const scoped = assignmentScopeCandidates(context, assignment.name ?? "", useIndex);
  return pathPrefix(assignment.blockPath, scoped.usePath);
}

function assignmentInScope(
  context: PythonAnalysisContext,
  name: string,
  useIndex: number,
): PythonLocalAssignment | undefined {
  return reachingAssignments(context, name, useIndex)[0];
}

export function nearestAssignment(
  context: PythonAnalysisContext,
  name: string,
  useIndex: number,
): PythonLocalAssignment | undefined {
  return assignmentInScope(context, name, useIndex);
}

function hasLocalShadow(context: PythonAnalysisContext, name: string, useIndex: number): boolean {
  const scope = functionAt(context, useIndex);
  if (!scope) return false;
  return scope.parameters.some((parameter) => parameter.name === name) ||
    context.assignments.some((assignment) => assignment.scopeId === scope.id && assignment.name === name) ||
    context.functions.some((candidate) =>
      candidate.name === name && functionAt(context, candidate.start)?.id === scope.id
    );
}

function statementDefinitionName(statement: PythonStatementContext): string | undefined {
  const tokens = statement.tokens;
  const keyword = tokens[0]?.value === "async" ? tokens[1]?.value : tokens[0]?.value;
  const offset = tokens[0]?.value === "async" ? 2 : 1;
  return ["def", "class"].includes(keyword ?? "") && tokens[offset]?.kind === "identifier"
    ? tokens[offset]!.value
    : undefined;
}

function visibleDefinitionShadow(context: PythonAnalysisContext, name: string, useIndex: number): boolean {
  const useScope = functionAt(context, useIndex);
  const usePath = statementAt(context, useIndex)?.blockPath ?? [];
  return context.statements.some((statement) => {
    if (statement.start >= useIndex || statementDefinitionName(statement) !== name) return false;
    const parent = functionAt(context, statement.start);
    if (parent?.id !== useScope?.id && parent !== undefined) return false;
    const path = statement.blockPath;
    return path.length <= usePath.length && path.every((block, index) => usePath[index] === block);
  });
}

export function isUnshadowedBuiltin(
  context: PythonAnalysisContext,
  name: string,
  useIndex: number,
): boolean {
  const scope = functionAt(context, useIndex);
  if (context.imports.some((binding) => binding.local === name && binding.tokenIndex < useIndex)) return false;
  if (scope?.parameters.some((parameter) => parameter.name === name)) return false;
  if (visibleDefinitionShadow(context, name, useIndex)) return false;
  return !context.assignments.some((assignment) =>
    assignment.name === name && assignment.tokenIndex < useIndex &&
    (assignment.scopeId === scope?.id || assignment.scopeId === undefined)
  );
}

export function directCallExpression(
  context: Pick<PythonAnalysisContext, "calls">,
  value: PythonExpression | undefined,
): PythonCall | undefined {
  const unwrapped = unwrapPythonExpression(value);
  const first = unwrapped.tokens[0];
  const last = unwrapped.tokens.at(-1);
  if (!first || !last) return undefined;
  return context.calls.find((call) => call.startIndex === first.index && call.closeIndex === last.index);
}

export function callsWithinExpression(
  context: Pick<PythonAnalysisContext, "calls">,
  value: PythonExpression | undefined,
): PythonCall[] {
  if (!value) return [];
  return context.calls.filter((call) => call.startIndex >= value.start && call.closeIndex <= value.end);
}

function resolveAssignedOrigin(
  context: PythonAnalysisContext,
  assignment: PythonLocalAssignment,
  aliasesRemaining: number,
  seen: ReadonlySet<string>,
): string[] | undefined {
  if (aliasesRemaining <= 0) return undefined;
  const call = directCallExpression(context, assignment.expression);
  if (call) return resolveCallOrigin(context, call, aliasesRemaining - 1, seen);
  const reference = pythonExpressionReference(unwrapPythonExpression(assignment.expression));
  if (!reference) return undefined;
  return resolveReferenceOrigin(
    context,
    reference,
    assignment.tokenIndex,
    aliasesRemaining - 1,
    seen,
  );
}

/** Resolve exact imports plus at most two source-ordered intrafile object aliases. */
export function resolveReferenceOrigin(
  context: PythonAnalysisContext,
  reference: readonly string[],
  useIndex: number,
  aliasesRemaining = 2,
  seen: ReadonlySet<string> = new Set(),
): string[] | undefined {
  const root = reference[0];
  if (!root) return undefined;
  const assignments = reachingAssignments(context, root, useIndex);
  if (assignments.length) {
    const assignment = assignments[0]!;
    if (assignments.length !== 1 || !assignmentDominatesUse(context, assignment, useIndex)) return undefined;
    const key = `${assignment.scopeId ?? "module"}:${assignment.tokenIndex}:${root}`;
    if (seen.has(key)) return undefined;
    const nextSeen = new Set(seen);
    nextSeen.add(key);
    const origin = resolveAssignedOrigin(context, assignment, aliasesRemaining, nextSeen);
    return origin ? [...origin, ...reference.slice(1)] : undefined;
  }
  if (hasLocalShadow(context, root, useIndex) || visibleDefinitionShadow(context, root, useIndex)) return undefined;
  const origin = pythonReferenceOrigin(context.document, reference, useIndex);
  return origin;
}

export function resolveCallOrigin(
  context: PythonAnalysisContext,
  call: PythonCall,
  aliasesRemaining = 2,
  seen: ReadonlySet<string> = new Set(),
): string[] | undefined {
  // Keep the shared exact-import implementation as the first and strongest proof.
  const imported = pythonCallOrigin(context.document, call);
  if (imported && !hasLocalShadow(context, call.reference[0] ?? "", call.startIndex)) return imported;
  return resolveReferenceOrigin(context, call.reference, call.startIndex, aliasesRemaining, seen);
}

export function originEquals(origin: readonly string[] | undefined, expected: string): boolean {
  return origin?.join(".") === expected;
}

export function originStartsWith(origin: readonly string[] | undefined, expected: string): boolean {
  const value = origin?.join(".");
  return value === expected || Boolean(value?.startsWith(`${expected}.`));
}

export function originEndsWith(origin: readonly string[] | undefined, expected: string): boolean {
  const value = origin?.join(".");
  return value === expected || Boolean(value?.endsWith(`.${expected}`));
}

export function argument(
  call: PythonCall,
  position: number,
  ...keywords: readonly string[]
): PythonArgument | undefined {
  for (const keyword of keywords) {
    const value = pythonKeywordArgument(call, keyword);
    if (value) return value;
  }
  return pythonPositionalArguments(call)[position];
}

export function hasSpreadArgument(call: PythonCall): boolean {
  return pythonHasSpreadArgument(call);
}

export function staticBoolean(argumentValue: PythonArgument | undefined): boolean | undefined {
  return pythonStaticBoolean(argumentValue?.expression);
}

export function staticString(argumentValue: PythonArgument | PythonExpression | undefined): string | undefined {
  if (!argumentValue) return undefined;
  return pythonStaticString("expression" in argumentValue ? argumentValue.expression : argumentValue);
}

export function staticStringList(
  argumentValue: PythonArgument | PythonExpression | undefined,
): string[] | undefined {
  if (!argumentValue) return undefined;
  return pythonStaticStringList("expression" in argumentValue ? argumentValue.expression : argumentValue);
}

export function directArgumentReference(argumentValue: PythonArgument | undefined): string[] | undefined {
  return pythonArgumentReference(argumentValue);
}

export function expressionReferencesName(value: PythonExpression | undefined, names: ReadonlySet<string>): boolean {
  if (!value) return false;
  return value.tokens.some((token, index) =>
    token.kind === "identifier" && names.has(token.value) && value.tokens[index - 1]?.value !== "."
  );
}

export function expressionIdentifierRoots(value: PythonExpression | undefined): string[] {
  if (!value) return [];
  return value.tokens.flatMap((token, index) =>
    token.kind === "identifier" && value.tokens[index - 1]?.value !== "." &&
      !["True", "False", "None", "await"].includes(token.value)
      ? [token.value]
      : []
  );
}

function unsafeOuterOperator(value: PythonExpression): boolean {
  let depth = 0;
  const unsafe = new Set([
    "+", "-", "*", "/", "//", "%", "@", "|", "&", "^", "<<", ">>",
    "or", "and", "if", "else", "==", "!=", "<", ">", "<=", ">=", "in", "is",
  ]);
  for (const token of value.tokens) {
    if (["(", "[", "{"].includes(token.value)) depth++;
    else if ([")", "]", "}"].includes(token.value)) depth--;
    else if (depth === 0 && unsafe.has(token.value)) return true;
  }
  return false;
}

function expressionRoot(value: PythonExpression): string | undefined {
  const unwrapped = unwrapPythonExpression(value);
  if (unsafeOuterOperator(unwrapped) || unwrapped.tokens[0]?.kind !== "identifier") return undefined;
  return unwrapped.tokens[0].value;
}

function annotationOrigins(
  context: PythonAnalysisContext,
  parameter: PythonParameter,
  useIndex: number,
): string[] {
  const output = new Set<string>();
  const tokens = parameter.annotation.tokens;
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (token.kind !== "identifier" || tokens[index - 1]?.value === ".") continue;
    const reference = [token.value];
    let cursor = index + 1;
    while (tokens[cursor]?.value === "." && tokens[cursor + 1]?.kind === "identifier") {
      reference.push(tokens[cursor + 1]!.value);
      cursor += 2;
    }
    const origin = resolveReferenceOrigin(context, reference, useIndex);
    if (origin) output.add(origin.join("."));
  }
  return [...output];
}

function routeFramework(
  context: PythonAnalysisContext,
  scope: PythonFunctionScope,
): "flask" | "fastapi" | undefined {
  for (const decorator of scope.decorators) {
    const call = context.calls.find((candidate) =>
      candidate.startIndex >= decorator.start && candidate.closeIndex <= decorator.end
    );
    if (!call) continue;
    const origin = resolveCallOrigin(context, call);
    const method = origin?.at(-1);
    if (!["route", "get", "post", "put", "patch", "delete", "options", "head", "websocket"].includes(method ?? "")) {
      continue;
    }
    const owner = origin?.slice(0, -1).join(".") ?? "";
    if (["flask.Flask", "flask.app.Flask", "flask.Blueprint", "flask.blueprints.Blueprint"].includes(owner)) {
      return "flask";
    }
    if ([
      "fastapi.FastAPI",
      "fastapi.applications.FastAPI",
      "fastapi.APIRouter",
      "fastapi.routing.APIRouter",
    ].includes(owner)) return "fastapi";
  }
  return undefined;
}

export function functionRouteFramework(
  context: PythonAnalysisContext,
  scope: PythonFunctionScope,
): "flask" | "fastapi" | undefined {
  return routeFramework(context, scope);
}

function requestParameterKind(
  context: PythonAnalysisContext,
  scope: PythonFunctionScope,
  name: string,
  useIndex: number,
): "starlette" | "django" | undefined {
  const parameter = scope.parameters.find((candidate) => candidate.name === name);
  if (!parameter) return undefined;
  const origins = annotationOrigins(context, parameter, useIndex);
  if (origins.some((origin) => ["fastapi.Request", "starlette.requests.Request", "starlette.requests.HTTPConnection"].includes(origin))) {
    return "starlette";
  }
  if (origins.some((origin) => ["django.http.HttpRequest", "django.core.handlers.wsgi.WSGIRequest"].includes(origin))) {
    return "django";
  }
  return undefined;
}

function injectedParameter(
  context: PythonAnalysisContext,
  parameter: PythonParameter,
): boolean {
  return [parameter.defaultValue, parameter.annotation].some((value) =>
    callsWithinExpression(context, value).some((call) => {
      const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
      return [
        "fastapi.Depends",
        "fastapi.params.Depends",
        "fastapi.Security",
        "fastapi.params.Security",
      ].includes(origin);
    })
  );
}

/** Exact framework request access or a proven decorated-route parameter. */
export function isDirectRequestSource(
  context: PythonAnalysisContext,
  value: PythonExpression | undefined,
  useIndex: number,
): boolean {
  if (!value) return false;
  const unwrapped = unwrapPythonExpression(value);
  const root = expressionRoot(unwrapped);
  if (!root) return false;
  const scope = functionAt(context, useIndex);
  if (scope) {
    const rootParameter = scope.parameters.find((parameter) => parameter.name === root);
    if (rootParameter && injectedParameter(context, rootParameter)) return false;
    const route = routeFramework(context, scope);
    if (
      route &&
      scope.parameters.some((parameter) => parameter.name === root && !["self", "cls"].includes(root))
    ) return true;
    const kind = requestParameterKind(context, scope, root, useIndex);
    const values = unwrapped.tokens.map((token) => token.value);
    if (kind === "starlette" && values.some((item) => ["query_params", "path_params"].includes(item))) return true;
    if (kind === "django" && values.some((item) => ["GET", "POST", "COOKIES", "headers"].includes(item))) return true;
    const djangoRequest = scope.parameters.find((parameter) =>
      requestParameterKind(context, scope, parameter.name, useIndex) === "django"
    );
    if (
      djangoRequest && root !== djangoRequest.name &&
      scope.parameters.some((parameter) => parameter.name === root && !["self", "cls"].includes(root))
    ) return true;
  }

  const imported = resolveReferenceOrigin(context, [root], useIndex);
  if (!originStartsWith(imported, "flask.request") && !originStartsWith(imported, "flask.globals.request")) {
    return false;
  }
  const values = unwrapped.tokens.map((token) => token.value);
  if (values.includes("files")) return values.includes("filename");
  return values.some((item) => [
    "args", "form", "values", "json", "get_json", "cookies", "headers",
  ].includes(item));
}

export type SanitizerPredicate = (
  context: PythonAnalysisContext,
  value: PythonExpression,
  useIndex: number,
) => boolean;

export function isKnownPathSanitizer(
  context: PythonAnalysisContext,
  value: PythonExpression,
  useIndex: number,
): boolean {
  const call = directCallExpression(context, value);
  if (call) {
    const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
    if (["flask.safe_join", "werkzeug.security.safe_join", "werkzeug.utils.safe_join"].includes(origin)) {
      const base = argument(call, 0)?.expression;
      return !hasSpreadArgument(call) && Boolean(base && isTrustedPathBase(context, base, useIndex));
    }
    if ([
      "werkzeug.utils.secure_filename",
      "os.path.basename",
      "ntpath.basename",
      "io.BytesIO",
      "io.StringIO",
    ].includes(origin)) return true;
  }
  const unwrapped = unwrapPythonExpression(value);
  const pathCall = callsWithinExpression(context, unwrapped).find((candidate) => {
    if (candidate.startIndex !== unwrapped.start) return false;
    const origin = resolveCallOrigin(context, candidate)?.join(".") ?? "";
    const suffix = context.document.tokens.slice(candidate.closeIndex + 1, unwrapped.end + 1).map((token) => token.value);
    return ["pathlib.Path", "pathlib.PurePath", "pathlib.PureWindowsPath"].includes(origin) &&
      suffix.length === 2 && suffix[0] === "." && suffix[1] === "name";
  });
  return Boolean(pathCall);
}

export function isTrustedPathBase(
  context: PythonAnalysisContext,
  value: PythonExpression,
  useIndex: number,
  seen: ReadonlySet<string> = new Set(),
  depth = 0,
): boolean {
  if (depth > 4) return false;
  const unwrapped = unwrapPythonExpression(value);
  const literal = pythonStaticString(unwrapped);
  if (literal !== undefined && literal.length > 0) return true;
  const call = directCallExpression(context, unwrapped);
  if (call && !hasSpreadArgument(call)) {
    const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
    if (["pathlib.Path", "pathlib.PurePath", "pathlib.PureWindowsPath"].includes(origin)) {
      const inner = argument(call, 0)?.expression;
      return Boolean(inner && isTrustedPathBase(context, inner, call.startIndex, seen, depth + 1));
    }
    if ([
      "os.path.realpath",
      "pathlib.Path.resolve",
      "pathlib.PosixPath.resolve",
      "pathlib.WindowsPath.resolve",
    ].includes(origin)) {
      const inner = argument(call, 0)?.expression ?? expressionFromReceiver(context, call);
      return Boolean(inner && isTrustedPathBase(context, inner, call.startIndex, seen, depth + 1));
    }
  }
  const reference = pythonExpressionReference(unwrapped);
  if (!reference || reference.length !== 1) return false;
  const name = reference[0]!;
  const assignments = reachingAssignments(context, name, useIndex);
  if (assignments.length !== 1) return false;
  const assignment = assignments[0]!;
  const key = `${assignment.scopeId ?? "module"}:${assignment.tokenIndex}:${name}`;
  if (seen.has(key)) return false;
  const nextSeen = new Set(seen);
  nextSeen.add(key);
  return isTrustedPathBase(context, assignment.expression, assignment.tokenIndex, nextSeen, depth + 1);
}

function expressionFromReceiver(
  context: PythonAnalysisContext,
  call: PythonCall,
): PythonExpression | undefined {
  if (call.reference.length < 2) return undefined;
  const receiver = call.reference.slice(0, -1);
  const length = receiver.length * 2 - 1;
  const tokens = context.document.tokens.slice(call.startIndex, call.startIndex + length);
  return pythonExpressionReference(expression(tokens)) ? expression(tokens) : undefined;
}

export function isKnownHtmlSanitizer(
  context: PythonAnalysisContext,
  value: PythonExpression,
  _useIndex: number,
): boolean {
  const call = directCallExpression(context, value);
  if (!call) return false;
  const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
  if (!["bleach.clean", "nh3.clean", "html.escape", "markupsafe.escape"].includes(origin)) return false;
  // Configurable sanitizer policies are not interpreted here. Only the
  // library's supported single-content default is accepted as a proof.
  return call.arguments.length === 1 && !call.arguments[0]?.name && !call.arguments[0]?.spread;
}

/**
 * Source-ordered, same-function request flow. Only whole-value access paths are
 * followed, and no more than two assignment aliases are traversed.
 */
export function expressionReachesRequest(
  context: PythonAnalysisContext,
  value: PythonExpression | undefined,
  useIndex: number,
  sanitizer?: SanitizerPredicate,
  seen: ReadonlySet<string> = new Set(),
  depth = 0,
): boolean {
  if (!value || depth > 2) return false;
  const unwrapped = unwrapPythonExpression(value);
  if (sanitizer?.(context, unwrapped, useIndex)) return false;
  if (isDirectRequestSource(context, unwrapped, useIndex)) return true;
  const root = expressionRoot(unwrapped);
  if (!root) return false;
  return reachingAssignments(context, root, useIndex).some((assignment) => {
    const key = `${assignment.scopeId ?? "module"}:${assignment.tokenIndex}:${root}`;
    if (seen.has(key)) return false;
    const nextSeen = new Set(seen);
    nextSeen.add(key);
    return expressionReachesRequest(
      context,
      assignment.expression,
      assignment.tokenIndex,
      sanitizer,
      nextSeen,
      depth + 1,
    );
  });
}

function compositionSegments(value: PythonExpression): PythonExpression[] {
  const output: PythonExpression[] = [];
  const operators = new Set([
    "+", "-", "*", "/", "//", "%", "@", "|", "&", "^", "<<", ">>",
    "or", "and", "if", "else",
  ]);
  let depth = 0;
  let start = 0;
  for (let index = 0; index <= value.tokens.length; index++) {
    const token = value.tokens[index];
    if (token && ["(", "[", "{"].includes(token.value)) depth++;
    else if (token && [")", "]", "}"].includes(token.value)) depth--;
    if (index === value.tokens.length || depth === 0 && token && operators.has(token.value)) {
      const candidate = expression(value.tokens.slice(start, index));
      if (candidate.tokens.length) output.push(candidate);
      start = index + 1;
    }
  }
  return output;
}

/** Compositional request taint for path/template sinks where any fragment matters. */
export function expressionContainsRequest(
  context: PythonAnalysisContext,
  value: PythonExpression | undefined,
  useIndex: number,
  sanitizer?: SanitizerPredicate,
  seen: ReadonlySet<string> = new Set(),
  depth = 0,
): boolean {
  if (!value || depth > 2) return false;
  const unwrapped = unwrapPythonExpression(value);
  if (sanitizer?.(context, unwrapped, useIndex)) return false;
  if (isDirectRequestSource(context, unwrapped, useIndex)) return true;

  for (const segment of compositionSegments(unwrapped)) {
    if (sanitizer?.(context, segment, useIndex)) continue;
    if (isDirectRequestSource(context, segment, useIndex)) return true;
    const reference = pythonExpressionReference(segment);
    const root = reference?.[0] ?? (
      segment.tokens.length === 1 && segment.tokens[0]?.kind === "identifier"
        ? segment.tokens[0].value
        : undefined
    );
    if (!root) continue;
    for (const assignment of reachingAssignments(context, root, useIndex)) {
      const key = `${assignment.scopeId ?? "module"}:${assignment.tokenIndex}:${root}`;
      if (seen.has(key)) continue;
      const nextSeen = new Set(seen);
      nextSeen.add(key);
      if (
        expressionContainsRequest(
          context,
          assignment.expression,
          assignment.tokenIndex,
          sanitizer,
          nextSeen,
          depth + 1,
        )
      ) return true;
    }
  }

  const sanitizerRanges = [
    ...compositionSegments(unwrapped).flatMap((segment) =>
      sanitizer?.(context, segment, useIndex)
        ? [{ start: segment.start, end: segment.end }]
        : []
    ),
    ...callsWithinExpression(context, unwrapped).flatMap((call) => {
    const callValue = expression(context.document.tokens.slice(call.startIndex, call.closeIndex + 1));
    return sanitizer?.(context, callValue, useIndex)
      ? [{ start: call.startIndex, end: call.closeIndex }]
      : [];
    }),
  ];
  for (let index = 0; index < unwrapped.tokens.length; index++) {
    const token = unwrapped.tokens[index]!;
    if (
      token.kind !== "identifier" || unwrapped.tokens[index - 1]?.value === "." ||
      sanitizerRanges.some((range) => token.index >= range.start && token.index <= range.end)
    ) continue;
    const direct = expression([token]);
    if (isDirectRequestSource(context, direct, useIndex)) return true;
    for (const assignment of reachingAssignments(context, token.value, useIndex)) {
      const key = `${assignment.scopeId ?? "module"}:${assignment.tokenIndex}:${token.value}`;
      if (seen.has(key)) continue;
      const nextSeen = new Set(seen);
      nextSeen.add(key);
      if (
        expressionContainsRequest(
          context,
          assignment.expression,
          assignment.tokenIndex,
          sanitizer,
          nextSeen,
          depth + 1,
        )
      ) return true;
    }
  }

  for (const call of callsWithinExpression(context, unwrapped)) {
    if (sanitizerRanges.some((range) =>
      call.startIndex >= range.start && call.closeIndex <= range.end
    )) continue;
    const callExpression = expression(context.document.tokens.slice(call.startIndex, call.closeIndex + 1));
    if (sanitizer?.(context, callExpression, useIndex)) continue;
    if (isDirectRequestSource(context, callExpression, call.startIndex)) return true;
    if (call.arguments.some((candidate) =>
      !candidate.spread && expressionContainsRequest(
        context,
        candidate.expression,
        call.startIndex,
        sanitizer,
        seen,
        depth,
      )
    )) return true;
  }
  return false;
}

export function requestRelatedNames(
  context: PythonAnalysisContext,
  useIndex: number,
): Set<string> {
  const output = new Set<string>();
  const scope = functionAt(context, useIndex);
  if (scope) {
    const route = routeFramework(context, scope);
    for (const parameter of scope.parameters) {
      if (injectedParameter(context, parameter)) continue;
      if (route || requestParameterKind(context, scope, parameter.name, useIndex)) output.add(parameter.name);
    }
  }
  for (const binding of context.imports) {
    const origin = resolveReferenceOrigin(context, [binding.local], useIndex);
    if (originStartsWith(origin, "flask.request") || originStartsWith(origin, "flask.globals.request")) {
      output.add(binding.local);
    }
  }
  for (let pass = 0; pass < 2; pass++) {
    for (const assignment of context.assignments) {
      if (assignment.tokenIndex >= useIndex || assignment.scopeId !== scope?.id || !assignment.name) continue;
      if (
        expressionReachesRequest(context, assignment.expression, assignment.tokenIndex) ||
        expressionReferencesName(assignment.expression, output)
      ) output.add(assignment.name);
    }
  }
  return output;
}

function terminating(statement: PythonStatementContext): boolean {
  const values = statement.tokens.map((token) => token.value);
  if (["return", "raise", "break", "continue"].includes(values[0] ?? "")) return true;
  return values.some((value, index) => value === "abort" && values[index + 1] === "(");
}

function conditionAndInlineBody(statement: PythonStatementContext): {
  condition: readonly PythonToken[];
  inline: readonly PythonToken[];
} | undefined {
  if (statement.tokens[0]?.value !== "if") return undefined;
  let depth = 0;
  for (let index = 1; index < statement.tokens.length; index++) {
    const value = statement.tokens[index]!.value;
    if (["(", "[", "{"].includes(value)) depth++;
    else if ([")", "]", "}"].includes(value)) depth--;
    else if (depth === 0 && value === ":") {
      return {
        condition: statement.tokens.slice(1, index),
        inline: statement.tokens.slice(index + 1),
      };
    }
  }
  return undefined;
}

export interface GuardPredicates {
  /** The condition itself proves the value safe while the sink is inside its body. */
  positive: (condition: readonly PythonToken[]) => boolean;
  /** The condition identifies an unsafe value and its body terminates before the sink. */
  rejecting: (condition: readonly PythonToken[]) => boolean;
}

/** Conservative indentation-aware dominating guard recognition. */
export function hasDominatingGuard(
  context: PythonAnalysisContext,
  sinkIndex: number,
  predicates: GuardPredicates,
): boolean {
  const sinkStatement = statementAt(context, sinkIndex);
  if (!sinkStatement) return false;
  const sinkScope = functionAt(context, sinkIndex);
  for (let index = 0; index < context.statements.length; index++) {
    const guard = context.statements[index]!;
    if (guard.start >= sinkIndex || functionAt(context, guard.start)?.id !== sinkScope?.id) continue;
    const parsed = conditionAndInlineBody(guard);
    if (!parsed) continue;
    const nextBoundary = context.statements.slice(index + 1).find((candidate) => candidate.column <= guard.column);
    const blockEnd = (nextBoundary?.start ?? context.document.tokens.length + 1) - 1;
    if (
      sinkIndex > guard.end && sinkIndex <= blockEnd && sinkStatement.column > guard.column &&
      predicates.positive(parsed.condition)
    ) return true;

    if (guard.column !== sinkStatement.column || blockEnd >= sinkIndex || !predicates.rejecting(parsed.condition)) {
      continue;
    }
    const inlineStatement: PythonStatementContext = {
      tokens: parsed.inline,
      start: parsed.inline[0]?.index ?? guard.end,
      end: parsed.inline.at(-1)?.index ?? guard.end,
      line: parsed.inline[0]?.line ?? guard.line,
      column: parsed.inline[0]?.column ?? guard.column,
      blockPath: guard.blockPath,
    };
    if (parsed.inline.length && terminating(inlineStatement)) return true;
    const body = context.statements.slice(index + 1).filter((candidate) =>
      candidate.start <= blockEnd && candidate.column > guard.column
    );
    const bodyColumn = body.reduce(
      (minimum, statement) => Math.min(minimum, statement.column),
      Number.POSITIVE_INFINITY,
    );
    if (body.some((statement) => statement.column === bodyColumn && terminating(statement))) return true;
  }
  return false;
}

export function tokenValues(tokens: readonly PythonToken[] | PythonExpression): string[] {
  return ("tokens" in tokens ? tokens.tokens : tokens).map((token) => token.value);
}

export function tokensMentionNames(tokens: readonly PythonToken[], names: ReadonlySet<string>): boolean {
  return tokens.some((token, index) =>
    token.kind === "identifier" && names.has(token.value) && tokens[index - 1]?.value !== "."
  );
}

export function importedModule(context: PythonAnalysisContext, prefix: string): boolean {
  return context.imports.some((binding) => binding.module === prefix || binding.module.startsWith(`${prefix}.`));
}

export function topLevelAssignment(
  context: PythonAnalysisContext,
  name: string,
): PythonLocalAssignment | undefined {
  return context.assignments
    .filter((assignment) => assignment.scopeId === undefined && assignment.name === name && assignment.column === 1)
    .sort((left, right) => right.tokenIndex - left.tokenIndex)[0];
}

export function memberTargetParts(target: PythonExpression): string[] | undefined {
  return pythonExpressionReference(target);
}

export function targetSubscriptString(target: PythonExpression): {
  root: string;
  attributes: string[];
  key: string;
} | undefined {
  const tokens = pythonSignificant(target.tokens);
  const open = tokens.findIndex((token) => token.value === "[");
  if (open < 1 || tokens.at(-1)?.value !== "]") return undefined;
  const reference = pythonExpressionReference(expression(tokens.slice(0, open)));
  const key = pythonStaticString(expression(tokens.slice(open + 1, -1)));
  if (!reference || key === undefined) return undefined;
  return { root: reference[0]!, attributes: reference.slice(1), key };
}

export function uniqueFindingsByLocation<T extends { rule_id: string; location: { file: string; start_line: number } }>(
  findings: readonly T[],
): T[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.rule_id}:${finding.location.file}:${finding.location.start_line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
