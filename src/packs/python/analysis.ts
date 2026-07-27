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
} from "./python.js";

export interface PythonImportBinding {
  local: string;
  module: string;
  imported?: string;
  tokenIndex: number;
  /** Internal lexical-scope identity used by provenance resolution. */
  scopeId?: number;
  /** False when the import is control-flow conditional or otherwise unprovable. */
  direct?: boolean;
}

export interface PythonAssignment {
  name: string;
  expression: PythonExpression;
  tokenIndex: number;
  line: number;
  column: number;
}

function expression(tokens: readonly PythonToken[]): PythonExpression {
  const values = pythonSignificant(tokens);
  return {
    tokens: values,
    start: values[0]?.index ?? -1,
    end: values.at(-1)?.index ?? -1,
  };
}

function unwrapOuter(tokens: readonly PythonToken[]): PythonToken[] {
  let values = pythonSignificant(tokens);
  while (
    values[0]?.value === "(" &&
    values[0].pairIndex === values.at(-1)?.index
  ) {
    values = values.slice(1, -1);
  }
  return values;
}

function dottedName(tokens: readonly PythonToken[]): string | undefined {
  const values = pythonSignificant(tokens);
  if (!values.length || values.length % 2 === 0) return undefined;
  const parts: string[] = [];
  for (let index = 0; index < values.length; index++) {
    if (index % 2 === 0) {
      if (values[index]?.kind !== "identifier") return undefined;
      parts.push(values[index]!.value);
    } else if (values[index]?.value !== ".") return undefined;
  }
  return parts.join(".");
}

function importItems(tokens: readonly PythonToken[]): PythonExpression[] {
  const unwrapped = unwrapOuter(tokens);
  return splitPythonTopLevel(unwrapped);
}

type PythonScopeKind = "module" | "function" | "class";

interface PythonScope {
  id: number;
  kind: PythonScopeKind;
  headerStart: number;
  bodyStart: number;
  end: number;
  column: number;
  parentId?: number;
  directIndent: number;
  inlineSuite: boolean;
  localNames: Set<string>;
  globals: Set<string>;
  nonlocals: Set<string>;
}

interface PythonNameEvent {
  name: string;
  kind: "import" | "other";
  tokenIndex: number;
  scopeId: number;
  binding?: PythonImportBinding;
}

interface PythonLexicalModel {
  scopes: PythonScope[];
  imports: PythonImportBinding[];
  events: PythonNameEvent[];
}

interface ScopeHeader {
  kind: Exclude<PythonScopeKind, "module">;
  name: string;
  statementIndex: number;
  start: number;
  column: number;
  colonIndex: number;
  inlineSuite: boolean;
  parameters: string[];
}

const lexicalModels = new WeakMap<PythonDocument, PythonLexicalModel>();

function topLevelToken(tokens: readonly PythonToken[], value: string, start = 0): number {
  let depth = 0;
  for (let index = start; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (["(", "[", "{"].includes(token.value)) depth++;
    else if ([")", "]", "}"].includes(token.value)) depth--;
    else if (depth === 0 && token.value === value) return index;
  }
  return -1;
}

function scopeHeader(tokens: readonly PythonToken[], statementIndex: number): ScopeHeader | undefined {
  const first = tokens[0];
  if (!first) return undefined;
  const declarationIndex = first.value === "async" && tokens[1]?.value === "def"
    ? 1
    : first.value === "def" || first.value === "class"
      ? 0
      : -1;
  if (declarationIndex < 0) return undefined;
  const declaration = tokens[declarationIndex]!.value;
  const name = tokens[declarationIndex + 1];
  if (name?.kind !== "identifier") return undefined;
  const colonOffset = topLevelToken(tokens, ":", declarationIndex + 2);
  if (colonOffset < 0) return undefined;
  const parameters: string[] = [];
  if (declaration === "def") {
    const openOffset = tokens.findIndex((token, index) => index > declarationIndex + 1 && token.value === "(");
    const open = tokens[openOffset];
    if (openOffset >= 0 && open?.pairIndex !== undefined) {
      const closeOffset = tokens.findIndex((token) => token.index === open.pairIndex);
      if (closeOffset > openOffset) {
        for (const item of splitPythonTopLevel(tokens.slice(openOffset + 1, closeOffset))) {
          const values = pythonSignificant(item.tokens);
          const candidate = values.find((token) => token.kind === "identifier");
          if (candidate && !["True", "False", "None"].includes(candidate.value)) parameters.push(candidate.value);
        }
      }
    }
  }
  return {
    kind: declaration === "def" ? "function" : "class",
    name: name.value,
    statementIndex,
    start: first.index,
    column: first.column,
    colonIndex: tokens[colonOffset]!.index,
    inlineSuite: colonOffset < tokens.length - 1,
    parameters,
  };
}

function parseImportTokens(
  tokens: readonly PythonToken[],
  scopeId: number,
  direct: boolean,
): PythonImportBinding[] {
  const bindings: PythonImportBinding[] = [];
  const first = tokens[0];
  if (!first) return bindings;
  if (first.value === "from") {
      const importIndex = tokens.findIndex((token, index) => index > 0 && token.value === "import");
      if (importIndex < 2) return bindings;
      const module = dottedName(tokens.slice(1, importIndex));
      if (!module) return bindings;
      for (const item of importItems(tokens.slice(importIndex + 1))) {
        const values = pythonSignificant(item.tokens);
        if (values[0]?.kind !== "identifier" || values[0].value === "*") continue;
        const asIndex = values.findIndex((token) => token.value === "as");
        const importedTokens = asIndex >= 0 ? values.slice(0, asIndex) : values;
        const imported = dottedName(importedTokens);
        const alias = asIndex >= 0 && values[asIndex + 1]?.kind === "identifier"
          ? values[asIndex + 1]!.value
          : undefined;
        if (!imported || asIndex >= 0 && !alias) continue;
        bindings.push({
          local: alias ?? imported.split(".").at(-1)!,
          module,
          imported,
          tokenIndex: first.index,
          scopeId,
          direct,
        });
      }
      return bindings;
    }
    if (first.value !== "import") return bindings;
    for (const item of importItems(tokens.slice(1))) {
      const values = pythonSignificant(item.tokens);
      const asIndex = values.findIndex((token) => token.value === "as");
      const moduleTokens = asIndex >= 0 ? values.slice(0, asIndex) : values;
      const module = dottedName(moduleTokens);
      const alias = asIndex >= 0 && values[asIndex + 1]?.kind === "identifier"
        ? values[asIndex + 1]!.value
        : undefined;
      if (!module || asIndex >= 0 && !alias) continue;
      bindings.push({
        local: alias ?? module.split(".")[0]!,
        module,
        tokenIndex: first.index,
        scopeId,
        direct,
      });
    }
  return bindings;
}

function declarationNames(tokens: readonly PythonToken[], keyword: "global" | "nonlocal"): string[] {
  if (tokens[0]?.value !== keyword) return [];
  return tokens.slice(1)
    .filter((token) => token.kind === "identifier")
    .map((token) => token.value);
}

function targetNames(tokens: readonly PythonToken[]): string[] {
  return [...new Set(tokens
    .filter((token) => token.kind === "identifier" && !["as", "in"].includes(token.value))
    .map((token) => token.value))];
}

function lexicalModel(document: PythonDocument): PythonLexicalModel {
  const cached = lexicalModels.get(document);
  if (cached) return cached;
  const statements = pythonStatements(document);
  const lastIndex = document.tokens.at(-1)?.index ?? 0;
  const headers = statements
    .map((statement, index) => scopeHeader(statement.tokens, index))
    .filter((header): header is ScopeHeader => Boolean(header));
  const scopes: PythonScope[] = [{
    id: 0,
    kind: "module",
    headerStart: 0,
    bodyStart: 0,
    end: lastIndex,
    column: 0,
    directIndent: 1,
    inlineSuite: false,
    localNames: new Set(),
    globals: new Set(),
    nonlocals: new Set(),
  }];

  for (const header of headers) {
    const nextDedent = statements.slice(header.statementIndex + 1)
      .find((statement) => (statement.tokens[0]?.column ?? 0) <= header.column);
    const end = nextDedent ? nextDedent.start - 1 : lastIndex;
    const bodyStart = header.inlineSuite ? header.colonIndex + 1 : statements[header.statementIndex]!.end + 1;
    scopes.push({
      id: scopes.length,
      kind: header.kind,
      headerStart: header.start,
      bodyStart,
      end,
      column: header.column,
      directIndent: header.column + 1,
      inlineSuite: header.inlineSuite,
      localNames: new Set(header.parameters),
      globals: new Set(),
      nonlocals: new Set(),
    });
  }

  const nonModule = scopes.slice(1);
  for (const scope of nonModule) {
    const parent = scopes
      .filter((candidate) => candidate.id !== scope.id && candidate.bodyStart <= scope.headerStart && scope.headerStart <= candidate.end)
      .sort((left, right) => right.column - left.column)[0] ?? scopes[0]!;
    scope.parentId = parent.id;
    if (!scope.inlineSuite) {
      const directStatement = statements
        .filter((statement) => statement.start >= scope.bodyStart && statement.start <= scope.end)
        .sort((left, right) => (left.tokens[0]?.column ?? Number.MAX_SAFE_INTEGER) - (right.tokens[0]?.column ?? Number.MAX_SAFE_INTEGER))[0];
      scope.directIndent = directStatement?.tokens[0]?.column ?? scope.column + 4;
    }
  }

  const scopeForIndex = (tokenIndex: number): PythonScope => scopes
    .filter((scope) => scope.bodyStart <= tokenIndex && tokenIndex <= scope.end)
    .sort((left, right) => right.column - left.column)[0] ?? scopes[0]!;
  const imports: PythonImportBinding[] = [];
  const events: PythonNameEvent[] = [];
  const addOther = (scope: PythonScope, name: string, tokenIndex: number): void => {
    if (!name) return;
    scope.localNames.add(name);
    events.push({ name, kind: "other", tokenIndex, scopeId: scope.id });
  };

  for (const header of headers) {
    const owner = scopeForIndex(header.start);
    addOther(owner, header.name, header.start);
    const ownScope = scopes.find((scope) => scope.headerStart === header.start && scope.kind === header.kind);
    for (const parameter of header.parameters) {
      if (ownScope) events.push({ name: parameter, kind: "other", tokenIndex: ownScope.bodyStart - 1, scopeId: ownScope.id });
    }
  }

  for (const statement of statements) {
    const first = statement.tokens[0];
    if (!first) continue;
    const scope = scopeForIndex(first.index);
    for (const name of declarationNames(statement.tokens, "global")) scope.globals.add(name);
    for (const name of declarationNames(statement.tokens, "nonlocal")) scope.nonlocals.add(name);

    const importStarts: number[] = [];
    if (first.value === "from" || first.value === "import") importStarts.push(0);
    else {
      for (let index = 1; index < statement.tokens.length; index++) {
        if (statement.tokens[index]?.value === "from" || statement.tokens[index]?.value === "import") {
          importStarts.push(index);
        }
      }
    }
    for (const start of importStarts) {
      const importToken = statement.tokens[start]!;
      const parsed = parseImportTokens(
        statement.tokens.slice(start),
        scope.id,
        start === 0 && importToken.column === scope.directIndent,
      );
      for (const binding of parsed) {
        imports.push(binding);
        scope.localNames.add(binding.local);
        events.push({ name: binding.local, kind: "import", tokenIndex: binding.tokenIndex, scopeId: scope.id, binding });
      }
    }

    const values = statement.tokens;
    for (let forOffset = 0; forOffset < values.length; forOffset++) {
      if (values[forOffset]?.value !== "for") continue;
      const inOffset = values.findIndex((token, index) => index > forOffset && token.value === "in");
      if (inOffset > forOffset + 1) {
        // Comprehensions have an implicit scope that is intentionally not
        // modeled yet. Binding at the statement start fails closed for calls
        // in the leading expression instead of leaking an outer import.
        const eventIndex = forOffset === 0 || values[forOffset - 1]?.value === "async"
          ? values[forOffset]!.index
          : statement.start;
        for (const name of targetNames(values.slice(forOffset + 1, inOffset))) addOther(scope, name, eventIndex);
      }
    }
    if (["with", "except"].includes(first.value) || first.value === "async" && values[1]?.value === "with") {
      for (let index = 0; index < values.length - 1; index++) {
        if (values[index]?.value === "as" && values[index + 1]?.kind === "identifier") {
          addOther(scope, values[index + 1]!.value, values[index + 1]!.index);
        }
      }
    }
    for (let index = 0; index < values.length; index++) {
      if (values[index]?.value !== "del") continue;
      for (const name of targetNames(values.slice(index + 1))) addOther(scope, name, values[index]!.index);
    }
    if (first.value === "case") {
      for (const name of targetNames(values.slice(1))) addOther(scope, name, first.index);
    }

    // Python decides function locals from every binding form before execution.
    // Capture unsupported assignment targets conservatively so an outer import
    // can never survive merely because the target was annotated, destructured,
    // augmented, placed in a one-line suite, or assigned by a walrus.
    let depth = 0;
    for (let index = 0; index < values.length; index++) {
      const token = values[index]!;
      if (["(", "[", "{"].includes(token.value)) {
        depth++;
        continue;
      }
      if ([")", "]", "}"].includes(token.value)) {
        depth--;
        continue;
      }
      if (token.value === ":=" && values[index - 1]?.kind === "identifier") {
        addOther(scope, values[index - 1]!.value, values[index - 1]!.index);
        continue;
      }
      if (["+=", "-=", "*=", "/=", "//=", "%=", "@=", "&=", "|=", "^=", ">>=", "<<=", "**="].includes(token.value)) {
        for (const name of targetNames(values.slice(0, index))) addOther(scope, name, statement.start);
        continue;
      }
      if (depth === 0 && token.value === "=") {
        const names = targetNames(values.slice(0, index));
        const simpleTarget = index === 1 && values[0]?.kind === "identifier";
        if (!simpleTarget) for (const name of names) addOther(scope, name, statement.start);
        continue;
      }
      if (
        scope.kind === "function" && depth === 0 && token.value === ":" &&
        values[index - 1]?.kind === "identifier"
      ) addOther(scope, values[index - 1]!.value, statement.start);
    }

    for (let index = 0; index < values.length; index++) {
      if (values[index]?.value !== "lambda") continue;
      const colon = values.findIndex((token, offset) => offset > index && token.value === ":");
      if (colon < 0) continue;
      for (const item of splitPythonTopLevel(values.slice(index + 1, colon))) {
        const parameter = item.tokens.find((token) => token.kind === "identifier");
        if (parameter) addOther(scope, parameter.value, statement.start);
      }
    }
  }

  for (const assignment of pythonAssignments(document)) {
    addOther(scopeForIndex(assignment.tokenIndex), assignment.name, assignment.tokenIndex);
  }
  events.sort((left, right) => left.tokenIndex - right.tokenIndex);
  imports.sort((left, right) => left.tokenIndex - right.tokenIndex);
  const model = { scopes, imports, events };
  lexicalModels.set(document, model);
  return model;
}

/** Retain absolute imports with lexical scope metadata; provenance remains fail-closed. */
export function pythonImports(document: PythonDocument): PythonImportBinding[] {
  return document.balanced ? lexicalModel(document).imports : [];
}

function assignmentOperator(tokens: readonly PythonToken[]): number {
  let depth = 0;
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (["(", "[", "{"].includes(token.value)) depth++;
    else if ([")", "]", "}"].includes(token.value)) depth--;
    else if (depth === 0 && token.value === "=") return index;
  }
  return -1;
}

function assignmentName(tokens: readonly PythonToken[]): string | undefined {
  const values = pythonSignificant(tokens);
  if (values[0]?.kind !== "identifier") return undefined;
  if (values.length === 1) return values[0].value;
  if (values[1]?.value !== ":") return undefined;
  // The annotation is deliberately not interpreted. Reject another top-level
  // assignment target so tuple/chained destructuring cannot be mistaken for one name.
  if (values.slice(2).some((token) => token.value === "=" || token.value === ",")) return undefined;
  return values[0].value;
}

export function pythonAssignments(document: PythonDocument): PythonAssignment[] {
  if (!document.balanced) return [];
  const assignments: PythonAssignment[] = [];
  for (const statement of pythonStatements(document)) {
    const operator = assignmentOperator(statement.tokens);
    if (operator <= 0) continue;
    const name = assignmentName(statement.tokens.slice(0, operator));
    const value = expression(statement.tokens.slice(operator + 1));
    const first = statement.tokens[0];
    if (!name || !value.tokens.length || !first) continue;
    assignments.push({
      name,
      expression: value,
      tokenIndex: first.index,
      line: first.line,
      column: first.column,
    });
  }
  return assignments;
}

function bindingForReference(
  document: PythonDocument,
  reference: readonly string[],
  useIndex: number,
): PythonImportBinding | undefined {
  const root = reference[0];
  if (!root) return undefined;
  const model = lexicalModel(document);
  const useScope = model.scopes
    .filter((scope) => scope.bodyStart <= useIndex && useIndex <= scope.end)
    .sort((left, right) => right.column - left.column)[0] ?? model.scopes[0]!;
  if (useScope.inlineSuite) return undefined;

  const resolve = (scope: PythonScope, childScopeId?: number): PythonImportBinding | undefined => {
    const scopeEvents = model.events.filter((event) => event.scopeId === scope.id && event.name === root);
    if (scope.kind !== "module" && scope.globals.has(root)) {
      if (scopeEvents.length) return undefined;
      return resolve(model.scopes[0]!, scope.id);
    }
    if (scope.kind !== "module" && scope.nonlocals.has(root)) {
      if (scopeEvents.length) return undefined;
      let parent = scope.parentId === undefined ? undefined : model.scopes[scope.parentId];
      while (parent && (parent.kind === "class" || !parent.localNames.has(root))) {
        parent = parent.parentId === undefined ? undefined : model.scopes[parent.parentId];
      }
      return parent ? resolve(parent, scope.id) : undefined;
    }

    if (scope.kind === "function" && scope.localNames.has(root)) {
      // A nested closure observes rebinding in its parent at runtime. Resolve
      // only a single stable import when crossing a function boundary.
      if (childScopeId !== undefined && (scopeEvents.length !== 1 || scopeEvents[0]?.kind !== "import")) return undefined;
      const before = scopeEvents.filter((event) => event.tokenIndex < useIndex).at(-1);
      if (!before || before.kind !== "import" || !before.binding?.direct) return undefined;
      return before.binding;
    }

    if (scope.kind === "module" && childScopeId !== undefined) {
      const child = model.scopes[childScopeId];
      return scopeEvents.length === 1 && scopeEvents[0]?.kind === "import" && scopeEvents[0].binding?.direct &&
        child !== undefined && scopeEvents[0].tokenIndex < child.headerStart
        ? scopeEvents[0].binding
        : undefined;
    }
    const before = scopeEvents.filter((event) => event.tokenIndex < useIndex).at(-1);
    if (before) return before.kind === "import" && before.binding?.direct ? before.binding : undefined;
    if (scope.kind === "module") return undefined;
    let parent = scope.parentId === undefined ? undefined : model.scopes[scope.parentId];
    if (scope.kind === "function") {
      while (parent?.kind === "class") {
        parent = parent.parentId === undefined ? undefined : model.scopes[parent.parentId];
      }
    }
    return parent ? resolve(parent, scope.id) : undefined;
  };

  return resolve(useScope);
}

/** Resolve an exact, lexically proven import plus a direct attribute chain. */
export function pythonReferenceOrigin(
  document: PythonDocument,
  reference: readonly string[],
  useIndex: number,
): string[] | undefined {
  const binding = bindingForReference(document, reference, useIndex);
  if (!binding) return undefined;
  if (binding.imported) {
    return [...binding.module.split("."), ...binding.imported.split("."), ...reference.slice(1)];
  }
  if (binding.local !== binding.module.split(".")[0]) {
    return [...binding.module.split("."), ...reference.slice(1)];
  }
  const full = reference.join(".");
  if (full !== binding.module && !full.startsWith(`${binding.module}.`)) return undefined;
  return reference.slice();
}

export function pythonCallOrigin(document: PythonDocument, call: PythonCall): string[] | undefined {
  return pythonReferenceOrigin(document, call.reference, call.startIndex);
}

export function pythonKeywordArgument(call: PythonCall, name: string): PythonArgument | undefined {
  return call.arguments.find((argument) => argument.name === name);
}

export function pythonPositionalArguments(call: PythonCall): PythonArgument[] {
  return call.arguments.filter((argument) => !argument.name && !argument.spread);
}

export function pythonHasSpreadArgument(call: PythonCall): boolean {
  return call.arguments.some((argument) => argument.spread);
}

export function pythonStaticBoolean(value: PythonExpression | undefined): boolean | undefined {
  const tokens = value ? unwrapOuter(value.tokens) : [];
  if (tokens.length !== 1 || tokens[0]?.kind !== "identifier") return undefined;
  if (tokens[0].value === "True") return true;
  if (tokens[0].value === "False") return false;
  return undefined;
}

export function pythonStaticString(value: PythonExpression | undefined): string | undefined {
  const tokens = value ? unwrapOuter(value.tokens) : [];
  return tokens.length === 1 && tokens[0]?.kind === "string"
    ? tokens[0].staticString
    : undefined;
}

export function pythonStaticStringList(value: PythonExpression | undefined): string[] | undefined {
  const tokens = value ? pythonSignificant(value.tokens) : [];
  if (tokens.length < 2) return undefined;
  const opening = tokens[0]?.value;
  const closing = opening === "[" ? "]" : opening === "(" ? ")" : undefined;
  if (!closing || tokens.at(-1)?.value !== closing || tokens[0]?.pairIndex !== tokens.at(-1)?.index) {
    return undefined;
  }
  const inner = tokens.slice(1, -1);
  if (!inner.length) return [];
  const items = splitPythonTopLevel(inner);
  const strings = items.map((item) => pythonStaticString(item));
  return strings.every((item): item is string => item !== undefined) ? strings : undefined;
}

/** Find a direct imported call that occupies the entire expression. */
export function pythonDirectCall(
  document: PythonDocument,
  value: PythonExpression | undefined,
): PythonCall | undefined {
  if (!value) return undefined;
  const tokens = unwrapOuter(value.tokens);
  const first = tokens[0];
  const last = tokens.at(-1);
  if (!first || !last) return undefined;
  return pythonCalls(document).find((call) => call.startIndex === first.index && call.closeIndex === last.index);
}

export function pythonTopLevelAssignment(
  document: PythonDocument,
  name: string,
): PythonAssignment | undefined {
  return pythonAssignments(document)
    .filter((assignment) => assignment.name === name && assignment.column === 1)
    .sort((left, right) => right.tokenIndex - left.tokenIndex)[0];
}

export function pythonArgumentReference(argument: PythonArgument | undefined): string[] | undefined {
  return pythonExpressionReference(argument?.expression);
}
