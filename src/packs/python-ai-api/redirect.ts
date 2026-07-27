import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  directArgumentReference,
  directCallExpression,
  expressionIdentifierRoots,
  expressionReachesRequest,
  functionAt,
  hasDominatingGuard,
  hasSpreadArgument,
  originEquals,
  reachingAssignments,
  resolveCallOrigin,
  statementAt,
  staticBoolean,
  staticString,
  staticStringList,
  unwrapPythonExpression,
  uniqueFindingsByLocation,
  type PythonAnalysisContext,
  type PythonStatementContext,
} from "./analysis.js";
import {
  pythonExpressionReference,
  splitPythonTopLevel,
  type PythonCall,
  type PythonExpression,
  type PythonToken,
} from "../python/python.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_UNTRUSTED_REDIRECT_RULE_ID = "ci-python-untrusted-redirect";

function redirectTarget(
  context: PythonAnalysisContext,
  call: PythonCall,
): PythonExpression | undefined {
  const origin = resolveCallOrigin(context, call);
  if ([
    "flask.redirect",
    "flask.helpers.redirect",
    "django.shortcuts.redirect",
    "django.http.HttpResponseRedirect",
    "django.http.HttpResponsePermanentRedirect",
    "starlette.responses.RedirectResponse",
    "fastapi.responses.RedirectResponse",
  ].some((expected) => originEquals(origin, expected))) {
    return argument(call, 0, "location", "to", "url")?.expression;
  }
  return undefined;
}

function safeDestination(context: PythonAnalysisContext, value: PythonExpression): boolean {
  if (staticString(value) !== undefined) return true;
  const call = directCallExpression(context, value);
  if (!call) return false;
  const origin = resolveCallOrigin(context, call);
  return ["flask.url_for", "django.urls.reverse"].some((expected) => originEquals(origin, expected));
}

function conditionParts(statement: PythonStatementContext): readonly PythonToken[] {
  let depth = 0;
  for (let index = 1; index < statement.tokens.length; index++) {
    const value = statement.tokens[index]!.value;
    if (["(", "[", "{"].includes(value)) depth++;
    else if ([")", "]", "}"].includes(value)) depth--;
    else if (depth === 0 && value === ":") return statement.tokens.slice(1, index);
  }
  return [];
}

function targetRoots(
  context: PythonAnalysisContext,
  target: PythonExpression,
  useIndex: number,
): Set<string> {
  const roots = new Set(expressionIdentifierRoots(target));
  for (let depth = 0; depth < 2; depth++) {
    for (const name of [...roots]) {
      const assignments = reachingAssignments(context, name, useIndex);
      if (assignments.length !== 1) continue;
      const reference = pythonExpressionReference(unwrapPythonExpression(assignments[0]!.expression));
      if (reference?.length === 1) roots.add(reference[0]!);
    }
  }
  return roots;
}

function urlParserSource(
  context: PythonAnalysisContext,
  name: string,
  roots: ReadonlySet<string>,
  useIndex: number,
  seen = new Set<string>(),
  depth = 0,
): string | undefined {
  if (depth > 2 || seen.has(name)) return undefined;
  seen.add(name);
  const assignments = reachingAssignments(context, name, useIndex);
  if (assignments.length !== 1) return undefined;
  const assignment = assignments[0]!;
  const call = directCallExpression(context, assignment.expression);
  if (call && ["urllib.parse.urlsplit", "urllib.parse.urlparse"].some((origin) =>
    originEquals(resolveCallOrigin(context, call), origin)
  )) {
    const input = directArgumentReference(argument(call, 0, "url"));
    if (input?.length === 1 && roots.has(input[0]!)) return input[0]!;
  }
  const alias = pythonExpressionReference(unwrapPythonExpression(assignment.expression));
  return alias?.length === 1
    ? urlParserSource(context, alias[0]!, roots, assignment.tokenIndex, seen, depth + 1)
    : undefined;
}

function propertySource(
  context: PythonAnalysisContext,
  tokens: readonly PythonToken[],
  propertyIndex: number,
  roots: ReadonlySet<string>,
): string | undefined {
  const dot = tokens[propertyIndex - 1];
  if (dot?.value !== ".") return undefined;
  const direct = tokens[propertyIndex - 2];
  if (direct?.kind === "identifier") {
    return urlParserSource(context, direct.value, roots, tokens[propertyIndex]!.index);
  }
  if (direct?.value !== ")") return undefined;
  const call = context.calls.find((candidate) => candidate.closeIndex === direct.index);
  if (!call || !["urllib.parse.urlsplit", "urllib.parse.urlparse"].some((origin) =>
    originEquals(resolveCallOrigin(context, call), origin)
  )) return undefined;
  const input = directArgumentReference(argument(call, 0, "url"));
  if (input?.length === 1 && roots.has(input[0]!)) return input[0]!;
  return undefined;
}

interface PropertyFact {
  source: string;
  property: "scheme" | "netloc" | "hostname" | "port";
  operator?: "==" | "!=" | "is";
  value?: string;
  truthy: boolean;
}

function negatedProperty(tokens: readonly PythonToken[], propertyIndex: number): boolean {
  let notCount = 0;
  for (let index = propertyIndex - 1; index >= 0; index--) {
    const token = tokens[index]!;
    if (token.kind === "identifier" && ["and", "or"].includes(token.value)) break;
    if (token.kind === "identifier" && token.value === "not") notCount++;
  }
  return notCount % 2 === 1;
}

function propertyFacts(
  context: PythonAnalysisContext,
  tokens: readonly PythonToken[],
  roots: ReadonlySet<string>,
): PropertyFact[] {
  const facts: PropertyFact[] = [];
  for (let index = 0; index < tokens.length; index++) {
    const propertyToken = tokens[index]!;
    if (
      propertyToken.kind !== "identifier" ||
      !["scheme", "netloc", "hostname", "port"].includes(propertyToken.value)
    ) continue;
    const source = propertySource(context, tokens, index, roots);
    if (!source || negatedProperty(tokens, index)) continue;
    const operator = tokens[index + 1];
    const compared = tokens[index + 2];
    if (
      operator && ["==", "!=", "is"].includes(operator.value) &&
      (operator.kind === "symbol" || operator.kind === "identifier") && compared
    ) {
      const value = compared.kind === "string"
        ? compared.staticString
        : compared.kind === "identifier" && compared.value === "None" || compared.kind === "number"
          ? compared.value
          : undefined;
      if (value !== undefined) {
        facts.push({
          source,
          property: propertyToken.value as PropertyFact["property"],
          operator: operator.value as "==" | "!=" | "is",
          value,
          truthy: false,
        });
        continue;
      }
    }
    if (
      operator && !["and", "or", ")"].includes(operator.value) ||
      operator?.value === "."
    ) continue;
    facts.push({
      source,
      property: propertyToken.value as PropertyFact["property"],
      truthy: true,
    });
  }
  return facts;
}

function logical(tokens: readonly PythonToken[], value: "and" | "or" | "not"): boolean {
  return tokens.some((token) => token.kind === "identifier" && token.value === value);
}

function backslashFact(
  tokens: readonly PythonToken[],
  roots: ReadonlySet<string>,
  expectedOperator: "in" | "not in",
): boolean {
  return tokens.some((token, index) => {
    const raw = token.raw;
    const isSingleBackslash = token.kind === "string" && raw.length === 4 &&
      ["\"", "'"].includes(raw[0] ?? "") && raw.at(-1) === raw[0] &&
      raw[1] === "\\" && raw[2] === "\\";
    if (!isSingleBackslash) return false;
    const operator = tokens[index + 1];
    const secondOperator = tokens[index + 2];
    const compared = expectedOperator === "not in" ? tokens[index + 3] : tokens[index + 2];
    return expectedOperator === "in"
      ? operator?.value === "in" && compared?.kind === "identifier" && roots.has(compared.value)
      : operator?.value === "not" && secondOperator?.value === "in" &&
        compared?.kind === "identifier" && roots.has(compared.value);
  });
}

function positiveUrlProof(
  context: PythonAnalysisContext,
  tokens: readonly PythonToken[],
  roots: ReadonlySet<string>,
): boolean {
  if (logical(tokens, "or")) return false;
  const facts = propertyFacts(context, tokens, roots);
  for (const source of new Set(facts.map((fact) => fact.source))) {
    const owned = facts.filter((fact) => fact.source === source);
    const scheme = owned.some((fact) => fact.property === "scheme" && fact.operator === "==" && fact.value === "");
    const netloc = owned.some((fact) => fact.property === "netloc" && fact.operator === "==" && fact.value === "");
    if (scheme && netloc && logical(tokens, "and") && backslashFact(tokens, roots, "not in")) return true;

    const https = owned.some((fact) => fact.property === "scheme" && fact.operator === "==" && fact.value === "https");
    const exactNetloc = owned.some((fact) => fact.property === "netloc" && fact.operator === "==" && Boolean(fact.value));
    if (https && exactNetloc && logical(tokens, "and")) return true;
    const hostname = owned.some((fact) => fact.property === "hostname" && fact.operator === "==" && Boolean(fact.value));
    const port = owned.some((fact) => fact.property === "port" && (
      fact.operator === "==" && ["None", "443"].includes(fact.value ?? "") ||
      fact.operator === "is" && fact.value === "None"
    ));
    if (https && hostname && port && logical(tokens, "and")) return true;
  }
  return false;
}

function staticAllowedHosts(value: PythonExpression | undefined): string[] | undefined {
  if (!value) return undefined;
  const list = staticStringList(value);
  if (list) return list.length && list.every(Boolean) ? list : undefined;
  const unwrapped = unwrapPythonExpression(value);
  if (unwrapped.tokens[0]?.value !== "{" || unwrapped.tokens.at(-1)?.value !== "}") return undefined;
  const values = splitPythonTopLevel(unwrapped.tokens.slice(1, -1)).map((item) => staticString(item));
  return values.length && values.every((item): item is string => Boolean(item)) ? values : undefined;
}

function strictHelperProof(
  context: PythonAnalysisContext,
  tokens: readonly PythonToken[],
  roots: ReadonlySet<string>,
): { negated: boolean } | undefined {
  const start = tokens[0]?.index ?? -1;
  const end = tokens.at(-1)?.index ?? -1;
  for (const call of context.calls) {
    if (
      call.startIndex < start || call.closeIndex > end ||
      !originEquals(resolveCallOrigin(context, call), "django.utils.http.url_has_allowed_host_and_scheme") ||
      hasSpreadArgument(call)
    ) continue;
    const target = directArgumentReference(argument(call, 0, "url"));
    const hosts = staticAllowedHosts(argument(call, 1, "allowed_hosts")?.expression);
    if (target?.length !== 1 || !roots.has(target[0]!) || !hosts ||
      staticBoolean(argument(call, -1, "require_https")) !== true) continue;
    const callPosition = tokens.findIndex((token) => token.index === call.startIndex);
    if (callPosition < 0) continue;
    const beforeComparison = tokens[callPosition - 1];
    const afterComparison = tokens.find((token) => token.index > call.closeIndex);
    if ([beforeComparison?.value, afterComparison?.value].some((value) =>
      ["==", "!=", "is", "in", "<", ">", "<=", ">="].includes(value ?? "")
    )) continue;
    let cursor = callPosition - 1;
    while (tokens[cursor]?.value === "(") cursor--;
    return { negated: tokens[cursor]?.kind === "identifier" && tokens[cursor]?.value === "not" };
  }
  return undefined;
}

function rejectingUrlProof(
  context: PythonAnalysisContext,
  tokens: readonly PythonToken[],
  roots: ReadonlySet<string>,
): boolean {
  const helper = strictHelperProof(context, tokens, roots);
  if (helper?.negated) return true;
  if (!logical(tokens, "or") || logical(tokens, "and") || !backslashFact(tokens, roots, "in")) return false;
  const facts = propertyFacts(context, tokens, roots);
  for (const source of new Set(facts.map((fact) => fact.source))) {
    const owned = facts.filter((fact) => fact.source === source);
    const rejectsScheme = owned.some((fact) => fact.property === "scheme" && (
      fact.truthy || fact.operator === "!=" && ["", "https"].includes(fact.value ?? "")
    ));
    const rejectsNetloc = owned.some((fact) => fact.property === "netloc" && (
      fact.truthy || fact.operator === "!=" && fact.value !== undefined
    ));
    if (rejectsScheme && rejectsNetloc) return true;
  }
  return false;
}

function hasSafeFallbackGuard(
  context: PythonAnalysisContext,
  sinkIndex: number,
  target: PythonExpression,
): boolean {
  const sink = statementAt(context, sinkIndex);
  const scope = functionAt(context, sinkIndex);
  const roots = targetRoots(context, target, sinkIndex);
  if (!sink || !roots.size) return false;
  for (let index = 0; index < context.statements.length; index++) {
    const guard = context.statements[index]!;
    if (
      guard.start >= sinkIndex || guard.column !== sink.column ||
      functionAt(context, guard.start)?.id !== scope?.id || guard.tokens[0]?.value !== "if"
    ) continue;
    const condition = conditionParts(guard);
    if (!rejectingUrlProof(context, condition, roots)) continue;
    const nextBoundary = context.statements.slice(index + 1).find((candidate) => candidate.column <= guard.column);
    const blockEnd = (nextBoundary?.start ?? context.document.tokens.length + 1) - 1;
    if (blockEnd >= sinkIndex) continue;
    const bodyStatements = context.statements.slice(index + 1).filter((candidate) =>
      candidate.start <= blockEnd && candidate.column > guard.column
    );
    const bodyColumn = bodyStatements.reduce(
      (minimum, statement) => Math.min(minimum, statement.column),
      Number.POSITIVE_INFINITY,
    );
    const fallback = context.assignments.find((assignment) =>
      assignment.name !== undefined && roots.has(assignment.name) &&
      assignment.tokenIndex > guard.end && assignment.tokenIndex <= blockEnd &&
      assignment.column === bodyColumn && safeDestination(context, assignment.expression)
    );
    if (fallback) return true;
  }
  return false;
}

function guardedRedirect(
  context: PythonAnalysisContext,
  sinkIndex: number,
  target: PythonExpression,
): boolean {
  if (hasSafeFallbackGuard(context, sinkIndex, target)) return true;
  const roots = targetRoots(context, target, sinkIndex);
  return hasDominatingGuard(context, sinkIndex, {
    positive: (tokens) => positiveUrlProof(context, tokens, roots) ||
      strictHelperProof(context, tokens, roots)?.negated === false,
    rejecting: (tokens) => rejectingUrlProof(context, tokens, roots),
  });
}

function vulnerable(context: PythonAnalysisContext, call: PythonCall): boolean {
  if (hasSpreadArgument(call)) return false;
  const target = redirectTarget(context, call);
  if (!target || safeDestination(context, target)) return false;
  if (!expressionReachesRequest(context, target, call.startIndex)) return false;
  return !guardedRedirect(context, call.startIndex, target);
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PYTHON_UNTRUSTED_REDIRECT_RULE_ID,
    title: "Request input controls a redirect target",
    severity: "medium",
    cwe: ["CWE-601"],
    owasp_web: ["A01:2021"],
    file,
    startLine: line,
    snippet: "Redirect destination is derived from request input [VALUE REDACTED]",
    message: "A proven Python redirect response receives an untrusted complete destination without a recognized origin or relative-URL guard.",
    remediation: {
      summary: "Use named internal routes or validate the complete redirect destination against an exact allowlist.",
      steps: [
        "Prefer framework route reversal such as url_for() or reverse() for internal destinations.",
        "If external redirects are required, parse the URL and require an exact HTTPS scheme and host allowlist match.",
        "Reject protocol-relative URLs, userinfo, unexpected ports, and encoded alternate-host forms.",
      ],
      references: [
        "CWE-601",
        "https://docs.djangoproject.com/en/5.2/topics/http/shortcuts/#redirect",
        "https://flask.palletsprojects.com/en/stable/api/#flask.redirect",
        "https://www.starlette.io/responses/",
      ],
    },
    confidence: "high",
  });
}

export async function runPythonUntrustedRedirect(
  input: PythonProjectInput,
): Promise<Finding[]> {
  const project = await resolvePythonProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const context = analyzePythonDocument(document);
    for (const call of context.calls) {
      if (vulnerable(context, call)) findings.push(finding(document.path, call.line));
    }
  }
  return uniqueFindingsByLocation(findings);
}
