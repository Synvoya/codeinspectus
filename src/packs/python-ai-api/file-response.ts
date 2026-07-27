import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  directCallExpression,
  expressionContainsRequest,
  expressionFromTokens,
  hasDominatingGuard,
  hasSpreadArgument,
  isKnownPathSanitizer,
  isTrustedPathBase,
  isUnshadowedBuiltin,
  originEquals,
  originStartsWith,
  reachingAssignments,
  resolveCallOrigin,
  resolveReferenceOrigin,
  unwrapPythonExpression,
  uniqueFindingsByLocation,
  type PythonAnalysisContext,
} from "./analysis.js";
import {
  pythonExpressionReference,
  splitPythonTopLevel,
  type PythonCall,
  type PythonExpression,
  type PythonToken,
} from "../python/python.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_UNTRUSTED_FILE_RESPONSE_RULE_ID = "ci-python-untrusted-file-response";

function originIn(origin: readonly string[] | undefined, values: readonly string[]): boolean {
  return values.some((value) => originEquals(origin, value));
}

function builtinOpen(context: PythonAnalysisContext, call: PythonCall): boolean {
  return call.reference.length === 1 && call.reference[0] === "open" &&
    isUnshadowedBuiltin(context, "open", call.startIndex);
}

function sinkPath(
  context: PythonAnalysisContext,
  call: PythonCall,
): PythonExpression | undefined {
  const origin = resolveCallOrigin(context, call);
  if (originIn(origin, ["flask.send_file", "flask.helpers.send_file"])) {
    return argument(call, 0, "path_or_file")?.expression;
  }
  if (originIn(origin, ["flask.send_from_directory", "flask.helpers.send_from_directory"])) {
    // Werkzeug safely joins the filename; only a request-controlled trusted
    // base directory defeats that contract.
    return argument(call, 0, "directory")?.expression;
  }
  if (originIn(origin, [
    "starlette.responses.FileResponse",
    "fastapi.responses.FileResponse",
  ])) return argument(call, 0, "path")?.expression;
  if (originIn(origin, ["django.http.FileResponse", "django.http.response.FileResponse"])) {
    const file = argument(call, 0, "streaming_content")?.expression;
    const open = directCallExpression(context, file);
    return open && builtinOpen(context, open)
      ? argument(open, 0, "file")?.expression
      : undefined;
  }
  return undefined;
}

function expressionName(value: PythonExpression | undefined): string | undefined {
  const reference = pythonExpressionReference(unwrapPythonExpression(value));
  return reference?.length === 1 ? reference[0] : undefined;
}

function candidateNames(
  context: PythonAnalysisContext,
  path: PythonExpression,
  sinkIndex: number,
): Set<string> {
  const names = new Set<string>();
  const root = expressionName(path);
  if (root) names.add(root);
  for (let depth = 0; depth < 2; depth++) {
    for (const name of [...names]) {
      const assignments = reachingAssignments(context, name, sinkIndex);
      if (assignments.length !== 1) continue;
      const alias = expressionName(assignments[0]!.expression);
      if (alias) names.add(alias);
    }
  }
  return names;
}

function canonicalExpression(context: PythonAnalysisContext, value: PythonExpression): boolean {
  const unwrapped = unwrapPythonExpression(value);
  const direct = directCallExpression(context, unwrapped);
  if (direct && originEquals(resolveCallOrigin(context, direct), "os.path.realpath")) return true;
  const tokens = unwrapped.tokens;
  if (
    tokens.length < 4 ||
    tokens.at(-4)?.value !== "." || tokens.at(-3)?.kind !== "identifier" ||
    tokens.at(-3)?.value !== "resolve" || tokens.at(-2)?.value !== "(" ||
    tokens.at(-2)?.pairIndex !== tokens.at(-1)?.index
  ) return false;

  const receiver = unwrapPythonExpression(expressionFromTokens(tokens.slice(0, -4)));
  const rootIndex = receiver.tokens.findIndex((token, index) =>
    token.kind === "identifier" && receiver.tokens[index - 1]?.value !== "."
  );
  const root = receiver.tokens[rootIndex];
  if (!root) return false;
  const useIndex = direct?.startIndex ?? unwrapped.start;
  const origin = resolveReferenceOrigin(context, [root.value], useIndex);
  if ([
    "pathlib.Path",
    "pathlib.PosixPath",
    "pathlib.WindowsPath",
  ].some((expected) => originStartsWith(origin, expected))) return true;
  return isTrustedPathBase(context, expressionFromTokens([root]), useIndex);
}

function canonicalName(
  context: PythonAnalysisContext,
  name: string,
  useIndex: number,
  seen = new Set<string>(),
  depth = 0,
): boolean {
  if (depth > 2 || seen.has(name)) return false;
  seen.add(name);
  const assignments = reachingAssignments(context, name, useIndex);
  if (assignments.length !== 1) return false;
  const value = assignments[0]!.expression;
  if (canonicalExpression(context, value)) return true;
  const alias = expressionName(value);
  return alias ? canonicalName(context, alias, assignments[0]!.tokenIndex, seen, depth + 1) : false;
}

function segmentStart(tokens: readonly PythonToken[], before: number): number {
  for (let index = before - 1; index >= 0; index--) {
    const token = tokens[index]!;
    if (token.kind === "identifier" && ["and", "or"].includes(token.value) || token.value === ",") return index + 1;
  }
  return 0;
}

function receiverName(
  tokens: readonly PythonToken[],
  propertyIndex: number,
  names: ReadonlySet<string>,
): string | undefined {
  const receiver = tokens[propertyIndex - 2];
  return receiver?.kind === "identifier" && names.has(receiver.value)
    ? receiver.value
    : undefined;
}

interface RelativeProof {
  negated: boolean;
}

function relativeProof(
  context: PythonAnalysisContext,
  tokens: readonly PythonToken[],
  names: ReadonlySet<string>,
  sinkIndex: number,
): RelativeProof | undefined {
  for (let index = 0; index < tokens.length - 2; index++) {
    const property = tokens[index]!;
    if (
      property.kind !== "identifier" || property.value !== "is_relative_to" ||
      tokens[index - 1]?.value !== "." || tokens[index + 1]?.value !== "("
    ) continue;
    const receiver = receiverName(tokens, index, names);
    if (!receiver || !canonicalName(context, receiver, sinkIndex)) continue;
    const close = tokens[index + 1]!.pairIndex;
    if (close === undefined) continue;
    const baseTokens = tokens.filter((token) => token.index > tokens[index + 1]!.index && token.index < close);
    const base = expressionFromTokens(baseTokens);
    if (!base.tokens.length || !isTrustedPathBase(context, base, sinkIndex)) continue;
    const start = segmentStart(tokens, index);
    const negated = tokens.slice(start, index).some((token) => token.kind === "identifier" && token.value === "not");
    return { negated };
  }
  return undefined;
}

function listItems(value: PythonExpression): PythonExpression[] | undefined {
  const unwrapped = unwrapPythonExpression(value);
  if (unwrapped.tokens[0]?.value !== "[" || unwrapped.tokens.at(-1)?.value !== "]") return undefined;
  return splitPythonTopLevel(unwrapped.tokens.slice(1, -1));
}

function commonPathProof(
  context: PythonAnalysisContext,
  tokens: readonly PythonToken[],
  names: ReadonlySet<string>,
  sinkIndex: number,
): "positive" | "rejecting" | undefined {
  const start = tokens[0]?.index ?? -1;
  const end = tokens.at(-1)?.index ?? -1;
  for (const call of context.calls) {
    if (call.startIndex < start || call.closeIndex > end || !originEquals(resolveCallOrigin(context, call), "os.path.commonpath")) {
      continue;
    }
    const items = listItems(argument(call, 0)?.expression ?? expressionFromTokens([]));
    if (!items || items.length !== 2) continue;
    const namesByItem = items.map(expressionName);
    const candidateIndex = namesByItem.findIndex((name) => Boolean(name && names.has(name)));
    if (candidateIndex < 0) continue;
    const candidate = namesByItem[candidateIndex]!;
    const base = items[1 - candidateIndex]!;
    const baseName = namesByItem[1 - candidateIndex];
    if (!canonicalName(context, candidate, sinkIndex) || !baseName ||
      !canonicalName(context, baseName, sinkIndex) || !isTrustedPathBase(context, base, sinkIndex)) continue;
    const operator = context.document.tokens[call.closeIndex + 1];
    if (operator?.kind !== "symbol" || !["==", "!="].includes(operator.value)) continue;
    const compared = context.document.tokens[call.closeIndex + 2];
    if (compared?.kind !== "identifier" || compared.value !== baseName) continue;
    return operator.value === "==" ? "positive" : "rejecting";
  }
  return undefined;
}

function guardedPath(
  context: PythonAnalysisContext,
  path: PythonExpression,
  sinkIndex: number,
): boolean {
  const names = candidateNames(context, path, sinkIndex);
  if (!names.size) return false;
  return hasDominatingGuard(context, sinkIndex, {
    positive: (tokens) => relativeProof(context, tokens, names, sinkIndex)?.negated === false ||
      commonPathProof(context, tokens, names, sinkIndex) === "positive",
    rejecting: (tokens) => relativeProof(context, tokens, names, sinkIndex)?.negated === true ||
      commonPathProof(context, tokens, names, sinkIndex) === "rejecting",
  });
}

function vulnerable(context: PythonAnalysisContext, call: PythonCall): boolean {
  if (hasSpreadArgument(call)) return false;
  const path = sinkPath(context, call);
  if (!path || !expressionContainsRequest(context, path, call.startIndex, isKnownPathSanitizer)) return false;
  return !guardedPath(context, path, call.startIndex);
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PYTHON_UNTRUSTED_FILE_RESPONSE_RULE_ID,
    title: "Untrusted path reaches a file response",
    severity: "high",
    cwe: ["CWE-22", "CWE-73"],
    owasp_web: ["A01:2021"],
    file,
    startLine: line,
    snippet: "File response path is derived from request input [VALUE REDACTED]",
    message: "A proven Python file-response API receives a request-controlled path without a recognized containment boundary.",
    remediation: {
      summary: "Resolve downloads below a fixed server-controlled directory and reject paths that escape it.",
      steps: [
        "Keep the base directory constant and map public identifiers to server-owned filenames where possible.",
        "Resolve the candidate path and require it to remain below the trusted base before opening it.",
        "Do not treat basename filtering alone as authorization; enforce access control for the selected file.",
      ],
      references: [
        "CWE-22",
        "CWE-73",
        "https://flask.palletsprojects.com/en/stable/api/#flask.send_file",
        "https://www.starlette.io/responses/",
        "https://docs.djangoproject.com/en/5.2/ref/request-response/",
      ],
    },
    confidence: "high",
  });
}

export async function runPythonUntrustedFileResponse(
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
