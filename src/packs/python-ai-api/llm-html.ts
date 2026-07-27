import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  callsWithinExpression,
  directCallExpression,
  expressionFromTokens,
  functionAt,
  functionRouteFramework,
  hasSpreadArgument,
  isKnownHtmlSanitizer,
  originEquals,
  resolveCallOrigin,
  reachingAssignments,
  staticString,
  uniqueFindingsByLocation,
  unwrapPythonExpression,
  type PythonAnalysisContext,
} from "./analysis.js";
import {
  pythonExpressionReference,
  splitPythonTopLevel,
  type PythonCall,
  type PythonExpression,
} from "../python/python.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_LLM_OUTPUT_DANGEROUS_HTML_RULE_ID = "ci-python-llm-output-dangerous-html";

type LlmResponseKind = "openai-responses" | "openai-chat" | "anthropic-message";

function responseKind(context: PythonAnalysisContext, call: PythonCall): LlmResponseKind | undefined {
  const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
  if (!origin.startsWith("openai.")) {
    if (
      origin.startsWith("anthropic.") &&
      (origin.endsWith("Anthropic.messages.create") || origin.endsWith("AsyncAnthropic.messages.create"))
    ) return "anthropic-message";
    return undefined;
  }
  if (origin.endsWith(".responses.create") || origin === "openai.responses.create") return "openai-responses";
  if (origin.endsWith(".chat.completions.create") || origin === "openai.chat.completions.create") return "openai-chat";
  return undefined;
}

function responseKindForName(
  context: PythonAnalysisContext,
  name: string,
  useIndex: number,
  aliasDepth: number,
  seen: ReadonlySet<string>,
): LlmResponseKind | undefined {
  if (aliasDepth > 2) return undefined;
  for (const assignment of reachingAssignments(context, name, useIndex)) {
    const key = `${assignment.scopeId ?? "module"}:${assignment.tokenIndex}:${name}`;
    if (seen.has(key)) continue;
    const call = directCallExpression(context, assignment.expression);
    if (call) {
      const kind = responseKind(context, call);
      if (kind) return kind;
    }
    const reference = pythonExpressionReference(unwrapPythonExpression(assignment.expression));
    if (!reference || reference.length !== 1) continue;
    const nextSeen = new Set(seen);
    nextSeen.add(key);
    const kind = responseKindForName(context, reference[0]!, assignment.tokenIndex, aliasDepth + 1, nextSeen);
    if (kind) return kind;
  }
  return undefined;
}

function outputShape(kind: LlmResponseKind, values: readonly string[]): boolean {
  if (kind === "openai-responses") return values.includes("output_text");
  if (kind === "openai-chat") {
    return values.includes("choices") && values.includes("message") && values.includes("content");
  }
  return values.includes("content") && values.includes("text");
}

function directSdkOutput(
  context: PythonAnalysisContext,
  value: PythonExpression,
  useIndex: number,
  aliasDepth: number,
  seen: ReadonlySet<string>,
): boolean {
  const values = value.tokens.map((token) => token.value);
  for (const call of callsWithinExpression(context, value)) {
    const kind = responseKind(context, call);
    if (!kind) continue;
    const suffix = context.document.tokens.slice(call.closeIndex + 1, value.end + 1).map((token) => token.value);
    if (outputShape(kind, suffix)) return true;
  }
  const reference = pythonExpressionReference(value);
  const root = reference?.[0] ?? (value.tokens[0]?.kind === "identifier" ? value.tokens[0].value : undefined);
  if (!root) return false;
  const kind = responseKindForName(context, root, useIndex, aliasDepth + 1, seen);
  return Boolean(kind && outputShape(kind, values.slice(1)));
}

function llmText(
  context: PythonAnalysisContext,
  value: PythonExpression | undefined,
  useIndex: number,
  seen: ReadonlySet<string> = new Set(),
  aliasDepth = 0,
): boolean {
  if (!value || aliasDepth > 2) return false;
  const unwrapped = unwrapPythonExpression(value);
  if (isKnownHtmlSanitizer(context, unwrapped, useIndex)) return false;

  const directCall = directCallExpression(context, unwrapped);
  if (directCall) {
    if (!callPreservesLlmTaint(context, directCall)) return false;
    return directCall.arguments.some((candidate) =>
      !candidate.spread && llmText(context, candidate.expression, directCall.startIndex, seen, aliasDepth)
    );
  }
  if (directSdkOutput(context, unwrapped, useIndex, aliasDepth, seen)) return true;

  const nestedCalls = callsWithinExpression(context, unwrapped);
  const sanitizerRanges = nestedCalls.flatMap((call) => {
    const callValue = expressionFromTokens(context.document.tokens.slice(call.startIndex, call.closeIndex + 1));
    return isKnownHtmlSanitizer(context, callValue, useIndex)
      ? [{ start: call.startIndex, end: call.closeIndex }]
      : [];
  });
  const opaqueCallRanges = nestedCalls.flatMap((call) => {
    const knownSanitizer = sanitizerRanges.some((range) =>
      range.start === call.startIndex && range.end === call.closeIndex
    );
    return !knownSanitizer && !callPreservesLlmTaint(context, call)
      ? [{ start: call.startIndex, end: call.closeIndex }]
      : [];
  });
  const values = unwrapped.tokens.map((token) => token.value);
  for (let index = 0; index < unwrapped.tokens.length; index++) {
    const token = unwrapped.tokens[index]!;
    if (
      token.kind !== "identifier" || unwrapped.tokens[index - 1]?.value === "." ||
      [...sanitizerRanges, ...opaqueCallRanges].some((range) =>
        token.index >= range.start && token.index <= range.end
      )
    ) continue;
    const kind = responseKindForName(context, token.value, useIndex, aliasDepth + 1, seen);
    if (kind && outputShape(kind, values.slice(index + 1))) return true;
    for (const nested of reachingAssignments(context, token.value, useIndex)) {
      const key = `${nested.scopeId ?? "module"}:${nested.tokenIndex}:${token.value}`;
      if (seen.has(key)) continue;
      const nextSeen = new Set(seen);
      nextSeen.add(key);
      if (llmText(context, nested.expression, nested.tokenIndex, nextSeen, aliasDepth + 1)) return true;
    }
  }

  const reference = pythonExpressionReference(unwrapped);
  if (!reference || reference.length !== 1) return false;
  const name = reference[0]!;
  return reachingAssignments(context, name, useIndex).some((assignment) => {
    const key = `${assignment.scopeId ?? "module"}:${assignment.tokenIndex}:${name}`;
    if (seen.has(key)) return false;
    const nextSeen = new Set(seen);
    nextSeen.add(key);
    return llmText(context, assignment.expression, assignment.tokenIndex, nextSeen, aliasDepth + 1);
  });
}

const TAINT_PRESERVING_HTML_TRANSFORMS = new Set([
  "django.utils.safestring.mark_safe",
  "markdown.markdown",
  "markdown2.markdown",
  "markupsafe.Markup",
]);

const HTML_SANITIZER_ORIGINS = new Set([
  "bleach.clean",
  "html.escape",
  "markupsafe.escape",
  "nh3.clean",
]);

const FLASK_JSON_ORIGINS = new Set([
  "flask.json.jsonify",
  "flask.jsonify",
]);

const FLASK_RESPONSE_ORIGINS = new Set([
  "flask.Response",
  "flask.make_response",
  "flask.wrappers.Response",
]);

function callPreservesLlmTaint(context: PythonAnalysisContext, call: PythonCall): boolean {
  const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
  return TAINT_PRESERVING_HTML_TRANSFORMS.has(origin) || HTML_SANITIZER_ORIGINS.has(origin);
}

function mappingStaticString(
  value: PythonExpression | undefined,
  key: string,
): string | undefined {
  const unwrapped = unwrapPythonExpression(value);
  if (
    unwrapped.tokens[0]?.value !== "{" || unwrapped.tokens.at(-1)?.value !== "}" ||
    unwrapped.tokens[0]?.pairIndex !== unwrapped.tokens.at(-1)?.index
  ) return undefined;
  for (const item of splitPythonTopLevel(unwrapped.tokens.slice(1, -1))) {
    let depth = 0;
    let colon = -1;
    for (let index = 0; index < item.tokens.length; index++) {
      const token = item.tokens[index]!;
      if (["(", "[", "{"].includes(token.value)) depth++;
      else if ([")", "]", "}"].includes(token.value)) depth--;
      else if (depth === 0 && token.value === ":") colon = index;
    }
    if (colon <= 0) continue;
    const itemKey = staticString(expressionFromTokens(item.tokens.slice(0, colon)));
    if (itemKey?.toLowerCase() !== key.toLowerCase()) continue;
    return staticString(expressionFromTokens(item.tokens.slice(colon + 1)));
  }
  return undefined;
}

function htmlMediaType(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  const normalized = value.split(";", 1)[0]?.trim().toLowerCase();
  return normalized === "text/html" || normalized === "application/xhtml+xml";
}

function exactHtmlMediaType(
  context: PythonAnalysisContext,
  call: PythonCall,
): boolean | undefined {
  const media = argument(call, -1, "media_type", "content_type", "mimetype");
  if (media) return htmlMediaType(staticString(media));

  const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
  const positionalHeaders = origin === "flask.make_response"
    ? 1
    : [
        "flask.Response",
        "flask.wrappers.Response",
        "starlette.responses.Response",
        "fastapi.Response",
        "fastapi.responses.Response",
      ].includes(origin)
      ? 2
      : -1;
  const headers = argument(call, positionalHeaders, "headers")?.expression;
  return htmlMediaType(mappingStaticString(headers, "content-type"));
}

function responseContent(
  context: PythonAnalysisContext,
  call: PythonCall,
): PythonExpression | undefined {
  if (hasSpreadArgument(call)) return undefined;
  const origin = resolveCallOrigin(context, call);
  if (["starlette.responses.HTMLResponse", "fastapi.responses.HTMLResponse"].some((expected) => originEquals(origin, expected))) {
    return argument(call, 0, "content")?.expression;
  }
  if (["starlette.responses.Response", "fastapi.Response", "fastapi.responses.Response"].some((expected) => originEquals(origin, expected))) {
    return exactHtmlMediaType(context, call) === true ? argument(call, 0, "content")?.expression : undefined;
  }
  if (["flask.Response", "flask.wrappers.Response", "flask.make_response"].some((expected) => originEquals(origin, expected))) {
    return exactHtmlMediaType(context, call) === false ? undefined : argument(call, 0, "response", "content")?.expression;
  }
  if (["django.http.HttpResponse", "django.http.response.HttpResponse"].some((expected) => originEquals(origin, expected))) {
    return exactHtmlMediaType(context, call) === false ? undefined : argument(call, 0, "content")?.expression;
  }
  return undefined;
}

function responseFindings(context: PythonAnalysisContext): Array<{ line: number }> {
  const output: Array<{ line: number }> = [];
  for (const call of context.calls) {
    const content = responseContent(context, call);
    if (content && llmText(context, content, call.startIndex)) output.push({ line: call.line });
  }
  return output;
}

function flaskReturnFindings(context: PythonAnalysisContext): Array<{ line: number }> {
  const output: Array<{ line: number }> = [];
  for (const statement of context.statements) {
    if (statement.tokens[0]?.value !== "return") continue;
    const scope = functionAt(context, statement.start);
    if (!scope || functionRouteFramework(context, scope) !== "flask") continue;
    const returned = expressionFromTokens(statement.tokens.slice(1));
    const unwrapped = unwrapPythonExpression(returned);
    const directCall = directCallExpression(context, unwrapped);
    const directOrigin = directCall ? resolveCallOrigin(context, directCall)?.join(".") ?? "" : "";
    if (directCall && (FLASK_JSON_ORIGINS.has(directOrigin) || FLASK_RESPONSE_ORIGINS.has(directOrigin))) {
      continue;
    }
    if (
      ["{", "["].includes(unwrapped.tokens[0]?.value ?? "") &&
      unwrapped.tokens[0]?.pairIndex === unwrapped.tokens.at(-1)?.index
    ) continue;

    const tuple = splitPythonTopLevel(unwrapped.tokens);
    const content = tuple.length > 1 ? tuple[0] : unwrapped;
    if (!content) continue;
    if (
      ["{", "["].includes(content.tokens[0]?.value ?? "") &&
      content.tokens[0]?.pairIndex === content.tokens.at(-1)?.index
    ) continue;
    const tupleMediaType = tuple.slice(1)
      .map((item) => htmlMediaType(mappingStaticString(item, "content-type")))
      .find((item) => item !== undefined);
    if (tupleMediaType === false) continue;
    if (llmText(context, content, statement.start)) output.push({ line: statement.line });
  }
  return output;
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PYTHON_LLM_OUTPUT_DANGEROUS_HTML_RULE_ID,
    title: "LLM output reaches a dangerous HTML response",
    severity: "high",
    cwe: ["CWE-79", "CWE-116"],
    owasp_web: ["A03:2021"],
    owasp_llm: ["LLM05:2025"],
    file,
    startLine: line,
    snippet: "LLM-generated text reaches an HTML response without recognized sanitization [VALUE REDACTED]",
    message: "Text from a proven OpenAI or Anthropic response reaches an HTML-rendering response surface without a recognized HTML sanitizer.",
    remediation: {
      summary: "Return model output as data or plain text, or sanitize it for the exact HTML context before rendering.",
      steps: [
        "Prefer JSONResponse or PlainTextResponse when the model output does not need to be HTML.",
        "If HTML is required, sanitize with a maintained allowlist sanitizer and keep dangerous URL and attribute protocols disabled.",
        "Do not assume Markdown conversion makes untrusted model output safe HTML.",
      ],
      references: [
        "CWE-79",
        "CWE-116",
        "https://www.starlette.io/responses/",
        "https://flask.palletsprojects.com/en/stable/quickstart/#about-responses",
        "https://github.com/openai/openai-python",
        "https://github.com/anthropics/anthropic-sdk-python",
      ],
    },
    confidence: "high",
  });
}

export async function runPythonLlmOutputDangerousHtml(
  input: PythonProjectInput,
): Promise<Finding[]> {
  const project = await resolvePythonProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const context = analyzePythonDocument(document);
    for (const candidate of [...responseFindings(context), ...flaskReturnFindings(context)]) {
      findings.push(finding(document.path, candidate.line));
    }
  }
  return uniqueFindingsByLocation(findings);
}
