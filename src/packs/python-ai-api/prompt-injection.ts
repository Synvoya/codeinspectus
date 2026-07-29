import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  expressionContainsRequest,
  hasSpreadArgument,
  originEquals,
  resolveCallOrigin,
  uniqueFindingsByLocation,
  unwrapPythonExpression,
  type PythonAnalysisContext,
} from "./analysis.js";
import type { PythonArgument, PythonCall, PythonExpression } from "../python/python.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_PROMPT_INJECTION_SINK_RULE_ID =
  "ci-python-prompt-injection-sink";

type LlmCallKind = "openai-responses" | "anthropic-messages";

function llmCallKind(
  context: PythonAnalysisContext,
  call: PythonCall,
): LlmCallKind | undefined {
  const origin = resolveCallOrigin(context, call);
  if ([
    "openai.responses.create",
    "openai.OpenAI.responses.create",
    "openai.AsyncOpenAI.responses.create",
  ].some((expected) => originEquals(origin, expected))) return "openai-responses";
  if ([
    "anthropic.Anthropic.messages.create",
    "anthropic.AsyncAnthropic.messages.create",
  ].some((expected) => originEquals(origin, expected))) return "anthropic-messages";
  return undefined;
}

function requestControlled(
  context: PythonAnalysisContext,
  value: PythonExpression | undefined,
  useIndex: number,
): boolean {
  return expressionContainsRequest(context, value, useIndex);
}

function staticallyEmptyCollection(value: PythonExpression): boolean {
  const unwrapped = unwrapPythonExpression(value);
  const first = unwrapped.tokens[0];
  const last = unwrapped.tokens.at(-1);
  return Boolean(
    first && last && unwrapped.tokens.length === 2 &&
    ((first.value === "[" && last.value === "]") ||
      (first.value === "(" && last.value === ")") ||
      (first.value === "{" && last.value === "}")) &&
    first.pairIndex === last.index,
  );
}

function toolAccessConfigured(value: PythonArgument | undefined): boolean {
  if (!value || value.spread) return false;
  const unwrapped = unwrapPythonExpression(value.expression);
  if (unwrapped.tokens.length === 1 && unwrapped.tokens[0]?.value === "None") return false;
  return !staticallyEmptyCollection(unwrapped);
}

function finding(
  file: string,
  line: number,
  hasTools: boolean,
  requestInSystemPosition: boolean,
): Finding {
  const severity = hasTools ? "high" : "medium";
  const position = requestInSystemPosition
    ? "the system/instructions position"
    : "an LLM input with tool access";
  return makeAiFinding({
    ruleId: PYTHON_PROMPT_INJECTION_SINK_RULE_ID,
    title: hasTools
      ? "Potential Python prompt-injection sink with tool access"
      : "Potential Python prompt-injection sink in system instructions",
    severity,
    cwe: ["CWE-1427"],
    owasp_llm: hasTools ? ["LLM01:2025", "LLM06:2025"] : ["LLM01:2025"],
    file,
    startLine: line,
    snippet: `Request input reaches ${position} [VALUE REDACTED]`,
    message: hasTools
      ? "Web request input reaches a proven OpenAI or Anthropic LLM prompt while the same call configures non-empty or dynamic tool access. A successful injection may influence tool selection or arguments; verify the trust boundary and tool permissions manually."
      : "Web request input reaches the system or instructions position of a proven OpenAI or Anthropic LLM call. It can override server instructions; verify whether callers are intentionally authorized to control this prompt.",
    remediation: {
      summary: "Keep request-controlled content out of privileged instructions and constrain every model-invoked tool.",
      steps: [
        "Keep server policy in a fixed system/instructions value and place request content in a separate user/input field.",
        "Validate request fields against the application's intended task boundary instead of accepting arbitrary instructions.",
        "Use an explicit minimal tool allowlist, authorize every tool call server-side, and require confirmation for sensitive actions.",
      ],
      references: [
        "CWE-1427",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
      ],
    },
    confidence: "medium",
  });
}

/**
 * Detect request input in privileged prompt positions, or in an LLM input that
 * shares a proven OpenAI/Anthropic call with configured tool access.
 */
export async function runPythonPromptInjectionSink(
  input: PythonProjectInput,
): Promise<Finding[]> {
  const project = await resolvePythonProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const context = analyzePythonDocument(document);
    for (const call of context.calls) {
      const kind = llmCallKind(context, call);
      if (!kind || hasSpreadArgument(call)) continue;

      const systemValue = argument(
        call,
        -1,
        kind === "openai-responses" ? "instructions" : "system",
      )?.expression;
      const inputValue = argument(
        call,
        -1,
        kind === "openai-responses" ? "input" : "messages",
      )?.expression;
      const tools = argument(call, -1, "tools", "functions");
      const hasTools = toolAccessConfigured(tools);
      const requestInSystemPosition = requestControlled(
        context,
        systemValue,
        call.startIndex,
      );
      const requestInInput = requestControlled(context, inputValue, call.startIndex);

      if (!requestInSystemPosition && !(hasTools && requestInInput)) continue;
      findings.push(finding(
        document.path,
        call.line,
        hasTools,
        requestInSystemPosition,
      ));
    }
  }
  return uniqueFindingsByLocation(findings);
}
