import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  callsWithinExpression,
  expressionIdentifierRoots,
  expressionReferencesName,
  functionAt,
  hasDominatingGuard,
  hasSpreadArgument,
  originEquals,
  resolveCallOrigin,
  staticBoolean,
  tokenValues,
  uniqueFindingsByLocation,
  type PythonAnalysisContext,
  type PythonFunctionScope,
  type PythonStatementContext,
} from "./analysis.js";
import type { PythonCall, PythonExpression, PythonToken } from "../python/python.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_UNSAFE_TOOL_EXECUTION_RULE_ID =
  "ci-python-llm-tool-argument-command-execution";

interface NamedFact {
  name: string;
  scopeId?: number;
  index: number;
}

interface WrapperFlow {
  fn: PythonFunctionScope;
  sink: PythonCall;
  paramIndex: number;
}

const LLM_CALL_ORIGINS = new Set([
  "openai.OpenAI.chat.completions.create",
  "openai.AsyncOpenAI.chat.completions.create",
  "openai.OpenAI.responses.create",
  "openai.AsyncOpenAI.responses.create",
  "anthropic.Anthropic.messages.create",
  "anthropic.AsyncAnthropic.messages.create",
]);

const SUBPROCESS_SHELL_ORIGINS = new Set([
  "subprocess.run",
  "subprocess.call",
  "subprocess.check_call",
  "subprocess.check_output",
  "subprocess.Popen",
]);

const INHERENT_SHELL_ORIGINS = new Set([
  "os.system",
  "os.popen",
  "subprocess.getoutput",
  "subprocess.getstatusoutput",
  "asyncio.create_subprocess_shell",
]);

function scopeIdAt(context: PythonAnalysisContext, index: number): number | undefined {
  return functionAt(context, index)?.id;
}

function visibleFacts(
  facts: readonly NamedFact[],
  context: PythonAnalysisContext,
  useIndex: number,
): Set<string> {
  const scopeId = scopeIdAt(context, useIndex);
  const local = facts.filter((fact) => fact.scopeId === scopeId && fact.index < useIndex);
  const localNames = new Set(local.map((fact) => fact.name));
  for (const fact of facts) {
    if (fact.scopeId === undefined && fact.index < useIndex && !localNames.has(fact.name)) {
      localNames.add(fact.name);
    }
  }
  return localNames;
}

function addFact(facts: NamedFact[], fact: NamedFact): boolean {
  if (facts.some((candidate) =>
    candidate.name === fact.name && candidate.scopeId === fact.scopeId && candidate.index === fact.index
  )) return false;
  facts.push(fact);
  return true;
}

function valuesContainInOrder(values: readonly string[], expected: readonly string[]): boolean {
  let cursor = 0;
  for (const value of values) {
    if (value === expected[cursor]) cursor++;
    if (cursor === expected.length) return true;
  }
  return false;
}

function isModelToolCollection(expression: PythonExpression): boolean {
  const values = tokenValues(expression);
  const openAi = valuesContainInOrder(values, ["choices", "message", "tool_calls"]) ||
    valuesContainInOrder(values, ["choices", "message", "function_call"]) ||
    valuesContainInOrder(values, ["output"]);
  const anthropic = values.includes("content") &&
    expression.tokens.some((token) => token.kind === "string" && token.staticString === "tool_use");
  return openAi || anthropic;
}

function forLoop(statement: PythonStatementContext): {
  target: string;
  iterable: PythonExpression;
} | undefined {
  const values = statement.tokens;
  if (values[0]?.value !== "for" || values[1]?.kind !== "identifier") return undefined;
  const inIndex = values.findIndex((token, index) => index > 1 && token.value === "in");
  const colon = values.findIndex((token, index) => index > inIndex && token.value === ":");
  if (inIndex < 0 || colon < 0) return undefined;
  const tokens = values.slice(inIndex + 1, colon);
  return {
    target: values[1]!.value,
    iterable: {
      tokens,
      start: tokens[0]?.index ?? -1,
      end: tokens.at(-1)?.index ?? -1,
    },
  };
}

function memberPathFromRoot(
  expression: PythonExpression,
  roots: ReadonlySet<string>,
  expected: readonly string[],
): boolean {
  const tokens = expression.tokens;
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index]?.kind !== "identifier" || !roots.has(tokens[index]!.value)) continue;
    let cursor = index + 1;
    let matched = 0;
    while (cursor < tokens.length && matched < expected.length) {
      if (tokens[cursor]?.value !== "." || tokens[cursor + 1]?.value !== expected[matched]) break;
      matched++;
      cursor += 2;
    }
    if (matched === expected.length) return true;
  }
  return false;
}

function isModelArgumentExpression(
  context: PythonAnalysisContext,
  expression: PythonExpression | undefined,
  useIndex: number,
  toolObjects: readonly NamedFact[],
): boolean {
  if (!expression) return false;
  const roots = visibleFacts(toolObjects, context, useIndex);
  if (
    memberPathFromRoot(expression, roots, ["function", "arguments"]) ||
    memberPathFromRoot(expression, roots, ["arguments"]) ||
    memberPathFromRoot(expression, roots, ["input"])
  ) return true;
  const values = tokenValues(expression);
  return (
    valuesContainInOrder(values, ["choices", "message", "tool_calls", "function", "arguments"]) ||
    valuesContainInOrder(values, ["choices", "message", "function_call", "arguments"]) ||
    valuesContainInOrder(values, ["output", "arguments"])
  );
}

function validatedReplacement(context: PythonAnalysisContext, expression: PythonExpression): boolean {
  return callsWithinExpression(context, expression).some((call) => {
    const name = call.reference.at(-1) ?? "";
    if (["loads", "load"].includes(name)) return false;
    return /(?:validate|sanitize|allowlist|approved|safe|model_validate|parse_obj)/i.test(name);
  });
}

function collectFacts(context: PythonAnalysisContext): {
  toolObjects: NamedFact[];
  tainted: NamedFact[];
  approvals: NamedFact[];
} {
  const collections: NamedFact[] = [];
  const toolObjects: NamedFact[] = [];
  const tainted: NamedFact[] = [];
  const approvals: NamedFact[] = [];

  for (const assignment of context.assignments) {
    if (!assignment.name) continue;
    if (isModelToolCollection(assignment.expression)) {
      addFact(collections, {
        name: assignment.name,
        scopeId: assignment.scopeId,
        index: assignment.tokenIndex,
      });
      const values = tokenValues(assignment.expression);
      if (values.includes("function_call") || values.lastIndexOf("tool_calls") < values.lastIndexOf("[")) {
        addFact(toolObjects, {
          name: assignment.name,
          scopeId: assignment.scopeId,
          index: assignment.tokenIndex,
        });
      }
    }
  }

  for (const statement of context.statements) {
    const loop = forLoop(statement);
    if (!loop) continue;
    const collectionNames = visibleFacts(collections, context, statement.start);
    if (
      expressionReferencesName(loop.iterable, collectionNames) ||
      isModelToolCollection(loop.iterable)
    ) {
      addFact(toolObjects, {
        name: loop.target,
        scopeId: scopeIdAt(context, statement.start),
        index: statement.start,
      });
    }
  }

  let changed = true;
  let passes = 0;
  while (changed && passes++ < 6) {
    changed = false;
    for (const assignment of context.assignments) {
      if (!assignment.name || validatedReplacement(context, assignment.expression)) continue;
      const visibleTaint = visibleFacts(tainted, context, assignment.tokenIndex);
      const source = isModelArgumentExpression(
        context,
        assignment.expression,
        assignment.tokenIndex,
        toolObjects,
      );
      if (!source && !expressionReferencesName(assignment.expression, visibleTaint)) continue;
      changed = addFact(tainted, {
        name: assignment.name,
        scopeId: assignment.scopeId,
        index: assignment.tokenIndex,
      }) || changed;
    }
  }

  for (const assignment of context.assignments) {
    if (!assignment.name) continue;
    const call = callsWithinExpression(context, assignment.expression).find((candidate) =>
      candidate.startIndex === assignment.expression.start
    );
    if (!call || !/(?:approve|confirm|authorize|allow|permit)/i.test(call.reference.at(-1) ?? "")) {
      continue;
    }
    const visibleTaint = visibleFacts(tainted, context, assignment.tokenIndex);
    if (!call.arguments.some((candidate) =>
      expressionReferencesName(candidate.expression, visibleTaint) ||
      isModelArgumentExpression(context, candidate.expression, assignment.tokenIndex, toolObjects)
    )) continue;
    approvals.push({
      name: assignment.name,
      scopeId: assignment.scopeId,
      index: assignment.tokenIndex,
    });
  }
  return { toolObjects, tainted, approvals };
}

function shellSink(context: PythonAnalysisContext, call: PythonCall): boolean {
  if (hasSpreadArgument(call)) return false;
  const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
  if (INHERENT_SHELL_ORIGINS.has(origin)) return true;
  return SUBPROCESS_SHELL_ORIGINS.has(origin) && staticBoolean(argument(call, -1, "shell")) === true;
}

function guarded(
  context: PythonAnalysisContext,
  sink: PythonCall,
  expression: PythonExpression,
  facts: ReturnType<typeof collectFacts>,
  extraTaint: ReadonlySet<string> = new Set(),
): boolean {
  const tainted = visibleFacts(facts.tainted, context, sink.startIndex);
  for (const name of extraTaint) tainted.add(name);
  const used = new Set(expressionIdentifierRoots(expression).filter((name) => tainted.has(name)));
  const approvals = visibleFacts(facts.approvals, context, sink.startIndex);
  if (!used.size && !approvals.size) return false;

  const mentions = (tokens: readonly PythonToken[], names: ReadonlySet<string>) =>
    tokens.some((token, index) =>
      token.kind === "identifier" && names.has(token.value) && tokens[index - 1]?.value !== "."
    );
  const values = (tokens: readonly PythonToken[]) => tokens.map((token) => token.value);
  return hasDominatingGuard(context, sink.startIndex, {
    positive: (condition) => {
      const conditionValues = values(condition);
      return (
        mentions(condition, approvals) ||
        mentions(condition, used) && conditionValues.includes("in") &&
          condition.some((token) => /(?:allow|safe|permit)/i.test(token.value))
      );
    },
    rejecting: (condition) => {
      const conditionValues = values(condition);
      if (conditionValues.includes("not") && mentions(condition, approvals)) return true;
      if (!mentions(condition, used)) return false;
      if (conditionValues.includes("not") && conditionValues.includes("in")) return true;
      return condition.some((token) => /(?:approve|confirm|authorize|allow|validate|permit)/i.test(token.value)) &&
        conditionValues.includes("not");
    },
  });
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PYTHON_UNSAFE_TOOL_EXECUTION_RULE_ID,
    title: "Python model-produced tool argument reaches shell execution",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-78", "CWE-1426"],
    owasp_llm: ["LLM05:2025", "LLM06:2025"],
    file,
    startLine: line,
    snippet: "Model-produced tool argument reaches a Python shell sink [VALUE REDACTED]",
    message:
      "A model-produced tool/function argument reaches a proven Python shell-execution API without a visible checked approval, allowlist, or validated replacement value. This is bounded repository evidence; verify runtime sandboxing and authorization manually.",
    remediation: {
      summary:
        "Treat model tool arguments as untrusted; map fixed tool names to server-owned actions and avoid shell command strings.",
      steps: [
        "Validate tool arguments with a strict schema and an explicit server-owned allowlist.",
        "Require human approval before command execution and reject when approval infrastructure is unavailable.",
        "Prefer subprocess calls with shell=False, a fixed executable, and a separated argument list.",
        "Run allowed actions in an isolated least-privilege sandbox with bounded filesystem and network access.",
      ],
      references: [
        "CWE-78",
        "CWE-1426",
        "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
        "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
      ],
    },
  });
}

function wrapperFlows(
  context: PythonAnalysisContext,
  sinks: readonly PythonCall[],
  facts: ReturnType<typeof collectFacts>,
): WrapperFlow[] {
  const output: WrapperFlow[] = [];
  for (const fn of context.functions) {
    for (const sink of sinks.filter((candidate) => functionAt(context, candidate.startIndex)?.id === fn.id)) {
      const sinkValue = argument(sink, 0)?.expression;
      if (!sinkValue) continue;
      const roots = new Set(expressionIdentifierRoots(sinkValue));
      const paramIndex = fn.parameters.findIndex((parameter) => roots.has(parameter.name));
      if (paramIndex < 0) continue;
      const parameter = fn.parameters[paramIndex]!.name;
      if (guarded(context, sink, sinkValue, facts, new Set([parameter]))) continue;
      output.push({ fn, sink, paramIndex });
    }
  }
  return output;
}

/** Detect model tool arguments reaching proven Python shell execution. */
export async function runPythonUnsafeToolExecution(
  input: PythonProjectInput,
): Promise<Finding[]> {
  const project = await resolvePythonProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const context = analyzePythonDocument(document);
    if (!context.calls.some((call) => LLM_CALL_ORIGINS.has(resolveCallOrigin(context, call)?.join(".") ?? ""))) {
      continue;
    }
    const sinks = context.calls.filter((call) => shellSink(context, call));
    if (!sinks.length) continue;
    const facts = collectFacts(context);
    const emitted = new Set<number>();

    for (const sink of sinks) {
      const value = argument(sink, 0)?.expression;
      if (!value) continue;
      const tainted = visibleFacts(facts.tainted, context, sink.startIndex);
      if (
        !expressionReferencesName(value, tainted) &&
        !isModelArgumentExpression(context, value, sink.startIndex, facts.toolObjects)
      ) continue;
      if (guarded(context, sink, value, facts)) continue;
      findings.push(finding(document.path, sink.line));
      emitted.add(sink.startIndex);
    }

    for (const flow of wrapperFlows(context, sinks, facts)) {
      for (const call of context.calls) {
        if (call.reference.length !== 1 || call.reference[0] !== flow.fn.name) continue;
        if (call.startIndex >= flow.fn.start && call.startIndex <= flow.fn.end) continue;
        const value = argument(call, flow.paramIndex)?.expression;
        if (!value) continue;
        const tainted = visibleFacts(facts.tainted, context, call.startIndex);
        if (
          !expressionReferencesName(value, tainted) &&
          !isModelArgumentExpression(context, value, call.startIndex, facts.toolObjects)
        ) continue;
        if (guarded(context, call, value, facts)) continue;
        if (!emitted.has(flow.sink.startIndex)) {
          findings.push(finding(document.path, flow.sink.line));
          emitted.add(flow.sink.startIndex);
        }
      }
    }
  }
  return uniqueFindingsByLocation(findings);
}
