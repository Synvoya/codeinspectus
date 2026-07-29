/**
 * Exact official OpenAI Java tool arguments reaching an actually-started shell process.
 * Analysis is intrafile, source ordered, and bounded to direct aliases, one parsing
 * helper, and one local command wrapper.
 */

import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";
import { resolveJavaProject, type JavaProjectInput } from "./project.js";

export const JAVA_UNSAFE_TOOL_EXECUTION_RULE_ID =
  "ci-java-llm-tool-argument-command-execution";

const MAX_BALANCED_CHARS = 64_000;

interface MethodSpan {
  name: string;
  params: string[];
  paramTypes: Map<string, string>;
  start: number;
  bodyStart: number;
  end: number;
}

interface Assignment {
  name: string;
  type?: string;
  rhs: string;
  start: number;
  expressionStart: number;
  end: number;
}

interface ShellSink {
  start: number;
  value: string;
}

interface ParserWrapper {
  name: string;
  paramIndex: number;
}

interface CommandWrapper {
  method: MethodSpan;
  paramIndex: number;
  sink: ShellSink;
}

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Mask comments without moving offsets; fail closed on malformed strings/comments. */
function maskJavaComments(input: string): { source: string; valid: boolean } {
  const chars = [...input];
  let quote: '"' | "'" | undefined;
  let escaped = false;
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    const next = chars[index + 1];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      else if (char === "\n" || char === "\r") return { source: chars.join(""), valid: false };
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "/" && next === "/") {
      chars[index] = " ";
      chars[index + 1] = " ";
      index += 2;
      while (index < chars.length && chars[index] !== "\n") chars[index++] = " ";
      index--;
      continue;
    }
    if (char === "/" && next === "*") {
      chars[index] = " ";
      chars[index + 1] = " ";
      index += 2;
      let closed = false;
      while (index < chars.length) {
        if (chars[index] === "*" && chars[index + 1] === "/") {
          chars[index] = " ";
          chars[index + 1] = " ";
          index++;
          closed = true;
          break;
        }
        if (chars[index] !== "\n" && chars[index] !== "\r") chars[index] = " ";
        index++;
      }
      if (!closed) return { source: chars.join(""), valid: false };
    }
  }
  return { source: chars.join(""), valid: quote === undefined };
}

function balancedClose(source: string, open: number, left: string, right: string): number | undefined {
  if (source[open] !== left) return undefined;
  let depth = 0;
  let quote: '"' | "'" | undefined;
  let escaped = false;
  const limit = Math.min(source.length, open + MAX_BALANCED_CHARS);
  for (let index = open; index < limit; index++) {
    const char = source[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === left) depth++;
    else if (char === right && --depth === 0) return index;
  }
  return undefined;
}

function splitTopLevel(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let round = 0;
  let square = 0;
  let curly = 0;
  let angle = 0;
  let quote: '"' | "'" | undefined;
  let escaped = false;
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === "(") round++;
    else if (char === ")") round--;
    else if (char === "[") square++;
    else if (char === "]") square--;
    else if (char === "{") curly++;
    else if (char === "}") curly--;
    else if (char === "<") angle++;
    else if (char === ">" && angle > 0) angle--;
    else if (char === "," && round === 0 && square === 0 && curly === 0 && angle === 0) {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

function parameters(value: string): Array<{ name: string; type: string }> {
  return splitTopLevel(value).flatMap((part) => {
    const cleaned = part.replace(/@[A-Za-z_$][\w$]*(?:\([^)]*\))?/g, " ")
      .replace(/\bfinal\b/g, " ").trim();
    const name = cleaned.match(/([A-Za-z_$][\w$]*)\s*(?:\[\s*\])?\s*$/)?.[1];
    if (!name) return [];
    const type = cleaned.slice(0, cleaned.lastIndexOf(name)).trim().replace(/\s+/g, "");
    return type ? [{ name, type }] : [];
  });
}

function methods(source: string): MethodSpan[] {
  const output: MethodSpan[] = [];
  const pattern = /^[ \t]*(?:(?:public|private|protected|static|final|synchronized|native|abstract)\s+)*(?:<[^>{}]+>\s+)?[A-Za-z_$][\w$.[\]<>?,]*\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws\s+[^\r\n{]+)?\s*\{/gm;
  for (const match of source.matchAll(pattern)) {
    const start = match.index ?? 0;
    const bodyStart = start + match[0].lastIndexOf("{");
    const end = balancedClose(source, bodyStart, "{", "}");
    if (end === undefined) continue;
    const parsedParameters = parameters(match[2] ?? "");
    output.push({
      name: match[1]!,
      params: parsedParameters.map((parameter) => parameter.name),
      paramTypes: new Map(parsedParameters.map((parameter) => [parameter.name, parameter.type])),
      start,
      bodyStart,
      end,
    });
  }
  return output;
}

function expressionEnd(source: string, start: number, methodEnd: number): number {
  let round = 0;
  let square = 0;
  let curly = 0;
  let quote: '"' | "'" | undefined;
  let escaped = false;
  for (let index = start; index < Math.min(methodEnd, start + 32_000); index++) {
    const char = source[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === "(") round++;
    else if (char === ")") round--;
    else if (char === "[") square++;
    else if (char === "]") square--;
    else if (char === "{") curly++;
    else if (char === "}") {
      if (curly === 0) return index;
      curly--;
    } else if (char === ";" && round === 0 && square === 0 && curly === 0) return index;
  }
  return Math.min(methodEnd, start + 32_000);
}

function assignments(source: string, method: MethodSpan): Assignment[] {
  const output: Assignment[] = [];
  const body = source.slice(method.bodyStart + 1, method.end);
  const declarations = /(?:^|[;{}\n])\s*(?:final\s+)?([A-Za-z_$][\w$.[\]<>?,]*)\s+([A-Za-z_$][\w$]*)\s*=\s*/gm;
  for (const match of body.matchAll(declarations)) {
    const expressionStart = method.bodyStart + 1 + (match.index ?? 0) + match[0].length;
    const end = expressionEnd(source, expressionStart, method.end);
    output.push({
      name: match[2]!,
      type: match[1],
      rhs: source.slice(expressionStart, end).trim(),
      start: method.bodyStart + 1 + (match.index ?? 0),
      expressionStart,
      end,
    });
  }
  return output.sort((left, right) => left.start - right.start);
}

function imports(source: string): Set<string> {
  return new Set([...source.matchAll(/\bimport\s+(?:static\s+)?([\w$.]+(?:\.\*)?)\s*;/g)].map((match) => match[1]!));
}

function officialOpenAiImports(source: string): Set<string> {
  return new Set([...imports(source)].filter((path) => path.startsWith("com.openai.")));
}

function shadowedOfficialTypes(source: string): boolean {
  return /\b(?:class|interface|record|enum)\s+(?:ChatCompletionMessageToolCall|ResponseFunctionToolCall)\b/.test(source);
}

function declaredTypes(source: string, method: MethodSpan, values: readonly Assignment[]): Map<string, string> {
  const output = new Map(method.paramTypes);
  for (const assignment of values) if (assignment.type) output.set(assignment.name, assignment.type);
  const body = source.slice(method.bodyStart + 1, method.end);
  for (const match of body.matchAll(/\bfor\s*\(\s*(?:final\s+)?([A-Za-z_$][\w$.[\]<>?,]*)\s+([A-Za-z_$][\w$]*)\s*:/g)) {
    output.set(match[2]!, match[1]!);
  }
  return output;
}

function toolCallType(type: string | undefined): boolean {
  return Boolean(type && /(?:^|\.)(?:ChatCompletionMessageToolCall|ResponseFunctionToolCall)$/.test(type));
}

function functionType(type: string | undefined, officialImports: ReadonlySet<string>): boolean {
  if (!type) return false;
  if (/(?:^|\.)ChatCompletionMessageToolCall\.Function$/.test(type)) return true;
  return type === "Function" && [...officialImports].some((path) => path.endsWith("ChatCompletionMessageToolCall.Function"));
}

function references(value: string): Set<string> {
  return new Set([...value.matchAll(/\b([A-Za-z_$][\w$]*)\b/g)].map((match) => match[1]!));
}

function modelArgumentsExpression(
  value: string,
  toolCalls: ReadonlySet<string>,
  functions: ReadonlySet<string>,
): boolean {
  for (const name of functions) {
    if (new RegExp(String.raw`\b${escapeRe(name)}\s*\.\s*arguments\s*\(`).test(value)) return true;
  }
  for (const name of toolCalls) {
    if (new RegExp(String.raw`\b${escapeRe(name)}\s*\.\s*(?:asFunction\s*\(\s*\)\s*\.\s*)?function\s*\(\s*\)\s*\.\s*arguments\s*\(`).test(value)) return true;
  }
  return false;
}

function parserWrappers(source: string, methodSpans: readonly MethodSpan[]): ParserWrapper[] {
  const output: ParserWrapper[] = [];
  for (const method of methodSpans) {
    if (!/(?:extract|parse|decode|deserialize|read)/i.test(method.name)) continue;
    const body = source.slice(method.bodyStart + 1, method.end);
    for (let index = 0; index < method.params.length; index++) {
      const parameter = method.params[index]!;
      const usedByReturn = [...body.matchAll(/\breturn\s+([^;]+);/g)]
        .some((match) => references(match[1] ?? "").has(parameter));
      const usedByParser = new RegExp(String.raw`(?:readValue|readTree|fromJson|substring|replace|charAt|indexOf)\s*\([^;]{0,1000}\b${escapeRe(parameter)}\b|\b${escapeRe(parameter)}\s*\.\s*(?:substring|replace|charAt|indexOf|contains)\s*\(`).test(body);
      if (usedByReturn || usedByParser) {
        output.push({ name: method.name, paramIndex: index });
        break;
      }
    }
  }
  return output;
}

function invocationArguments(value: string, name: string): string[][] {
  const output: string[][] = [];
  const pattern = new RegExp(String.raw`\b${escapeRe(name)}\s*\(`, "g");
  for (const match of value.matchAll(pattern)) {
    const open = (match.index ?? 0) + match[0].lastIndexOf("(");
    const close = balancedClose(value, open, "(", ")");
    if (close !== undefined) output.push(splitTopLevel(value.slice(open + 1, close)).map((part) => part.trim()));
  }
  return output;
}

function javaString(value: string): string | undefined {
  const match = value.trim().match(/^"((?:\\.|[^"\\])*)"$/s);
  if (!match) return undefined;
  return match[1]!.replace(/\\([\\"'])/g, "$1").replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t");
}

function unwrapCommandArguments(value: string): string[] {
  let trimmed = value.trim();
  const array = trimmed.match(/^new\s+String\s*\[\s*\]\s*\{([\s\S]*)\}$/);
  if (array) trimmed = array[1]!;
  const collection = trimmed.match(/^(?:List\.of|Arrays\.asList)\s*\(([\s\S]*)\)$/);
  if (collection) trimmed = collection[1]!;
  return splitTopLevel(trimmed).map((part) => part.trim());
}

function shellValue(value: string): string | undefined {
  const args = unwrapCommandArguments(value);
  const shell = javaString(args[0] ?? "")?.toLowerCase();
  if (!shell) return undefined;
  const unix = new Set(["sh", "/bin/sh", "bash", "/bin/bash", "dash", "zsh", "ksh"]);
  const cmd = new Set(["cmd", "cmd.exe"]);
  const powershell = new Set(["powershell", "powershell.exe", "pwsh", "pwsh.exe"]);
  let flagIndex = -1;
  if (unix.has(shell)) flagIndex = args.findIndex((arg, index) => index > 0 && javaString(arg)?.toLowerCase() === "-c");
  else if (cmd.has(shell)) flagIndex = args.findIndex((arg, index) => index > 0 && javaString(arg)?.toLowerCase() === "/c");
  else if (powershell.has(shell)) {
    flagIndex = args.findIndex((arg, index) => index > 0 && ["-c", "-command"].includes(javaString(arg)?.toLowerCase() ?? ""));
  }
  return flagIndex >= 1 && flagIndex + 1 < args.length ? args[flagIndex + 1] : undefined;
}

function processBuilderStarted(
  source: string,
  method: MethodSpan,
  values: readonly Assignment[],
  callStart: number,
  callEnd: number,
): boolean {
  if (/^\s*(?:\.[A-Za-z_$][\w$]*\s*\([^;]{0,500}\)\s*)*\.\s*start\s*\(/.test(source.slice(callEnd + 1, Math.min(method.end, callEnd + 1_000)))) {
    return true;
  }
  const owner = values.find((assignment) => callStart >= assignment.expressionStart && callStart <= assignment.end);
  if (!owner) return false;
  return new RegExp(String.raw`\b${escapeRe(owner.name)}\s*\.\s*(?:[A-Za-z_$][\w$]*\s*\([^;]*\)\s*\.\s*)*start\s*\(`)
    .test(source.slice(owner.end, method.end));
}

function shellSinks(source: string, method: MethodSpan, values: readonly Assignment[]): ShellSink[] {
  const output: ShellSink[] = [];
  const body = source.slice(method.bodyStart + 1, method.end);
  for (const match of body.matchAll(/\bnew\s+ProcessBuilder\s*\(/g)) {
    const start = method.bodyStart + 1 + (match.index ?? 0);
    const open = start + match[0].lastIndexOf("(");
    const close = balancedClose(source, open, "(", ")");
    if (close === undefined || !processBuilderStarted(source, method, values, start, close)) continue;
    const value = shellValue(source.slice(open + 1, close));
    if (value) output.push({ start, value });
  }
  for (const match of body.matchAll(/\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/g)) {
    const start = method.bodyStart + 1 + (match.index ?? 0);
    const open = start + match[0].lastIndexOf("(");
    const close = balancedClose(source, open, "(", ")");
    if (close === undefined) continue;
    const value = shellValue(source.slice(open + 1, close));
    if (value) output.push({ start, value });
  }
  return output.sort((left, right) => left.start - right.start);
}

function hasTerminatingGuard(prefix: string, value: string): boolean {
  const candidates = [...references(value)];
  for (const candidate of candidates) {
    const name = escapeRe(candidate);
    const guardConditions = [
      String.raw`!\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:is)?(?:approved|authorized|confirmed|permitted|allowed)\s*(?:\(\s*${name}\b[^)]*\))?`,
      String.raw`!\s*(?:(?:allow|permit|safe|approved|authorized)[\w$]*|[A-Za-z_$][\w$]*(?:allow|permit|safe|approved|authorized)[\w$]*)\s*\.\s*contains\s*\(\s*${name}\s*\)`,
      String.raw`!\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:isAllowed|isPermitted|approve|authorize|confirm)\s*\([^)]*\b${name}\b[^)]*\)`,
    ];
    for (const condition of guardConditions) {
      const guarded = new RegExp(
        String.raw`\bif\s*\(\s*(?:${condition})\s*\)\s*(?:\{[\s\S]{0,1200}?\b(?:return|throw)\b|\b(?:return|throw)\b)`,
        "i",
      );
      if (guarded.test(prefix)) return true;
    }
  }
  return false;
}

function commandWrappers(
  source: string,
  methodSpans: readonly MethodSpan[],
): CommandWrapper[] {
  const output: CommandWrapper[] = [];
  for (const method of methodSpans) {
    const values = assignments(source, method);
    for (const sink of shellSinks(source, method, values)) {
      const used = references(sink.value);
      const paramIndex = method.params.findIndex((parameter) => used.has(parameter));
      if (paramIndex < 0) continue;
      if (hasTerminatingGuard(source.slice(method.bodyStart + 1, sink.start), sink.value)) continue;
      output.push({ method, paramIndex, sink });
    }
  }
  return output;
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < source.length; cursor++) if (source[cursor] === "\n") line++;
  return line;
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: JAVA_UNSAFE_TOOL_EXECUTION_RULE_ID,
    title: "Java model-produced tool argument reaches shell execution",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-78", "CWE-1426"],
    owasp_llm: ["LLM05:2025", "LLM06:2025"],
    file,
    startLine: line,
    snippet: "Model-produced tool argument reaches a Java shell sink [VALUE REDACTED]",
    message:
      "An official OpenAI Java model-produced tool argument reaches an actually-started ProcessBuilder or Runtime shell execution without a visible checked approval, allowlist, or validated replacement value. This is bounded repository evidence; verify runtime sandboxing and authorization manually.",
    remediation: {
      summary: "Treat model tool arguments as untrusted; map fixed tool names to server-owned Java actions and avoid shell command strings.",
      steps: [
        "Deserialize tool arguments into a strict schema and map an allowlisted action identifier to server-owned behavior.",
        "Require human approval before process execution and reject when approval infrastructure is unavailable.",
        "Use ProcessBuilder with a fixed executable and separated, validated arguments, without a shell interpreter.",
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

function analyzeDocument(path: string, input: string): Finding[] {
  const masked = maskJavaComments(input);
  if (!masked.valid) return [];
  const source = masked.source;
  const officialImports = officialOpenAiImports(source);
  if (officialImports.size === 0 || shadowedOfficialTypes(source)) return [];
  const methodSpans = methods(source);
  const parsers = parserWrappers(source, methodSpans);
  const wrappers = commandWrappers(source, methodSpans);
  const findings: Finding[] = [];
  const emitted = new Set<number>();

  for (const method of methodSpans) {
    const values = assignments(source, method);
    const types = declaredTypes(source, method, values);
    const toolCalls = new Set([...types].filter(([, type]) => toolCallType(type)).map(([name]) => name));
    const functions = new Set([...types].filter(([, type]) => functionType(type, officialImports)).map(([name]) => name));
    for (let pass = 0; pass < 2; pass++) {
      for (const assignment of values) {
        if (toolCalls.has(assignment.name) || functions.has(assignment.name)) continue;
        for (const toolCall of toolCalls) {
          if (new RegExp(String.raw`\b${escapeRe(toolCall)}\s*\.\s*(?:asFunction\s*\(\s*\)\s*\.\s*)?function\s*\(\s*\)`).test(assignment.rhs)) {
            functions.add(assignment.name);
          }
        }
      }
    }

    const tainted = new Set<string>();
    const expressionTainted = (value: string, depth = 0): boolean => {
      if (modelArgumentsExpression(value, toolCalls, functions)) return true;
      if ([...references(value)].some((name) => tainted.has(name))) return true;
      if (depth >= 2) return false;
      return parsers.some((parser) => invocationArguments(value, parser.name)
        .some((args) => expressionTainted(args[parser.paramIndex] ?? "", depth + 1)));
    };

    const events = [
      ...values.map((assignment) => ({ kind: "assignment" as const, start: assignment.start, assignment })),
      ...shellSinks(source, method, values).map((sink) => ({ kind: "sink" as const, start: sink.start, sink })),
    ].sort((left, right) => left.start - right.start || (left.kind === "assignment" ? -1 : 1));

    for (const event of events) {
      if (event.kind === "assignment") {
        if (expressionTainted(event.assignment.rhs)) tainted.add(event.assignment.name);
        for (const wrapper of wrappers) {
          for (const args of invocationArguments(event.assignment.rhs, wrapper.method.name)) {
            if (!expressionTainted(args[wrapper.paramIndex] ?? "")) continue;
            if (hasTerminatingGuard(source.slice(method.bodyStart + 1, event.assignment.start), args[wrapper.paramIndex] ?? "")) continue;
            if (!emitted.has(wrapper.sink.start)) {
              emitted.add(wrapper.sink.start);
              findings.push(finding(path, lineOf(source, wrapper.sink.start)));
            }
          }
        }
        continue;
      }
      if (!expressionTainted(event.sink.value)) continue;
      if (hasTerminatingGuard(source.slice(method.bodyStart + 1, event.sink.start), event.sink.value)) continue;
      if (!emitted.has(event.sink.start)) {
        emitted.add(event.sink.start);
        findings.push(finding(path, lineOf(source, event.sink.start)));
      }
    }

    const body = source.slice(method.bodyStart + 1, method.end);
    for (const wrapper of wrappers) {
      const calls = invocationArguments(body, wrapper.method.name);
      for (const args of calls) {
        if (!expressionTainted(args[wrapper.paramIndex] ?? "")) continue;
        const relativeCall = body.indexOf(`${wrapper.method.name}(`);
        const callStart = relativeCall >= 0 ? method.bodyStart + 1 + relativeCall : method.bodyStart + 1;
        if (hasTerminatingGuard(source.slice(method.bodyStart + 1, callStart), args[wrapper.paramIndex] ?? "")) continue;
        if (!emitted.has(wrapper.sink.start)) {
          emitted.add(wrapper.sink.start);
          findings.push(finding(path, lineOf(source, wrapper.sink.start)));
        }
      }
    }
  }
  return findings;
}

export async function runJavaUnsafeToolExecution(input: JavaProjectInput): Promise<Finding[]> {
  const project = await resolveJavaProject(input);
  return project.files.flatMap((document) => analyzeDocument(document.path, document.content));
}
