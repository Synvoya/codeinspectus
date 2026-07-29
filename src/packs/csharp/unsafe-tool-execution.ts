/**
 * Exact official OpenAI .NET tool arguments reaching an actually-started shell process.
 * Analysis is intrafile, source ordered, and bounded to direct aliases, one parsing
 * helper, and one local command wrapper.
 */

import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";
import { resolveCsharpProject, type CsharpProjectInput } from "./project.js";

export const CSHARP_UNSAFE_TOOL_EXECUTION_RULE_ID =
  "ci-csharp-llm-tool-argument-command-execution";

const MAX_BALANCED_CHARS = 64_000;
const CONTROL_NAMES = new Set(["if", "for", "foreach", "while", "switch", "catch", "using", "lock"]);

interface MethodSpan {
  name: string;
  params: string[];
  toolParams: string[];
  start: number;
  bodyStart: number;
  end: number;
}

interface Assignment {
  name: string;
  rhs: string;
  start: number;
}

interface ShellSink {
  start: number;
  value: string;
}

interface CommandWrapper {
  name: string;
  paramIndex: number;
  sink: ShellSink;
}

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Preserve offsets and string contents while removing comments. Raw strings fail closed. */
function maskCsharpComments(input: string): { source: string; valid: boolean } {
  const chars = [...input];
  let mode: "normal" | "verbatim" | "char" | undefined;
  let escaped = false;
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    const next = chars[index + 1];
    if (!mode && (char === '$' || char === '"')) {
      const raw = input.slice(index).match(/^(\$*)("{3,})/);
      if (raw) {
        const delimiter = raw[2]!;
        const contentStart = index + raw[0].length;
        const close = input.indexOf(delimiter, contentStart);
        if (close < 0) return { source: chars.join(""), valid: false };
        for (let cursor = index; cursor < close + delimiter.length; cursor++) {
          if (chars[cursor] !== "\n" && chars[cursor] !== "\r") chars[cursor] = " ";
        }
        index = close + delimiter.length - 1;
        continue;
      }
    }
    if (mode === "normal" || mode === "char") {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if ((mode === "normal" && char === '"') || (mode === "char" && char === "'")) mode = undefined;
      else if ((char === "\n" || char === "\r") && mode === "normal") return { source: chars.join(""), valid: false };
      continue;
    }
    if (mode === "verbatim") {
      if (char === '"' && next === '"') index++;
      else if (char === '"') mode = undefined;
      continue;
    }
    if (char === "'" ) {
      mode = "char";
      continue;
    }
    if (char === '@' && next === '"' || char === '$' && next === '@' && chars[index + 2] === '"' || char === '@' && next === '$' && chars[index + 2] === '"') {
      if (char !== '@') index++;
      if (chars[index + 1] === '$') index++;
      mode = "verbatim";
      continue;
    }
    if (char === '$' && next === '"') {
      index++;
      mode = "normal";
      continue;
    }
    if (char === '"') {
      mode = "normal";
      continue;
    }
    if (char === "/" && next === "/") {
      chars[index] = chars[index + 1] = " ";
      index += 2;
      while (index < chars.length && chars[index] !== "\n") chars[index++] = " ";
      index--;
      continue;
    }
    if (char === "/" && next === "*") {
      chars[index] = chars[index + 1] = " ";
      index += 2;
      let closed = false;
      while (index < chars.length) {
        if (chars[index] === "*" && chars[index + 1] === "/") {
          chars[index] = chars[index + 1] = " ";
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
  return { source: chars.join(""), valid: mode === undefined };
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
  const output: string[] = [];
  let start = 0;
  let round = 0;
  let square = 0;
  let curly = 0;
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
    else if (char === "," && round === 0 && square === 0 && curly === 0) {
      output.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  output.push(value.slice(start).trim());
  return output;
}

function methods(source: string): MethodSpan[] {
  const output: MethodSpan[] = [];
  const pattern = /(?:^|[;}])\s*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|unsafe|partial|new|extern)\s+)*(?:[A-Za-z_]\w*(?:\s*[<\[?.,>]\s*|\s+)?)+\s+([A-Za-z_]\w*)\s*\(([^()]*)\)\s*(?:where\b[^\{]+)?\{/gm;
  for (const match of source.matchAll(pattern)) {
    const name = match[1]!;
    if (CONTROL_NAMES.has(name)) continue;
    const bodyStart = (match.index ?? 0) + match[0].lastIndexOf("{");
    const close = balancedClose(source, bodyStart, "{", "}");
    if (close === undefined) continue;
    const declarations = splitTopLevel(match[2] ?? "");
    const params = declarations.map((parameter) =>
      parameter.replace(/=.*/s, "").trim().match(/([A-Za-z_]\w*)\s*$/)?.[1]
    ).filter((value): value is string => Boolean(value));
    const toolParams = declarations.map((parameter) =>
      parameter.replace(/=.*/s, "").trim()
        .match(/\b(?:OpenAI\.Chat\.)?ChatToolCall\s*\??\s+([A-Za-z_]\w*)\s*$/)?.[1]
    ).filter((value): value is string => Boolean(value));
    output.push({ name, params, toolParams, start: match.index ?? 0, bodyStart, end: close + 1 });
  }
  return output.sort((left, right) => left.start - right.start);
}

function assignments(source: string, offset = 0): Assignment[] {
  const output: Assignment[] = [];
  const declaration = /(?:^|[;{}]\s*|\n\s*)(?:var|[A-Za-z_][\w.<>?,\[\]]*)\s+([A-Za-z_]\w*)\s*=\s*([^;]{1,65536});/gm;
  for (const match of source.matchAll(declaration)) {
    const rhs = match[2]?.trim();
    if (rhs) output.push({
      name: match[1]!,
      rhs,
      start: offset + (match.index ?? 0) + match[0].indexOf(match[1]!),
    });
  }
  return output;
}

function references(value: string): Set<string> {
  return new Set([...value.matchAll(/\b[A-Za-z_]\w*\b/g)].map((match) => match[0]));
}

function referencesAny(value: string, names: ReadonlySet<string>): boolean {
  for (const name of references(value)) if (names.has(name)) return true;
  return false;
}

function directAliasExpression(value: string, names: ReadonlySet<string>): boolean {
  for (const name of names) {
    const escaped = escapeRe(name);
    if (new RegExp(`^\\s*(?:\\([^)]*\\)\\s*)?${escaped}\\s*!?\\s*(?:\\.\\s*ToString\\s*\\(\\s*\\))?\\s*$`).test(value)) {
      return true;
    }
  }
  return false;
}

function exactOpenAiEvidence(source: string): boolean {
  return /^\s*using\s+OpenAI\.Chat\s*;/m.test(source) || /\bOpenAI\.Chat\.ChatToolCall\b/.test(source);
}

function diagnosticsEvidence(source: string): { process: string; processInfo: string } | undefined {
  if (/^\s*using\s+System\.Diagnostics\s*;/m.test(source)) {
    return { process: "(?:System\\.Diagnostics\\.)?Process", processInfo: "(?:System\\.Diagnostics\\.)?ProcessStartInfo" };
  }
  if (/\bSystem\.Diagnostics\.(?:Process|ProcessStartInfo)\b/.test(source)) {
    return { process: "System\\.Diagnostics\\.Process", processInfo: "System\\.Diagnostics\\.ProcessStartInfo" };
  }
  return undefined;
}

function toolVariables(source: string, initial: Iterable<string> = []): Set<string> {
  const output = new Set(initial);
  for (const match of source.matchAll(/\b(?:OpenAI\.Chat\.)?ChatToolCall\s+([A-Za-z_]\w*)\b/g)) output.add(match[1]!);
  for (const assignment of assignments(source)) {
    if (/\b(?:ToolCalls|toolCalls)\s*\[/.test(assignment.rhs)) output.add(assignment.name);
  }
  return output;
}

function sourceExpression(value: string, tools: ReadonlySet<string>): boolean {
  for (const tool of tools) {
    if (new RegExp(`\\b${escapeRe(tool)}\\s*\\.\\s*FunctionArguments\\b`).test(value)) return true;
  }
  return false;
}

function parserExpression(
  value: string,
  tainted: ReadonlySet<string>,
  tools: ReadonlySet<string>,
): boolean {
  return /(?:System\.Text\.Json\.)?JsonSerializer\s*\.\s*Deserialize\s*</.test(value) &&
    (referencesAny(value, tainted) || sourceExpression(value, tools));
}

function commandExtraction(value: string, parsed: ReadonlySet<string>): boolean {
  for (const name of parsed) {
    const escaped = escapeRe(name);
    if (new RegExp(`\\b${escaped}\\s*\\[\\s*[\"'](?:command|cmd|script)[\"']\\s*\\]`, "i").test(value)) return true;
    if (new RegExp(`\\b${escaped}\\s*\\.\\s*RootElement\\s*\\.\\s*GetProperty\\(\\s*[\"'](?:command|cmd|script)[\"']\\s*\\)`, "i").test(value)) return true;
  }
  return false;
}

function parserWrappers(source: string, methodSpans: readonly MethodSpan[]): Map<string, number> {
  const output = new Map<string, number>();
  for (const method of methodSpans) {
    const body = source.slice(method.bodyStart + 1, method.end - 1);
    for (let index = 0; index < method.params.length; index++) {
      const parameter = method.params[index]!;
      if (!new RegExp(`JsonSerializer\\s*\\.\\s*Deserialize[\\s\\S]{0,1024}\\b${escapeRe(parameter)}\\b`).test(body)) continue;
      if (/return\s+[\s\S]{0,512}(?:\[\s*["'](?:command|cmd|script)["']\s*\]|GetProperty\(\s*["'](?:command|cmd|script)["']\s*\))/i.test(body)) {
        output.set(method.name, index);
      }
    }
  }
  return output;
}

function literal(value: string): string | undefined {
  const trimmed = value.trim();
  const match = trimmed.match(/^(?:@)?"([^"\r\n]*)"$/);
  return match?.[1]?.replace(/""/g, '"');
}

function shellKind(value: string): "unix" | "cmd" | "powershell" | undefined {
  const lower = value.replace(/\\/g, "/").split("/").at(-1)?.toLowerCase();
  if (["sh", "bash", "zsh", "dash", "ksh"].includes(lower ?? "")) return "unix";
  if (["cmd", "cmd.exe"].includes(lower ?? "")) return "cmd";
  if (["powershell", "powershell.exe", "pwsh", "pwsh.exe"].includes(lower ?? "")) return "powershell";
  return undefined;
}

function shellArguments(kind: "unix" | "cmd" | "powershell", value: string, tainted: ReadonlySet<string>): boolean {
  if (!referencesAny(value, tainted)) return false;
  const compact = value.replace(/\\"/g, '"');
  if (kind === "unix") return /["']\s*-c(?:\s|["'])/i.test(compact);
  if (kind === "cmd") return /["']\s*\/c(?:\s|["'])/i.test(compact);
  return /["']\s*-(?:c|command)(?:\s|["'])/i.test(compact);
}

function processInfoAssignments(
  source: string,
  offset: number,
  processInfoPattern: string,
): Map<string, { start: number; executable: string; arguments: string }> {
  const output = new Map<string, { start: number; executable: string; arguments: string }>();
  for (const assignment of assignments(source, offset)) {
    if (!new RegExp(`^new\\s+${processInfoPattern}\\b`).test(assignment.rhs)) continue;
    const executableExpression = assignment.rhs.match(/\bFileName\s*=\s*((?:@)?"[^"\r\n]*")/s)?.[1];
    const argumentsExpression = assignment.rhs.match(/\bArguments\s*=\s*([\s\S]+?)(?=,\s*[A-Za-z_]\w*\s*=|}\s*$)/)?.[1];
    const executable = executableExpression ? literal(executableExpression) : undefined;
    if (executable && argumentsExpression) {
      output.set(assignment.name, { start: assignment.start, executable, arguments: argumentsExpression.trim() });
    }
  }
  return output;
}

function calls(source: string, pattern: RegExp, offset: number): Array<{ start: number; args: string }> {
  const output: Array<{ start: number; args: string }> = [];
  for (const match of source.matchAll(pattern)) {
    const openIndex = (match.index ?? 0) + match[0].lastIndexOf("(");
    const close = balancedClose(source, openIndex, "(", ")");
    if (close === undefined) continue;
    output.push({ start: offset + (match.index ?? 0), args: source.slice(openIndex + 1, close) });
  }
  return output;
}

function shellSinks(
  source: string,
  offset: number,
  diagnostics: { process: string; processInfo: string },
  tainted: ReadonlySet<string>,
): ShellSink[] {
  const output: ShellSink[] = [];
  const infos = processInfoAssignments(source, offset, diagnostics.processInfo);
  const processCalls = calls(source, new RegExp(`\\b${diagnostics.process}\\s*\\.\\s*Start\\s*\\(`, "g"), offset);
  for (const call of processCalls) {
    const args = splitTopLevel(call.args);
    if (args.length === 1) {
      const info = infos.get(args[0]?.trim() ?? "");
      if (info) {
        const kind = shellKind(info.executable);
        if (kind && shellArguments(kind, info.arguments, tainted)) {
          output.push({ start: info.start, value: info.arguments });
        }
        continue;
      }
      const direct = args[0]?.match(new RegExp(`^new\\s+${diagnostics.processInfo}\\s*\\((.*)\\)$`, "s"));
      if (direct) {
        const constructor = splitTopLevel(direct[1] ?? "");
        const executable = constructor[0] ? literal(constructor[0]) : undefined;
        const kind = executable ? shellKind(executable) : undefined;
        if (kind && constructor[1] && shellArguments(kind, constructor[1], tainted)) {
          output.push({ start: call.start, value: constructor[1] });
        }
      }
    } else if (args.length >= 2) {
      const executable = literal(args[0] ?? "");
      const kind = executable ? shellKind(executable) : undefined;
      if (kind && shellArguments(kind, args[1] ?? "", tainted)) {
        output.push({ start: call.start, value: args[1]! });
      }
    }
  }
  return output;
}

function hasTerminatingGuard(sourceBeforeSink: string, value: string): boolean {
  const names = [...references(value)];
  for (const name of names) {
    const escaped = escapeRe(name);
    const patterns = [
      new RegExp(`if\\s*\\([^)]*!\\s*(?:approved|authorized|confirmed|allowed)\\b[^)]*\\)\\s*(?:\\{[\\s\\S]{0,256})?(?:return\\b|throw\\b)`, "i"),
      new RegExp(`if\\s*\\([^)]*!\\s*[A-Za-z_]\\w*\\s*\\.\\s*Contains\\s*\\(\\s*${escaped}\\s*\\)[^)]*\\)\\s*(?:\\{[\\s\\S]{0,256})?(?:return\\b|throw\\b)`, "i"),
    ];
    if (patterns.some((pattern) => pattern.test(sourceBeforeSink))) return true;
  }
  return false;
}

function commandWrappers(
  source: string,
  methodsFound: readonly MethodSpan[],
  diagnostics: { process: string; processInfo: string },
): CommandWrapper[] {
  const output: CommandWrapper[] = [];
  for (const method of methodsFound) {
    const body = source.slice(method.bodyStart + 1, method.end - 1);
    for (let index = 0; index < method.params.length; index++) {
      const parameter = method.params[index]!;
      const tainted = new Set([parameter]);
      for (const sink of shellSinks(body, method.bodyStart + 1, diagnostics, tainted)) {
        const before = source.slice(method.bodyStart + 1, sink.start);
        if (!hasTerminatingGuard(before, sink.value)) output.push({ name: method.name, paramIndex: index, sink });
      }
    }
  }
  return output;
}

function scopeTaint(
  source: string,
  parserMethods: ReadonlyMap<string, number>,
  initialTools: Iterable<string> = [],
): { tainted: Set<string>; parsed: Set<string> } {
  const tools = toolVariables(source, initialTools);
  const tainted = new Set<string>();
  const parsed = new Set<string>();
  const values = assignments(source);
  for (let pass = 0; pass < values.length + 2; pass++) {
    let changed = false;
    for (const assignment of values) {
      if (sourceExpression(assignment.rhs, tools) || directAliasExpression(assignment.rhs, tainted)) {
        if (!tainted.has(assignment.name)) {
          tainted.add(assignment.name);
          changed = true;
        }
      }
      if (parserExpression(assignment.rhs, tainted, tools)) {
        if (!parsed.has(assignment.name)) {
          parsed.add(assignment.name);
          changed = true;
        }
      }
      if (commandExtraction(assignment.rhs, parsed)) {
        if (!tainted.has(assignment.name)) {
          tainted.add(assignment.name);
          changed = true;
        }
      }
      for (const [name, paramIndex] of parserMethods) {
        const call = assignment.rhs.match(new RegExp(`^${escapeRe(name)}\\s*\\((.*)\\)$`, "s"));
        if (call) {
          const args = splitTopLevel(call[1] ?? "");
          if (args[paramIndex] && (sourceExpression(args[paramIndex]!, tools) || referencesAny(args[paramIndex]!, tainted))) {
            if (!tainted.has(assignment.name)) {
              tainted.add(assignment.name);
              changed = true;
            }
          }
        }
      }
    }
    if (!changed) break;
  }
  return { tainted, parsed };
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < source.length; cursor++) if (source[cursor] === "\n") line++;
  return line;
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: CSHARP_UNSAFE_TOOL_EXECUTION_RULE_ID,
    title: "C# model-produced tool argument reaches shell execution",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-78", "CWE-1426"],
    owasp_llm: ["LLM05:2025", "LLM06:2025"],
    file,
    startLine: line,
    snippet: "Model-produced tool argument reaches a C# shell sink [VALUE REDACTED]",
    message: "An official OpenAI .NET model-produced tool argument reaches an actually-started Process shell without a visible checked approval, allowlist, or validated replacement value. This is bounded repository evidence; verify runtime sandboxing and authorization manually.",
    remediation: {
      summary: "Treat model tool arguments as untrusted; map fixed tool names to server-owned C# actions and avoid shell command strings.",
      steps: [
        "Deserialize tool arguments into a strict type and map an allowlisted action identifier to server-owned behavior.",
        "Require human approval before process execution and reject when approval infrastructure is unavailable.",
        "Use ProcessStartInfo with a fixed executable and separated, validated ArgumentList values, without a shell interpreter.",
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
  const masked = maskCsharpComments(input);
  if (!masked.valid || !exactOpenAiEvidence(masked.source)) return [];
  const diagnostics = diagnosticsEvidence(masked.source);
  if (!diagnostics) return [];
  const methodSpans = methods(masked.source);
  const parserMethods = parserWrappers(masked.source, methodSpans);
  const wrappers = commandWrappers(masked.source, methodSpans, diagnostics);
  const output = new Map<number, Finding>();

  const scopes: Array<{ source: string; offset: number; tools: string[] }> = [];
  const topLevel = [...masked.source];
  for (const method of methodSpans) {
    for (let index = method.start; index < method.end; index++) {
      if (topLevel[index] !== "\n" && topLevel[index] !== "\r") topLevel[index] = " ";
    }
    scopes.push({
      source: masked.source.slice(method.bodyStart + 1, method.end - 1),
      offset: method.bodyStart + 1,
      tools: method.toolParams,
    });
  }
  scopes.push({ source: topLevel.join(""), offset: 0, tools: [] });

  for (const scope of scopes) {
    const { tainted } = scopeTaint(scope.source, parserMethods, scope.tools);
    if (tainted.size === 0) continue;
    for (const sink of shellSinks(scope.source, scope.offset, diagnostics, tainted)) {
      const before = masked.source.slice(scope.offset, sink.start);
      if (!hasTerminatingGuard(before, sink.value)) output.set(sink.start, finding(path, lineOf(masked.source, sink.start)));
    }
    const tools = toolVariables(scope.source, scope.tools);
    for (const wrapper of wrappers) {
      for (const call of calls(scope.source, new RegExp(`\\b${escapeRe(wrapper.name)}\\s*\\(`, "g"), scope.offset)) {
        const args = splitTopLevel(call.args);
        const argument = args[wrapper.paramIndex];
        if (argument && (referencesAny(argument, tainted) || sourceExpression(argument, tools))) {
          const before = masked.source.slice(scope.offset, call.start);
          if (!hasTerminatingGuard(before, argument)) output.set(wrapper.sink.start, finding(path, lineOf(masked.source, wrapper.sink.start)));
        }
      }
    }
  }
  return [...output.entries()].sort(([left], [right]) => left - right).map(([, value]) => value);
}

export async function runCsharpUnsafeToolExecution(input: CsharpProjectInput): Promise<Finding[]> {
  const project = await resolveCsharpProject(input);
  return project.files.flatMap((document) => analyzeDocument(document.path, document.content));
}
