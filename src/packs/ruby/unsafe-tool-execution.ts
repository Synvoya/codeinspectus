/** Bounded official OpenAI Ruby tool arguments reaching Ruby command-execution sinks. */

import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";
import { resolveRubyProject, type RubyProjectInput } from "./project.js";

export const RUBY_UNSAFE_TOOL_EXECUTION_RULE_ID =
  "ci-ruby-llm-tool-argument-command-execution";

const MAX_BALANCED_CHARS = 64_000;
const RESPONSE_TOOL_CALL_TYPE = "OpenAI::Models::Responses::ResponseFunctionToolCall";

interface FunctionSpan {
  name: string;
  params: string[];
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

/** Preserve offsets and ordinary strings while removing Ruby comments. Heredocs fail closed. */
function maskRubyComments(input: string): { source: string; valid: boolean } {
  if (/<<[-~]?\s*['"]?[A-Za-z_]\w*['"]?/.test(input)) return { source: input, valid: false };
  const chars = [...input];
  let blockComment = false;
  let offset = 0;
  for (const line of input.match(/.*(?:\r?\n|$)/g)?.filter(Boolean) ?? []) {
    const startsBlock = /^=begin\b/.test(line);
    const endsBlock = /^=end\b/.test(line);
    if (!blockComment && startsBlock) blockComment = true;
    if (blockComment) {
      for (let index = offset; index < offset + line.length; index++) {
        if (chars[index] !== "\n" && chars[index] !== "\r") chars[index] = " ";
      }
    }
    if (blockComment && endsBlock) blockComment = false;
    offset += line.length;
  }
  if (blockComment) return { source: chars.join(""), valid: false };

  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
    } else if (char === "'" || char === '"') {
      quote = char;
    } else if (char === "#") {
      chars[index] = " ";
      index++;
      while (index < chars.length && chars[index] !== "\n" && chars[index] !== "\r") chars[index++] = " ";
      index--;
    }
  }
  return { source: chars.join(""), valid: quote === undefined };
}

function balancedClose(source: string, open: number, left: string, right: string): number | undefined {
  if (source[open] !== left) return undefined;
  let depth = 0;
  let quote: "'" | '"' | undefined;
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
    if (char === "'" || char === '"') quote = char;
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
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"') quote = char;
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

function maskRubyStrings(value: string): string {
  const chars = [...value];
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      if (char !== "\n" && char !== "\r") chars[index] = " ";
    } else if (char === "'" || char === '"') {
      quote = char;
      chars[index] = " ";
    }
  }
  return chars.join("");
}

function blockDelta(line: string): number {
  const value = maskRubyStrings(line);
  let starts = 0;
  if (/^\s*(?:def|class|module|if|unless|case|begin|while|until|for)\b/.test(value)) starts++;
  if (/=\s*(?:if|unless|case|begin)\b/.test(value)) starts++;
  if (/\bdo\b/.test(value) && !/^\s*(?:while|until|for)\b[^;]*\bdo\b/.test(value)) starts++;
  const ends = [...value.matchAll(/\bend\b/g)].length;
  return starts - ends;
}

function parameterNames(value: string): string[] {
  return splitTopLevel(value).flatMap((parameter) => {
    const normalized = parameter.replace(/=.*/s, "").replace(/^\*\*?|^&/, "").trim();
    const match = /^([a-z_]\w*)\s*:?[!?=]?$/.exec(normalized);
    return match?.[1] ? [match[1]] : [];
  });
}

function functions(source: string): FunctionSpan[] {
  const lines = source.match(/.*(?:\r?\n|$)/g)?.filter(Boolean) ?? [];
  const starts: number[] = [];
  let offset = 0;
  for (const line of lines) {
    starts.push(offset);
    offset += line.length;
  }
  const output: FunctionSpan[] = [];
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = maskRubyStrings(lines[lineIndex]!);
    const signature = /^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?=]?)\s*(?:\(([^)]*)\)|([^;\r\n]*))?/.exec(line);
    if (!signature) continue;
    let depth = 0;
    let closeLine: number | undefined;
    for (let candidate = lineIndex; candidate < lines.length; candidate++) {
      depth += blockDelta(lines[candidate]!);
      if (depth === 0) {
        closeLine = candidate;
        break;
      }
    }
    if (closeLine === undefined || closeLine === lineIndex) continue;
    const start = starts[lineIndex]!;
    const bodyStart = start + lines[lineIndex]!.length;
    output.push({
      name: signature[1]!,
      params: parameterNames(signature[2] ?? signature[3] ?? ""),
      start,
      bodyStart,
      end: starts[closeLine]!,
    });
    lineIndex = closeLine;
  }
  return output;
}

function assignments(source: string, offset = 0): Assignment[] {
  const output: Assignment[] = [];
  const pattern = /^\s*(@{0,2}[a-z_]\w*)\s*=\s*(?![=>])([^;\r\n]{1,65536})/gm;
  for (const match of source.matchAll(pattern)) {
    const rhs = match[2]?.trim();
    if (rhs) output.push({ name: match[1]!, rhs, start: offset + (match.index ?? 0) });
  }
  return output;
}

function references(value: string): Set<string> {
  return new Set([...value.matchAll(/(?<![A-Za-z0-9_])@{0,2}[a-z_]\w*/g)].map((match) => match[0]));
}

function referencesAny(value: string, names: ReadonlySet<string>): boolean {
  for (const name of references(value)) if (names.has(name)) return true;
  return false;
}

function directAliasExpression(value: string, names: ReadonlySet<string>): boolean {
  return [...names].some((name) => new RegExp(`^\\s*${escapeRe(name)}\\s*$`).test(value));
}

function typedResponseItems(source: string): Set<string> {
  const output = new Set<string>();
  const type = escapeRe(RESPONSE_TOOL_CALL_TYPE);
  for (const match of maskRubyStrings(source).matchAll(new RegExp(`\\b([a-z_]\\w*)\\s*\\.\\s*is_a\\?\\s*\\(\\s*${type}\\s*\\)`, "g"))) {
    if (match[1]) output.add(match[1]);
  }
  return output;
}

function sourceExpression(value: string, responseItems: ReadonlySet<string>): boolean {
  for (const quoted of value.matchAll(/"(?:[^"\\]|\\.)*"/gs)) {
    for (const match of quoted[0].matchAll(/#\{([^{}]{1,4096})\}/g)) {
      let slashes = 0;
      for (let index = (match.index ?? 0) - 1; index >= 0 && quoted[0][index] === "\\"; index--) slashes++;
      if (slashes % 2 === 1) continue;
      const interpolation = match[1] ?? "";
      if (/\b@{0,2}[a-z_]\w*\s*(?:\.|&\.)\s*function\s*(?:\.|&\.)\s*arguments\b/.test(interpolation)) return true;
      if ([...responseItems].some((name) =>
        new RegExp(`\\b${escapeRe(name)}\\s*(?:\\.|&\\.)\\s*arguments\\b`).test(interpolation)
      )) return true;
    }
  }
  const code = maskRubyStrings(value);
  if (/\b@{0,2}[a-z_]\w*\s*(?:\.|&\.)\s*function\s*(?:\.|&\.)\s*arguments\b/.test(code)) return true;
  return [...responseItems].some((name) =>
    new RegExp(`\\b${escapeRe(name)}\\s*(?:\\.|&\\.)\\s*arguments\\b`).test(code)
  );
}

function jsonParseExpression(
  value: string,
  tainted: ReadonlySet<string>,
  responseItems: ReadonlySet<string>,
): boolean {
  const call = /^JSON\s*\.\s*parse\s*\((.*)\)$/s.exec(value);
  if (!call) return false;
  const first = splitTopLevel(call[1] ?? "")[0];
  return first !== undefined && (sourceExpression(first, responseItems) || referencesAny(first, tainted));
}

function commandExtraction(value: string, parsed: ReadonlySet<string>): boolean {
  for (const name of parsed) {
    const escaped = escapeRe(name);
    if (new RegExp(`${escaped}\\s*\\[\\s*(?:['"](?:command|cmd|script)['"]|:(?:command|cmd|script))\\s*\\]`, "i").test(value)) return true;
    if (new RegExp(`${escaped}\\s*\\.\\s*(?:fetch|dig)\\s*\\(\\s*(?:['"](?:command|cmd|script)['"]|:(?:command|cmd|script))`, "i").test(value)) return true;
  }
  return false;
}

function parserWrappers(source: string, spans: readonly FunctionSpan[]): Map<string, number> {
  const output = new Map<string, number>();
  for (const span of spans) {
    const body = source.slice(span.bodyStart, span.end);
    for (let index = 0; index < span.params.length; index++) {
      const parameter = escapeRe(span.params[index]!);
      if (!new RegExp(`JSON\\s*\\.\\s*parse\\s*\\(\\s*${parameter}\\s*\\)`).test(body)) continue;
      if (/(?:\[\s*(?:['"](?:command|cmd|script)['"]|:(?:command|cmd|script))\s*\]|\.\s*(?:fetch|dig)\s*\(\s*(?:['"](?:command|cmd|script)['"]|:(?:command|cmd|script)))/i.test(body)) {
        output.set(span.name, index);
      }
    }
  }
  return output;
}

function calls(source: string, pattern: RegExp, offset: number): Array<{ start: number; args: string; name: string }> {
  const output: Array<{ start: number; args: string; name: string }> = [];
  for (const match of maskRubyStrings(source).matchAll(pattern)) {
    const openIndex = (match.index ?? 0) + match[0].lastIndexOf("(");
    const close = balancedClose(source, openIndex, "(", ")");
    if (close === undefined) continue;
    output.push({ start: offset + (match.index ?? 0), args: source.slice(openIndex + 1, close), name: match[1] ?? "" });
  }
  return output;
}

function staticRubyString(value: string): string | undefined {
  const trimmed = value.trim();
  const match = /^(['"])([\s\S]*)\1$/.exec(trimmed);
  if (!match || /#\{/.test(match[2] ?? "")) return undefined;
  if (match[1] === "'") return (match[2] ?? "").replace(/\\(['\\])/g, "$1");
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

function shellShape(executable: string | undefined, flag: string | undefined): boolean {
  const program = executable?.toLowerCase().split(/[\\/]/).at(-1);
  const option = flag?.toLowerCase();
  if (["sh", "bash", "dash", "zsh", "ksh"].includes(program ?? "")) return option === "-c";
  if (["cmd", "cmd.exe"].includes(program ?? "")) return option === "/c";
  return ["powershell", "powershell.exe", "pwsh", "pwsh.exe"].includes(program ?? "") &&
    ["-c", "-command"].includes(option ?? "");
}

function shellSinks(
  source: string,
  offset: number,
  tainted: ReadonlySet<string>,
  responseItems: ReadonlySet<string>,
  open3Imported: boolean,
): ShellSink[] {
  const pattern = /\b((?:Kernel\s*\.\s*)?(?:system|exec)|IO\s*\.\s*popen|Open3\s*\.\s*(?:capture2|capture2e|capture3|popen2|popen2e|popen3))\s*\(/gm;
  return calls(source, pattern, offset).flatMap((call) => {
    if (/^Open3\b/.test(call.name) && !open3Imported) return [];
    const args = splitTopLevel(call.args);
    const value = args.length === 1
      ? args[0]
      : shellShape(staticRubyString(args[0] ?? ""), staticRubyString(args[1] ?? ""))
        ? args[2]
        : undefined;
    return value && (sourceExpression(value, responseItems) || referencesAny(value, tainted))
      ? [{ start: call.start, value }]
      : [];
  });
}

function hasTerminatingGuard(sourceBeforeSink: string, value: string): boolean {
  for (const name of references(value)) {
    const escaped = escapeRe(name);
    const approval = /(?:return|raise)\b[^\r\n]{0,160}\bunless\s+(?:approved|authorized|confirmed|allowed)\b/i;
    const approvalBlock = /unless\s+(?:approved|authorized|confirmed|allowed)\b[\s\S]{0,256}(?:return|raise)\b/i;
    const allowed = new RegExp(`(?:return|raise)\\b[^\\r\\n]{0,200}\\bunless\\s+[A-Z_a-z]\\w*\\s*\\.\\s*include\\?\\s*\\(\\s*${escaped}\\s*\\)`, "i");
    const allowedBlock = new RegExp(`unless\\s+[A-Z_a-z]\\w*\\s*\\.\\s*include\\?\\s*\\(\\s*${escaped}\\s*\\)[\\s\\S]{0,256}(?:return|raise)\\b`, "i");
    if (approval.test(sourceBeforeSink) || approvalBlock.test(sourceBeforeSink) ||
      allowed.test(sourceBeforeSink) || allowedBlock.test(sourceBeforeSink)) return true;
  }
  return false;
}

function commandWrappers(
  source: string,
  spans: readonly FunctionSpan[],
  open3Imported: boolean,
): CommandWrapper[] {
  const output: CommandWrapper[] = [];
  for (const span of spans) {
    const body = source.slice(span.bodyStart, span.end);
    for (let index = 0; index < span.params.length; index++) {
      const parameter = span.params[index]!;
      for (const sink of shellSinks(body, span.bodyStart, new Set([parameter]), new Set(), open3Imported)) {
        if (!hasTerminatingGuard(source.slice(span.bodyStart, sink.start), sink.value)) {
          output.push({ name: span.name, paramIndex: index, sink });
        }
      }
    }
  }
  return output;
}

function scopeTaint(
  source: string,
  parserMethods: ReadonlyMap<string, number>,
  responseItems: ReadonlySet<string>,
): { tainted: Set<string>; parsed: Set<string> } {
  const tainted = new Set<string>();
  const parsed = new Set<string>();
  const values = assignments(source);
  for (let pass = 0; pass < values.length + 2; pass++) {
    let changed = false;
    for (const assignment of values) {
      if (sourceExpression(assignment.rhs, responseItems) || directAliasExpression(assignment.rhs, tainted)) {
        if (!tainted.has(assignment.name)) { tainted.add(assignment.name); changed = true; }
      }
      if (jsonParseExpression(assignment.rhs, tainted, responseItems)) {
        if (!parsed.has(assignment.name)) { parsed.add(assignment.name); changed = true; }
      }
      if (commandExtraction(assignment.rhs, parsed)) {
        if (!tainted.has(assignment.name)) { tainted.add(assignment.name); changed = true; }
      }
      for (const [name, paramIndex] of parserMethods) {
        const call = new RegExp(`^(?:self\\s*\\.\\s*)?${escapeRe(name)}\\s*\\((.*)\\)$`, "s").exec(assignment.rhs);
        if (!call) continue;
        const argument = splitTopLevel(call[1] ?? "")[paramIndex];
        if (argument && (sourceExpression(argument, responseItems) || referencesAny(argument, tainted)) && !tainted.has(assignment.name)) {
          tainted.add(assignment.name);
          changed = true;
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
    ruleId: RUBY_UNSAFE_TOOL_EXECUTION_RULE_ID,
    title: "Ruby model-produced tool argument reaches command execution",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-78", "CWE-1426"],
    owasp_llm: ["LLM05:2025", "LLM06:2025"],
    file,
    startLine: line,
    snippet: "Model-produced tool argument reaches a Ruby command sink [VALUE REDACTED]",
    message: "An official OpenAI Ruby model-produced tool argument reaches a Ruby command-execution sink without a supported checked approval or full-command allowlist. This is bounded repository evidence; verify custom validators, runtime sandboxing, and authorization manually.",
    remediation: {
      summary: "Treat model tool arguments as untrusted; map fixed tool names to server-owned Ruby actions and avoid command strings.",
      steps: [
        "Decode tool arguments into a strict schema and map an allowlisted action identifier to server-owned behavior.",
        "Require human approval before command execution and reject when approval infrastructure is unavailable.",
        "Prefer fixed executable/argument APIs without a shell; never concatenate or pass model-produced command strings.",
        "Run allowed actions in an isolated least-privilege sandbox with bounded filesystem and network access.",
      ],
      references: [
        "CWE-78", "CWE-1426",
        "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
        "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
      ],
    },
  });
}

function analyzeDocument(path: string, input: string): Finding[] {
  const masked = maskRubyComments(input);
  if (!masked.valid) return [];
  const hasChatSource = /\b@{0,2}[a-z_]\w*\s*(?:\.|&\.)\s*function\s*(?:\.|&\.)\s*arguments\b/.test(masked.source);
  const hasResponsesSource = masked.source.includes(RESPONSE_TOOL_CALL_TYPE) && /\barguments\b/.test(masked.source);
  if (!hasChatSource && !hasResponsesSource) return [];

  const spans = functions(masked.source);
  const parserMethods = parserWrappers(masked.source, spans);
  const open3Imported = /^\s*require\s*(?:\(\s*)?['"]open3['"]\s*\)?\s*$/m.test(masked.source);
  const wrappers = commandWrappers(masked.source, spans, open3Imported);
  const output = new Map<number, Finding>();
  const scopes: Array<{ source: string; offset: number }> = [];
  const topLevel = [...masked.source];
  for (const span of spans) {
    for (let index = span.start; index < span.end; index++) {
      if (topLevel[index] !== "\n" && topLevel[index] !== "\r") topLevel[index] = " ";
    }
    scopes.push({ source: masked.source.slice(span.bodyStart, span.end), offset: span.bodyStart });
  }
  scopes.push({ source: topLevel.join(""), offset: 0 });

  for (const scope of scopes) {
    const responseItems = typedResponseItems(scope.source);
    const { tainted } = scopeTaint(scope.source, parserMethods, responseItems);
    for (const sink of shellSinks(scope.source, scope.offset, tainted, responseItems, open3Imported)) {
      if (!hasTerminatingGuard(masked.source.slice(scope.offset, sink.start), sink.value)) {
        output.set(sink.start, finding(path, lineOf(masked.source, sink.start)));
      }
    }
    for (const wrapper of wrappers) {
      const pattern = new RegExp(`\\b(?:self\\s*\\.\\s*)?(${escapeRe(wrapper.name)})\\s*\\(`, "g");
      for (const call of calls(scope.source, pattern, scope.offset)) {
        const argument = splitTopLevel(call.args)[wrapper.paramIndex];
        if (argument && (sourceExpression(argument, responseItems) || referencesAny(argument, tainted)) &&
          !hasTerminatingGuard(masked.source.slice(scope.offset, call.start), argument)) {
          output.set(wrapper.sink.start, finding(path, lineOf(masked.source, wrapper.sink.start)));
        }
      }
    }
  }
  return [...output.entries()].sort(([left], [right]) => left - right).map(([, value]) => value);
}

export async function runRubyUnsafeToolExecution(input: RubyProjectInput): Promise<Finding[]> {
  const project = await resolveRubyProject(input);
  return project.files.flatMap((document) => analyzeDocument(document.path, document.content));
}
