/** Bounded OpenAI PHP tool arguments reaching PHP command-execution sinks. */

import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";
import { resolvePhpProject, type PhpProjectInput } from "./project.js";

export const PHP_UNSAFE_TOOL_EXECUTION_RULE_ID =
  "ci-php-llm-tool-argument-command-execution";

const MAX_BALANCED_CHARS = 64_000;

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

/** Preserve offsets and ordinary strings while removing PHP comments. Heredocs fail closed. */
function maskPhpComments(input: string): { source: string; valid: boolean } {
  if (/<<<\s*['"]?[A-Za-z_]\w*['"]?/.test(input)) return { source: input, valid: false };
  const chars = [...input];
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    const next = chars[index + 1];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if ((char === "/" && next === "/") || char === "#") {
      if (char === "/") chars[index + 1] = " ";
      chars[index] = " ";
      index += char === "/" ? 2 : 1;
      while (index < chars.length && chars[index] !== "\n" && chars[index] !== "\r") chars[index++] = " ";
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

function functions(source: string): FunctionSpan[] {
  const output: FunctionSpan[] = [];
  const pattern = /\bfunction\s+([A-Za-z_]\w*)\s*\(([^()]*)\)\s*(?::\s*[^\{]+)?\{/gm;
  for (const match of source.matchAll(pattern)) {
    const bodyStart = (match.index ?? 0) + match[0].lastIndexOf("{");
    const close = balancedClose(source, bodyStart, "{", "}");
    if (close === undefined) continue;
    const params = splitTopLevel(match[2] ?? "").map((parameter) =>
      parameter.replace(/=.*/s, "").trim().match(/(\$[A-Za-z_]\w*)\s*$/)?.[1]
    ).filter((value): value is string => Boolean(value));
    output.push({ name: match[1]!, params, start: match.index ?? 0, bodyStart, end: close + 1 });
  }
  return output.sort((left, right) => left.start - right.start);
}

function assignments(source: string, offset = 0): Assignment[] {
  const output: Assignment[] = [];
  const pattern = /(?:^|[;{}]\s*|\n\s*)(\$[A-Za-z_]\w*)\s*=\s*([^;]{1,65536});/gm;
  for (const match of source.matchAll(pattern)) {
    const rhs = match[2]?.trim();
    if (rhs) output.push({ name: match[1]!, rhs, start: offset + (match.index ?? 0) + match[0].indexOf(match[1]!) });
  }
  return output;
}

function references(value: string): Set<string> {
  return new Set([...value.matchAll(/\$[A-Za-z_]\w*/g)].map((match) => match[0]));
}

function referencesAny(value: string, names: ReadonlySet<string>): boolean {
  for (const name of references(value)) if (names.has(name)) return true;
  return false;
}

function directAliasExpression(value: string, names: ReadonlySet<string>): boolean {
  for (const name of names) {
    if (new RegExp(`^\\s*(?:\\([^)]*\\)\\s*)?${escapeRe(name)}\\s*$`).test(value)) return true;
  }
  return false;
}

function sourceExpression(value: string): boolean {
  return /\$[A-Za-z_]\w*\s*->\s*function\s*->\s*arguments\b/.test(value);
}

function jsonDecodeExpression(value: string, tainted: ReadonlySet<string>): boolean {
  const call = value.match(/^(?:\\)?json_decode\s*\((.*)\)$/s);
  if (!call) return false;
  const args = splitTopLevel(call[1] ?? "");
  return args[0] !== undefined && (sourceExpression(args[0]) || referencesAny(args[0], tainted)) &&
    /^true$/i.test(args[1]?.trim() ?? "");
}

function commandExtraction(value: string, parsed: ReadonlySet<string>): boolean {
  for (const name of parsed) {
    if (new RegExp(`${escapeRe(name)}\\s*\\[\\s*['"](?:command|cmd|script)['"]\\s*\\]`, "i").test(value)) return true;
  }
  return false;
}

function parserWrappers(source: string, spans: readonly FunctionSpan[]): Map<string, number> {
  const output = new Map<string, number>();
  for (const span of spans) {
    const body = source.slice(span.bodyStart + 1, span.end - 1);
    for (let index = 0; index < span.params.length; index++) {
      const parameter = span.params[index]!;
      if (!new RegExp(`json_decode[\\s\\S]{0,1024}${escapeRe(parameter)}[\\s\\S]{0,1024}true`, "i").test(body)) continue;
      if (/return\s+[\s\S]{0,512}\[\s*['"](?:command|cmd|script)['"]\s*\]/i.test(body)) output.set(span.name, index);
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

function shellSinks(source: string, offset: number, tainted: ReadonlySet<string>): ShellSink[] {
  const pattern = /(?:^|[^A-Za-z0-9_>:])(?:\\)?(?:exec|system|shell_exec|passthru)\s*\(/gm;
  return calls(source, pattern, offset).flatMap((call) => {
    const value = splitTopLevel(call.args)[0];
    return value && referencesAny(value, tainted) ? [{ start: call.start, value }] : [];
  });
}

function hasTerminatingGuard(sourceBeforeSink: string, value: string): boolean {
  for (const name of references(value)) {
    const escaped = escapeRe(name);
    const rejection = new RegExp(`if\\s*\\([^)]*!\\s*\\$(?:approved|authorized|confirmed|allowed)\\b[^)]*\\)\\s*(?:\\{[\\s\\S]{0,256})?(?:return\\b|throw\\b)`, "i");
    const allowlist = new RegExp(`if\\s*\\(\\s*!\\s*in_array\\s*\\(\\s*${escaped}\\s*,\\s*\\$[A-Za-z_]\\w*\\s*,\\s*true\\s*\\)\\s*\\)\\s*(?:\\{[\\s\\S]{0,256})?(?:return\\b|throw\\b)`, "i");
    if (rejection.test(sourceBeforeSink) || allowlist.test(sourceBeforeSink)) return true;
  }
  return false;
}

function commandWrappers(source: string, spans: readonly FunctionSpan[]): CommandWrapper[] {
  const output: CommandWrapper[] = [];
  for (const span of spans) {
    const body = source.slice(span.bodyStart + 1, span.end - 1);
    for (let index = 0; index < span.params.length; index++) {
      const parameter = span.params[index]!;
      for (const sink of shellSinks(body, span.bodyStart + 1, new Set([parameter]))) {
        const before = source.slice(span.bodyStart + 1, sink.start);
        if (!hasTerminatingGuard(before, sink.value)) output.push({ name: span.name, paramIndex: index, sink });
      }
    }
  }
  return output;
}

function scopeTaint(
  source: string,
  parserMethods: ReadonlyMap<string, number>,
): { tainted: Set<string>; parsed: Set<string> } {
  const tainted = new Set<string>();
  const parsed = new Set<string>();
  const values = assignments(source);
  for (let pass = 0; pass < values.length + 2; pass++) {
    let changed = false;
    for (const assignment of values) {
      if (sourceExpression(assignment.rhs) || directAliasExpression(assignment.rhs, tainted)) {
        if (!tainted.has(assignment.name)) { tainted.add(assignment.name); changed = true; }
      }
      if (jsonDecodeExpression(assignment.rhs, tainted)) {
        if (!parsed.has(assignment.name)) { parsed.add(assignment.name); changed = true; }
      }
      if (commandExtraction(assignment.rhs, parsed)) {
        if (!tainted.has(assignment.name)) { tainted.add(assignment.name); changed = true; }
      }
      for (const [name, paramIndex] of parserMethods) {
        const call = assignment.rhs.match(new RegExp(`^(?:\\$this\\s*->\\s*)?${escapeRe(name)}\\s*\\((.*)\\)$`, "s"));
        if (!call) continue;
        const argument = splitTopLevel(call[1] ?? "")[paramIndex];
        if (argument && (sourceExpression(argument) || referencesAny(argument, tainted)) && !tainted.has(assignment.name)) {
          tainted.add(assignment.name);
          changed = true;
        }
      }
    }
    if (!changed) break;
  }
  return { tainted, parsed };
}

function mappedDynamicDispatch(source: string, scope: string, wrapper: CommandWrapper, parsed: ReadonlySet<string>): boolean {
  const name = escapeRe(wrapper.name);
  const mapping = new RegExp(`['"]${name}['"]\\s*=>\\s*\\[\\s*\\$this\\s*,\\s*['"]${name}['"]\\s*\\]`).test(source);
  if (!mapping) return false;
  for (const variable of parsed) {
    if (new RegExp(`\\$[A-Za-z_]\\w*\\s*\\(\\s*\\.\\.\\.\\s*${escapeRe(variable)}\\s*\\)`).test(scope)) return true;
  }
  return false;
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < source.length; cursor++) if (source[cursor] === "\n") line++;
  return line;
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PHP_UNSAFE_TOOL_EXECUTION_RULE_ID,
    title: "PHP model-produced tool argument reaches command execution",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-78", "CWE-1426"],
    owasp_llm: ["LLM05:2025", "LLM06:2025"],
    file,
    startLine: line,
    snippet: "Model-produced tool argument reaches a PHP command sink [VALUE REDACTED]",
    message: "An OpenAI PHP model-produced tool argument reaches a PHP command-execution sink without a supported checked approval or full-command allowlist. This is bounded repository evidence; verify custom validators, runtime sandboxing, and authorization manually.",
    remediation: {
      summary: "Treat model tool arguments as untrusted; map fixed tool names to server-owned PHP actions and avoid command strings.",
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
  const masked = maskPhpComments(input);
  if (!masked.valid || !/\$[A-Za-z_]\w*\s*->\s*function\s*->\s*arguments\b/.test(masked.source)) return [];
  const spans = functions(masked.source);
  const parserMethods = parserWrappers(masked.source, spans);
  const wrappers = commandWrappers(masked.source, spans);
  const output = new Map<number, Finding>();

  const scopes: Array<{ source: string; offset: number }> = [];
  const topLevel = [...masked.source];
  for (const span of spans) {
    for (let index = span.start; index < span.end; index++) {
      if (topLevel[index] !== "\n" && topLevel[index] !== "\r") topLevel[index] = " ";
    }
    scopes.push({ source: masked.source.slice(span.bodyStart + 1, span.end - 1), offset: span.bodyStart + 1 });
  }
  scopes.push({ source: topLevel.join(""), offset: 0 });

  for (const scope of scopes) {
    const { tainted, parsed } = scopeTaint(scope.source, parserMethods);
    for (const sink of shellSinks(scope.source, scope.offset, tainted)) {
      const before = masked.source.slice(scope.offset, sink.start);
      if (!hasTerminatingGuard(before, sink.value)) output.set(sink.start, finding(path, lineOf(masked.source, sink.start)));
    }
    for (const wrapper of wrappers) {
      for (const call of calls(scope.source, new RegExp(`(?:\\$this\\s*->\\s*)?${escapeRe(wrapper.name)}\\s*\\(`, "g"), scope.offset)) {
        const argument = splitTopLevel(call.args)[wrapper.paramIndex];
        if (argument && (sourceExpression(argument) || referencesAny(argument, tainted))) {
          const before = masked.source.slice(scope.offset, call.start);
          if (!hasTerminatingGuard(before, argument)) output.set(wrapper.sink.start, finding(path, lineOf(masked.source, wrapper.sink.start)));
        }
      }
      if (mappedDynamicDispatch(masked.source, scope.source, wrapper, parsed)) {
        output.set(wrapper.sink.start, finding(path, lineOf(masked.source, wrapper.sink.start)));
      }
    }
  }
  return [...output.entries()].sort(([left], [right]) => left - right).map(([, value]) => value);
}

export async function runPhpUnsafeToolExecution(input: PhpProjectInput): Promise<Finding[]> {
  const project = await resolvePhpProject(input);
  return project.files.flatMap((document) => analyzeDocument(document.path, document.content));
}
