/**
 * Exact async-openai tool arguments reaching recognized Rust shell execution.
 * Analysis is intrafile, source ordered, non-executing, and deliberately bounded.
 */

import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";
import { resolveRustProject, type RustProjectInput } from "./project.js";

export const RUST_UNSAFE_TOOL_EXECUTION_RULE_ID =
  "ci-rust-llm-tool-argument-command-execution";

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

interface SinkCall {
  start: number;
  end: number;
  value: string;
}

interface CommandWrapper {
  fn: FunctionSpan;
  paramIndex: number;
  sink: SinkCall;
}

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function rawStringEnd(source: string, start: number): number | undefined {
  const match = /^(?:b)?r(#{0,16})"/.exec(source.slice(start));
  if (!match) return undefined;
  const close = `"${match[1] ?? ""}`;
  const end = source.indexOf(close, start + match[0].length);
  return end < 0 ? undefined : end + close.length;
}

/** Mask nested Rust comments without moving offsets; reject malformed literals/comments. */
function maskRustComments(input: string): { source: string; valid: boolean } {
  const chars = [...input];
  for (let index = 0; index < chars.length;) {
    const rawEnd = rawStringEnd(input, index);
    if (rawEnd !== undefined) {
      index = rawEnd;
      continue;
    }
    const char = chars[index]!;
    const next = chars[index + 1];
    if (char === '"' || char === "'") {
      const quote = char;
      let escaped = false;
      let closed = false;
      index++;
      while (index < chars.length) {
        const current = chars[index]!;
        if (escaped) escaped = false;
        else if (current === "\\") escaped = true;
        else if (current === quote) {
          closed = true;
          index++;
          break;
        }
        index++;
      }
      if (!closed) return { source: chars.join(""), valid: false };
      continue;
    }
    if (char === "/" && next === "/") {
      chars[index] = " ";
      chars[index + 1] = " ";
      index += 2;
      while (index < chars.length && chars[index] !== "\n") chars[index++] = " ";
      continue;
    }
    if (char === "/" && next === "*") {
      let depth = 1;
      chars[index] = " ";
      chars[index + 1] = " ";
      index += 2;
      while (index < chars.length && depth > 0) {
        if (chars[index] === "/" && chars[index + 1] === "*") {
          chars[index] = chars[index + 1] = " ";
          depth++;
          index += 2;
        } else if (chars[index] === "*" && chars[index + 1] === "/") {
          chars[index] = chars[index + 1] = " ";
          depth--;
          index += 2;
        } else {
          if (chars[index] !== "\n" && chars[index] !== "\r") chars[index] = " ";
          index++;
        }
      }
      if (depth !== 0) return { source: chars.join(""), valid: false };
      continue;
    }
    index++;
  }
  return { source: chars.join(""), valid: true };
}

function balancedClose(source: string, open: number, left: string, right: string): number | undefined {
  if (source[open] !== left) return undefined;
  let depth = 0;
  const limit = Math.min(source.length, open + MAX_BALANCED_CHARS);
  for (let index = open; index < limit;) {
    const rawEnd = rawStringEnd(source, index);
    if (rawEnd !== undefined) {
      index = rawEnd;
      continue;
    }
    const char = source[index]!;
    if (char === '"' || char === "'") {
      const quote = char;
      index++;
      let escaped = false;
      while (index < limit) {
        const current = source[index]!;
        if (escaped) escaped = false;
        else if (current === "\\") escaped = true;
        else if (current === quote) {
          index++;
          break;
        }
        index++;
      }
      continue;
    }
    if (char === left) depth++;
    else if (char === right && --depth === 0) return index;
    index++;
  }
  return undefined;
}

function splitTopLevel(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let round = 0;
  let square = 0;
  let curly = 0;
  for (let index = 0; index < value.length;) {
    const rawEnd = rawStringEnd(value, index);
    if (rawEnd !== undefined) {
      index = rawEnd;
      continue;
    }
    const char = value[index]!;
    if (char === '"' || char === "'") {
      const quote = char;
      index++;
      let escaped = false;
      while (index < value.length) {
        const current = value[index]!;
        if (escaped) escaped = false;
        else if (current === "\\") escaped = true;
        else if (current === quote) {
          index++;
          break;
        }
        index++;
      }
      continue;
    }
    if (char === "(") round++;
    else if (char === ")") round--;
    else if (char === "[") square++;
    else if (char === "]") square--;
    else if (char === "{") curly++;
    else if (char === "}") curly--;
    else if (char === "," && round === 0 && square === 0 && curly === 0) {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
    index++;
  }
  parts.push(value.slice(start));
  return parts;
}

function parameterNames(value: string): string[] {
  return splitTopLevel(value).flatMap((part) => {
    const match = /(?:^|\s)(?:mut\s+)?([A-Za-z_]\w*)\s*:/.exec(part.trim());
    return match?.[1] ? [match[1]] : [];
  });
}

function functions(source: string): FunctionSpan[] {
  const output: FunctionSpan[] = [];
  for (const match of source.matchAll(/\bfn\s+([A-Za-z_]\w*)\s*(?:<[^>{}]{0,200}>)?\s*\(/g)) {
    const start = match.index ?? 0;
    const open = start + match[0].lastIndexOf("(");
    const close = balancedClose(source, open, "(", ")");
    if (close === undefined) continue;
    const searchEnd = Math.min(source.length, close + 2_000);
    let bodyStart = close + 1;
    while (bodyStart < searchEnd && source[bodyStart] !== "{" && source[bodyStart] !== ";") bodyStart++;
    if (source[bodyStart] !== "{") continue;
    const end = balancedClose(source, bodyStart, "{", "}");
    if (end === undefined) continue;
    output.push({
      name: match[1]!,
      params: parameterNames(source.slice(open + 1, close)),
      start,
      bodyStart,
      end,
    });
  }
  return output;
}

function assignments(source: string, fn: FunctionSpan): Assignment[] {
  const output: Assignment[] = [];
  const body = source.slice(fn.bodyStart + 1, fn.end);
  const declaration = /\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::\s*[^=;\n]+)?=\s*/g;
  for (const match of body.matchAll(declaration)) {
    const expressionStart = fn.bodyStart + 1 + (match.index ?? 0) + match[0].length;
    let end = expressionStart;
    let round = 0;
    let square = 0;
    let curly = 0;
    for (; end < Math.min(fn.end, expressionStart + 16_000);) {
      const rawEnd = rawStringEnd(source, end);
      if (rawEnd !== undefined) {
        end = rawEnd;
        continue;
      }
      const char = source[end]!;
      if (char === '"' || char === "'") {
        const quote = char;
        end++;
        let escaped = false;
        while (end < fn.end) {
          const current = source[end]!;
          if (escaped) escaped = false;
          else if (current === "\\") escaped = true;
          else if (current === quote) {
            end++;
            break;
          }
          end++;
        }
        continue;
      }
      if (char === "(") round++;
      else if (char === ")") round--;
      else if (char === "[") square++;
      else if (char === "]") square--;
      else if (char === "{") curly++;
      else if (char === "}") {
        if (curly === 0 && round === 0 && square === 0) break;
        curly--;
      } else if (char === ";" && round === 0 && square === 0 && curly === 0) break;
      end++;
    }
    const rhs = source.slice(expressionStart, end).trim();
    if (rhs) output.push({ name: match[1]!, rhs, start: expressionStart });
  }
  return output.sort((left, right) => left.start - right.start);
}

function refs(expression: string): Set<string> {
  const output = new Set<string>();
  for (const match of expression.matchAll(/\b[A-Za-z_]\w*\b/g)) output.add(match[0]);
  return output;
}

function compact(value: string): string {
  return value.replace(/\s+/g, "");
}

function sourceArgument(expression: string, modelResults: ReadonlySet<string>): boolean {
  const value = compact(expression);
  if (/\b[A-Za-z_]\w*\.function\.arguments\b/.test(value)) return true;
  return [...modelResults].some((name) =>
    new RegExp(`\\b${escapeRe(name)}\\.arguments\\b`).test(value)
  );
}

function validatedReplacement(expression: string): boolean {
  return /\b(?:validate|sanitize|allowlist|approved|safe|permit|authorize)[A-Za-z0-9_]*\s*\(/i.test(expression) &&
    !/\bserde_json::from_str\s*\(/.test(expression);
}

function staticRustString(value: string): string | undefined {
  const trimmed = value.trim().replace(/^&/, "").trim();
  const raw = /^(?:b)?r(#{0,16})"([\s\S]*)"\1$/.exec(trimmed);
  if (raw) return raw[2];
  if (!/^"(?:[^"\\]|\\.)*"$/.test(trimmed)) return undefined;
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

function processSinkCalls(source: string, fn: FunctionSpan): SinkCall[] {
  const output: SinkCall[] = [];
  const body = source.slice(fn.bodyStart + 1, fn.end);
  const imported = /\buse\s+(?:std|tokio)::process::(?:\{[^}]*\bCommand\b[^}]*\}|Command)\s*;/.test(source);
  const regex = /\b(?:(?:std|tokio)::process::)?Command::new\s*\(/g;
  for (const match of body.matchAll(regex)) {
    const start = fn.bodyStart + 1 + (match.index ?? 0);
    if (!imported && !/^(?:std|tokio)::process::/.test(match[0])) continue;
    const open = start + match[0].lastIndexOf("(");
    const close = balancedClose(source, open, "(", ")");
    if (close === undefined) continue;
    const executable = staticRustString(source.slice(open + 1, close));
    const chainEnd = source.indexOf(";", close + 1);
    const end = chainEnd < 0 || chainEnd > fn.end ? Math.min(fn.end, close + 4_000) : chainEnd;
    const chain = source.slice(close + 1, end);
    const args: string[] = [];
    for (const argMatch of chain.matchAll(/\.arg\s*\(/g)) {
      const argOpen = close + 1 + (argMatch.index ?? 0) + argMatch[0].lastIndexOf("(");
      const argClose = balancedClose(source, argOpen, "(", ")");
      if (argClose === undefined || argClose > end) continue;
      args.push(source.slice(argOpen + 1, argClose));
    }
    if (shellShape(executable, staticRustString(args[0] ?? "")) && args[1]) {
      output.push({ start, end, value: args[1]!.trim() });
    }
  }
  return output;
}

function dockerSinkCalls(source: string, fn: FunctionSpan): SinkCall[] {
  if (!/\buse\s+bollard::exec::CreateExecOptions\s*;/.test(source)) return [];
  const output: SinkCall[] = [];
  const body = source.slice(fn.bodyStart + 1, fn.end);
  if (!/\.create_exec\s*\(/.test(body) || !/\.start_exec\s*\(/.test(body)) return [];
  for (const match of body.matchAll(/\bcmd\s*:\s*Some\s*\(\s*vec!\s*\[/g)) {
    const start = fn.bodyStart + 1 + (match.index ?? 0);
    const open = start + match[0].lastIndexOf("[");
    const close = balancedClose(source, open, "[", "]");
    if (close === undefined) continue;
    const args = splitTopLevel(source.slice(open + 1, close));
    if (shellShape(staticRustString(args[0] ?? ""), staticRustString(args[1] ?? "")) && args[2]) {
      output.push({ start, end: close, value: args[2]!.trim() });
    }
  }
  return output;
}

function sinkCalls(source: string, fn: FunctionSpan): SinkCall[] {
  return [...processSinkCalls(source, fn), ...dockerSinkCalls(source, fn)]
    .sort((left, right) => left.start - right.start);
}

function rejectingGuard(prefix: string, value: string, tainted: ReadonlySet<string>): boolean {
  const used = [...refs(value)].filter((name) => tainted.has(name));
  const terminates = String.raw`\{[\s\S]{0,500}?\b(?:return|continue|break|panic!\s*\()`;
  for (const name of used) {
    const escaped = escapeRe(name);
    const approval = String.raw`(?:approve|confirm|authorize|allow|permit|validate)[A-Za-z0-9_]*\s*\([^)]*\b${escaped}\b[^)]*\)`;
    if (new RegExp(String.raw`\bif\s*!\s*${approval}\s*${terminates}`, "i").test(prefix)) return true;
    if (new RegExp(String.raw`\bif\s*!\s*[A-Za-z_]\w*(?:allow|safe|permit|approv)[A-Za-z0-9_]*\s*\.contains\s*\(\s*&?${escaped}\s*\)\s*${terminates}`, "i").test(prefix)) return true;
  }
  return false;
}

function commandWrappers(source: string, fns: readonly FunctionSpan[]): CommandWrapper[] {
  const output: CommandWrapper[] = [];
  for (const fn of fns) {
    for (const sink of sinkCalls(source, fn)) {
      const used = refs(sink.value);
      const paramIndex = fn.params.findIndex((parameter) => used.has(parameter));
      if (paramIndex < 0) continue;
      const parameter = fn.params[paramIndex]!;
      if (rejectingGuard(source.slice(fn.bodyStart + 1, sink.start), sink.value, new Set([parameter]))) continue;
      output.push({ fn, paramIndex, sink });
    }
  }
  return output;
}

function callArguments(expression: string, name: string): string[] | undefined {
  const match = new RegExp(`\\b${escapeRe(name)}\\s*\\(`).exec(expression);
  if (!match) return undefined;
  const open = match.index + match[0].lastIndexOf("(");
  const close = balancedClose(expression, open, "(", ")");
  return close === undefined ? undefined : splitTopLevel(expression.slice(open + 1, close));
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < source.length; cursor++) {
    if (source[cursor] === "\n") line++;
  }
  return line;
}

function finding(file: string, line: number, docker: boolean): Finding {
  return makeAiFinding({
    ruleId: RUST_UNSAFE_TOOL_EXECUTION_RULE_ID,
    title: "Rust model-produced tool argument reaches shell execution",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-78", "CWE-1426"],
    owasp_llm: ["LLM05:2025", "LLM06:2025"],
    file,
    startLine: line,
    snippet: "Model-produced tool argument reaches a Rust shell sink [VALUE REDACTED]",
    message:
      `An async-openai model-produced tool argument reaches a recognized Rust ${docker ? "Docker exec" : "process"} shell invocation without a visible checked approval, allowlist, or validated replacement value. This is bounded repository evidence; verify runtime sandboxing and authorization manually.`,
    remediation: {
      summary: "Treat model tool arguments as untrusted; map fixed tool names to server-owned actions and avoid shell command strings.",
      steps: [
        "Validate tool arguments with a strict schema and an explicit server-owned allowlist.",
        "Require human approval before command execution and reject when approval infrastructure is unavailable.",
        "Use a fixed executable with separated argument values instead of sh, cmd, or PowerShell command strings.",
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
  const masked = maskRustComments(input);
  if (!masked.valid || !/\b(?:use|extern\s+crate)\s+async_openai(?:::|\s*;)/.test(masked.source)) return [];
  const source = masked.source;
  const fns = functions(source);
  const wrappers = commandWrappers(source, fns);
  const findings: Finding[] = [];
  const emitted = new Set<number>();

  for (const fn of fns) {
    const modelResults = new Set<string>();
    const tainted = new Set<string>();
    const allAssignments = assignments(source, fn);
    for (const assignment of allAssignments) {
      if (/\bgenerate_function_call\s*\(/.test(assignment.rhs)) modelResults.add(assignment.name);
    }
    let changed = true;
    let passes = 0;
    while (changed && passes++ < 10) {
      changed = false;
      for (const assignment of allAssignments) {
        if (validatedReplacement(assignment.rhs)) continue;
        const carries = sourceArgument(assignment.rhs, modelResults) ||
          [...tainted].some((name) => refs(assignment.rhs).has(name));
        if (carries && !tainted.has(assignment.name)) {
          tainted.add(assignment.name);
          changed = true;
        }
      }
    }

    for (const sink of sinkCalls(source, fn)) {
      const carries = sourceArgument(sink.value, modelResults) ||
        [...tainted].some((name) => refs(sink.value).has(name));
      if (!carries || rejectingGuard(source.slice(fn.bodyStart + 1, sink.start), sink.value, tainted)) continue;
      findings.push(finding(path, lineOf(input, sink.start), /\bcmd\s*:/.test(source.slice(sink.start, sink.end))));
      emitted.add(sink.start);
    }

    const body = source.slice(fn.bodyStart + 1, fn.end);
    for (const wrapper of wrappers) {
      const regex = new RegExp(`\\b${escapeRe(wrapper.fn.name)}\\s*\\(`, "g");
      for (const match of body.matchAll(regex)) {
        const callStart = fn.bodyStart + 1 + (match.index ?? 0);
        if (callStart >= wrapper.fn.start && callStart <= wrapper.fn.end) continue;
        const args = callArguments(source.slice(callStart, fn.end), wrapper.fn.name);
        const argument = args?.[wrapper.paramIndex] ?? "";
        const carries = sourceArgument(argument, modelResults) ||
          [...tainted].some((name) => refs(argument).has(name));
        if (!carries || rejectingGuard(source.slice(fn.bodyStart + 1, callStart), argument, tainted)) continue;
        if (!emitted.has(wrapper.sink.start)) {
          findings.push(finding(path, lineOf(input, wrapper.sink.start), /\bcmd\s*:/.test(source.slice(wrapper.sink.start, wrapper.sink.end))));
          emitted.add(wrapper.sink.start);
        }
      }
    }
  }
  return findings;
}

export async function runRustUnsafeToolExecution(input: RustProjectInput): Promise<Finding[]> {
  const project = await resolveRustProject(input);
  return project.files.flatMap((document) => analyzeDocument(document.path, document.content));
}
