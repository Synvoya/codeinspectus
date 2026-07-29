/**
 * Exact OpenAI Go tool arguments reaching import-proven os/exec shell execution.
 * The analysis is intrafile, source ordered, and deliberately bounded to direct flow,
 * JSON-unmarshal aliases, one JSON parsing helper, and one local command wrapper.
 */

import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";
import { resolveGoProject, type GoProjectInput } from "./project.js";

export const GO_UNSAFE_TOOL_EXECUTION_RULE_ID =
  "ci-go-llm-tool-argument-command-execution";

const MAX_BALANCED_CHARS = 64_000;

interface FunctionSpan {
  name: string;
  params: string[];
  start: number;
  bodyStart: number;
  end: number;
}

interface Assignment {
  names: string[];
  rhs: string;
  start: number;
}

interface SinkCall {
  start: number;
  end: number;
  value: string;
}

interface ParseWrapper {
  name: string;
  paramIndex: number;
}

interface CommandWrapper {
  fn: FunctionSpan;
  paramIndex: number;
  sink: SinkCall;
}

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Mask comments without moving offsets; reject malformed strings/comments. */
function maskGoComments(input: string): { source: string; valid: boolean } {
  const chars = [...input];
  let quote: '"' | "'" | "`" | undefined;
  let escaped = false;
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    const next = chars[index + 1];
    if (quote) {
      if (quote === "`") {
        if (char === "`") quote = undefined;
        continue;
      }
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      else if (char === "\n" || char === "\r") return { source: chars.join(""), valid: false };
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
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
  let quote: '"' | "'" | "`" | undefined;
  let escaped = false;
  const limit = Math.min(source.length, open + MAX_BALANCED_CHARS);
  for (let index = open; index < limit; index++) {
    const char = source[index]!;
    if (quote) {
      if (quote === "`") {
        if (char === "`") quote = undefined;
        continue;
      }
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") quote = char;
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
  let quote: '"' | "'" | "`" | undefined;
  let escaped = false;
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (quote) {
      if (quote === "`") {
        if (char === "`") quote = undefined;
        continue;
      }
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") quote = char;
    else if (char === "(") round++;
    else if (char === ")") round--;
    else if (char === "[") square++;
    else if (char === "]") square--;
    else if (char === "{") curly++;
    else if (char === "}") curly--;
    else if (char === "," && round === 0 && square === 0 && curly === 0) {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

function params(value: string): string[] {
  return splitTopLevel(value).flatMap((part) => {
    const beforeType = part.trim().split(/\s+/).slice(0, -1).join(" ");
    const names = beforeType || part.trim().match(/^([A-Za-z_]\w*)\s+/)?.[1] || "";
    return names.split(",").map((name) => name.trim()).filter((name) => /^[A-Za-z_]\w*$/.test(name));
  });
}

function functions(source: string): FunctionSpan[] {
  const output: FunctionSpan[] = [];
  for (const match of source.matchAll(/\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(/g)) {
    const start = match.index ?? 0;
    const open = start + match[0].lastIndexOf("(");
    const close = balancedClose(source, open, "(", ")");
    if (close === undefined) continue;
    let bodyStart = close + 1;
    let quote: '"' | "'" | "`" | undefined;
    let escaped = false;
    for (; bodyStart < Math.min(source.length, close + 2_000); bodyStart++) {
      const char = source[bodyStart]!;
      if (quote) {
        if (quote === "`") {
          if (char === "`") quote = undefined;
          continue;
        }
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === quote) quote = undefined;
        continue;
      }
      if (char === '"' || char === "'" || char === "`") quote = char;
      else if (char === "{") break;
      else if (char === ";") break;
    }
    if (source[bodyStart] !== "{") continue;
    const end = balancedClose(source, bodyStart, "{", "}");
    if (end === undefined) continue;
    output.push({
      name: match[1]!,
      params: params(source.slice(open + 1, close)),
      start,
      bodyStart,
      end,
    });
  }
  return output;
}

function importAliases(source: string): Map<string, Set<string>> {
  const aliases = new Map<string, Set<string>>();
  const add = (path: string, alias?: string) => {
    const segments = path.split("/");
    const packageSegment = /^v\d+$/.test(segments.at(-1) ?? "")
      ? segments.at(-2)
      : segments.at(-1);
    const effective = alias || (packageSegment === "openai-go" ? "openai" : packageSegment) || "";
    if (!effective || effective === "." || effective === "_") return;
    const values = aliases.get(path) ?? new Set<string>();
    values.add(effective);
    aliases.set(path, values);
  };
  for (const match of source.matchAll(/\bimport\s+(?:([A-Za-z_]\w*|[._])\s+)?"([^"]+)"/g)) {
    add(match[2]!, match[1]);
  }
  for (const block of source.matchAll(/\bimport\s*\(([\s\S]*?)\)/g)) {
    for (const match of (block[1] ?? "").matchAll(/(?:^|\n)\s*(?:([A-Za-z_]\w*|[._])\s+)?"([^"]+)"/g)) {
      add(match[2]!, match[1]);
    }
  }
  return aliases;
}

function aliasesFor(imports: Map<string, Set<string>>, pathPattern: RegExp): Set<string> {
  const output = new Set<string>();
  for (const [path, aliases] of imports) {
    if (pathPattern.test(path)) for (const alias of aliases) output.add(alias);
  }
  return output;
}

function assignments(source: string, fn: FunctionSpan): Assignment[] {
  const output: Assignment[] = [];
  const body = source.slice(fn.bodyStart + 1, fn.end);
  const declaration = /(?:^|[;{}\n])\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|=(?!=))\s*/gm;
  for (const match of body.matchAll(declaration)) {
    const start = fn.bodyStart + 1 + (match.index ?? 0) + match[0].lastIndexOf(match[1]!);
    const expressionStart = fn.bodyStart + 1 + (match.index ?? 0) + match[0].length;
    let round = 0;
    let square = 0;
    let curly = 0;
    let quote: '"' | "'" | "`" | undefined;
    let escaped = false;
    let end = expressionStart;
    for (; end < Math.min(fn.end, expressionStart + 16_000); end++) {
      const char = source[end]!;
      if (quote) {
        if (quote === "`") {
          if (char === "`") quote = undefined;
          continue;
        }
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === quote) quote = undefined;
        continue;
      }
      if (char === '"' || char === "'" || char === "`") quote = char;
      else if (char === "(") round++;
      else if (char === ")") round--;
      else if (char === "[") square++;
      else if (char === "]") square--;
      else if (char === "{") curly++;
      else if (char === "}") {
        if (curly === 0 && round === 0 && square === 0) break;
        curly--;
      } else if ((char === "\n" || char === ";") && round === 0 && square === 0 && curly === 0) {
        break;
      }
    }
    const rhs = source.slice(expressionStart, end).trim();
    if (!rhs) continue;
    output.push({
      names: match[1]!.split(",").map((name) => name.trim()).filter((name) => name !== "_"),
      rhs,
      start,
    });
  }
  return output.sort((left, right) => left.start - right.start);
}

function refs(expression: string): Set<string> {
  const output = new Set<string>();
  let quote: '"' | "'" | "`" | undefined;
  let escaped = false;
  for (let index = 0; index < expression.length;) {
    const char = expression[index]!;
    if (quote) {
      if (quote === "`") {
        if (char === "`") quote = undefined;
        index++;
        continue;
      }
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      index++;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      quote = char;
      index++;
      continue;
    }
    const identifier = /^[A-Za-z_]\w*/.exec(expression.slice(index));
    if (identifier) {
      output.add(identifier[0]);
      index += identifier[0].length;
    } else index++;
  }
  return output;
}

function compact(value: string): string {
  return value.replace(/\s+/g, "");
}

function hasPath(expression: string, root: string, suffix: RegExp): boolean {
  return new RegExp(`\\b${escapeRe(root)}${suffix.source}`).test(compact(expression));
}

function sourceArgument(
  expression: string,
  responses: ReadonlySet<string>,
  toolObjects: ReadonlySet<string>,
): boolean {
  const value = compact(expression);
  for (const response of responses) {
    if (hasPath(value, response, /\.Choices\[[^\]]+\]\.Message\.ToolCalls\[[^\]]+\]\.Function\.Arguments/)) {
      return true;
    }
  }
  for (const tool of toolObjects) {
    if (new RegExp(`\\b${escapeRe(tool)}\\.Function\\.Arguments\\b`).test(value)) return true;
  }
  return false;
}

function toolCollection(expression: string, responses: ReadonlySet<string>): boolean {
  const value = compact(expression);
  return [...responses].some((response) =>
    new RegExp(`\\b${escapeRe(response)}\\.Choices\\[[^\\]]+\\]\\.Message\\.ToolCalls\\b`).test(value)
  );
}

function validatedReplacement(expression: string): boolean {
  return /\b(?:validate|sanitize|allowlist|approved|safe|permit|authorize)[A-Za-z0-9_]*\s*\(/i.test(expression) &&
    !/\bjson\.Unmarshal\s*\(/.test(expression);
}

function parseWrappers(source: string, fns: readonly FunctionSpan[], jsonAliases: ReadonlySet<string>): ParseWrapper[] {
  const output: ParseWrapper[] = [];
  for (const fn of fns) {
    const body = source.slice(fn.bodyStart + 1, fn.end);
    for (let index = 0; index < fn.params.length; index++) {
      const parameter = fn.params[index]!;
      for (const jsonAlias of jsonAliases) {
        const unmarshal = new RegExp(
          `\\b${escapeRe(jsonAlias)}\\.Unmarshal\\s*\\(\\s*(?:\\[\\]byte\\s*\\(\\s*)?${escapeRe(parameter)}\\s*\\)?\\s*,\\s*&\\s*([A-Za-z_]\\w*)\\s*\\)`,
        );
        const match = unmarshal.exec(body);
        if (!match) continue;
        if (new RegExp(`\\breturn\\s+${escapeRe(match[1]!)}\\b`).test(body.slice(match.index))) {
          output.push({ name: fn.name, paramIndex: index });
        }
      }
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

function directUnmarshalTargets(
  body: string,
  jsonAliases: ReadonlySet<string>,
  tainted: ReadonlySet<string>,
  responses: ReadonlySet<string>,
  tools: ReadonlySet<string>,
): string[] {
  const targets: string[] = [];
  for (const jsonAlias of jsonAliases) {
    const regex = new RegExp(`\\b${escapeRe(jsonAlias)}\\.Unmarshal\\s*\\(`, "g");
    for (const match of body.matchAll(regex)) {
      const open = (match.index ?? 0) + match[0].lastIndexOf("(");
      const close = balancedClose(body, open, "(", ")");
      if (close === undefined) continue;
      const args = splitTopLevel(body.slice(open + 1, close));
      const source = args[0] ?? "";
      const target = /^\s*&\s*([A-Za-z_]\w*)\s*$/.exec(args[1] ?? "")?.[1];
      if (!target) continue;
      const sourceRefs = refs(source);
      if (
        sourceArgument(source, responses, tools) ||
        [...tainted].some((name) => sourceRefs.has(name))
      ) targets.push(target);
    }
  }
  return targets;
}

function staticGoString(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.startsWith("`") && trimmed.endsWith("`") && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  if (!trimmed.startsWith('"') || !trimmed.endsWith('"')) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

function sinkCalls(
  source: string,
  fn: FunctionSpan,
  execAliases: ReadonlySet<string>,
): SinkCall[] {
  const output: SinkCall[] = [];
  const body = source.slice(fn.bodyStart + 1, fn.end);
  for (const execAlias of execAliases) {
    const regex = new RegExp(`\\b${escapeRe(execAlias)}\\.(Command|CommandContext)\\s*\\(`, "g");
    for (const match of body.matchAll(regex)) {
      const relativeStart = match.index ?? 0;
      const start = fn.bodyStart + 1 + relativeStart;
      const prefix = source.slice(fn.bodyStart + 1, start);
      if (
        new RegExp(`(?:\\b(?:var|const|type)\\s+${escapeRe(execAlias)}\\b|\\b${escapeRe(execAlias)}\\s*:=)`).test(prefix)
      ) continue;
      const open = start + match[0].lastIndexOf("(");
      const close = balancedClose(source, open, "(", ")");
      if (close === undefined) continue;
      const args = splitTopLevel(source.slice(open + 1, close));
      const offset = match[1] === "CommandContext" ? 1 : 0;
      const executable = staticGoString(args[offset] ?? "")?.toLowerCase();
      const flag = staticGoString(args[offset + 1] ?? "")?.toLowerCase();
      const shell = ["sh", "bash", "dash", "zsh", "ksh"].includes(executable ?? "") && flag === "-c";
      const windows = ["cmd", "cmd.exe"].includes(executable ?? "") && flag === "/c";
      const powershell = ["powershell", "powershell.exe", "pwsh", "pwsh.exe"].includes(executable ?? "") &&
        ["-c", "-command"].includes(flag ?? "");
      if (!shell && !windows && !powershell) continue;
      output.push({ start, end: close, value: args[offset + 2]?.trim() ?? "" });
    }
  }
  return output;
}

function rejectingGuard(prefix: string, value: string, tainted: ReadonlySet<string>): boolean {
  const used = [...refs(value)].filter((name) => tainted.has(name));
  if (used.length === 0) return false;
  const terminates = String.raw`\{[\s\S]{0,500}?\b(?:return|continue|break|panic\s*\()`;
  for (const name of used) {
    const escaped = escapeRe(name);
    const approval = String.raw`(?:approve|confirm|authorize|allow|permit|validate)[A-Za-z0-9_]*\s*\([^)]*\b${escaped}\b[^)]*\)`;
    if (new RegExp(String.raw`\bif\s*!\s*${approval}\s*${terminates}`, "i").test(prefix)) return true;
    for (const match of prefix.matchAll(new RegExp(
      String.raw`\b([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*)?\s*:=\s*${approval}`,
      "gi",
    ))) {
      const approved = escapeRe(match[1]!);
      const after = prefix.slice((match.index ?? 0) + match[0].length);
      if (new RegExp(String.raw`\bif\s+(?:[^\{]{0,200}\|\|\s*)?!\s*${approved}\b[^\{]*${terminates}`, "i").test(after)) {
        return true;
      }
    }
    for (const match of prefix.matchAll(new RegExp(
      String.raw`\b_\s*,\s*([A-Za-z_]\w*)\s*:=\s*(?=\w*(?:allow|safe|permit|approv))[A-Za-z_]\w*\s*\[\s*${escaped}(?:\s*\.\s*[A-Za-z_]\w*)*\s*\]`,
      "gi",
    ))) {
      const okay = escapeRe(match[1]!);
      const after = prefix.slice((match.index ?? 0) + match[0].length);
      if (new RegExp(String.raw`\bif\s*!\s*${okay}\b[^\{]*${terminates}`, "i").test(after)) return true;
    }
  }
  return false;
}

function commandWrappers(
  source: string,
  fns: readonly FunctionSpan[],
  execAliases: ReadonlySet<string>,
): CommandWrapper[] {
  const output: CommandWrapper[] = [];
  for (const fn of fns) {
    for (const sink of sinkCalls(source, fn, execAliases)) {
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

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < source.length; cursor++) {
    if (source[cursor] === "\n") line++;
  }
  return line;
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: GO_UNSAFE_TOOL_EXECUTION_RULE_ID,
    title: "Go model-produced tool argument reaches shell execution",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-78", "CWE-1426"],
    owasp_llm: ["LLM05:2025", "LLM06:2025"],
    file,
    startLine: line,
    snippet: "Model-produced tool argument reaches a Go shell sink [VALUE REDACTED]",
    message:
      "An OpenAI model-produced tool argument reaches import-proven Go os/exec shell execution without a visible checked approval, allowlist, or validated replacement value. This is bounded repository evidence; verify runtime sandboxing and authorization manually.",
    remediation: {
      summary:
        "Treat model tool arguments as untrusted; map fixed tool names to server-owned actions and avoid shell command strings.",
      steps: [
        "Validate tool arguments with a strict schema and an explicit server-owned allowlist.",
        "Require human approval before command execution and reject when approval infrastructure is unavailable.",
        "Prefer exec.CommandContext with a fixed executable and separated argument values, without a shell interpreter.",
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
  const masked = maskGoComments(input);
  if (!masked.valid) return [];
  const source = masked.source;
  const imports = importAliases(source);
  const openaiAliases = aliasesFor(imports, /^github\.com\/openai\/openai-go(?:\/v\d+)?$/);
  const execAliases = aliasesFor(imports, /^os\/exec$/);
  const jsonAliases = aliasesFor(imports, /^encoding\/json$/);
  if (openaiAliases.size === 0 || execAliases.size === 0 || jsonAliases.size === 0) return [];
  const fns = functions(source);
  const parseHelpers = parseWrappers(source, fns, jsonAliases);
  const wrappers = commandWrappers(source, fns, execAliases);
  const findings: Finding[] = [];
  const emitted = new Set<number>();

  for (const fn of fns) {
    const allAssignments = assignments(source, fn);
    const clients = new Set<string>();
    const responses = new Set<string>();
    const toolObjects = new Set<string>();
    const tainted = new Set<string>();
    const body = source.slice(fn.bodyStart + 1, fn.end);

    for (const assignment of allAssignments) {
      if ([...openaiAliases].some((alias) => new RegExp(`\\b${escapeRe(alias)}\\.NewClient\\s*\\(`).test(assignment.rhs))) {
        for (const name of assignment.names) clients.add(name);
      }
      if ([...clients].some((client) =>
        new RegExp(`\\b${escapeRe(client)}\\.(?:Chat\\.Completions|Responses)\\.New\\s*\\(`).test(compact(assignment.rhs))
      )) {
        if (assignment.names[0]) responses.add(assignment.names[0]);
      }
    }

    for (const loop of body.matchAll(/\bfor\s+(?:[A-Za-z_]\w*|_)\s*,\s*([A-Za-z_]\w*)\s*:=\s*range\s+([^\n{]+)\{/g)) {
      if (toolCollection(loop[2] ?? "", responses)) toolObjects.add(loop[1]!);
    }
    for (const assignment of allAssignments) {
      if (toolCollection(assignment.rhs, responses) && /\[[^\]]+\]/.test(assignment.rhs)) {
        for (const name of assignment.names) toolObjects.add(name);
      }
    }

    let changed = true;
    let passes = 0;
    while (changed && passes++ < 8) {
      changed = false;
      for (const assignment of allAssignments) {
        if (validatedReplacement(assignment.rhs)) continue;
        const used = refs(assignment.rhs);
        let carries = sourceArgument(assignment.rhs, responses, toolObjects) ||
          [...tainted].some((name) => used.has(name));
        for (const helper of parseHelpers) {
          const args = callArguments(assignment.rhs, helper.name);
          const value = args?.[helper.paramIndex];
          if (value && (sourceArgument(value, responses, toolObjects) || [...tainted].some((name) => refs(value).has(name)))) {
            carries = true;
          }
        }
        if (!carries) continue;
        for (const name of assignment.names) {
          if (!tainted.has(name)) {
            tainted.add(name);
            changed = true;
          }
        }
      }
      for (const name of directUnmarshalTargets(body, jsonAliases, tainted, responses, toolObjects)) {
        if (!tainted.has(name)) {
          tainted.add(name);
          changed = true;
        }
      }
    }

    for (const sink of sinkCalls(source, fn, execAliases)) {
      if (![...tainted].some((name) => refs(sink.value).has(name)) && !sourceArgument(sink.value, responses, toolObjects)) {
        continue;
      }
      if (rejectingGuard(source.slice(fn.bodyStart + 1, sink.start), sink.value, tainted)) continue;
      findings.push(finding(path, lineOf(input, sink.start)));
      emitted.add(sink.start);
    }

    for (const wrapper of wrappers) {
      const regex = new RegExp(`\\b${escapeRe(wrapper.fn.name)}\\s*\\(`, "g");
      for (const match of body.matchAll(regex)) {
        const callStart = fn.bodyStart + 1 + (match.index ?? 0);
        if (callStart >= wrapper.fn.start && callStart <= wrapper.fn.end) continue;
        const open = callStart + match[0].lastIndexOf("(");
        const close = balancedClose(source, open, "(", ")");
        if (close === undefined) continue;
        const argument = splitTopLevel(source.slice(open + 1, close))[wrapper.paramIndex] ?? "";
        if (![...tainted].some((name) => refs(argument).has(name)) && !sourceArgument(argument, responses, toolObjects)) {
          continue;
        }
        if (rejectingGuard(source.slice(fn.bodyStart + 1, callStart), argument, tainted)) continue;
        if (!emitted.has(wrapper.sink.start)) {
          findings.push(finding(path, lineOf(input, wrapper.sink.start)));
          emitted.add(wrapper.sink.start);
        }
      }
    }
  }
  return findings;
}

export async function runGoUnsafeToolExecution(input: GoProjectInput): Promise<Finding[]> {
  const project = await resolveGoProject(input);
  return project.files.flatMap((document) => analyzeDocument(document.path, document.content));
}
