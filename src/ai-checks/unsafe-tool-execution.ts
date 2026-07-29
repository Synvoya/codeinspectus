/**
 * Model-produced tool arguments reaching a Node shell sink without a visible approval or
 * validation boundary. This is deliberately narrower than general command injection:
 *
 *   - the file must contain a recognized LLM SDK call and a recognized tool-call result shape;
 *   - the sink must be import/require-proven child_process.exec or execSync (including a
 *     promisified alias);
 *   - dataflow is intrafile and supports one named local wrapper hop;
 *   - a checked approval/allowlist rejection gate or validated replacement value suppresses.
 *
 * CWE-78 is the concrete shell-injection risk. CWE-1426 captures the missing validation of
 * generative-AI output. OWASP LLM05 and LLM06 describe the output-handling and agency boundary.
 * Findings remain medium confidence because runtime sandboxing or approval may exist elsewhere.
 */

import type { Finding } from "../types.js";
import { makeAiFinding } from "./finding.js";
import { collectFiles, lineOf, lineText } from "./walk.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
const RULE_ID = "ci-ai-llm-tool-argument-command-execution";
const MAX_BALANCED_CHARS = 16_000;

interface Span {
  start: number;
  end: number;
}

interface FunctionSpan extends Span {
  name: string;
  params: string[];
  bodyStart: number;
}

interface Assignment {
  lhs: string;
  rhs: string;
}

interface ShellBindings {
  direct: Set<string>;
  namespaces: Set<string>;
}

interface ShellCall {
  calleeStart: number;
  openParen: number;
  closeParen: number;
  firstArg: string;
}

interface WrapperFlow {
  name: string;
  definition: FunctionSpan;
  sink: ShellCall;
  paramIndex: number;
}

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Replace comments with spaces while retaining source offsets, lines, and string literals. */
function maskComments(source: string): string {
  const chars = [...source];
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;

  for (let i = 0; i < chars.length; i++) {
    const char = chars[i]!;
    const next = chars[i + 1];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === "/" && next === "/") {
      chars[i] = " ";
      chars[i + 1] = " ";
      i += 2;
      while (i < chars.length && chars[i] !== "\n") chars[i++] = " ";
      i--;
      continue;
    }
    if (char === "/" && next === "*") {
      chars[i] = " ";
      chars[i + 1] = " ";
      i += 2;
      while (i < chars.length && !(chars[i] === "*" && chars[i + 1] === "/")) {
        if (chars[i] !== "\n") chars[i] = " ";
        i++;
      }
      if (i < chars.length) {
        chars[i] = " ";
        if (i + 1 < chars.length) chars[i + 1] = " ";
        i++;
      }
    }
  }
  return chars.join("");
}

function balancedClose(source: string, open: number, left: string, right: string): number | undefined {
  if (source[open] !== left) return undefined;
  let depth = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  const limit = Math.min(source.length, open + MAX_BALANCED_CHARS);
  for (let i = open; i < limit; i++) {
    const char = source[i]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === left) depth++;
    else if (char === right && --depth === 0) return i;
  }
  return undefined;
}

function splitTopLevel(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let round = 0;
  let square = 0;
  let curly = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  for (let i = 0; i < value.length; i++) {
    const char = value[i]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") quote = char;
    else if (char === "(") round++;
    else if (char === ")") round--;
    else if (char === "[") square++;
    else if (char === "]") square--;
    else if (char === "{") curly++;
    else if (char === "}") curly--;
    else if (char === "," && round === 0 && square === 0 && curly === 0) {
      parts.push(value.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

function simpleParams(value: string): string[] {
  return splitTopLevel(value).map((part) => {
    const match = /^\s*(?:\.\.\.\s*)?([A-Za-z_$][\w$]*)/.exec(part);
    return match?.[1] ?? "";
  });
}

function parseFunctions(source: string): FunctionSpan[] {
  const functions: FunctionSpan[] = [];
  const seen = new Set<string>();
  const add = (name: string, params: string, start: number, bodyStart: number) => {
    const end = balancedClose(source, bodyStart, "{", "}");
    if (end === undefined) return;
    const key = `${start}:${end}`;
    if (seen.has(key)) return;
    seen.add(key);
    functions.push({ name, params: simpleParams(params), start, bodyStart, end });
  };

  for (const match of source.matchAll(
    /\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g,
  )) {
    const start = match.index ?? 0;
    const openParen = start + match[0].lastIndexOf("(");
    const closeParen = balancedClose(source, openParen, "(", ")");
    if (closeParen === undefined) continue;
    const bodyStart = source.slice(closeParen + 1).search(/\S/) + closeParen + 1;
    if (source[bodyStart] !== "{") continue;
    add(match[1]!, source.slice(openParen + 1, closeParen), start, bodyStart);
  }
  for (const match of source.matchAll(
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*\{/g,
  )) {
    const bodyStart = (match.index ?? 0) + match[0].lastIndexOf("{");
    add(match[1]!, match[2] ?? match[3] ?? "", match.index ?? 0, bodyStart);
  }
  return functions;
}

function enclosingFunction(functions: FunctionSpan[], index: number): FunctionSpan | undefined {
  return functions
    .filter((fn) => index > fn.bodyStart && index < fn.end)
    .sort((a, b) => a.end - a.start - (b.end - b.start))[0];
}

function collectShellBindings(source: string): ShellBindings {
  const direct = new Set<string>();
  const namespaces = new Set<string>();
  const addSpecifiers = (specifiers: string) => {
    for (const specifier of specifiers.split(",")) {
      const match = /^\s*(execSync|exec)\s*(?:as|:)\s*([A-Za-z_$][\w$]*)\s*$/.exec(specifier);
      if (match) direct.add(match[2]!);
      else {
        const plain = /^\s*(execSync|exec)\s*$/.exec(specifier);
        if (plain) direct.add(plain[1]!);
      }
    }
  };

  for (const match of source.matchAll(
    /\bimport\s*\{([^}]+)\}\s*from\s*["'](?:node:)?child_process["']/g,
  )) addSpecifiers(match[1] ?? "");
  for (const match of source.matchAll(
    /\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/g,
  )) addSpecifiers(match[1] ?? "");

  for (const match of source.matchAll(
    /\bimport\s*\*\s*as\s*([A-Za-z_$][\w$]*)\s*from\s*["'](?:node:)?child_process["']/g,
  )) namespaces.add(match[1]!);
  for (const match of source.matchAll(
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/g,
  )) namespaces.add(match[1]!);

  // A common Promise wrapper. The underlying exec binding must already be proven.
  let changed = true;
  while (changed) {
    changed = false;
    for (const match of source.matchAll(
      /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[A-Za-z_$][\w$]*\.)?promisify\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g,
    )) {
      if (direct.has(match[2]!) && !direct.has(match[1]!)) {
        direct.add(match[1]!);
        changed = true;
      }
    }
  }
  return { direct, namespaces };
}

function callFirstArg(source: string, openParen: number): { closeParen: number; firstArg: string } | undefined {
  const closeParen = balancedClose(source, openParen, "(", ")");
  if (closeParen === undefined) return undefined;
  const args = source.slice(openParen + 1, closeParen);
  return { closeParen, firstArg: splitTopLevel(args)[0]?.trim() ?? "" };
}

function shellCalls(
  source: string,
  bindings: ShellBindings,
  functions: FunctionSpan[],
): ShellCall[] {
  const calls: ShellCall[] = [];
  const addMatches = (regex: RegExp, localName?: string) => {
    for (const match of source.matchAll(regex)) {
      const calleeStart = match.index ?? 0;
      const openParen = calleeStart + match[0].lastIndexOf("(");
      const call = callFirstArg(source, openParen);
      if (!call) continue;
      const scope = enclosingFunction(functions, calleeStart);
      if (localName && scope?.params.includes(localName)) continue; // imported binding is shadowed
      if (
        localName &&
        scope &&
        new RegExp(`\\b(?:const|let|var|function|class)\\s+${escapeRe(localName)}\\b`).test(
          source.slice(scope.bodyStart + 1, calleeStart),
        )
      ) continue;
      calls.push({ calleeStart, openParen, closeParen: call.closeParen, firstArg: call.firstArg });
    }
  };

  for (const name of bindings.direct) {
    addMatches(new RegExp(`(?<![\\w$.])${escapeRe(name)}\\s*\\(`, "g"), name);
  }
  for (const namespace of bindings.namespaces) {
    addMatches(
      new RegExp(`\\b${escapeRe(namespace)}\\s*\\.\\s*(?:exec|execSync)\\s*\\(`, "g"),
      namespace,
    );
  }
  addMatches(
    /\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*(?:exec|execSync)\s*\(/g,
  );
  return calls;
}

function assignments(source: string): Assignment[] {
  const found: Assignment[] = [];
  const declaration = /\b(?:const|let|var)\s+(\{[^}\n]{1,300}\}|[A-Za-z_$][\w$]*)\s*=\s*/g;
  for (const match of source.matchAll(declaration)) {
    const expressionStart = (match.index ?? 0) + match[0].length;
    let round = 0;
    let square = 0;
    let curly = 0;
    let quote: "'" | '"' | "`" | undefined;
    let escaped = false;
    let end = expressionStart;
    const limit = Math.min(source.length, expressionStart + 4_000);
    for (; end < limit; end++) {
      const char = source[end]!;
      if (quote) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === quote) quote = undefined;
        continue;
      }
      if (char === "'" || char === '"' || char === "`") quote = char;
      else if (char === "(") round++;
      else if (char === ")") round--;
      else if (char === "[") square++;
      else if (char === "]") square--;
      else if (char === "{") curly++;
      else if (char === "}") curly--;
      else if ((char === ";" || char === "\n") && round === 0 && square === 0 && curly === 0) break;
    }
    const rhs = source.slice(expressionStart, end).trim();
    if (rhs) found.push({ lhs: match[1]!, rhs });
  }
  return found;
}

/** Identifiers used as code, excluding words inside ordinary strings; template ${...} is code. */
function referencedIdentifiers(expression: string): Set<string> {
  const refs = new Set<string>();
  let i = 0;
  let quote: "'" | '"' | undefined;
  let escaped = false;
  while (i < expression.length) {
    const char = expression[i]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      i++;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      i++;
      continue;
    }
    if (char === "`") {
      const end = expression.indexOf("`", i + 1);
      const templateEnd = end === -1 ? expression.length : end;
      const template = expression.slice(i + 1, templateEnd);
      for (const interpolation of template.matchAll(/\$\{([\s\S]*?)\}/g)) {
        for (const ref of referencedIdentifiers(interpolation[1] ?? "")) refs.add(ref);
      }
      i = templateEnd + 1;
      continue;
    }
    const identifier = /^[A-Za-z_$][\w$]*/.exec(expression.slice(i));
    if (identifier) {
      refs.add(identifier[0]);
      i += identifier[0].length;
    } else i++;
  }
  return refs;
}

function lhsIdentifiers(lhs: string): string[] {
  if (!lhs.trim().startsWith("{")) return [lhs.trim()];
  return lhs
    .slice(1, -1)
    .split(",")
    .map((part) => part.split(":").pop()?.trim().match(/^[A-Za-z_$][\w$]*/)?.[0] ?? "")
    .filter(Boolean);
}

function compactExpression(expression: string): string {
  return expression.replace(/\s+/g, "").replace(/\?\./g, ".");
}

function isToolObjectSource(expression: string): boolean {
  const compact = compactExpression(expression);
  return (
    /\.choices\[[^\]]+\]\.message\.(?:function_call|tool_calls\[[^\]]+\])/.test(compact) ||
    (/\.output\.(?:find|filter)\(/.test(compact) && /["']function_call["']/.test(expression)) ||
    (/\.content\.(?:find|filter)\(/.test(compact) && /["']tool_use["']/.test(expression)) ||
    /\.functionCalls\(\)\[[^\]]+\]/.test(compact)
  );
}

function isModelArgumentExpression(expression: string, toolAliases: Set<string>): boolean {
  const compact = compactExpression(expression);
  for (const alias of toolAliases) {
    const base = escapeRe(alias);
    if (new RegExp(`\\b${base}(?:\\.function)?\\.arguments\\b`).test(compact)) return true;
    if (new RegExp(`\\b${base}\\.(?:input|args)\\b`).test(compact)) return true;
  }
  return (
    /\.choices\[[^\]]+\]\.message\.(?:function_call\.arguments|tool_calls\[[^\]]+\]\.function\.arguments)/.test(compact) ||
    /\.output\[[^\]]+\]\.arguments\b/.test(compact) ||
    /\.content\[[^\]]+\]\.input\b/.test(compact) ||
    /\.functionCalls\(\)\[[^\]]+\]\.args\b/.test(compact)
  );
}

function isValidatedReplacement(expression: string): boolean {
  return (
    /\b(?:validate|sanitize|allowlist|approved|safe|assertSafe|parseTool|parseCommand)[A-Za-z0-9_$]*\s*\(/i.test(expression) ||
    /\b[A-Za-z_$][\w$]*(?:Schema|Validator)\s*\.\s*(?:parse|safeParse)\s*\(/.test(expression)
  );
}

function hasLlmSdkCall(source: string): boolean {
  return /\.(?:createChatCompletion|chat\.completions\.(?:create|stream)|responses\.(?:create|stream)|messages\.(?:create|stream)|generateContent|generateText|streamText)\s*\(/.test(
    source,
  );
}

function collectModelTaint(source: string): Set<string> {
  const allAssignments = assignments(source);
  const toolAliases = new Set<string>();
  for (const assignment of allAssignments) {
    if (isToolObjectSource(assignment.rhs)) {
      for (const name of lhsIdentifiers(assignment.lhs)) toolAliases.add(name);
    }
  }

  const tainted = new Set<string>();
  let changed = true;
  let passes = 0;
  while (changed && passes++ < 8) {
    changed = false;
    for (const assignment of allAssignments) {
      if (isValidatedReplacement(assignment.rhs)) continue;
      const refs = referencedIdentifiers(assignment.rhs);
      if (
        !isModelArgumentExpression(assignment.rhs, toolAliases) &&
        ![...tainted].some((name) => refs.has(name))
      ) continue;
      for (const name of lhsIdentifiers(assignment.lhs)) {
        if (!tainted.has(name)) {
          tainted.add(name);
          changed = true;
        }
      }
    }
  }
  return tainted;
}

function expressionIsTainted(expression: string, tainted: Set<string>): boolean {
  const refs = referencedIdentifiers(expression);
  return [...tainted].some((name) => refs.has(name));
}

function rejectionGateBefore(prefix: string, expression: string, tainted: Set<string>): boolean {
  const refs = [...referencedIdentifiers(expression)].filter((name) => tainted.has(name));
  const ending = String.raw`\s*\)\s*(?:\{[\s\S]{0,320}?\b(?:return|throw|continue)\b|(?:return|throw|continue)\b)`;
  for (const name of refs) {
    const value = escapeRe(name);
    const checkCall = String.raw`(?:[A-Za-z_$][\w$]*\.)?(?:approve|confirm|authorize|allow|validate|permit|guard)[A-Za-z0-9_$]*\s*\([^)]*\b${value}\b[^)]*\)`;
    if (new RegExp(String.raw`\bif\s*\(\s*!\s*(?:await\s+)?${checkCall}${ending}`, "i").test(prefix)) {
      return true;
    }
    const allowedSet = String.raw`(?=[\w$]*(?:allow|safe|permit|approv))[A-Za-z_$][\w$]*\.has\s*\([^)]*\b${value}\b[^)]*\)`;
    if (new RegExp(String.raw`\bif\s*\(\s*!\s*${allowedSet}${ending}`, "i").test(prefix)) return true;

    for (const assignment of prefix.matchAll(
      new RegExp(
        String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?${checkCall}\s*;?`,
        "gi",
      ),
    )) {
      const result = escapeRe(assignment[1]!);
      const after = prefix.slice((assignment.index ?? 0) + assignment[0].length);
      if (new RegExp(String.raw`\bif\s*\(\s*!\s*${result}\b${ending}`, "i").test(after)) return true;
    }
  }
  return false;
}

function scopePrefix(
  source: string,
  functions: FunctionSpan[],
  index: number,
): string {
  const scope = enclosingFunction(functions, index);
  const start = Math.max(scope ? scope.bodyStart + 1 : 0, index - 6_000);
  return source.slice(start, index);
}

function wrapperFlows(
  source: string,
  functions: FunctionSpan[],
  calls: ShellCall[],
  tainted: Set<string>,
): WrapperFlow[] {
  const flows: WrapperFlow[] = [];
  for (const fn of functions) {
    for (const sink of calls.filter((call) => call.calleeStart > fn.bodyStart && call.calleeStart < fn.end)) {
      const refs = referencedIdentifiers(sink.firstArg);
      const paramIndex = fn.params.findIndex((param) => param && refs.has(param));
      if (paramIndex === -1) continue;
      const param = fn.params[paramIndex]!;
      if (rejectionGateBefore(source.slice(fn.bodyStart + 1, sink.calleeStart), param, new Set([param]))) {
        continue;
      }
      flows.push({ name: fn.name, definition: fn, sink, paramIndex });
    }
  }
  return flows;
}

function findingFor(file: string, source: string, sink: ShellCall): Finding {
  const line = lineOf(source, sink.calleeStart);
  return makeAiFinding({
    ruleId: RULE_ID,
    title: "Model-produced tool argument reaches shell execution",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-78", "CWE-1426"],
    owasp_llm: ["LLM05:2025", "LLM06:2025"],
    file,
    startLine: line,
    snippet: lineText(source, line),
    message:
      "A model-produced tool/function argument appears to reach import-proven child_process.exec/execSync without a visible checked approval, allowlist, or validated replacement value. This is bounded static evidence; verify runtime approval and sandboxing manually.",
    remediation: {
      summary:
        "Treat model tool arguments as untrusted: validate against a strict schema and server-owned allowlist, require approval for sensitive actions, and avoid shell command strings.",
      steps: [
        "Map a fixed tool name to a server-owned implementation; never let the model choose an executable or arbitrary shell string.",
        "Validate every argument against an allowlist/schema and reject unknown properties or values.",
        "Require explicit human approval before command execution and run allowed actions with least privilege in an isolated sandbox.",
        "Prefer execFile/spawn with a fixed executable and separated argument array over exec/execSync.",
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

export async function runUnsafeToolExecutionCheck(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false });

  for (const file of files) {
    const source = maskComments(file.content);
    if (!hasLlmSdkCall(source) || !/(?:function_call|tool_calls|tool_use|functionCalls)/.test(source)) {
      continue;
    }
    const bindings = collectShellBindings(source);
    if (bindings.direct.size === 0 && bindings.namespaces.size === 0 && !/require\s*\(\s*["'](?:node:)?child_process/.test(source)) {
      continue;
    }

    const functions = parseFunctions(source);
    const calls = shellCalls(source, bindings, functions);
    if (calls.length === 0) continue;
    const tainted = collectModelTaint(source);
    if (tainted.size === 0) continue;
    const emitted = new Set<number>();

    for (const sink of calls) {
      if (!expressionIsTainted(sink.firstArg, tainted)) continue;
      const prefix = scopePrefix(source, functions, sink.calleeStart);
      if (rejectionGateBefore(prefix, sink.firstArg, tainted)) continue;
      findings.push(findingFor(file.rel, file.content, sink));
      emitted.add(sink.calleeStart);
    }

    for (const flow of wrapperFlows(source, functions, calls, tainted)) {
      const callRe = new RegExp(`(?<![\\w$.])${escapeRe(flow.name)}\\s*\\(`, "g");
      for (const match of source.matchAll(callRe)) {
        const callStart = match.index ?? 0;
        if (callStart >= flow.definition.start && callStart <= flow.definition.bodyStart) continue;
        const openParen = callStart + match[0].lastIndexOf("(");
        const call = callFirstArg(source, openParen);
        if (!call) continue;
        const argument = splitTopLevel(source.slice(openParen + 1, call.closeParen))[flow.paramIndex]?.trim() ?? "";
        if (!expressionIsTainted(argument, tainted) && !isModelArgumentExpression(argument, new Set())) continue;
        if (rejectionGateBefore(scopePrefix(source, functions, callStart), argument, tainted)) continue;
        if (!emitted.has(flow.sink.calleeStart)) {
          findings.push(findingFor(file.rel, file.content, flow.sink));
          emitted.add(flow.sink.calleeStart);
        }
      }
    }
  }
  return findings;
}
