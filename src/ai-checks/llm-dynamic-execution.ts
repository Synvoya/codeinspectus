/**
 * Model SDK output reaching dynamic code or shell-string execution.
 *
 * Bounded to intrafile direct/split-variable flows and import-proven shell APIs. Global eval and
 * Function lookalikes are suppressed when visibly shadowed. Cross-file flows, custom model
 * wrappers, callback/stream accumulation, and indirect sink aliases are documented false negatives.
 */
import type { Finding } from "../types.js";
import { makeAiFinding } from "./finding.js";
import { collectFiles, lineOf, lineText } from "./walk.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
const RULE_ID = "ci-ai-llm-output-dynamic-execution";
const MAX_BALANCED_CHARS = 16_000;
const MODEL_CALL_RE =
  /\b(?:openai|client|ai|anthropic|llm|model|genai|genAI|cohere|groq|mistral)\b[\w.]*\.(?:chat\.completions\.(?:create|stream)|completions\.(?:create|stream)|messages\.(?:create|stream)|responses\.(?:create|stream)|generateContent|generateText|streamText|invoke|complete|chat)\s*\(|\b(?:generateText|streamText|generateContent|generateObject|streamObject)\s*\(/;
const MODEL_OUTPUT_RE =
  /\.output_text\b|\.choices\s*\[[^\]]+\]\s*\.message\s*\.content\b|\.content\s*\[[^\]]+\]\s*\.text\b/;
const VALIDATED_RE =
  /\b(?:validate|sanitize|allowlist|approved|safe|assertSafe|parseModel|parseCode|parseCommand)[A-Za-z0-9_$]*\s*\(|\b[A-Za-z_$][\w$]*(?:Schema|Validator)\s*\.\s*(?:parse|safeParse)\s*\(/i;

interface FunctionSpan {
  start: number;
  bodyStart: number;
  end: number;
  params: string[];
}

interface Sink {
  index: number;
  expression: string;
  kind: "code" | "shell";
}

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

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
      chars[i] = chars[i + 1] = " ";
      i += 2;
      while (i < chars.length && chars[i] !== "\n") chars[i++] = " ";
      i--;
    } else if (char === "/" && next === "*") {
      chars[i] = chars[i + 1] = " ";
      i += 2;
      while (i < chars.length && !(chars[i] === "*" && chars[i + 1] === "/")) {
        if (chars[i] !== "\n") chars[i] = " ";
        i++;
      }
      if (i < chars.length) chars[i] = chars[i + 1] = " ";
      i++;
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
    if (char === "'" || char === '"' || char === "`") quote = char;
    else if (char === left) depth++;
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

function parseFunctions(source: string): FunctionSpan[] {
  const found: FunctionSpan[] = [];
  for (const match of source.matchAll(/\b(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(/g)) {
    const start = match.index ?? 0;
    const open = start + match[0].lastIndexOf("(");
    const close = balancedClose(source, open, "(", ")");
    if (close === undefined) continue;
    const bodyOffset = source.slice(close + 1).search(/\S/);
    if (bodyOffset < 0) continue;
    const bodyStart = close + 1 + bodyOffset;
    const end = balancedClose(source, bodyStart, "{", "}");
    if (end === undefined) continue;
    const params = splitTopLevel(source.slice(open + 1, close))
      .map((part) => /^\s*(?:\.\.\.\s*)?([A-Za-z_$][\w$]*)/.exec(part)?.[1] ?? "")
      .filter(Boolean);
    found.push({ start, bodyStart, end, params });
  }
  return found;
}

function enclosingFunction(functions: FunctionSpan[], index: number): FunctionSpan | undefined {
  return functions
    .filter((fn) => index > fn.bodyStart && index < fn.end)
    .sort((a, b) => a.end - a.start - (b.end - b.start))[0];
}

function identifiers(expression: string): Set<string> {
  const found = new Set<string>();
  for (const match of expression.matchAll(/\b[A-Za-z_$][\w$]*\b/g)) found.add(match[0]);
  return found;
}

function lhsIdentifiers(lhs: string): string[] {
  if (!lhs.trim().startsWith("{")) return [lhs.trim()];
  return lhs
    .slice(1, -1)
    .split(",")
    .map((part) => part.split(":").pop()?.trim().match(/^[A-Za-z_$][\w$]*/)?.[0] ?? "")
    .filter(Boolean);
}

function collectModelTaint(source: string): Set<string> {
  const assignments = [...source.matchAll(
    /\b(?:const|let|var)\s+(\{[^}\n]{1,300}\}|[A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)/g,
  )];
  const tainted = new Set<string>();
  let changed = true;
  let passes = 0;
  while (changed && passes++ < 8) {
    changed = false;
    for (const assignment of assignments) {
      const rhs = assignment[2] ?? "";
      if (VALIDATED_RE.test(rhs)) continue;
      const refs = identifiers(rhs);
      const model = MODEL_CALL_RE.test(rhs) || MODEL_OUTPUT_RE.test(rhs) || [...tainted].some((id) => refs.has(id));
      if (!model) continue;
      for (const id of lhsIdentifiers(assignment[1]!)) {
        if (!tainted.has(id)) {
          tainted.add(id);
          changed = true;
        }
      }
    }
  }
  return tainted;
}

function expressionIsModelOutput(expression: string, tainted: Set<string>): boolean {
  if (VALIDATED_RE.test(expression)) return false;
  if (MODEL_CALL_RE.test(expression) || MODEL_OUTPUT_RE.test(expression)) return true;
  const refs = identifiers(expression);
  return [...tainted].some((id) => refs.has(id));
}

function namedImports(source: string, modulePattern: string, names: Set<string>): Set<string> {
  const bindings = new Set<string>();
  const importRe = new RegExp(`\\bimport\\s*\\{([^}]+)\\}\\s*from\\s*["']${modulePattern}["']`, "g");
  const requireRe = new RegExp(`\\b(?:const|let|var)\\s*\\{([^}]+)\\}\\s*=\\s*require\\s*\\(\\s*["']${modulePattern}["']\\s*\\)`, "g");
  for (const match of [...source.matchAll(importRe), ...source.matchAll(requireRe)]) {
    for (const part of (match[1] ?? "").split(",")) {
      const specifier = /^\s*([A-Za-z_$][\w$]*)\s*(?:(?:as|:)\s*([A-Za-z_$][\w$]*))?\s*$/.exec(part);
      if (specifier && names.has(specifier[1]!)) bindings.add(specifier[2] ?? specifier[1]!);
    }
  }
  return bindings;
}

function isShadowed(source: string, functions: FunctionSpan[], index: number, name: string): boolean {
  const scope = enclosingFunction(functions, index);
  if (scope?.params.includes(name)) return true;
  const start = scope ? scope.bodyStart + 1 : 0;
  return new RegExp(`\\b(?:const|let|var|function|class)\\s+${escapeRe(name)}\\b`).test(source.slice(start, index));
}

function collectCalls(source: string, regex: RegExp, kind: Sink["kind"], localName?: string, functions: FunctionSpan[] = []): Sink[] {
  const calls: Sink[] = [];
  for (const match of source.matchAll(regex)) {
    const index = match.index ?? 0;
    if (localName && isShadowed(source, functions, index, localName)) continue;
    const open = index + match[0].lastIndexOf("(");
    const close = balancedClose(source, open, "(", ")");
    if (close === undefined) continue;
    const expression = splitTopLevel(source.slice(open + 1, close))[0]?.trim() ?? "";
    if (expression) calls.push({ index, expression, kind });
  }
  return calls;
}

function collectSinks(source: string, functions: FunctionSpan[]): Sink[] {
  const sinks: Sink[] = [];
  sinks.push(...collectCalls(source, /(?<![\w$.])eval\s*\(/g, "code", "eval", functions));
  sinks.push(...collectCalls(source, /(?<![\w$.])(?:new\s+)?Function\s*\(/g, "code", "Function", functions));
  const shell = namedImports(source, "(?:node:)?child_process", new Set(["exec", "execSync"]));
  const execa = namedImports(source, "execa", new Set(["execaCommand", "execaCommandSync"]));
  for (const name of [...shell, ...execa]) {
    sinks.push(
      ...collectCalls(source, new RegExp(`(?<![\\w$.])${escapeRe(name)}\\s*\\(`, "g"), "shell", name, functions),
    );
  }
  return sinks;
}

function makeFinding(file: string, original: string, sink: Sink): Finding {
  const line = lineOf(original, sink.index);
  const shell = sink.kind === "shell";
  return makeAiFinding({
    ruleId: RULE_ID,
    title: shell ? "Model output reaches shell-string execution" : "Model output reaches dynamic code execution",
    severity: "high",
    confidence: "medium",
    cwe: [shell ? "CWE-78" : "CWE-94", "CWE-1426"],
    owasp_llm: ["LLM05:2025"],
    file,
    startLine: line,
    snippet: lineText(original, line),
    message:
      `Model-generated output appears to reach ${shell ? "a shell-string API" : "eval/Function"} without a visible validated replacement. ` +
      "Treat model output as untrusted; this is bounded intrafile evidence and runtime controls still require manual verification.",
    remediation: {
      summary: shell
        ? "Do not construct shell commands from model output; map validated values to fixed executables and argument arrays."
        : "Do not evaluate model-generated code; map validated output to fixed, server-owned operations.",
      steps: [
        "Validate model output against a strict schema and server-owned allowlist.",
        shell
          ? "Use execFile/spawn with a fixed executable and separated arguments; do not enable a shell."
          : "Remove eval/Function and dispatch only to fixed implementations selected by an allowlisted identifier.",
        "Apply least privilege, isolation, and explicit approval before sensitive execution.",
      ],
      references: [
        shell ? "CWE-78" : "CWE-94",
        "CWE-1426",
        "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
      ],
    },
  });
}

export async function runLlmDynamicExecutionCheck(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false })) {
    const source = maskComments(file.content);
    if (!MODEL_CALL_RE.test(source)) continue;
    const tainted = collectModelTaint(source);
    if (tainted.size === 0) continue;
    const functions = parseFunctions(source);
    for (const sink of collectSinks(source, functions)) {
      if (expressionIsModelOutput(sink.expression, tainted)) findings.push(makeFinding(file.rel, file.content, sink));
    }
  }
  return findings;
}
