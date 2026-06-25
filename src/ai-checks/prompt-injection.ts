/**
 * §6.3 — Prompt-injection sinks in the user's code (CodeInspectus AI-code check).
 * CWE-1426 (improper handling of GenAI input); OWASP LLM01 (+ LLM06 with tool access).
 *
 * CG-06 rework. The CG-05 version fired whenever untrusted input appeared near an LLM
 * call — INCLUDING the safe pattern (input in a user-role message, no tools), which is
 * the documented mitigation (PRD §6.3). It produced 0 real-world true positives. This
 * version is ROLE-AWARE and TOOL-AWARE: it fires only at higher-risk positions.
 *
 * Detection contract — fixtures/prompt-injection-corpus/CONTRACT.md:
 *   FIRES when untrusted input (req.body/query/params, .json()/.text(), searchParams,
 *   process.argv, and values transitively derived from them) reaches EITHER
 *     (a) a SYSTEM position — a role:"system" content, an Anthropic top-level `system`
 *         param, a genai `systemInstruction`, or a single instruction+input `prompt`
 *         string (no message-role boundary)            -> medium, LLM01; OR
 *     (b) an LLM call that ALSO configures tools/function-calling (excessive agency),
 *         with untrusted input reaching the call anywhere -> high, LLM01 + LLM06.
 *   STAYS SILENT when untrusted input reaches ONLY a user-role message with no tools,
 *   when it is sanitized/validated first, or when there is no untrusted data. Ambiguous
 *   flows prefer silence (a false negative is safer than retraining users to ignore us).
 *
 * Honest framing (PRD §6.3): confidence is always `medium`; findings are worded
 * "potential prompt-injection sink." Scope: prompt-injection-specific only, NOT SAST.
 */

import type { Finding } from "../types.js";
import { collectFiles, lineOf, lineText } from "./walk.js";
import { makeAiFinding } from "./finding.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "py"];

// Untrusted-input sources (request-shaped; see CONTRACT "known blind spots").
const SOURCE_RE =
  /\b(?:req|request|ctx|context)\.(?:body|query|params|headers)\b|\b(?:req|request)\.(?:json|text|formData)\s*\(\s*\)|\bsearchParams\.get\s*\(|\bprocess\.argv\b|\b\w+\.(?:text|json)\s*\(\s*\)/;

// Sanitization / validation — input that passes through these is treated as clean.
const SANITIZE_RE =
  /\b(?:sanitize|escape|stripTags|DOMPurify|validate|allowlist|whitelist)\b|\.(?:safeParse|parse)\s*\(/i;

// LLM SDK sink calls. The trailing `(` is included so we can locate the argument list.
const SINK_RE =
  /\b(?:openai|client|ai|anthropic|llm|model|genai|genAI|cohere|groq|mistral)\b[\w.]*\.(?:chat\.completions\.(?:create|stream)|completions\.(?:create|stream)|messages\.(?:create|stream)|responses\.(?:create|stream)|generateContent|generateText|streamText|invoke|complete|chat)\s*\(|\b(?:generateText|streamText|generateContent|generateObject|streamObject)\s*\(/g;

// Tool / function-calling configuration in the call (excessive agency, LLM06).
const TOOLS_RE = /\btools\s*:|\bfunctions\s*:|\btool_choice\b|\bfunctionDeclarations\b|\bfunction_call\b/;

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Tainted variable names in a file. Seeds from direct source assignments, then
 * propagates transitively (a var derived from a tainted var). A value that flows
 * through a sanitizer (zod `.parse`, `sanitize`, ...) is NOT tainted.
 */
function collectTaintedVars(content: string): Set<string> {
  const tainted = new Set<string>();
  const assignRe = /(?:const|let|var)\s+(?:\{\s*([^}]+)\s*\}|([A-Za-z0-9_]+))\s*=\s*([^;\n]+)/g;
  let changed = true;
  let pass = 0;
  while (changed && pass++ < 6) {
    changed = false;
    for (const m of content.matchAll(assignRe)) {
      const rhs = m[3] ?? "";
      if (SANITIZE_RE.test(rhs)) continue; // sanitized -> derived var is clean
      const rhsTainted =
        SOURCE_RE.test(rhs) ||
        [...tainted].some((v) => new RegExp("\\b" + escapeRe(v) + "\\b").test(rhs));
      if (!rhsTainted) continue;
      const add = (id: string | undefined) => {
        const name = id?.trim();
        if (name && !tainted.has(name)) {
          tainted.add(name);
          changed = true;
        }
      };
      if (m[1]) for (const part of m[1].split(",")) add(part.split(":").pop()?.replace(/\s.*$/, ""));
      add(m[2]);
    }
    // Multiline template-literal assignments — `const sys = `...${tainted}...`` — whose
    // body spans newlines (a common system-prompt shape) that the line-bounded scan
    // above misses. taintRef keeps this strict (a bare word in static text won't taint).
    for (const m of content.matchAll(/(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(`[\s\S]*?`)/g)) {
      const name = m[1];
      if (name && !tainted.has(name) && m[2] && segHasTaint(m[2], tainted)) {
        tainted.add(name);
        changed = true;
      }
    }
  }
  return tainted;
}

/** The balanced `( ... )` argument string following a call's open paren. */
function extractCallArgs(content: string, openParenIdx: number): string {
  let depth = 0;
  const end = Math.min(content.length, openParenIdx + 6000);
  for (let i = openParenIdx; i < end; i++) {
    const c = content[i];
    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return content.slice(openParenIdx, i + 1);
  }
  return content.slice(openParenIdx, end);
}

/**
 * Is the tainted var `v` USED AS A REFERENCE in this segment — interpolation `${v}`,
 * a value position (`: v`, `, v`, `( v`, `+ v`, `return v`), or a concat `v +` — rather
 * than appearing as a bare word inside static string text? A var named `prompt`/
 * `message`/`content` must not match the English word in a static prompt (CG-06 FP).
 */
function taintRef(seg: string, v: string): boolean {
  const ev = escapeRe(v);
  return (
    new RegExp("\\$\\{[^}]*\\b" + ev + "\\b[^}]*\\}").test(seg) ||
    new RegExp("(?:[=:,([+]|=>|\\breturn|\\?\\?|\\|\\||&&)\\s*" + ev + "\\b").test(seg) ||
    new RegExp("\\b" + ev + "\\s*\\+").test(seg) ||
    new RegExp("^\\s*" + ev + "\\s*$").test(seg) // the segment IS the bare var value (e.g. `system: sysPrompt`)
  );
}

/** Does a segment carry untrusted input (an inline source, or a tainted var reference)? */
function segHasTaint(seg: string, tainted: Set<string>): boolean {
  if (SOURCE_RE.test(seg)) return true;
  for (const v of tainted) if (taintRef(seg, v)) return true;
  return false;
}

/** Contents of `role:"<role>"` message blocks within a call-args string. */
function roleContents(args: string, role: string): string[] {
  const re = new RegExp(
    "role\\s*:\\s*[\"'`]" + role + "[\"'`]([\\s\\S]*?)(?=role\\s*:\\s*[\"'`]|$)",
    "gi",
  );
  return [...args.matchAll(re)].map((m) => m[1] ?? "");
}

/** Top-level system positions with no role boundary: `system:` / `systemInstruction:`. */
function systemParamSegments(args: string): string[] {
  return [
    ...args.matchAll(
      /\b(?:systemInstruction|system)\s*:\s*([^,}\n][\s\S]{0,400}?)(?=,\s*[A-Za-z_]+\s*:|\n\s*[}\]]|$)/g,
    ),
  ].map((m) => m[1] ?? "");
}

/** A single instruction+input `prompt:` string: literal instructions mixed with taint. */
function promptIsInjectable(args: string, tainted: Set<string>): boolean {
  // Only the single-string-prompt shape (generateText/completions). A role-structured
  // call uses `messages:` — there, any "prompt:" is inside a message's content string
  // (e.g. `content: `prompt: ${x}``), NOT a config key, so it must not match here.
  if (/\bmessages\s*:/.test(args)) return false;
  const m = /\bprompt\s*:\s*(`[\s\S]*?`|"[\s\S]*?"|'[\s\S]*?'|[^,}\n]+)/.exec(args);
  if (!m) return false;
  const val = m[1] ?? "";
  if (!segHasTaint(val, tainted)) return false;
  const literals = val.replace(/\$\{[^}]*\}/g, " ").replace(/[`"']/g, " ");
  return /[A-Za-z]{4,}/.test(literals); // literal instruction text around the input
}

export async function runPromptInjectionCheck(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false });

  for (const f of files) {
    const content = f.content;
    SINK_RE.lastIndex = 0;
    if (!SINK_RE.test(content) || !SOURCE_RE.test(content)) continue; // cheap pre-filter

    const tainted = collectTaintedVars(content);

    SINK_RE.lastIndex = 0;
    for (const m of content.matchAll(SINK_RE)) {
      const sinkIdx = m.index ?? 0;
      const args = extractCallArgs(content, sinkIdx + m[0].length - 1); // m[0] ends with '('

      if (SANITIZE_RE.test(args)) continue; // sanitized inside the call
      if (!segHasTaint(args, tainted)) continue; // no untrusted input reaches this call

      const hasTools = TOOLS_RE.test(args);
      const systemSegs = [...roleContents(args, "system"), ...systemParamSegments(args)];
      const taintInSystem =
        systemSegs.some((s) => segHasTaint(s, tainted)) || promptIsInjectable(args, tainted);

      // Decide. Tool access dominates (the model can act on injected content). Then
      // system-position injection. Input only in a user-role message with no tools is
      // the documented-safe pattern -> stay silent.
      let severity: "high" | "medium";
      let owaspLlm: string[];
      let why: string;
      let titleSuffix: string;
      if (hasTools) {
        severity = "high";
        owaspLlm = ["LLM01:2025", "LLM06:2025"];
        why =
          " The same call grants the model tool/function-calling access, so a successful injection can trigger actions (excessive agency, LLM06).";
        titleSuffix = " with tool/function-calling access";
      } else if (taintInSystem) {
        severity = "medium";
        owaspLlm = ["LLM01:2025"];
        why =
          " The input reaches the system prompt / instruction context with no message-role boundary, so it can override the model's instructions.";
        titleSuffix = " (untrusted input in the system prompt)";
      } else {
        continue; // user-role message, no tools — the documented-safe pattern
      }

      const line = lineOf(content, sinkIdx);
      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-prompt-injection-sink",
          title: "Potential prompt-injection sink" + titleSuffix,
          severity,
          cwe: ["CWE-1426"],
          owasp_llm: owaspLlm,
          file: f.rel,
          startLine: line,
          snippet: lineText(content, line),
          message:
            "Untrusted input appears to reach an LLM call at a higher-risk position." +
            why +
            " Prompt-injection detection is heuristic — verify manually.",
          remediation: {
            summary:
              "Keep untrusted content as data in a separate user-role message, never concatenated into the system prompt; validate it first; and gate any tool actions.",
            steps: [
              "Do not concatenate request/user input into the system prompt or a single instruction string.",
              "Place untrusted content in its own user-role message and validate it first.",
              "For tool/function-calling, require confirmation before any sensitive action.",
            ],
            references: ["CWE-1426", "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"],
          },
          confidence: "medium",
        }),
      );
    }
  }

  return findings;
}
