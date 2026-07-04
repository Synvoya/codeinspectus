/**
 * LLM05 / A03 — untrusted input OR LLM/model output rendered as raw HTML without sanitization
 * (CodeInspectus AI-code check). CWE-79 (primary) + CWE-116; OWASP A03:2021; OWASP LLM05:2025 on
 * the model-output arm. The second community-intake detection (CG-51).
 *
 * The footgun: `dangerouslySetInnerHTML={{ __html: X }}` renders X as raw HTML with no escaping.
 * If X is untrusted user input (reflected/stored XSS) or LLM/model output (insecure output
 * handling, LLM05) and is not sanitized, it is a direct XSS sink. Opengrep's bundled ruleset
 * covers DOM sinks (innerHTML=, document.write) but DEFERS this React attribute (CG-50 Part-4) —
 * this rule fills that gap, it does not duplicate commodity SAST.
 *
 * Detection contract — fixtures/llm-dangerous-html-corpus/CONTRACT.md (frozen before this analyzer):
 *   FIRES when the __html value of the sink is tainted AND not sanitized, via
 *     ARM A (untrusted -> XSS, A03): req.body/query/params/headers, req.json()/text(),
 *            searchParams.get(), location.search/hash, process.argv, a fetched .text()/.json(); OR
 *     ARM B (model output -> LLM05, THE MOAT): an LLM SDK call (openai/anthropic/@google-genai/
 *            Vercel AI SDK) or a model-output accessor (.choices[].message.content, .content[].text).
 *   Inline and split-variable (intrafile taint) both fire.
 *   STAYS SILENT when the value is wrapped by a known sanitizer (DOMPurify.sanitize / sanitize-html /
 *   xss()), is a constant/trusted literal, or is not in __html (a text node / other attribute).
 *   Ambiguity prefers silence.
 *
 * Honest framing: confidence is `medium` (verify the source is actually untrusted/model-derived);
 * severity stays `high` (XSS into the DOM is real client compromise) — the hedge is in the wording.
 * Scope: intrafile only. Cross-file taint, the object-var-then-spread sink shape, and custom
 * sanitizer wrappers are documented false-negatives.
 *
 * The untrusted-source and LLM-SDK-call vocabularies below intentionally MIRROR (are duplicated
 * from) the frozen §6.3 prompt-injection analyzer rather than importing its module-local consts —
 * this keeps prompt-injection.ts untouched (§6.3 is a locked pillar).
 */

import type { Finding } from "../types.js";
import { collectFiles, lineOf, lineText } from "./walk.js";
import { makeAiFinding } from "./finding.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];

// The React raw-HTML sink: dangerouslySetInnerHTML={{ __html: X }}. X is captured up to the object
// close. An X that itself contains braces (e.g. an inline object arg) is a documented FN — rare.
const SINK_RE = /dangerouslySetInnerHTML\s*=\s*\{\{\s*(?:['"]?__html['"]?)\s*:\s*([^{}]+?)\s*\}\s*\}/g;

// Well-known HTML sanitizers — a wrapped value is safe even if the inner source is tainted.
const SANITIZE_RE =
  /\bDOMPurify\b|\bsanitize(?:Html|_html)?\s*\(|\bsanitizeHtml\b|\bxss\s*\(|\bescapeHtml\s*\(|\.\s*sanitize\s*\(/i;

// Untrusted-input sources — mirrors §6.3's SOURCE vocabulary, plus browser location.
const UNTRUSTED_RE =
  /\b(?:req|request|ctx|context)\.(?:body|query|params|headers)\b|\b(?:req|request)\.(?:json|text|formData)\s*\(\s*\)|\bsearchParams\.get\s*\(|\bprocess\.argv\b|\blocation\.(?:search|hash|href)\b|\bwindow\.location\b|\b\w+\.(?:text|json)\s*\(\s*\)/;

// LLM/model-output sources — mirrors §6.3's SDK-call recognition.
const LLM_CALL_RE =
  /\b(?:openai|client|ai|anthropic|llm|model|genai|genAI|cohere|groq|mistral)\b[\w.]*\.(?:chat\.completions\.(?:create|stream)|completions\.(?:create|stream)|messages\.(?:create|stream)|responses\.(?:create|stream)|generateContent|generateText|streamText|invoke|complete|chat)\s*\(|\b(?:generateText|streamText|generateContent|generateObject|streamObject)\s*\(/;

type Taint = "untrusted" | "model";

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Is any tainted var of `kind` referenced (as a word) in `expr`? */
function refsKind(expr: string, tainted: Map<string, Taint>, kind: Taint): boolean {
  for (const [v, k] of tainted) {
    if (k === kind && new RegExp("\\b" + escapeRe(v) + "\\b").test(expr)) return true;
  }
  return false;
}

/**
 * Vars carrying untrusted input or model output (intrafile, fixpoint). A value that flows through
 * a known sanitizer is NOT tainted. Model precedence: a var derived from a model source stays model.
 */
function collectTaint(content: string): Map<string, Taint> {
  const tainted = new Map<string, Taint>();
  const assignRe = /(?:const|let|var)\s+(?:\{\s*([^}]+?)\s*\}|([A-Za-z0-9_$]+))\s*=\s*([^;\n]+)/g;
  let changed = true;
  let pass = 0;
  while (changed && pass++ < 6) {
    changed = false;
    for (const m of content.matchAll(assignRe)) {
      const rhs = m[3] ?? "";
      if (SANITIZE_RE.test(rhs)) continue; // sanitized -> derived var is clean
      let kind: Taint | undefined;
      if (LLM_CALL_RE.test(rhs) || refsKind(rhs, tainted, "model")) kind = "model";
      else if (UNTRUSTED_RE.test(rhs) || refsKind(rhs, tainted, "untrusted")) kind = "untrusted";
      if (!kind) continue;
      const add = (id: string | undefined) => {
        const name = id?.split(":").pop()?.trim().replace(/\s.*$/, "");
        if (!name) return;
        if (tainted.get(name) === "model") return; // never downgrade model
        if (tainted.get(name) !== kind) {
          tainted.set(name, kind!);
          changed = true;
        }
      };
      if (m[1]) for (const part of m[1].split(",")) add(part);
      add(m[2]);
    }
  }
  return tainted;
}

/** Classify the __html expression. Sanitizer wins (silent); then model (arm B); then untrusted (arm A). */
function classify(x: string, tainted: Map<string, Taint>): "clean" | Taint | "trusted" {
  if (SANITIZE_RE.test(x)) return "clean";
  if (LLM_CALL_RE.test(x) || refsKind(x, tainted, "model")) return "model";
  if (UNTRUSTED_RE.test(x) || refsKind(x, tainted, "untrusted")) return "untrusted";
  return "trusted";
}

export async function runLlmDangerousHtmlCheck(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false });

  for (const f of files) {
    const content = f.content;
    if (!content.includes("dangerouslySetInnerHTML")) continue; // cheap pre-filter

    const tainted = collectTaint(content);
    const firedLines = new Set<number>();

    for (const m of content.matchAll(SINK_RE)) {
      const x = (m[1] ?? "").trim();
      const kind = classify(x, tainted);
      if (kind === "clean" || kind === "trusted") continue; // sanitized / constant -> silent

      const line = lineOf(content, m.index ?? 0);
      if (firedLines.has(line)) continue; // one finding per sink line
      firedLines.add(line);

      const model = kind === "model";
      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-llm-output-dangerous-html",
          title: "Untrusted or model output rendered as raw HTML via dangerouslySetInnerHTML",
          severity: "high",
          cwe: ["CWE-79", "CWE-116"],
          owasp_web: ["A03:2021"],
          // Arm B (model output) is the LLM05 insecure-output-handling case; arm A is plain XSS.
          owasp_llm: model ? ["LLM05:2025"] : undefined,
          file: f.rel,
          startLine: line,
          snippet: lineText(content, line),
          message:
            "Untrusted or model-generated content is rendered via dangerouslySetInnerHTML without " +
            "sanitization — a direct XSS sink. AI tools often render LLM output or user input as raw " +
            "HTML assuming it's safe. Sanitize with DOMPurify before rendering, or render as text. " +
            "Verify the source is actually untrusted/model-derived before treating as exploitable.",
          remediation: {
            summary:
              "Sanitize the value with DOMPurify before assigning it to __html, or render it as text " +
              "so React escapes it. Never pass untrusted or model-generated content to __html raw.",
            steps: [
              "Wrap the value: __html: DOMPurify.sanitize(value).",
              "Or drop dangerouslySetInnerHTML and render {value} as text (React escapes it).",
              "Treat model output like untrusted input — validate/sanitize before rendering as HTML.",
            ],
            code_suggestion:
              "import DOMPurify from 'dompurify'; // then: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(value) }}",
            references: [
              "CWE-79",
              "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
              "https://github.com/cure53/DOMPurify",
            ],
          },
          confidence: "medium",
        }),
      );
    }
  }

  return findings;
}
