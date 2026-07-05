# Example report — AI chatbot / RAG app

> **This is an illustrative example/demo report, not a real audit.** The findings,
> paths, and values below are synthetic and exist only to show the *shape* of
> CodeInspectus output. Run `codeinspectus_scan` on your own repo for real results.
> Prompt-injection detection is heuristic and immature — such findings are worded
> "potential …" and marked medium confidence.

**Target:** `example-chatbot/` (synthetic) · **Profile:** Next.js + OpenAI + vector store
**Scan:** local · zero network egress at scan time

## Summary

| Severity | Count |
|----------|-------|
| High     | 2 |
| Medium   | 2 |

## Findings (CWE-keyed)

### 1. Model output rendered as raw HTML — **high**
- **Rule:** `ci-ai-llm-output-dangerous-html` · **CWE-79/116** · OWASP **LLM05** · confidence: medium
- **Where:** `components/ChatMessage.tsx:18` — model output passed to React's raw inner-HTML prop
- **What:** LLM/model output is rendered as raw HTML without sanitization — a direct XSS sink.
- **Fix:** Wrap the value in `DOMPurify.sanitize(...)`, or render as text/markdown with a safe renderer.

### 2. Client-exposed AI provider key — **high**
- **Rule:** `ci-ai-client-secret-exposure` · **CWE-522** · confidence: high
- **Where:** `.env.local` — `NEXT_PUBLIC_OPENAI_API_KEY=<redacted>`
- **What:** The `NEXT_PUBLIC_` prefix ships this key to the browser, where anyone can read and abuse it.
- **Fix:** Remove the prefix; call the provider from a server route and keep the key server-side.

### 3. Potential prompt-injection sink into a tool call — **medium**
- **Rule:** `ci-ai-prompt-injection-sink` · **CWE-77** · confidence: medium (heuristic)
- **Where:** `app/api/agent/route.ts:41`
- **What:** Retrieved document text is concatenated into a system prompt that can trigger tool
  execution, with no delimiter/whitelist between untrusted context and instructions.
- **Fix:** Isolate untrusted context from instructions; constrain tools; validate tool arguments.

### 4. Model output passed into a dynamic code evaluator — **medium**
- **Rule:** `security-baseline/no-model-output-eval` · **CWE-94** · confidence: medium
- **Where:** `lib/formula.ts:12` — model reply passed into a dynamic code-generation constructor
- **What:** Model-generated text is compiled and executed at runtime — arbitrary code execution risk.
- **Fix:** Never execute model output. Parse to a constrained AST or use a sandboxed interpreter.

## Compliance (code-visible subset — not certification)

These findings touch code-visible controls under OWASP LLM Top 10 (2025) and OWASP Top 10
(2021) A03. CodeInspectus reports **code-level control coverage only** — never a
"% compliant" verdict. See [`docs/COMPLIANCE-RATIONALE.md`](../../docs/COMPLIANCE-RATIONALE.md).

## Next step

Apply fixes, then run `codeinspectus_rescan` to diff against this scan
(resolved / remaining / introduced).
