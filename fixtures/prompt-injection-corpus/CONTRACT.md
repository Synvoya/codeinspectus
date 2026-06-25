# §6.3 prompt-injection — detection contract (CG-06)

Ground-truth corpus for the reworked prompt-injection analyzer. **Not part of the
17-eval `vulnerable-app` corpus** — scanned separately. Built BEFORE the detection
logic so the logic is written to the contract, not the other way round.

## The contract

**FIRES** (potential prompt-injection sink) when untrusted input — `req.body` / `query`
/ `params`, `await req.json()/text()`, `searchParams.get()`, `process.argv`, and values
transitively derived from them — reaches an LLM SDK call (`openai`, `anthropic`,
`@google/genai`, `ai`/Vercel SDK) at a **higher-risk position**, with no intervening
sanitization:

- **(a) System position — no role boundary:** a `role: "system"` message content, an
  Anthropic top-level `system:` param, a `@google/genai` `systemInstruction`, or a
  single instruction+input `prompt:` string (template/concat mixing literal
  instructions with the untrusted value). Severity **medium**, OWASP **LLM01**.
- **(b) Tool/function-calling access (excessive agency):** the call also configures
  `tools` / `functions` / `tool_choice` / `functionDeclarations`, and untrusted input
  reaches the call **anywhere** (even a user message). Severity **high**, OWASP
  **LLM01 + LLM06**.

**STAYS SILENT** when:

- Untrusted input reaches **only a `role: "user"` message** (or genai `contents`) and
  the call has **no tools** — a message-role boundary is the documented mitigation
  (PRD §6.3). This is the pattern CG-05 wrongly flagged.
- The input passes through **sanitization/validation** first (`zod` `.parse()` /
  `.safeParse()`, `sanitize`, `escape`, `validate`, `DOMPurify`, allowlist).
- The prompt has **no untrusted data** (static/templated with literals only).

**Honest framing (PRD §6.3):** confidence is always `medium`; findings are worded
"potential prompt-injection sink," never a certainty. Ambiguous flows prefer
**silence** (a false negative is safer than retraining users to ignore the tool).

## Fixtures

- `tp/` — 6 files that MUST fire (system concat, tools+user-input, anthropic system,
  genai systemInstruction, express system concat, single-string prompt).
- `fp/` — 5 files that MUST NOT fire (user-message+no-tools ×2, sanitized, static,
  genai user `contents`).

## Known blind spots (prefer silence; honest)

- True interprocedural taint via **function parameters** across functions (the
  analyzer propagates taint by variable reuse within a file, not through call args).
- Untrusted input from **DB rows / fetched web/PDF content** (PRD lists these as
  sources, but they're indistinguishable from trusted data without dataflow we don't
  have). Only request-shaped sources are seeded.
- A single-string `prompt:` that is a **bare untrusted variable** with no literal
  instructions (treated as user-input-like → silent).
