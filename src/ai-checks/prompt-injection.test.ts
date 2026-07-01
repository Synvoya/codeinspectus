/**
 * CG-43 — §6.3 prompt-injection analyzer public regression lock.
 *
 * §6.3 (ci-ai-prompt-injection-sink, CWE-1426 / OWASP LLM01, +LLM06 with tools) is the
 * deliberately-conservative pillar: role- and tool-aware taint dataflow that fires only at
 * higher-risk positions and prefers silence on ambiguous flows (CG-06). Until now its only
 * regression lock was the internal corpus + CONTRACT.md; there was NO shipped test, and the
 * fail-closed public seed (CG-40) excludes the whole prompt-injection corpus. This test — and
 * the corpus files it reads, newly allow-listed in scripts/seed-public.mjs (CG-43) — give
 * contributors and public CI a real lock: a §6.3 regression now fails a test they can run.
 *
 * The detection CONTRACT.md stays EXCLUDED from the public seed (fail-closed, CG-40). So the
 * per-fixture expectations live INLINE here — this test IS the public spec for §6.3 behavior.
 * It mirrors the CG-06 ship-gate: all 7 true-positive fixtures fire; all 5 false-positive
 * fixtures stay silent. The analyzer itself is not touched by this session.
 *
 * Read-only: runs the shipped analyzer over the committed corpus as-is; no fixtures mutated.
 */

import { describe, test, expect, beforeAll } from "vitest";
import { join } from "node:path";
import { runPromptInjectionCheck } from "./prompt-injection.js";
import type { Finding } from "../types.js";

const CORPUS = join(process.cwd(), "fixtures", "prompt-injection-corpus");
const RULE = "ci-ai-prompt-injection-sink";
const TITLE_BASE = "Potential prompt-injection sink";

const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((f) => f.location.file.endsWith(suffix));

// True positives — each MUST fire exactly once. Two fire modes (CG-06):
//   system position (no role boundary)  -> medium, LLM01
//   tool/function-calling access        -> high,   LLM01 + LLM06
// confidence is ALWAYS "medium" regardless of severity — the §6.3 honest-framing invariant
// (a high-severity finding is still only medium-confidence; prompt-injection detection is
// heuristic). tp/03 is the load-bearing case for that: severity high, confidence medium.
interface TpCase {
  file: string;
  severity: "medium" | "high";
  owaspLlm: string[];
  titleSuffix: string;
}
const TP: TpCase[] = [
  { file: "tp/01-openai-system-concat.ts",    severity: "medium", owaspLlm: ["LLM01:2025"],                 titleSuffix: " (untrusted input in the system prompt)" },
  { file: "tp/02-anthropic-system.ts",        severity: "medium", owaspLlm: ["LLM01:2025"],                 titleSuffix: " (untrusted input in the system prompt)" },
  { file: "tp/03-openai-tools-userinput.ts",  severity: "high",   owaspLlm: ["LLM01:2025", "LLM06:2025"],   titleSuffix: " with tool/function-calling access" },
  { file: "tp/04-google-genai-system.ts",     severity: "medium", owaspLlm: ["LLM01:2025"],                 titleSuffix: " (untrusted input in the system prompt)" },
  { file: "tp/05-express-system-concat.js",   severity: "medium", owaspLlm: ["LLM01:2025"],                 titleSuffix: " (untrusted input in the system prompt)" },
  { file: "tp/06-single-string-prompt.ts",    severity: "medium", owaspLlm: ["LLM01:2025"],                 titleSuffix: " (untrusted input in the system prompt)" },
  { file: "tp/07-stream-var-systemprompt.ts", severity: "medium", owaspLlm: ["LLM01:2025"],                 titleSuffix: " (untrusted input in the system prompt)" },
];

// False positives — each MUST stay silent. This half is load-bearing: it locks the FP
// discipline (user-role message, sanitized input, or no untrusted data → no finding) that
// makes §6.3 worth trusting. A regression that starts flagging these is exactly what erodes it.
const FP: string[] = [
  "fp/01-openai-user-message-safe.ts", // untrusted input in a user-role message, no tools
  "fp/02-anthropic-user-safe.ts",      // user message, static top-level system, no tools
  "fp/03-sanitized-input.ts",          // zod .parse() sanitizes before the system prompt
  "fp/04-static-prompt.ts",            // fully static prompt, no untrusted data
  "fp/05-google-genai-user-safe.ts",   // untrusted input as user `contents`, static systemInstruction
];

describe("§6.3 prompt-injection analyzer — public regression lock (CG-43)", () => {
  let findings: Finding[];
  beforeAll(async () => {
    findings = await runPromptInjectionCheck(CORPUS);
  });

  test.each(TP)("TP $file fires ($severity, medium-confidence)", (tp) => {
    const hits = atFile(findings, tp.file).filter((f) => f.rule_id === RULE);
    expect(hits.length).toBe(1);
    const f = hits[0]!;
    expect(f.severity).toBe(tp.severity);
    expect(f.confidence).toBe("medium"); // always medium — §6.3 honest-framing invariant
    expect(f.cwe).toContain("CWE-1426");
    expect(f.owasp_llm).toEqual(tp.owaspLlm);
    expect(f.title).toBe(TITLE_BASE + tp.titleSuffix);
    expect(f.engine).toBe("codeinspectus-ai");
    // Honest wording: the message names its own heuristic nature (PRD §6.3).
    expect(f.message).toContain("Prompt-injection detection is heuristic — verify manually.");
  });

  test.each(FP)("FP %s stays silent", (file) => {
    expect(atFile(findings, file).filter((f) => f.rule_id === RULE).length).toBe(0);
  });

  test("mirrors the CG-06 ship-gate: 7 TP fire, 5 FP silent, exactly 7 findings total", () => {
    // Every finding the analyzer emits over the corpus is this rule and nothing else —
    // locks against both a missed TP and a leaked/duplicated finding.
    expect(findings.every((f) => f.rule_id === RULE)).toBe(true);
    expect(findings.length).toBe(TP.length); // 7, one per TP fixture — no FP leaked, no dupes

    const tpFired = TP.filter((tp) => atFile(findings, tp.file).some((f) => f.rule_id === RULE));
    const fpFired = FP.filter((file) => atFile(findings, file).some((f) => f.rule_id === RULE));
    expect(tpFired.length).toBe(7);
    expect(fpFired.length).toBe(0);
  });
});
