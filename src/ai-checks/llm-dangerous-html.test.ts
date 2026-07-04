/**
 * CG-51 — ci-ai-llm-output-dangerous-html corpus lock (LLM05, second community-intake rule).
 *
 * Untrusted input OR LLM/model output rendered as raw HTML (the React `__html` sink) without
 * sanitization is a direct XSS sink (CWE-79/CWE-116; OWASP A03:2021; OWASP LLM05:2025 on the
 * model-output arm). Opengrep's bundled ruleset covers DOM sinks but defers this React attribute
 * (CG-50 Part-4) — this rule fills that gap.
 *
 * Dual-direction lock over the FROZEN fixtures/llm-dangerous-html-corpus (CONTRACT.md). The contract
 * is authored before the analyzer and never softened. CONTRACT.md is excluded from the public seed
 * (fail-closed); these inline expectations ARE the public spec.
 */

import { describe, test, expect, beforeAll } from "vitest";
import { join } from "node:path";
import { runLlmDangerousHtmlCheck } from "./llm-dangerous-html.js";
import type { Finding } from "../types.js";

const CORPUS = join(process.cwd(), "fixtures", "llm-dangerous-html-corpus");
const RULE = "ci-ai-llm-output-dangerous-html";

const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((f) => f.location.file.endsWith(suffix));

// True positives — each MUST fire exactly once. `model` cases carry the LLM05 (insecure output
// handling) tag; the untrusted-input cases do not (they are A03 XSS only).
interface TpCase {
  file: string;
  model: boolean;
}
const TP: TpCase[] = [
  { file: "tp/01-arm-a-inline.tsx", model: false },
  { file: "tp/02-arm-a-split.tsx", model: false },
  { file: "tp/03-arm-b-inline.tsx", model: true },
  { file: "tp/04-arm-b-split.tsx", model: true },
  { file: "tp/05-arm-b-anthropic.tsx", model: true },
];

// False positives / true negatives — each MUST stay silent.
const FP: string[] = [
  "fp/01-sanitized.tsx", // DOMPurify.sanitize on both an untrusted and a model source
  "fp/02-constant-trusted.tsx", // string literal + local constant
  "fp/03-plaintext.tsx", // model/untrusted rendered as TEXT (no raw-HTML sink)
  "fp/04-noise.tsx", // untrusted value in non-__html positions
];

describe("ci-ai-llm-output-dangerous-html — frozen corpus lock (CG-51)", () => {
  let findings: Finding[];
  beforeAll(async () => {
    findings = await runLlmDangerousHtmlCheck(CORPUS);
  });

  test.each(TP)("TP $file fires (high, medium-confidence, CWE-79/116)", (tp) => {
    const hits = atFile(findings, tp.file).filter((f) => f.rule_id === RULE);
    expect(hits.length).toBe(1);
    const f = hits[0]!;
    expect(f.severity).toBe("high");
    expect(f.confidence).toBe("medium"); // hedge in wording, not a dropped severity
    expect(f.cwe).toContain("CWE-79");
    expect(f.cwe).toContain("CWE-116");
    expect(f.owasp_web).toContain("A03:2021");
    expect(f.engine).toBe("codeinspectus-ai");
    expect(f.message).toContain("without sanitization");
    if (tp.model) {
      // Arm B — the moat: model output gets the LLM05 insecure-output-handling tag.
      expect(f.owasp_llm ?? []).toContain("LLM05:2025");
    } else {
      // Arm A — untrusted input XSS: no LLM05 tag.
      expect(f.owasp_llm ?? []).not.toContain("LLM05:2025");
    }
  });

  test.each(FP)("FP %s stays silent", (file) => {
    expect(atFile(findings, file).filter((f) => f.rule_id === RULE).length).toBe(0);
  });

  test("exactly 5 findings over the corpus — no missed TP, no leaked FP, no dupes", () => {
    expect(findings.every((f) => f.rule_id === RULE)).toBe(true);
    expect(findings.length).toBe(TP.length); // 5, one per TP fixture
    const tpFired = TP.filter((tp) => atFile(findings, tp.file).some((f) => f.rule_id === RULE));
    const fpFired = FP.filter((file) => atFile(findings, file).some((f) => f.rule_id === RULE));
    expect(tpFired.length).toBe(5);
    expect(fpFired.length).toBe(0);
  });
});
