import { describe, expect, test } from "vitest";

import { reconcileNativeSast } from "./native-sast-reconciliation.js";
import type { Finding } from "./types.js";

function finding(engine: "opengrep" | "codeinspectus-ai", overrides: Partial<Finding> = {}): Finding {
  return {
    id: `${engine}-id`,
    fingerprint: `${engine}-fingerprint`,
    title: "Weak hashing algorithm (MD5/SHA1) used.",
    severity: "medium",
    engine,
    engines: [engine],
    rule_id: "ci-baseline-weak-hash",
    cwe: ["CWE-327"],
    owasp_web: ["A02:2021"],
    location: { file: "src/hash.ts", start_line: 4, end_line: 4, snippet: 'createHash("md5")' },
    message: "Weak hashing algorithm (MD5/SHA1) used. Use SHA-256+ or a password KDF (bcrypt/scrypt/argon2) for credentials.\n",
    remediation: {
      summary: "Replace risky cryptographic algorithms with modern, vetted primitives.",
      steps: ["Use modern cryptographic algorithms and libraries."],
      references: ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    frameworks: [],
    confidence: "medium",
    producer_components: engine === "opengrep" ? ["opengrep:ruleset"] : ["sast:javascript-weak-hash"],
    finding_kind: "sast",
    ...overrides,
  };
}

describe("native SAST reconciliation", () => {
  test("an exact reference/native pair surfaces only native provenance", () => {
    const reference = finding("opengrep");
    const candidate = finding("codeinspectus-ai");
    const result = reconcileNativeSast(true, [reference], [candidate]);
    expect(result.findings).toEqual([candidate]);
    expect(result.findings[0]?.engines).toEqual(["codeinspectus-ai"]);
    expect(result.note).toBeUndefined();
  });

  test("reference-only stays Opengrep and candidate-only is suppressed", () => {
    const reference = finding("opengrep", { location: { file: "src/ref.ts", start_line: 1, end_line: 1 } });
    const candidate = finding("codeinspectus-ai", { location: { file: "src/native.ts", start_line: 2, end_line: 2 } });
    const result = reconcileNativeSast(true, [reference], [candidate]);
    expect(result.findings).toEqual([reference]);
    expect(result.referenceOnlyCount).toBe(1);
    expect(result.suppressedCandidateCount).toBe(1);
  });

  test("metadata mismatch retains Opengrep and suppresses native", () => {
    const reference = finding("opengrep");
    const candidate = finding("codeinspectus-ai", { confidence: "high" });
    const result = reconcileNativeSast(true, [reference], [candidate]);
    expect(result.findings).toEqual([reference]);
    expect(result.metadataMismatchCount).toBe(1);
  });

  test("Opengrep unavailable uses native fallback without mixed provenance", () => {
    const candidate = finding("codeinspectus-ai");
    const result = reconcileNativeSast(false, [], [candidate]);
    expect(result.findings).toEqual([candidate]);
    expect(result.usedFallback).toBe(true);
    expect(result.note).toMatch(/native fallback/i);
  });

  test("unrelated Opengrep findings pass through unchanged", () => {
    const unrelated = finding("opengrep", { rule_id: "ci-baseline-xss-innerhtml" });
    const result = reconcileNativeSast(true, [unrelated], []);
    expect(result.findings).toEqual([unrelated]);
    expect(result.referenceOnlyCount).toBe(0);
  });
});
