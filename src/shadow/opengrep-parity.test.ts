import { describe, expect, test } from "vitest";

import { parseJavaScriptSource } from "../packs/react-native/javascript.js";
import { runJavaScriptBaselineCandidates } from "../packs/javascript-baseline/index.js";
import { compareShadowFindings } from "./opengrep-parity.js";

async function oneCandidate() {
  const result = await runJavaScriptBaselineCandidates({
    target: "/fixture",
    root: "/fixture",
    files: [parseJavaScriptSource("index.ts", `crypto.createHash("md5");\n`)],
  });
  return result.findings[0]!;
}

describe("Opengrep/native shadow comparator", () => {
  test("ignores producer identity but requires the complete gating projection", async () => {
    const candidate = await oneCandidate();
    const reference = structuredClone(candidate);
    reference.id = "reference-id";
    reference.fingerprint = "reference-fingerprint";
    reference.engine = "opengrep";
    reference.engines = ["opengrep"];
    reference.producer_components = ["opengrep:binary", "opengrep:ruleset"];

    expect(compareShadowFindings([reference], [candidate])).toMatchObject({
      exact: true,
      matched_count: 1,
      reference_only: [],
      candidate_only: [],
      metadata_mismatches: [],
    });

    reference.message = `${reference.message}changed`;
    expect(compareShadowFindings([reference], [candidate])).toMatchObject({
      exact: false,
      metadata_mismatches: [{ fields: ["message"] }],
    });
  });

  test("compares identity as a multiset", async () => {
    const candidate = await oneCandidate();
    const comparison = compareShadowFindings([candidate], [candidate, structuredClone(candidate)]);
    expect(comparison).toMatchObject({
      exact: false,
      reference_count: 1,
      candidate_count: 2,
      matched_count: 1,
    });
    expect(comparison.candidate_only).toHaveLength(1);
  });
});
