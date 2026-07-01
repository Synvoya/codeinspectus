/**
 * CG-25b B-11 — dangerouslyAllowBrowser detection (ci-ai-llm-key-browser-exposed).
 *
 * Runs the real client-secrets analyzer over the committed secret-rls-corpus and
 * regression-locks both directions: the TP fixture (flag set to true) fires; the FP
 * fixture (no flag / flag set to false) does not.
 */

import { describe, test, expect } from "vitest";
import { join } from "node:path";
import { runClientSecretsCheck } from "./client-secrets.js";

const CORPUS = join(process.cwd(), "fixtures", "secret-rls-corpus");
const RULE = "ci-ai-llm-key-browser-exposed";

describe("B-11 dangerouslyAllowBrowser (ci-ai-llm-key-browser-exposed)", () => {
  test("fires on the TP fixture and not the FP fixture", async () => {
    const findings = await runClientSecretsCheck(CORPUS);
    const browser = findings.filter((f) => f.rule_id === RULE);

    const tp = browser.filter((f) => f.location.file.endsWith("tp/src/llm-browser-exposed.ts"));
    expect(tp.length).toBe(1);
    expect(tp[0]!.severity).toBe("high");
    expect(tp[0]!.cwe).toContain("CWE-798");

    const fp = browser.filter((f) => f.location.file.endsWith("fp/src/llm-browser-safe.ts"));
    expect(fp.length).toBe(0);
  });
});
