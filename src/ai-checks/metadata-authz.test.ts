/**
 * CG-50 — ci-ai-client-metadata-authz corpus lock (V1.5, first community-intake rule).
 *
 * Client-writable user_metadata used for an authorization decision is a privilege-escalation
 * footgun (CWE-639; OWASP A01:2021): any signed-in user can self-assign user_metadata.role
 * via /auth/v1/user. The correct, server-only field is app_metadata.
 *
 * Dual-direction lock over the FROZEN fixtures/metadata-authz-corpus (CONTRACT.md). The contract
 * is authored before the analyzer and never softened to make a weak rule pass. CONTRACT.md is
 * excluded from the public seed (fail-closed); these inline expectations ARE the public spec.
 */

import { describe, test, expect, beforeAll } from "vitest";
import { join } from "node:path";
import { runClientMetadataAuthzCheck } from "./metadata-authz.js";
import type { Finding } from "../types.js";

const CORPUS = join(process.cwd(), "fixtures", "metadata-authz-corpus");
const RULE = "ci-ai-client-metadata-authz";

const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((f) => f.location.file.endsWith(suffix));

// True positives — each MUST fire exactly once.
const TP: string[] = [
  "tp/01-inline-role.ts",
  "tp/02-split-role.ts",
  "tp/03-destructured-role.ts",
  "tp/04-is-admin-flag.ts",
  "tp/05-permissions-includes.ts",
  "tp/06-raw-user-meta-data.ts",
  "tp/07-generic-field-privileged-literal.ts",
];

// False positives / true negatives — each MUST stay silent.
const FP: string[] = [
  "fp/01-feature-gate-plan.tsx", // entitlement field + tier literal (feature gate)
  "fp/02-display-badge-role.tsx", // role-ish field but display only, no guard
  "fp/03-display-name.ts", // benign read
  "fp/04-app-metadata-correct.ts", // server-only field — the correct pattern (TN)
  "fp/05-unrelated-nonauthz.ts", // non-role field + non-privileged literal
];

describe("ci-ai-client-metadata-authz — frozen corpus lock (CG-50)", () => {
  let findings: Finding[];
  beforeAll(async () => {
    findings = await runClientMetadataAuthzCheck(CORPUS);
  });

  test.each(TP)("TP %s fires (high, medium-confidence, CWE-639)", (file) => {
    const hits = atFile(findings, file).filter((f) => f.rule_id === RULE);
    expect(hits.length).toBe(1);
    const f = hits[0]!;
    expect(f.severity).toBe("high");
    expect(f.confidence).toBe("medium"); // honest hedge carried in confidence + wording, not severity
    expect(f.cwe).toContain("CWE-639");
    expect(f.owasp_web).toContain("A01:2021");
    expect(f.engine).toBe("codeinspectus-ai");
    // Honest wording: names the client-writable root cause and asks the user to verify the boundary.
    expect(f.message).toContain("client-writable");
    expect(f.message).toContain("app_metadata");
  });

  test.each(FP)("FP %s stays silent", (file) => {
    expect(atFile(findings, file).filter((f) => f.rule_id === RULE).length).toBe(0);
  });

  test("exactly 7 findings over the corpus — no missed TP, no leaked FP, no dupes", () => {
    expect(findings.every((f) => f.rule_id === RULE)).toBe(true);
    expect(findings.length).toBe(TP.length); // 7, one per TP fixture
    const tpFired = TP.filter((file) => atFile(findings, file).some((f) => f.rule_id === RULE));
    const fpFired = FP.filter((file) => atFile(findings, file).some((f) => f.rule_id === RULE));
    expect(tpFired.length).toBe(7);
    expect(fpFired.length).toBe(0);
  });
});
