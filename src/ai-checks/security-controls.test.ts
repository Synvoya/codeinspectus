/**
 * Project CI Enhancement 2 — explicit repository-evidence contract lock.
 *
 * Findings require planted explicit insecurity. Safe, development/report-only,
 * hosted-unknown, disabled-CAPTCHA, and conflicting-layer fixtures remain silent.
 */

import { beforeAll, describe, expect, test } from "vitest";
import { join } from "node:path";

import { runAiChecks } from "./index.js";
import { runSecurityControlChecks, type SecurityControlAnalysis } from "./security-controls.js";
import { securityControlEvidenceSchema } from "../schemas.js";

const CORPUS = join(process.cwd(), "fixtures", "security-controls-corpus");
const at = (rel: string) => join(CORPUS, rel);

const RULES = {
  header: "ci-ai-security-header-disabled",
  csp: "ci-ai-unsafe-production-csp",
  referrer: "ci-ai-unsafe-referrer-policy",
  permissions: "ci-ai-overbroad-permissions-policy",
  cookie: "ci-ai-insecure-session-cookie",
  captcha: "ci-ai-supabase-captcha-token-missing",
} as const;

const CONTROL = {
  hsts: "http.header.strict-transport-security",
  contentType: "http.header.x-content-type-options",
  frame: "http.header.x-frame-options",
  csp: "http.header.content-security-policy",
  referrer: "http.header.referrer-policy",
  permissions: "http.header.permissions-policy",
  cookie: "http.cookie.session-security",
  captcha: "supabase.auth.captcha-token",
} as const;

function state(result: SecurityControlAnalysis, controlId: string): string | undefined {
  return result.evidence.find((record) => record.control_id === controlId)?.state;
}

describe("security-control analyzer — frozen evidence corpus", () => {
  const results = new Map<string, SecurityControlAnalysis>();

  beforeAll(async () => {
    const repos = [
      "tp/headers-next",
      "tp/headers-next-order",
      "tp/headers-route-mixed",
      "tp/headers-helmet",
      "tp/headers-cloudflare",
      "tp/headers-nginx",
      "tp/csp-vercel",
      "tp/csp-helmet",
      "tp/referrer-next",
      "tp/referrer-express",
      "tp/permissions-nginx",
      "tp/cookies",
      "tp/cookies-mixed",
      "tp/captcha",
      "tp/captcha-mixed",
      "safe/next",
      "safe/helmet",
      "safe/nginx",
      "safe/cookies",
      "safe/captcha",
      "near-miss/csp-development",
      "near-miss/csp-report-only",
      "near-miss/preference-cookie",
      "near-miss/captcha-disabled",
      "near-miss/captcha-hosted-unknown",
      "near-miss/non-production-paths",
      "near-miss/header-policy-weaker",
      "near-miss/header-policy-lookalikes",
      "near-miss/helmet-policy-disabled",
      "near-miss/header-policy-response-lookalike",
      "near-miss/header-policy-next-decoy",
      "conflict/headers",
    ];
    await Promise.all(
      repos.map(async (repo) => {
        results.set(repo, await runSecurityControlChecks(at(repo)));
      }),
    );
  });

  test.each([
    ["tp/headers-next", RULES.header, 1, CONTROL.hsts],
    ["tp/headers-next-order", RULES.header, 1, CONTROL.hsts],
    ["tp/headers-route-mixed", RULES.header, 1, CONTROL.hsts],
    ["tp/headers-helmet", RULES.header, 1, CONTROL.contentType],
    ["tp/headers-cloudflare", RULES.header, 1, CONTROL.frame],
    ["tp/headers-nginx", RULES.header, 1, CONTROL.hsts],
    ["tp/csp-vercel", RULES.csp, 1, CONTROL.csp],
    ["tp/csp-helmet", RULES.csp, 1, CONTROL.csp],
    ["tp/referrer-next", RULES.referrer, 1, CONTROL.referrer],
    ["tp/referrer-express", RULES.referrer, 1, CONTROL.referrer],
    ["tp/permissions-nginx", RULES.permissions, 1, CONTROL.permissions],
    ["tp/cookies", RULES.cookie, 3, CONTROL.cookie],
    ["tp/cookies-mixed", RULES.cookie, 1, CONTROL.cookie],
    ["tp/captcha", RULES.captcha, 3, CONTROL.captcha],
    ["tp/captcha-mixed", RULES.captcha, 1, CONTROL.captcha],
  ])("%s emits exactly %i %s finding(s) with insecure evidence", (repo, rule, count, control) => {
    const result = results.get(repo)!;
    expect(result.findings.filter((finding) => finding.rule_id === rule)).toHaveLength(count);
    expect(result.findings).toHaveLength(count);
    expect(state(result, control)).toBe("insecure_configuration_found");
  });

  test("all new findings carry canonical CWE/OWASP context and no source values", () => {
    const findings = [...results.values()].flatMap((result) => result.findings);
    for (const finding of findings) {
      expect(finding.cwe[0]).toMatch(/^CWE-(?:200|693|942|1004)$/);
      expect(finding.owasp_web).toContain("A05:2021");
      expect(finding.owasp_api).toContain("API8:2023");
      expect(finding.confidence).toBe("high");
    }
    const surfaced = JSON.stringify(findings);
    expect(surfaced).not.toContain("SUPABASE_AUTH_CAPTCHA_SECRET");
    expect(surfaced).not.toContain('response.cookie("session", "value"');
  });

  test.each([
    ["safe/next", [CONTROL.hsts, CONTROL.contentType, CONTROL.frame, CONTROL.csp, CONTROL.referrer, CONTROL.permissions]],
    ["safe/helmet", [CONTROL.hsts, CONTROL.contentType, CONTROL.frame, CONTROL.csp, CONTROL.referrer]],
    ["safe/nginx", [CONTROL.hsts, CONTROL.contentType, CONTROL.frame, CONTROL.csp]],
    ["safe/cookies", [CONTROL.cookie]],
    ["safe/captcha", [CONTROL.captcha]],
  ])("%s is silent and verifies its exercised controls", (repo, controls) => {
    const result = results.get(repo)!;
    expect(result.findings).toHaveLength(0);
    for (const control of controls) expect(state(result, control)).toBe("verified_in_repository");
  });

  test.each([
    "near-miss/csp-development",
    "near-miss/csp-report-only",
    "near-miss/preference-cookie",
    "near-miss/captcha-disabled",
    "near-miss/captcha-hosted-unknown",
    "near-miss/non-production-paths",
    "near-miss/header-policy-weaker",
    "near-miss/header-policy-lookalikes",
    "near-miss/helmet-policy-disabled",
    "near-miss/header-policy-response-lookalike",
    "near-miss/header-policy-next-decoy",
  ])("%s remains silent", (repo) => {
    expect(results.get(repo)!.findings).toHaveLength(0);
  });

  test("disabled and hosted-unknown CAPTCHA do not claim protection", () => {
    expect(state(results.get("near-miss/captcha-disabled")!, CONTROL.captcha)).toBe(
      "not_verifiable_from_repository",
    );
    expect(state(results.get("near-miss/captcha-hosted-unknown")!, CONTROL.captcha)).toBe(
      "not_verifiable_from_repository",
    );
  });

  test("weaker, removed, lookalike, and Helmet-disabled policy evidence remains unknown", () => {
    for (const repo of [
      "near-miss/header-policy-weaker",
      "near-miss/header-policy-lookalikes",
      "near-miss/helmet-policy-disabled",
    ]) {
      const result = results.get(repo)!;
      expect(result.findings).toHaveLength(0);
      expect(state(result, CONTROL.referrer)).toBe("not_verifiable_from_repository");
      expect(state(result, CONTROL.permissions)).toBe("not_verifiable_from_repository");
    }
  });

  test("test, example, and explicit development config paths do not claim runtime state", () => {
    const result = results.get("near-miss/non-production-paths")!;
    expect(result.evidence.every((record) => record.state === "not_verifiable_from_repository")).toBe(
      true,
    );
    expect(result.evidence.every((record) => record.evidence_locations.length === 0)).toBe(true);
  });

  test("conflicting effective HSTS values resolve to unknown and emit no finding", () => {
    const result = results.get("conflict/headers")!;
    expect(result.findings).toHaveLength(0);
    expect(state(result, CONTROL.hsts)).toBe("not_verifiable_from_repository");
    expect(
      result.evidence.find((record) => record.control_id === CONTROL.hsts)?.evidence_locations,
    ).toHaveLength(2);
  });

  test("Next.js same-source duplicate headers honor documented last-value ordering", () => {
    const result = results.get("tp/headers-next-order")!;
    expect(state(result, CONTROL.hsts)).toBe("insecure_configuration_found");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.location.start_line).toBe(12);
  });

  test.each([
    ["tp/headers-route-mixed", CONTROL.hsts],
    ["tp/cookies-mixed", CONTROL.cookie],
    ["tp/captcha-mixed", CONTROL.captcha],
  ])("%s preserves an explicit insecure path alongside a safe path", (repo, control) => {
    const result = results.get(repo)!;
    expect(result.findings).toHaveLength(1);
    expect(state(result, control)).toBe("insecure_configuration_found");
  });

  test("every evidence record satisfies the public schema", () => {
    for (const result of results.values()) {
      expect(result.evidence).toHaveLength(8);
      for (const record of result.evidence) {
        expect(securityControlEvidenceSchema.safeParse(record).success).toBe(true);
      }
    }
  });

  test("AI runner assigns rule-specific provenance and returns evidence metadata", async () => {
    const result = await runAiChecks(at("tp/captcha"));
    const findings = result.findings.filter((finding) => finding.rule_id === RULES.captcha);
    expect(findings).toHaveLength(3);
    for (const finding of findings) {
      expect(finding.producer_components).toContain("ai:supabase-captcha-integration");
    }
    expect(result.componentSignatures["ai:supabase-captcha-integration"]).toMatch(/^sha256:/);
    expect(result.securityControlEvidence).toHaveLength(8);
  });
});
