/**
 * CG-31 — build-output bucket keeps STRUCTURED secrets from ANY engine (fixes CG-30 Flag 1)
 * and drops only generic-entropy / public-collision-ambiguous noise + non-secret findings.
 * Pure routing tests (synthetic findings, forced into the build_output bucket).
 */

import { describe, test, expect } from "vitest";
import type { Finding } from "./types.js";
import { routeFindings, bucketFor } from "./file-routing.js";

function mk(rule_id: string, over: Partial<Finding> = {}): Finding {
  return {
    id: "CI-0001",
    fingerprint: `fp-${rule_id}-${over.engine ?? "gitleaks"}`,
    title: "Hard-coded secret",
    severity: "high",
    engine: "gitleaks",
    engines: ["gitleaks"],
    rule_id,
    cwe: ["CWE-798"],
    location: { file: `dist/bundle-${rule_id}.js`, start_line: 1, end_line: 1, snippet: "[redacted]" },
    message: "secret",
    remediation: { summary: "rotate", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    is_secret: true,
    ...over,
  };
}

const allBuild = () => "build_output" as const;
const keptRules = (findings: Finding[]) => findings.map((f) => f.rule_id);

describe("CG-31 build_output: keep structured secrets from any engine", () => {
  test("KEEP: named-provider commodity secrets (any engine) survive, labelled shipped-to-browser", () => {
    const structured = [
      mk("aws-access-token"),
      mk("github-pat"),
      mk("gitlab-pat"),
      mk("sendgrid"),
      mk("twilio"),
      mk("slack-bot-token"),
      mk("openai-api-key"),
      mk("private-key", { severity: "critical" }),
      mk("codeinspectus-stripe-live-secret", { severity: "critical" }),
      mk("codeinspectus-anthropic-key"),
    ];
    const { findings } = routeFindings(structured, allBuild);
    expect(findings.length).toBe(structured.length); // none dropped
    for (const f of findings) {
      expect(`${f.title} ${f.message}`.toLowerCase()).toMatch(/build output|shipped|bundle/);
      expect(f.is_secret).toBe(true); // redaction still applies
      expect(f.location.snippet).toBe("[redacted]"); // routing never un-redacts
    }
  });

  test("KEEP: the §6.1 AI bundle check (codeinspectus-ai) still survives", () => {
    const ai = mk("ci-ai-secret-in-bundle", {
      engine: "codeinspectus-ai",
      engines: ["codeinspectus-ai"],
      severity: "critical",
      title: "Secret compiled into shipped bundle",
    });
    const { findings } = routeFindings([ai], allBuild);
    expect(keptRules(findings)).toContain("ci-ai-secret-in-bundle");
  });

  test("DROP: generic-entropy noise", () => {
    const { findings, stats } = routeFindings(
      [mk("generic-api-key"), mk("high-entropy-string"), mk("generic")],
      allBuild,
    );
    expect(findings.length).toBe(0);
    expect(stats.dropped_build_noise).toBe(3);
  });

  test("DROP: public-collision-ambiguous classes (redacted → can't disambiguate)", () => {
    // jwt/jwt-token → Supabase anon ships by design; gcp-api-key → Firebase apiKey is public;
    // stripe-access-token (gitleaks default) → matches publishable pk_; our keyword JWT rule → anon.
    const ambiguous = [
      mk("jwt"),
      mk("jwt-token", { engine: "trivy", engines: ["trivy"] }),
      mk("gcp-api-key"),
      mk("stripe-access-token"),
      mk("codeinspectus-supabase-service-role"),
    ];
    const { findings } = routeFindings(ambiguous, allBuild);
    expect(findings.length).toBe(0);
  });

  test("DROP: non-secret findings in build output (SCA/IaC/SAST on minified output)", () => {
    const nonSecret = [
      mk("CVE-2021-23337", { engine: "trivy", engines: ["trivy"], is_secret: false, cwe: ["CWE-1395"] }),
      mk("javascript.lang.security.audit.xss", { engine: "opengrep", engines: ["opengrep"], is_secret: false, cwe: ["CWE-79"] }),
    ];
    const { findings } = routeFindings(nonSecret, allBuild);
    expect(findings.length).toBe(0);
  });

  test("real sk_live recall path: kept via the precise custom rule even though gitleaks default stripe is dropped", () => {
    // gitleaks default stripe-access-token (pk-ambiguous) dropped; the precise sk/rk_live custom rule kept.
    const both = [mk("stripe-access-token"), mk("codeinspectus-stripe-live-secret", { severity: "critical" })];
    const { findings } = routeFindings(both, allBuild);
    expect(keptRules(findings)).toEqual(["codeinspectus-stripe-live-secret"]);
  });

  test("FAIL-CLOSED: public-by-design provider tokens + unknown rules are DROPPED (allow-list, not deny-list)", () => {
    // These are is_secret=true (gitleaks forces it) but public-by-design or unknown — they must
    // NOT pass through as kept "shipped to browser" secrets. An allow-list fails closed here.
    const passThroughRisk = [
      mk("mapbox-public-token"),
      mk("sentry-dsn"),
      mk("segment-public-api-token"),
      mk("algolia-search-key"),
      mk("recaptcha-site-key"),
      mk("some-future-provider-token"), // unknown rule a gitleaks bump might add
    ];
    const { findings, stats } = routeFindings(passThroughRisk, allBuild);
    expect(findings.length).toBe(0);
    expect(stats.dropped_build_noise).toBe(passThroughRisk.length);
  });
});

describe("CG-31 broadened build-dir set", () => {
  test("Jekyll/Eleventy _site, Storybook, Expo web are recognized as build output", () => {
    for (const d of ["_site", "storybook-static", "web-build"]) {
      expect(bucketFor(`${d}/index.js`, new Set())).toBe("build_output");
    }
  });
});
