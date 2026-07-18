/**
 * CG-24 A3-1 / A6-2 — value-agnostic redaction at the normalizer.
 *
 * The redaction invariant must hold for ANY is_secret finding, regardless of whether
 * the secret's shape is one of the 11 known SECRET_PATTERNS. A Gitleaks default-rule
 * hit (generic-api-key, sendgrid, gitlab-pat, entropy) carries the raw value in the
 * SARIF region snippet (and, adversarially, in the message). After normalization the
 * raw value must appear in NO field of the finding — snippet, message, or anywhere in
 * its JSON serialization.
 */

import { describe, test, expect } from "vitest";
import { normalizeSarif } from "./normalize.js";
import type { SarifLog } from "./types.js";

const TARGET = "/repo";

// Secrets whose shapes are NOT in redact.ts SECRET_PATTERNS.
const SG = "SG.aB3dE5gH7jK9lM1nO2pQ.rS4tU6vW8xY0zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1";
const GLPAT = "glpat-AbCdEf1234567890XyZw";
const ENTROPY = "f3Q8zR1xW9kL2mN7pV4tB6cD0sJ5hG8aQ2wE4rT6yU8";

function gitleaksSarif(): SarifLog {
  const result = (ruleId: string, desc: string, line: number, secret: string, putInMessage: boolean) => ({
    ruleId,
    message: { text: putInMessage ? `${ruleId} detected ${secret} in app.ts` : `${ruleId} has detected a secret in app.ts` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: "/repo/app.ts" },
          region: { startLine: line, endLine: line, snippet: { text: `const v = "${secret}";` } },
        },
      },
    ],
  });
  return {
    runs: [
      {
        tool: {
          driver: {
            name: "gitleaks",
            rules: [
              { id: "generic-api-key", shortDescription: { text: "Generic API Key" } },
              { id: "gitlab-pat", shortDescription: { text: "GitLab Personal Access Token" } },
              { id: "sendgrid-api-token", shortDescription: { text: "SendGrid API Token" } },
            ],
          },
        },
        // SG also planted in the message (adversarial): assert it can't leak there either.
        results: [
          result("sendgrid-api-token", "SendGrid", 1, SG, true),
          result("gitlab-pat", "GitLab", 2, GLPAT, false),
          result("generic-api-key", "Generic", 3, ENTROPY, false),
        ],
      },
    ],
  };
}

describe("normalizeSarif redacts non-allowlisted secrets (CG-24 A3-1/A6-2)", () => {
  const findings = normalizeSarif(gitleaksSarif(), "gitleaks", TARGET);

  test("every gitleaks result is treated as a secret finding", () => {
    expect(findings).toHaveLength(3);
    expect(findings.every((f) => f.is_secret)).toBe(true);
  });

  for (const raw of [SG, GLPAT, ENTROPY]) {
    test(`raw value ${raw.slice(0, 8)}… appears in NO field`, () => {
      for (const f of findings) {
        expect(f.location.snippet ?? "").not.toContain(raw);
        expect(f.message).not.toContain(raw);
        expect(JSON.stringify(f)).not.toContain(raw);
      }
    });
  }
});

describe("normalizeSarif path portability", () => {
  test("makes a Windows absolute SARIF path relative to a backslash target", () => {
    const target = "D:\\a\\codeinspectus-dev\\codeinspectus-dev\\fixtures\\vulnerable-app";
    const sarif: SarifLog = {
      runs: [
        {
          tool: {
            driver: {
              name: "opengrep",
              rules: [
                {
                  id: "ci-baseline-sql-injection-string-build",
                  properties: { cwe: "CWE-89" },
                },
              ],
            },
          },
          results: [
            {
              ruleId: "ci-baseline-sql-injection-string-build",
              message: { text: "Potential SQL injection (CWE-89)" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri: "D:\\a\\codeinspectus-dev\\codeinspectus-dev\\fixtures\\vulnerable-app\\src\\db.ts",
                    },
                    region: { startLine: 11, endLine: 11 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const [finding] = normalizeSarif(sarif, "opengrep", target);
    expect(finding?.location.file).toBe("src/db.ts");
    expect(finding?.location.start_line).toBe(11);
    expect(finding?.cwe).toContain("CWE-89");
  });
});

describe("Trivy finding_kind and provenance attribution are structural", () => {
  test.each([
    ["LanguageSpecificPackageVulnerability", ["vulnerability", "security"], "vulnerability", true],
    ["License", ["license", "security"], "license", false],
    ["Misconfiguration", ["misconfiguration", "security"], "misconfiguration", false],
  ] as const)("%s maps to %s components without message/CVE parsing", (name, tags, expectedKind, needsDb) => {
    const sarif: SarifLog = {
      runs: [{
        tool: { driver: { name: "trivy", rules: [{ id: `rule-${expectedKind}`, name, properties: { tags: [...tags] } }] } },
        results: [{
          ruleId: `rule-${expectedKind}`,
          message: { text: "opaque finding text" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "/repo/package-lock.json" }, region: { startLine: 1 } } }],
        }],
      }],
    };
    const [finding] = normalizeSarif(sarif, "trivy", TARGET);
    expect(finding?.finding_kind).toBe(expectedKind);
    expect(finding?.producer_components).toContain("trivy:checks");
    expect(finding?.producer_components?.includes("trivy:vulnerability-db")).toBe(needsDb);
  });
});
