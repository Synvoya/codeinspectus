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
import { normalizeSarif, splitMagentoPatchFixed } from "./normalize.js";
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
  test("normalizes absolute and relative direct-file URIs to the same basename", () => {
    const result = (uri: string): SarifLog => ({
      runs: [{
        tool: { driver: { name: "trivy", rules: [{ id: "CVE-2026-0001" }] } },
        results: [{
          ruleId: "CVE-2026-0001",
          message: { text: "vulnerable dependency" },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri },
              region: { startLine: 1, endLine: 1 },
            },
          }],
        }],
      }],
    });
    const target = "/repo/pubspec.lock";
    expect(normalizeSarif(result(target), "trivy", target)[0]?.location.file).toBe("pubspec.lock");
    expect(normalizeSarif(result("pubspec.lock"), "trivy", target)[0]?.location.file).toBe("pubspec.lock");
  });

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

describe("Opengrep SAST classification", () => {
  test("authored confidence tags take precedence over generic SARIF precision", () => {
    const sarif: SarifLog = { runs: [{
      tool: { driver: { name: "opengrep", rules: [{
        id: "ci-baseline-weak-hash",
        properties: { precision: "very-high", tags: ["MEDIUM CONFIDENCE", "CWE-327"] },
      }] } },
      results: [{
        ruleId: "ci-baseline-weak-hash",
        message: { text: "Weak hash." },
        locations: [{ physicalLocation: { artifactLocation: { uri: "/repo/hash.ts" }, region: { startLine: 1 } } }],
      }],
    }] };
    expect(normalizeSarif(sarif, "opengrep", TARGET)[0]?.confidence).toBe("medium");
  });

  test("CORS credentials wording remains a SAST finding, not a hard-coded secret", () => {
    const sarif: SarifLog = {
      runs: [{
        tool: {
          driver: {
            name: "opengrep",
            rules: [{
              id: "ci-baseline-cors-arbitrary-origin-credentials",
              properties: { cwe: "CWE-942", confidence: "HIGH" },
            }],
          },
        },
        results: [{
          ruleId: "ci-baseline-cors-arbitrary-origin-credentials",
          message: { text: "CORS accepts an arbitrary origin while credentials are enabled." },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: "/repo/server.ts" },
              region: { startLine: 4, endLine: 4, snippet: { text: "cors({ origin: true, credentials: true })" } },
            },
          }],
        }],
      }],
    };

    const [finding] = normalizeSarif(sarif, "opengrep", TARGET);
    expect(finding?.finding_kind).toBe("sast");
    expect(finding?.is_secret).toBeUndefined();
    expect(finding?.title).toContain("CORS accepts an arbitrary origin");
    expect(finding?.owasp_api).toEqual(["API8:2023"]);
    expect(finding?.confidence).toBe("high");
  });
});

describe("Trivy license results are never secrets", () => {
  // Field validation: ghostfolio's "MIT in passport-headerapikey" was a secret, CWE-798, high.
  test("a package name with a secret-like word stays a license finding", () => {
    const sarif: SarifLog = {
      runs: [{
        tool: { driver: { name: "trivy", rules: [{ id: "passport-headerapikey:MIT", name: "License", properties: { tags: ["license", "notice"] } }] } },
        results: [{
          ruleId: "passport-headerapikey:MIT", level: "note",
          message: { text: "Artifact: package-lock.json\nLicense MIT\nPkgName: passport-headerapikey\n Classification: notice" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "package-lock.json" }, region: { startLine: 1 } } }],
        }],
      }],
    };
    const [finding] = normalizeSarif(sarif, "trivy", TARGET);
    expect(finding?.finding_kind).toBe("license");
    expect(finding?.is_secret).toBeUndefined();
    expect(finding?.cwe).not.toContain("CWE-798");
    expect(finding?.message).toContain("PkgName: passport-headerapikey");
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

describe("Trivy vulnerability findings carry the structured package", () => {
  function trivyVulnerability(uri: string, message: string, kind = "LanguageSpecificPackageVulnerability"): SarifLog {
    return {
      runs: [{
        tool: { driver: { name: "trivy", rules: [{ id: "CVE-2026-111497", name: kind, properties: { tags: ["vulnerability", "security"] } }] } },
        results: [{
          ruleId: "CVE-2026-111497",
          message: { text: message },
          locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 2 } } }],
        }],
      }],
    };
  }
  const message = (name: string, version: string) =>
    `Package: ${name}\nInstalled Version: ${version}\nVulnerability CVE-2026-111497\nSeverity: CRITICAL\nFixed Version: 1.2.1\nLink: [CVE-2026-111497](https://avd.aquasec.com/nvd/cve-2026-111497)`;

  test.each([
    ["/repo/requirements.txt", "PyPI"],
    ["/repo/svc/requirements-dev.txt", "PyPI"],
    ["/repo/package-lock.json", "npm"],
    ["/repo/app/pubspec.lock", "Pub"],
    ["/repo/composer.lock", "Packagist"],
    ["/repo/usr/lib/python3/site-packages/thing.dist-info/METADATA", "unknown"],
  ])("parses Package / Installed Version and derives the ecosystem from %s", (uri, ecosystem) => {
    const [finding] = normalizeSarif(trivyVulnerability(uri, message("Brotli", "1.2.0")), "trivy", TARGET);
    expect(finding?.finding_kind).toBe("vulnerability");
    expect(finding?.package).toEqual({ ecosystem, name: "Brotli", version: "1.2.0" });
  });

  test("a vulnerability message without a Package line gets no package, and non-vulnerability results never do", () => {
    const [opaque] = normalizeSarif(trivyVulnerability("/repo/requirements.txt", "opaque finding text"), "trivy", TARGET);
    expect(opaque?.package).toBeUndefined();
    const [misconfiguration] = normalizeSarif({
      runs: [{
        tool: { driver: { name: "trivy", rules: [{ id: "DS002", name: "Misconfiguration", properties: { tags: ["misconfiguration"] } }] } },
        results: [{
          ruleId: "DS002",
          message: { text: message("Brotli", "1.2.0") },
          locations: [{ physicalLocation: { artifactLocation: { uri: "/repo/Dockerfile" }, region: { startLine: 1 } } }],
        }],
      }],
    }, "trivy", TARGET);
    expect(misconfiguration?.package).toBeUndefined();
  });
});

describe("Trivy dependency remediation", () => {
  // Field re-test (immich mobile/android/Gemfile.lock): Ruby advisories state the fix as a
  // constraint with a space, which left 12 findings with the generic remediation.
  test("keeps a fixed-version constraint that contains spaces", () => {
    const sarif: SarifLog = {
      runs: [{
        tool: { driver: { name: "trivy", rules: [{ id: "CVE-2026-35611", name: "LanguageSpecificPackageVulnerability", shortDescription: { text: "addressable: Denial of Service via crafted URI templates" }, properties: { tags: ["vulnerability"] } }] } },
        results: [{
          ruleId: "CVE-2026-35611",
          message: { text: "Package: addressable\nInstalled Version: 2.8.6\nVulnerability CVE-2026-35611\nSeverity: HIGH\nFixed Version: ~> 2.8.7, >= 2.9.0\nLink: [CVE-2026-35611](https://avd.aquasec.com/nvd/cve-2026-35611)" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "Gemfile.lock" }, region: { startLine: 1 } } }],
        }],
      }],
    };
    const [finding] = normalizeSarif(sarif, "trivy", TARGET);
    expect(finding?.title).toBe("addressable: Denial of Service via crafted URI templates (addressable@2.8.6)");
    expect(finding?.remediation.summary).toBe(
      "Upgrade addressable from 2.8.6 to a fixed version (~> 2.8.7, >= 2.9.0; choose the one on your release line), then rebuild the lockfile.",
    );
  });
});

describe("Trivy Magento -pN patch releases (field N2)", () => {
  // Real Trivy 0.76.1 messages (offline, DB 2026-10-31) for magento/community-edition locked at 2.4.7-p3 and
  // 2.4.6-p11. Trivy orders a `-pN` patch release before its base release (as a pre-release) and compares N
  // as text, so 2.4.7-p3 reads as below the 2.4.7 fix and 2.4.6-p11 as below the 2.4.6-p6 fix.
  const result = (id: string, name: string, installed: string, fixed: string, line = 5) => ({
    ruleId: id,
    message: { text: `Package: ${name}\nInstalled Version: ${installed}\nVulnerability ${id}\nSeverity: HIGH\nFixed Version: ${fixed}\nLink: [${id}](https://avd.aquasec.com/nvd/${id.toLowerCase()})` },
    locations: [{ physicalLocation: { artifactLocation: { uri: "composer.lock", uriBaseId: "ROOTPATH" }, region: { startLine: line, startColumn: 1, endLine: line + 4, endColumn: 1 } } }],
  });
  const sarif = (results: ReturnType<typeof result>[]): SarifLog => ({
    runs: [{
      tool: { driver: { name: "Trivy", rules: [...new Set(results.map((entry) => entry.ruleId))].map((id) => ({ id, name: "LanguageSpecificPackageVulnerability", shortDescription: { text: `Magento ${id}` }, properties: { tags: ["vulnerability", "security", "HIGH"], "security-severity": "8.1" } })) } },
      results,
    }],
  });
  const CE = "magento/community-edition";
  const findings = normalizeSarif(sarif([
    // Fixed on the 2.4.7 line by 2.4.7 itself: 2.4.7-p3 is later. Trivy reports it (false positive).
    result("CVE-2024-20758", CE, "2.4.7-p3", "2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8"),
    // Fixed on the 2.4.7 line by 2.4.7-p6: 2.4.7-p3 is affected (true positive).
    result("CVE-2025-47110", CE, "2.4.7-p3", "2.4.8-p1, 2.4.7-p6, 2.4.5-p13, 2.4.6-p11"),
    // No fixed release listed: never provably fixed.
    result("CVE-2025-54236", CE, "2.4.7-p3", ""),
    // Fixed exactly at the installed release, and fixed at p6 < p11 (Trivy compares "p11" < "p6" as text).
    result("CVE-2025-47110", CE, "2.4.6-p11", "2.4.8-p1, 2.4.7-p6, 2.4.5-p13, 2.4.6-p11", 20),
    result("CVE-2024-34102", CE, "2.4.6-p11", "2.4.6-p6, 2.4.5-p8, 2.4.4-p9", 20),
    // Only a later line is fixed: nothing proves 2.4.7-p3 fixed.
    result("CVE-2025-24434", CE, "2.4.7-p3", "2.4.8-beta2"),
    // Not a Magento core package, and a core package without a -pN suffix: untouched.
    result("CVE-2026-0001", "acme/thing", "2.4.7-p3", "2.4.7"),
    result("CVE-2026-0002", CE, "2.4.6", "2.4.6"),
  ]), "trivy", "/repo");

  test("drops only findings whose installed -pN release is at or above every fix on its own release line, and names them", () => {
    const { kept, suppressed } = splitMagentoPatchFixed(findings);
    expect(suppressed.map((entry) => `${entry.rule_id}@${entry.version}`)).toEqual([
      "CVE-2024-20758@2.4.7-p3",
      "CVE-2025-47110@2.4.6-p11",
      "CVE-2024-34102@2.4.6-p11",
    ]);
    expect(suppressed[0]).toEqual({ file: "composer.lock", name: CE, version: "2.4.7-p3", rule_id: "CVE-2024-20758" });
    expect(kept.map((finding) => `${finding.rule_id}@${finding.package?.version}`)).toEqual([
      "CVE-2025-47110@2.4.7-p3",
      "CVE-2025-54236@2.4.7-p3",
      "CVE-2025-24434@2.4.7-p3",
      "CVE-2026-0001@2.4.7-p3",
      "CVE-2026-0002@2.4.6",
    ]);
  });

  test("kept findings are the very objects normalisation produced: fingerprints and ids unchanged", () => {
    const { kept } = splitMagentoPatchFixed(findings);
    for (const finding of kept) expect(findings).toContain(finding);
    const again = normalizeSarif(sarif([result("CVE-2025-47110", CE, "2.4.7-p3", "2.4.8-p1, 2.4.7-p6, 2.4.5-p13, 2.4.6-p11")]), "trivy", "/repo");
    expect(kept[0]!.fingerprint).toBe(again[0]!.fingerprint);
  });

  test("the other locked Magento core names are covered; other engines' findings are never touched", () => {
    for (const name of ["magento/product-community-edition", "magento/project-community-edition", "magento/magento2-base", "magento/product-enterprise-edition"]) {
      const [finding] = normalizeSarif(sarif([result("CVE-2024-20758", name, "2.4.7-p3", "2.4.7")]), "trivy", "/repo");
      expect(splitMagentoPatchFixed([finding!]).suppressed).toHaveLength(1);
    }
    const osv = { ...findings[0]!, engine: "osv-scanner" as const, engines: ["osv-scanner" as const] };
    expect(splitMagentoPatchFixed([osv]).kept).toEqual([osv]);
  });

  test("a fix list Magento ordering cannot read keeps the finding", () => {
    const [finding] = normalizeSarif(sarif([result("CVE-2026-0003", CE, "2.4.7-p3", "2.4.7-hotfix, 2.4.6-p5")]), "trivy", "/repo");
    expect(splitMagentoPatchFixed([finding!]).kept).toHaveLength(1);
  });
});
