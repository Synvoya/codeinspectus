/**
 * G7 redaction invariant (CG-23 finding A4-1).
 *
 * The JWT DETECTOR (client-secrets.ts JWT_RE → emits a critical
 * `ci-ai-supabase-service-role-client` finding) and the JWT REDACTOR
 * (redact.ts SECRET_PATTERNS "JSON Web Token", the only snippet protection via
 * redactSnippet) must stay consistent: every token the detector can match MUST be
 * redactable, or a raw token leaks verbatim in location.snippet.
 *
 * Property under test: detector ⊆ redactor — for any string JWT_RE matches,
 * redactSnippet must not echo it verbatim.
 */

import { describe, test, expect } from "vitest";
import { JWT_RE } from "./ai-checks/client-secrets.js";
import { redactSnippet, redactSecretText } from "./redact.js";

/** True if the JWT detector matches the token (reset /g lastIndex first). */
function detects(token: string): boolean {
  JWT_RE.lastIndex = 0;
  return JWT_RE.test(token);
}

// A base64url-safe segment of n chars, and a header/payload segment (starts "eyJ").
const seg = (n: number): string => "A".repeat(n);
const hdr = (n: number): string => "eyJ" + "A".repeat(n);

// Each token is a genuine JWT_RE match. The first three were NOT redacted by the
// pre-fix redactor (it required {10,}-char segments / eyJ+{10,} headers), so they
// leaked. The fourth is a realistic token that was always redacted (regression guard).
const TOKENS: Array<{ label: string; token: string }> = [
  { label: "8-char signature (documented repro)", token: `${hdr(8)}.${hdr(8)}.${seg(8)}` },
  { label: "9-char signature", token: `${hdr(8)}.${hdr(8)}.${seg(9)}` },
  { label: "minimal 11-char header segment", token: `${hdr(8)}.${hdr(8)}.${seg(43)}` },
  { label: "realistic long token", token: `${hdr(34)}.${hdr(60)}.${seg(43)}` },
];

describe("JWT detector ⊆ redactor (G7 redaction invariant)", () => {
  for (const { label, token } of TOKENS) {
    test(`${label}: is detected by JWT_RE`, () => {
      expect(detects(token)).toBe(true);
    });

    test(`${label}: is redacted by redactSnippet`, () => {
      const out = redactSnippet(`const key = "${token}";`);
      expect(out).not.toContain(token);
    });
  }

  test("token glued to a preceding word char still redacts (detector has no \\b anchor)", () => {
    const token = `${hdr(34)}.${hdr(60)}.${seg(43)}`;
    const snippet = `secret${token}`; // preceded by a word char — a leading \b in the redactor would miss this
    expect(detects(snippet)).toBe(true);
    expect(redactSnippet(snippet)).not.toContain(token);
  });
});

// CG-24 A3-2: a private-key block must be redacted through END, not just the header.
describe("PEM private-key block redaction (CG-24 A3-2)", () => {
  const PEM_BODY = "MIIEowIBAAKCAQEA1Sf4kQv8ttJqExampleBodyLine0123456789abcdefXYZ==";
  const PEM = ["-----BEGIN RSA PRIVATE KEY-----", PEM_BODY, "ZW5kb2ZrZXlib2R5", "-----END RSA PRIVATE KEY-----"].join("\n");

  test("redactSnippet removes the key body, not only the BEGIN header", () => {
    const out = redactSnippet(`const key = \`${PEM}\`;`);
    expect(out).not.toContain(PEM_BODY);
    expect(out).not.toContain("ZW5kb2ZrZXlib2R5");
  });

  test("PKCS#8 header (no RSA/EC prefix) is also fully redacted", () => {
    const pem = ["-----BEGIN PRIVATE KEY-----", PEM_BODY, "-----END PRIVATE KEY-----"].join("\n");
    expect(redactSnippet(pem)).not.toContain(PEM_BODY);
  });
});

// CG-24 A3-1: value-agnostic scrub — a secret whose shape is NOT in the 11 known
// patterns must still be removed (the field is dropped rather than echoed raw).
describe("redactSecretText: value-agnostic scrub (CG-24 A3-1)", () => {
  const NON_ALLOWLISTED = [
    { label: "SendGrid key", value: "SG.aB3dE5gH7jK9lM1nO2pQ.rS4tU6vW8xY0zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1" },
    { label: "GitLab PAT", value: "glpat-AbCdEf1234567890XyZw" },
    { label: "high-entropy generic", value: "f3Q8zR1xW9kL2mN7pV4tB6cD0sJ5hG8a" },
  ];

  for (const { label, value } of NON_ALLOWLISTED) {
    test(`${label}: raw value never survives`, () => {
      const out = redactSecretText(`const apiKey = "${value}";`, "generic-api-key");
      expect(out).not.toContain(value);
    });
  }

  test("a KNOWN pattern is masked in place (preview kept, prose preserved)", () => {
    const out = redactSecretText('token = "sk_live_0123456789abcdefghij" // note', "stripe");
    expect(out).not.toContain("sk_live_0123456789abcdefghij");
    expect(out).toContain("note"); // surrounding prose survives when we can localize the secret
  });

  test("empty / whitespace input is returned unchanged", () => {
    expect(redactSecretText("", "x")).toBe("");
    expect(redactSecretText("   ", "x")).toBe("   ");
  });
});
