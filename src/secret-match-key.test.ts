import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { hashSecret } from "./redact.js";
import { normalizeSarif } from "./sarif/normalize.js";
import type { SarifLog } from "./sarif/types.js";
import type { Finding } from "./types.js";
import { secretMatchKeys, secretValueAt } from "./secret-match-key.js";

// Values are assembled at run time so this file holds no secret-shaped literal.
const j = (...parts: string[]): string => parts.join("");
const VALUE = j("Qm7ZpX2kL9vR4tY8", "wB3nC6dF1gH5jK0s");
const PAT = j("ghp_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5");

/** A Gitleaks SARIF result as Gitleaks 8.30 writes it with --redact=100 (the snippet carries no value). */
function gitleaksResult(uri: string, line: number, endColumn: number, ruleId = "generic-api-key") {
  return {
    ruleId,
    message: { text: `${ruleId} has detected secret for file ${uri}.` },
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line, startColumn: 1, endLine: line, endColumn, snippet: { text: "REDACTED" } } } }],
  };
}

function sarif(engine: string, results: unknown[]): SarifLog {
  // Trivy's rule metadata for its secret rules, as Trivy 0.76 writes it.
  const rules = engine === "trivy" ? [{ id: "github-pat", name: "Secret", properties: { tags: ["secret", "security", "CRITICAL"] } }] : [];
  return { runs: [{ tool: { driver: { name: engine, rules } }, results }] } as unknown as SarifLog;
}

describe("secretValueAt — the secret Gitleaks matched, read back from the source line", () => {
  // End columns are the ones real Gitleaks 8.30 reported for these lines: exact on line 1, one byte
  // further on later lines.
  test("a quoted value on line 1", () => {
    const line = `export const config = { api_key: "${VALUE}" };`;
    expect(secretValueAt(Buffer.from(line), 67)).toBe(VALUE);
  });

  test("a quoted value on a later line, where the end column covers the terminator too", () => {
    const line = `const x = 1; const apiKey = "${VALUE}"; // é`;
    expect(secretValueAt(Buffer.from(line), 63)).toBe(VALUE);
  });

  test("an unquoted KEY=value assignment and a curl Authorization header", () => {
    expect(secretValueAt(Buffer.from(`API_KEY=${VALUE}`), 41)).toBe(VALUE);
    expect(secretValueAt(Buffer.from(`curl -H "Authorization: Bearer ${VALUE}" https://x`), 64)).toBe(VALUE);
  });

  test("columns count bytes, so a multi-byte character before the value does not shift it", () => {
    const line = `const été = "${VALUE}";`;
    expect(secretValueAt(Buffer.from(line), Buffer.byteLength(`const été = "${VALUE}"`))).toBe(VALUE);
  });

  test("no value of secret length before the end column gives no value", () => {
    expect(secretValueAt(Buffer.from("const a = 'x';"), 13)).toBeUndefined();
    expect(secretValueAt(Buffer.from(`k = "${VALUE}"`), 0)).toBeUndefined();
  });
});

describe("secretMatchKeys — routing-only keys for redacted Gitleaks and Trivy secrets", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(await realpath(tmpdir()), "ci-secret-key-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  async function write(rel: string, text: string): Promise<void> {
    await mkdir(dirname(join(root, rel)), { recursive: true });
    await writeFile(join(root, rel), text, "utf8");
  }

  test("the same value under different names in two files gets one key, the hash of the value, and no new finding field", async () => {
    await write("src/keys.ts", `export const config = { api_key: "${VALUE}" };\n`);
    await write("tests/keys.test.ts", `// fixture\nconst apiKey = "${VALUE}";\n`);
    const findings = normalizeSarif(sarif("gitleaks", [
      gitleaksResult(join(root, "src/keys.ts"), 1, 67),
      gitleaksResult(join(root, "tests/keys.test.ts"), 2, 50),
    ]), "gitleaks", root);
    expect(findings).toHaveLength(2);
    const before = JSON.stringify(findings);
    const keys = await secretMatchKeys(root, findings);
    expect(keys.get(findings[0]!)).toBe(hashSecret(VALUE));
    expect(keys.get(findings[1]!)).toBe(hashSecret(VALUE));
    // Routing-only: the findings (and so every fingerprint, stored and exported field) are untouched.
    expect(JSON.stringify(findings)).toBe(before);
    expect(findings.every((finding) => finding.secret_value_hash === undefined)).toBe(true);
    expect(before).not.toContain(VALUE);
    expect(before).not.toContain(hashSecret(VALUE));
  });

  test("a Trivy secret (masked, no columns) is keyed by the known-pattern value on its line", async () => {
    await write("src/token.ts", `const token = "${PAT}";\n`);
    const [finding] = normalizeSarif(sarif("trivy", [{
      ruleId: "github-pat",
      ruleIndex: 0,
      message: { text: "Artifact: src/token.ts\nType: \nSecret GitHub Personal Access Token\nSeverity: CRITICAL\nMatch: const token = \"****\";" },
      locations: [{ physicalLocation: { artifactLocation: { uri: "src/token.ts" }, region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 } } }],
    }]), "trivy", root);
    expect(finding?.is_secret).toBe(true);
    expect((await secretMatchKeys(root, [finding!])).get(finding!)).toBe(hashSecret(PAT));
  });

  /** A Trivy secret finding as the normalizer builds it (masked, no columns). */
  function trivySecret(file: string, extra: Partial<Finding> = {}): Finding {
    const [finding] = normalizeSarif(sarif("trivy", [{
      ruleId: "github-pat",
      ruleIndex: 0,
      message: { text: `Artifact: ${file}\nType: \nSecret GitHub Personal Access Token\nSeverity: CRITICAL\nMatch: const token = "****";` },
      locations: [{ physicalLocation: { artifactLocation: { uri: file }, region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 } } }],
    }]), "trivy", root);
    return { ...finding!, ...extra };
  }

  test("a symbolic link and a missing file give no key", async () => {
    await write("real/keys.ts", `const apiKey = "${VALUE}";\n`);
    await mkdir(join(root, "src"), { recursive: true });
    await symlink(join(root, "real/keys.ts"), join(root, "src/link.ts"));
    const findings = normalizeSarif(sarif("gitleaks", [
      gitleaksResult(join(root, "real/keys.ts"), 1, 49),
      gitleaksResult(join(root, "src/link.ts"), 1, 49),
      gitleaksResult(join(root, "src/missing.ts"), 1, 49),
    ]), "gitleaks", root);
    const keys = await secretMatchKeys(root, findings);
    expect([...keys.keys()].map((finding) => finding.location.file)).toEqual(["real/keys.ts"]);
  });

  test("a path outside the target, a finding that already has a secret_value_hash, and a non-secret are not read", async () => {
    await write("src/token.ts", `const token = "${PAT}";\n`);
    expect((await secretMatchKeys(root, [trivySecret("src/token.ts")])).size).toBe(1);
    const outside = trivySecret("src/token.ts", { location: { file: "../token.ts", start_line: 1, end_line: 1 } });
    const hashed = trivySecret("src/token.ts", { secret_value_hash: hashSecret("other") });
    const code = trivySecret("src/token.ts", { is_secret: undefined });
    expect((await secretMatchKeys(root, [outside, hashed, code])).size).toBe(0);
  });
});
