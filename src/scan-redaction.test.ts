/**
 * Every finding snippet surfaced by a scan must be free of credential material, including values
 * that sit NEXT TO the located finding (neighbouring lines, truncated context windows) and values
 * inside non-secret findings. Values below are synthetic, high-entropy test strings.
 */
import { describe, expect, test } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runScan } from "./scan.js";
import { scrubCredentialContext } from "./redact.js";

const GENERIC_PASSWORD = "Pq7xL9vR2mT8kW4nB6yH3jD5";
const GITHUB_TOKEN = `ghp_${"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}`;
const AWS_SECRET = "WbBN8fQ2x7Lr9TzK4mVp6Hs1Yd3Gc5Jn0Ea8Uq2W";
const HEADER_KEY = "a9F3kQ7mZ2xL8vR4tW6yB1nC5";
const STRIPE_KEY = `sk_live_${"4eC39HqLyjWDarjtT1zdp7dc"}`;

function leaks(output: string, secret: string, window = 12): boolean {
  for (let start = 0; start + window <= secret.length; start++) {
    if (output.includes(secret.slice(start, start + window))) return true;
  }
  return false;
}

describe("scrubCredentialContext", () => {
  test.each([
    ["credential-named assignment", `const dbPassword = "${GENERIC_PASSWORD}";`, GENERIC_PASSWORD],
    ["truncated provider token at a window edge", `${GITHUB_TOKEN.slice(6)}"; const k = 1;`, GITHUB_TOKEN.slice(6)],
    ["unprefixed high-entropy value", `secretAccessKey: "${AWS_SECRET}"`, AWS_SECRET],
    ["bracketed header key", `headers["x-api-key"] = "${HEADER_KEY}";`, HEADER_KEY],
  ])("masks a %s", (_label, text, secret) => {
    expect(leaks(scrubCredentialContext(text), secret)).toBe(false);
  });

  test.each([
    ["URL credentials", "const url = 'postgres://admin:Sup3rS3cretPw@db.internal:5432/app';", "Sup3rS3cretPw"],
    ["a quote character inside the quoted value", `const dbPassword = "p@ss'W0rd-Xy9Q";`, "p@ss'W0rd-Xy9Q"],
    ["an unquoted .env value", "DB_PASSWORD=CorrectHorseBatteryStaple", "CorrectHorseBatteryStaple"],
    ["an unquoted YAML value", "  password: Summer2024!Secret", "Summer2024!Secret"],
    ["a JSON-escaped value", String.raw`{"password": "ab\"cdEFgh12"}`, "cdEFgh12"],
  ])("masks %s", (_label, text, secret) => {
    expect(scrubCredentialContext(text)).not.toContain(secret);
  });

  test.each([
    ["an all-lowercase env value", "STRIPE_SECRET_KEY=hunterhunterhunter", "hunterhunterhunter"],
    ["a bearer token after its scheme", "Authorization: Bearer 8f3a9c2e1b7d", "8f3a9c2e1b7d"],
  ])("masks %s", (_label, text, secret) => {
    expect(scrubCredentialContext(text)).not.toContain(secret);
  });

  test.each([
    ["a long key before the keyword", `const ${"a".repeat(80)}_password = "hunter2hunter2";`, "hunter2hunter2"],
    ["a long quoted low-entropy value", `const password = "${"ab".repeat(400)}";`, "ab".repeat(400)],
    ["a URL with a long user part", `postgres://${"u".repeat(300)}:S3cretPw9@db/app`, "S3cretPw9"],
  ])("masks %s", (_label, text, secret) => {
    expect(scrubCredentialContext(text)).not.toContain(secret);
  });

  test("masks every Basic credential, including short base64 without digits", () => {
    expect(scrubCredentialContext("curl -H 'Authorization: Basic dXNlcjpwYXNz'")).not.toContain("dXNlcjpwYXNz");
    const letters = "abcdefghijklmnopqrstuvwxyz";
    for (let index = 0; index < 2_000; index++) {
      const word = (length: number) => Array.from({ length }, (_value, position) => letters[(index * 7 + position * 13) % 26]).join("");
      const encoded = Buffer.from(`${word(3 + (index % 6))}:${word(3 + (index % 5))}`).toString("base64");
      expect(scrubCredentialContext(`Authorization: Basic ${encoded}`)).not.toContain(encoded);
    }
  });

  test.each([
    ["prose after Token", "// Token revocation disabled for tests"],
    ["prose after Basic", "// Basic middleware applies to every route"],
  ])("keeps %s readable", (_label, text) => {
    expect(scrubCredentialContext(text)).toBe(text);
  });

  test("keeps the auth scheme word readable", () => {
    expect(scrubCredentialContext("Authorization: Bearer 8f3a9c2e1b7d")).toContain("Bearer ");
  });

  test.each([
    ["a 1 MB hex run", `dangerouslyAllowBrowser: true, k: "${"a1b2c3d4e5f6".repeat(90_000)}"`],
    ["a repeated credential keyword", `${"token".repeat(200_000)}: x`],
    ["many dotted segments", `${"a.".repeat(500_000)}b`],
  ])("scrubs %s in linear time", (_label, text) => {
    const started = performance.now();
    scrubCredentialContext(text);
    expect(performance.now() - started).toBeLessThan(2_000);
  });

  test.each([
    ["a UUID", "const id = '123e4567-e89b-12d3-a456-426614174000';"],
    ["an SRI integrity hash", `integrity="sha512-9aB3xYz0Qw8Lk2Jp5Rt7Uv1Mn4Hg6Fd3Sa9Zx2Cv5Bn8Mq1Wr4Et7Yu0Io3Pa6Sd9Fg=="`],
    ["a pinned action SHA", "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"],
    ["a template-literal credential reference", "headers.Authorization = `Bearer ${token}`;"],
    ["an environment reference", "const password = process.env.DB_PASSWORD;"],
    ["a variable reference", "  password: userPassword,"],
  ])("keeps %s readable", (_label, text) => {
    expect(scrubCredentialContext(text)).toBe(text);
  });

  test("keeps ordinary code readable", () => {
    const code = `if (user.user_metadata.role === "admin") { return renderDashboard(sessionId); }`;
    expect(scrubCredentialContext(code)).toBe(code);
  });
});

describe("scan output redaction", () => {
  test("no finding snippet carries a neighbouring or embedded secret", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-scan-redaction-"));
    await mkdir(join(dir, "src", "server"), { recursive: true });
    await writeFile(join(dir, "src", "r1.ts"), `const dbPassword = "${GENERIC_PASSWORD}";\nconst k = "${STRIPE_KEY}";\n`);
    await writeFile(join(dir, "src", "r3.ts"), `const gh = "${GITHUB_TOKEN}"; const k = "${STRIPE_KEY}";\n`);
    await writeFile(join(dir, "src", "server", "aws.ts"),
      `export const cfg = { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "${AWS_SECRET}" };\n`);
    await writeFile(join(dir, "src", "server", "authz.ts"),
      `export function h(user: any, headers: any) {\n  if (user.user_metadata.role === "admin") { headers["x-api-key"] = "${HEADER_KEY}"; }\n}\n`);

    const result = await runScan({ path: dir, scanners: ["ai"] });

    expect(result.findings.length).toBeGreaterThan(0);
    const output = JSON.stringify(result);
    for (const secret of [GENERIC_PASSWORD, GITHUB_TOKEN, AWS_SECRET, HEADER_KEY, STRIPE_KEY]) {
      expect(leaks(output, secret), secret.slice(0, 4)).toBe(false);
    }
  });

  test("a finding on a very long minified line is scrubbed quickly", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-scan-longline-"));
    await writeFile(join(dir, "client.ts"),
      `import OpenAI from "openai"; const c = new OpenAI({ dangerouslyAllowBrowser: true, k: "${"a1b2c3d4e5f6".repeat(12_500)}" });\n`);
    const started = performance.now();

    const result = await runScan({ path: dir, scanners: ["ai"] });

    expect(performance.now() - started).toBeLessThan(10_000);
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) expect((finding.location.snippet ?? "").length).toBeLessThanOrEqual(4_200);
  }, 30_000);
});
