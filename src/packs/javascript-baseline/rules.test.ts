import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

import { parseJavaScriptSource } from "../react-native/javascript.js";
import {
  CREDENTIAL_CHAIN_SOURCE,
  CREDENTIAL_TARGET_SOURCE,
  hasCredentialWord,
  JAVASCRIPT_WEAK_CIPHER_RULE_ID,
  JAVASCRIPT_WEAK_HASH_RULE_ID,
  runJavaScriptBaselineCandidates,
} from "./rules.js";
import type { JavaScriptBaselineProject } from "./project.js";

function project(sources: Record<string, string>): JavaScriptBaselineProject {
  return {
    target: "/fixture",
    root: "/fixture",
    files: Object.entries(sources).map(([path, source]) => parseJavaScriptSource(path, source)),
  };
}

describe("JavaScript baseline shadow candidates", () => {
  test("matches every selected Opengrep arm including a bare named import", async () => {
    const result = await runJavaScriptBaselineCandidates(project({
      "hash.js": `
        const crypto = require("node:crypto");
        crypto.createHash("md5").update(password);
        const tokenDigest = crypto.createHash("sha1").digest("hex");
      `,
      "cipher.ts": `
        import { createHash, createCipheriv, createCipher } from "node:crypto";
        const signature = createHash("sha1").update(body).digest("hex");
        createCipheriv("des", key, iv);
        createCipheriv("des-ede3", key, iv);
        createCipheriv("rc4", key, iv);
        createCipher("aes-256-cbc", password);
      `,
    }));

    expect(result.limitations).toEqual([]);
    expect(result.findings.filter((finding) => finding.rule_id === JAVASCRIPT_WEAK_HASH_RULE_ID)).toHaveLength(3);
    expect(result.findings.filter((finding) => finding.rule_id === JAVASCRIPT_WEAK_CIPHER_RULE_ID)).toHaveLength(4);
    for (const finding of result.findings) {
      // Design 10.6 precision pass: weak-hash is a low/low hygiene finding (0 of 13 field hits were
      // credential hashing); weak-cipher keeps medium/medium.
      const weakHash = finding.rule_id === JAVASCRIPT_WEAK_HASH_RULE_ID;
      expect(finding).toMatchObject({
        severity: weakHash ? "low" : "medium",
        confidence: weakHash ? "low" : "medium",
        cwe: ["CWE-327"],
        owasp_web: ["A02:2021"],
        finding_kind: "sast",
      });
    }
  });

  test("excludes modern, dynamic, case-variant, literal, and lookalike shapes", async () => {
    const result = await runJavaScriptBaselineCandidates(project({
      "safe.tsx": `
        const text = "crypto.createHash('md5')";
        const template = \`crypto.createCipher('des')\`;
        // crypto.createCipheriv("rc4", key, iv)
        crypto.createHash("sha256");
        crypto.createHash("SHA1");
        crypto.createHash(algorithm);
        crypto.createCipheriv("aes-256-gcm", key, iv);
        const createCipher = false;
      `,
    }));

    expect(result).toEqual({ findings: [], limitations: [], gaps: [] });
  });

  test("retains duplicate same-line multiplicity and multiline end ranges", async () => {
    const result = await runJavaScriptBaselineCandidates(project({
      "multiplicity.jsx": `crypto.createHash("md5").update(pwd); crypto.createHash("sha1").update(secret);`,
      "multiline.ts": `crypto.createCipheriv(\n  "rc4",\n  key,\n  iv,\n);`,
    }));
    expect(result.findings).toHaveLength(3);
    expect(result.findings.filter((finding) => finding.location.file === "multiplicity.jsx"))
      .toHaveLength(2);
    expect(result.findings.find((finding) => finding.location.file === "multiline.ts")?.location)
      .toMatchObject({ start_line: 1, end_line: 5 });
  });

  // M7 (Ruling 10): one credential-word list, matched as a word after camelCase / snake / kebab splitting.
  test.each([
    ["password", true], ["userPassword", true], ["passwordMd5", true], ["PASSWORD", true], ["db_passwd", true],
    ["passphrase", true], ["pwd", true], ["pass", true], ["clientSecret", true], ["authToken", true],
    ["apikey", true], ["apiKey", true], ["API_KEY", true], ["api-key", true], ["APIKey", true],
    ["credential", true], ["credentials", true], ["signature", true], ["sig", true], ["hmacKey", true],
    ["salt", true], ["PASSWORDHash", true],
    ["footprint", false], ["spinner", false], ["tokenizer", false], ["bypass", false], ["passage", false],
    ["compass", false], ["Passport", false], ["signal", false], ["SIGINT", false], ["PASSWORDS", false],
    ["tokens", false], ["etag", false], ["cacheKey", false], ["checksum", false],
  ])("credential word in %s: %s", (name, expected) => {
    expect(hasCredentialWord(name)).toBe(expected);
  });

  test("the Opengrep rule uses the same credential regexes", () => {
    const yaml = readFileSync(join(import.meta.dirname, "../../../detection-db/opengrep-rules/security-baseline/crypto.yaml"), "utf8");
    const quoted = (source: string): string => `'${source.replace(/'/g, "''")}'`;
    expect(yaml).toContain(`regex: ${quoted(CREDENTIAL_CHAIN_SOURCE)}`);
    expect(yaml).toContain(`regex: ${quoted(CREDENTIAL_TARGET_SOURCE)}`);
  });

  test("weak-hash fires only in a credential context", async () => {
    const result = await runJavaScriptBaselineCandidates(project({
      "tp.ts": [
        'import crypto, { createHash } from "node:crypto";',
        'crypto.createHash("md5").update(password).digest("hex");',
        'createHash("sha1").update(`${user}:${password}`).digest("hex");',
        'const passwordMd5 = createHash("md5").update(x).digest("hex");',
        'const out = { signature: createHash("sha1").update(payload + secret).digest("hex") };',
        'user.passwordHash = crypto.createHash("md5").update(pw).digest("hex");',
        'crypto.createHash("md5").update(req.body.password);',
        'const apiKeyHash: string = createHash("sha1").update(x).digest("hex");',
        'const obj = { "token": createHash("md5").update(x).digest("hex") };',
        'createHash("md5").update(user + ":" + pass);',
      ].join("\n"),
      "fp.ts": [
        'import crypto, { createHash } from "node:crypto";',
        'const cacheKey = crypto.createHash("md5").update(url).digest("hex");',
        'const headers = { etag: createHash("sha1").update(body).digest("base64") };',
        'const checksum = crypto.createHash("md5").update(fileBuffer).digest("hex");',
        'crypto.createHash("md5").update(footprint).digest("hex");',
        'const bypassHash = createHash("sha1").update(bypass).digest("hex");',
        'crypto.createHash("sha256").update(password).digest("hex");',
        'const tokenizer = createHash("md5").update(x).digest("hex");',
        'const secretLength = createHash("md5").update(x).digest("hex").length;',
        'createHash("md5").update(count * password);',
        'createHash("md5").update(prefix + password.length);',
        'const label = flag ? token : createHash("md5").update(x).digest("hex");',
      ].join("\n"),
      "known-gap.ts": [
        'import crypto from "node:crypto";',
        // Two statements: neither implementation follows the hash object into a later update().
        'const h = crypto.createHash("md5");',
        'h.update(password);',
        // A member expression interpolated in a template: Opengrep 1.33.1 does not match it either.
        'createHash("md5").update(`${user.name}:${user.password}`);',
      ].join("\n"),
    }));
    const lines = (file: string) => result.findings
      .filter((finding) => finding.rule_id === JAVASCRIPT_WEAK_HASH_RULE_ID && finding.location.file === file)
      .map((finding) => finding.location.start_line);
    expect(lines("tp.ts")).toEqual([2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(lines("fp.ts")).toEqual([]);
    expect(lines("known-gap.ts")).toEqual([]);
  });
});
