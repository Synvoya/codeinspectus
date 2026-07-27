import { describe, expect, test } from "vitest";

import { parseJavaScriptSource } from "../react-native/javascript.js";
import {
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
        crypto.createHash("md5");
        crypto.createHash("sha1");
      `,
      "cipher.ts": `
        import { createHash, createCipheriv, createCipher } from "node:crypto";
        createHash("sha1");
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
      expect(finding).toMatchObject({
        severity: "medium",
        confidence: "medium",
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

    expect(result).toEqual({ findings: [], limitations: [] });
  });

  test("retains duplicate same-line multiplicity and multiline end ranges", async () => {
    const result = await runJavaScriptBaselineCandidates(project({
      "multiplicity.jsx": `crypto.createHash("md5"); crypto.createHash("sha1");`,
      "multiline.ts": `crypto.createCipheriv(\n  "rc4",\n  key,\n  iv,\n);`,
    }));
    expect(result.findings).toHaveLength(3);
    expect(result.findings.filter((finding) => finding.location.file === "multiplicity.jsx"))
      .toHaveLength(2);
    expect(result.findings.find((finding) => finding.location.file === "multiline.ts")?.location)
      .toMatchObject({ start_line: 1, end_line: 5 });
  });
});
