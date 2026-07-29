import { afterEach, describe, expect, test, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  listNativePacks,
  nativePackInventory,
  nativePackNotRunCoverage,
  registeredNativeAnalyzers,
} from "./registry.js";
import { aiFindingComponents, aiSignaturesForComponents } from "../provenance.js";
import { runAiChecks } from "../ai-checks/index.js";
import { makeAiFinding } from "../ai-checks/finding.js";
import { log } from "../logger.js";
import type { DetectedTechnology } from "../types.js";
import type { NativeAnalyzerResult, NativeDetectorPack } from "./types.js";
import { pythonAiApiPack } from "./python-ai-api-pack.js";
import { goAiPack } from "./go-ai-pack.js";
import { javaAiPack } from "./java-ai-pack.js";
import { csharpAiPack } from "./csharp-ai-pack.js";
import { phpAiPack } from "./php-ai-pack.js";
import { rustAiPack } from "./rust-ai-pack.js";
import { rubyAiPack } from "./ruby-ai-pack.js";
import { firebasePack } from "./firebase-pack.js";
import { githubActionsPack } from "./github-actions-pack.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { recursive: true, force: true })
  ));
});

async function temporaryProject(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-pack-"));
  temporaryDirectories.push(directory);
  return directory;
}

function testFinding() {
  return makeAiFinding({
    ruleId: "ci-ai-prompt-injection-sink",
    title: "Test finding",
    severity: "medium",
    cwe: ["CWE-1427"],
    file: "src/test.ts",
    startLine: 1,
    snippet: "test",
    message: "test",
    remediation: { summary: "test", steps: [], references: [] },
    confidence: "medium",
  });
}

function testPack(
  promptRun: () => Promise<NativeAnalyzerResult>,
  apiRun: () => Promise<NativeAnalyzerResult>,
  isApplicable?: (detectedTechnologies: readonly DetectedTechnology[]) => boolean,
): NativeDetectorPack {
  return {
    id: "test-pack",
    version: "1.0.0-test",
    scannerKind: "ai",
    languages: ["typescript"],
    frameworks: ["test-framework"],
    platforms: [],
    limitations: ["Test limitation."],
    ...(isApplicable ? { isApplicable } : {}),
    createAnalyzers: () => [
      {
        id: "prompt-injection",
        components: ["ai:prompt-injection"],
        ruleIds: ["ci-ai-prompt-injection-sink"],
        run: promptRun,
      },
      {
        id: "api-boundary",
        components: [
          "ai:client-error-leak",
          "ai:sensitive-api-response",
          "ai:unvalidated-request-write",
          "ai:sensitive-log",
        ],
        ruleIds: [
          "ci-ai-client-error-leak",
          "ci-ai-sensitive-api-response",
          "ci-ai-unvalidated-request-write",
          "ci-ai-sensitive-log",
        ],
        run: apiRun,
      },
    ],
  };
}

describe("native detector pack registry", () => {
  test("language-gates ecosystem-neutral OpenAI pack dispatch", () => {
    const goOpenAi = [
      { id: "go", kind: "language", confidence: "high", evidence: [] },
      { id: "openai", kind: "framework", confidence: "high", evidence: [] },
    ] satisfies DetectedTechnology[];
    const pythonOpenAi = [
      { id: "python", kind: "language", confidence: "high", evidence: [] },
      { id: "openai", kind: "framework", confidence: "high", evidence: [] },
    ] satisfies DetectedTechnology[];
    const javaOpenAi = [
      { id: "java", kind: "language", confidence: "high", evidence: [] },
      { id: "openai", kind: "framework", confidence: "high", evidence: [] },
    ] satisfies DetectedTechnology[];
    const csharpOpenAi = [
      { id: "csharp", kind: "language", confidence: "high", evidence: [] },
      { id: "openai", kind: "framework", confidence: "high", evidence: [] },
    ] satisfies DetectedTechnology[];
    const phpOpenAi = [
      { id: "php", kind: "language", confidence: "high", evidence: [] },
      { id: "openai", kind: "framework", confidence: "high", evidence: [] },
    ] satisfies DetectedTechnology[];
    const rustOpenAi = [
      { id: "rust", kind: "language", confidence: "high", evidence: [] },
      { id: "openai", kind: "framework", confidence: "high", evidence: [] },
    ] satisfies DetectedTechnology[];
    const rubyOpenAi = [
      { id: "ruby", kind: "language", confidence: "high", evidence: [] },
      { id: "openai", kind: "framework", confidence: "high", evidence: [] },
    ] satisfies DetectedTechnology[];

    expect(goAiPack.isApplicable?.(goOpenAi)).toBe(true);
    expect(pythonAiApiPack.isApplicable?.(goOpenAi)).toBe(false);
    expect(javaAiPack.isApplicable?.(goOpenAi)).toBe(false);
    expect(csharpAiPack.isApplicable?.(goOpenAi)).toBe(false);
    expect(phpAiPack.isApplicable?.(goOpenAi)).toBe(false);
    expect(rustAiPack.isApplicable?.(goOpenAi)).toBe(false);
    expect(goAiPack.isApplicable?.(pythonOpenAi)).toBe(false);
    expect(pythonAiApiPack.isApplicable?.(pythonOpenAi)).toBe(true);
    expect(javaAiPack.isApplicable?.(pythonOpenAi)).toBe(false);
    expect(csharpAiPack.isApplicable?.(pythonOpenAi)).toBe(false);
    expect(phpAiPack.isApplicable?.(pythonOpenAi)).toBe(false);
    expect(rustAiPack.isApplicable?.(pythonOpenAi)).toBe(false);
    expect(goAiPack.isApplicable?.(javaOpenAi)).toBe(false);
    expect(pythonAiApiPack.isApplicable?.(javaOpenAi)).toBe(false);
    expect(javaAiPack.isApplicable?.(javaOpenAi)).toBe(true);
    expect(csharpAiPack.isApplicable?.(javaOpenAi)).toBe(false);
    expect(phpAiPack.isApplicable?.(javaOpenAi)).toBe(false);
    expect(rustAiPack.isApplicable?.(javaOpenAi)).toBe(false);
    expect(goAiPack.isApplicable?.(csharpOpenAi)).toBe(false);
    expect(pythonAiApiPack.isApplicable?.(csharpOpenAi)).toBe(false);
    expect(javaAiPack.isApplicable?.(csharpOpenAi)).toBe(false);
    expect(csharpAiPack.isApplicable?.(csharpOpenAi)).toBe(true);
    expect(phpAiPack.isApplicable?.(csharpOpenAi)).toBe(false);
    expect(rustAiPack.isApplicable?.(csharpOpenAi)).toBe(false);
    expect(goAiPack.isApplicable?.(phpOpenAi)).toBe(false);
    expect(pythonAiApiPack.isApplicable?.(phpOpenAi)).toBe(false);
    expect(javaAiPack.isApplicable?.(phpOpenAi)).toBe(false);
    expect(csharpAiPack.isApplicable?.(phpOpenAi)).toBe(false);
    expect(phpAiPack.isApplicable?.(phpOpenAi)).toBe(true);
    expect(rustAiPack.isApplicable?.(phpOpenAi)).toBe(false);
    expect(goAiPack.isApplicable?.(rustOpenAi)).toBe(false);
    expect(pythonAiApiPack.isApplicable?.(rustOpenAi)).toBe(false);
    expect(javaAiPack.isApplicable?.(rustOpenAi)).toBe(false);
    expect(csharpAiPack.isApplicable?.(rustOpenAi)).toBe(false);
    expect(phpAiPack.isApplicable?.(rustOpenAi)).toBe(false);
    expect(rustAiPack.isApplicable?.(rustOpenAi)).toBe(true);
    expect(rubyAiPack.isApplicable?.(rustOpenAi)).toBe(false);
    expect(goAiPack.isApplicable?.(rubyOpenAi)).toBe(false);
    expect(pythonAiApiPack.isApplicable?.(rubyOpenAi)).toBe(false);
    expect(javaAiPack.isApplicable?.(rubyOpenAi)).toBe(false);
    expect(csharpAiPack.isApplicable?.(rubyOpenAi)).toBe(false);
    expect(phpAiPack.isApplicable?.(rubyOpenAi)).toBe(false);
    expect(rustAiPack.isApplicable?.(rubyOpenAi)).toBe(false);
    expect(rubyAiPack.isApplicable?.(rubyOpenAi)).toBe(true);
    expect(firebasePack.isApplicable?.(rubyOpenAi)).toBe(false);
    expect(firebasePack.isApplicable?.([
      { id: "firebase", kind: "platform", confidence: "high", evidence: [] },
    ])).toBe(true);
    expect(githubActionsPack.isApplicable?.([
      { id: "github-actions", kind: "platform", confidence: "high", evidence: [] },
    ])).toBe(true);
    expect(githubActionsPack.isApplicable?.(rubyOpenAi)).toBe(false);
  });

  test("registers the existing analyzer groups in their original order", () => {
    expect(listNativePacks().map((pack) => pack.id)).toEqual([
      "javascript-typescript",
      "flutter",
      "android",
      "ios",
      "react-native",
      "expo",
      "python-ai-api",
      "javascript-baseline",
      "go-ai",
      "java-ai",
      "csharp-ai",
      "php-ai",
      "rust-ai",
      "ruby-ai",
      "firebase",
      "github-actions",
    ]);
    expect(registeredNativeAnalyzers("/tmp/codeinspectus-pack-registry").map((analyzer) => analyzer.id)).toEqual([
      "client-secrets",
      "supabase-rls",
      "prompt-injection",
      "unsafe-tool-execution",
      "client-metadata-authz",
      "llm-dangerous-html",
      "api-boundary",
      "security-controls",
      "flutter-tls-verification",
      "flutter-sensitive-preferences",
      "flutter-webview-untrusted-content",
      "flutter-sensitive-log",
      "flutter-supabase-privileged-key",
      "flutter-cleartext-network",
      "android-configuration",
      "ios-configuration",
      "react-native-sensitive-async-storage",
      "react-native-webview-untrusted-content",
      "react-native-webview-mixed-content",
      "react-native-webview-universal-file-access",
      "expo-secret-in-public-config",
      "expo-unsigned-cleartext-updates",
      "python-hardcoded-signing-secret",
      "python-credentialed-cors",
      "python-untrusted-file-response",
      "python-untrusted-redirect",
      "python-untrusted-template-source",
      "python-llm-output-dangerous-html",
      "python-faiss-dangerous-deserialization",
      "python-langchain-web-loader-ssrf",
      "python-prompt-injection-sink",
      "python-unsafe-tool-execution",
      "javascript-baseline-crypto",
      "go-unsafe-tool-execution",
      "java-unsafe-tool-execution",
      "csharp-unsafe-tool-execution",
      "php-unsafe-tool-execution",
      "rust-unsafe-tool-execution",
      "ruby-unsafe-tool-execution",
      "firebase-security-rules",
      "github-actions-workflow-security",
    ]);
  });

  test("keeps pack, analyzer, and producer-component identities unique", () => {
    const packs = listNativePacks();
    const analyzers = registeredNativeAnalyzers("/tmp/codeinspectus-pack-registry");
    const packIds = packs.map((pack) => pack.id);
    const analyzerIds = analyzers.map((analyzer) => analyzer.id);
    const components = analyzers.flatMap((analyzer) => analyzer.components);
    const ruleIds = analyzers.flatMap((analyzer) => analyzer.ruleIds);

    expect(new Set(packIds).size).toBe(packIds.length);
    expect(new Set(analyzerIds).size).toBe(analyzerIds.length);
    for (const analyzer of analyzers) {
      expect(new Set(analyzer.components).size).toBe(analyzer.components.length);
    }
    const sharedComponents = components.filter((component, index) => components.indexOf(component) !== index);
    expect(new Set(sharedComponents)).toEqual(new Set([
      "pack:flutter:dispatch",
      "flutter:dart-structural-parser",
      "pack:react-native:dispatch",
      "react-native:javascript-structural-parser",
      "pack:expo:dispatch",
      "expo:static-config-parser",
      "pack:python-ai-api:dispatch",
      "python:lezer-structural-parser",
    ]));
    expect(new Set(ruleIds).size).toBe(ruleIds.length);
    expect(ruleIds).toHaveLength(65);

    const javascriptAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "javascript-typescript");
    expect(javascriptAnalyzers).toHaveLength(8);
    expect(javascriptAnalyzers.every((analyzer) => analyzer.packVersion === "1.3.0")).toBe(true);
    expect(javascriptAnalyzers.every((analyzer) => analyzer.packLanguages.includes("typescript"))).toBe(true);
    expect(javascriptAnalyzers.every((analyzer) => analyzer.packFrameworks.includes("supabase"))).toBe(true);

    const flutterAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "flutter");
    expect(flutterAnalyzers).toHaveLength(6);
    expect(flutterAnalyzers.every((analyzer) => analyzer.packVersion === "1.0.0")).toBe(true);
    expect(flutterAnalyzers.every((analyzer) => analyzer.packLanguages.includes("dart"))).toBe(true);
    expect(flutterAnalyzers.every((analyzer) => analyzer.packFrameworks.includes("flutter"))).toBe(true);

    for (const platform of ["android", "ios"]) {
      const platformAnalyzers = analyzers.filter((analyzer) => analyzer.packId === platform);
      expect(platformAnalyzers).toHaveLength(1);
      expect(platformAnalyzers[0]?.packVersion).toBe("1.0.0");
      expect(platformAnalyzers[0]?.packLanguages).toEqual(["xml"]);
      expect(platformAnalyzers[0]?.packFrameworks).toEqual([]);
      expect(platformAnalyzers[0]?.packPlatforms).toEqual([platform]);
      expect(platformAnalyzers[0]?.ruleIds).toHaveLength(4);
    }

    const reactNativeAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "react-native");
    expect(reactNativeAnalyzers).toHaveLength(4);
    expect(reactNativeAnalyzers.every((analyzer) => analyzer.packVersion === "1.0.0")).toBe(true);
    expect(reactNativeAnalyzers.every((analyzer) => analyzer.packFrameworks.includes("react-native"))).toBe(true);

    const expoAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "expo");
    expect(expoAnalyzers).toHaveLength(2);
    expect(expoAnalyzers.every((analyzer) => analyzer.packVersion === "1.0.0")).toBe(true);
    expect(expoAnalyzers.every((analyzer) => analyzer.packFrameworks.includes("expo"))).toBe(true);

    const pythonAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "python-ai-api");
    expect(pythonAnalyzers).toHaveLength(10);
    expect(pythonAnalyzers.every((analyzer) => analyzer.packVersion === "1.4.0")).toBe(true);
    expect(pythonAnalyzers.every((analyzer) => analyzer.packLanguages.includes("python"))).toBe(true);
    expect(pythonAnalyzers.every((analyzer) => analyzer.packFrameworks.includes("fastapi"))).toBe(true);
    expect(pythonAnalyzers.every((analyzer) => analyzer.packFrameworks.includes("openai"))).toBe(true);
    expect(pythonAnalyzers.every((analyzer) => analyzer.packFrameworks.includes("langchain"))).toBe(true);

    const baselineAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "javascript-baseline");
    expect(baselineAnalyzers).toHaveLength(1);
    expect(baselineAnalyzers[0]?.packScannerKind).toBe("sast");
    expect(baselineAnalyzers[0]?.ruleIds).toHaveLength(2);

    const goAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "go-ai");
    expect(goAnalyzers).toHaveLength(1);
    expect(goAnalyzers[0]?.packVersion).toBe("1.0.0");
    expect(goAnalyzers[0]?.packLanguages).toEqual(["go"]);
    expect(goAnalyzers[0]?.packFrameworks).toEqual(["openai"]);
    expect(goAnalyzers[0]?.ruleIds).toEqual(["ci-go-llm-tool-argument-command-execution"]);

    const javaAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "java-ai");
    expect(javaAnalyzers).toHaveLength(1);
    expect(javaAnalyzers[0]?.packVersion).toBe("1.0.0");
    expect(javaAnalyzers[0]?.packLanguages).toEqual(["java"]);
    expect(javaAnalyzers[0]?.packFrameworks).toEqual(["openai"]);
    expect(javaAnalyzers[0]?.ruleIds).toEqual(["ci-java-llm-tool-argument-command-execution"]);

    const csharpAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "csharp-ai");
    expect(csharpAnalyzers).toHaveLength(1);
    expect(csharpAnalyzers[0]?.packVersion).toBe("1.0.0");
    expect(csharpAnalyzers[0]?.packLanguages).toEqual(["csharp"]);
    expect(csharpAnalyzers[0]?.packFrameworks).toEqual(["openai"]);
    expect(csharpAnalyzers[0]?.ruleIds).toEqual(["ci-csharp-llm-tool-argument-command-execution"]);

    const phpAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "php-ai");
    expect(phpAnalyzers).toHaveLength(1);
    expect(phpAnalyzers[0]?.packVersion).toBe("1.0.0");
    expect(phpAnalyzers[0]?.packLanguages).toEqual(["php"]);
    expect(phpAnalyzers[0]?.packFrameworks).toEqual(["openai"]);
    expect(phpAnalyzers[0]?.ruleIds).toEqual(["ci-php-llm-tool-argument-command-execution"]);

    const rustAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "rust-ai");
    expect(rustAnalyzers).toHaveLength(1);
    expect(rustAnalyzers[0]?.packVersion).toBe("1.0.0");
    expect(rustAnalyzers[0]?.packLanguages).toEqual(["rust"]);
    expect(rustAnalyzers[0]?.packFrameworks).toEqual(["openai"]);
    expect(rustAnalyzers[0]?.ruleIds).toEqual(["ci-rust-llm-tool-argument-command-execution"]);

    const rubyAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "ruby-ai");
    expect(rubyAnalyzers).toHaveLength(1);
    expect(rubyAnalyzers[0]?.packVersion).toBe("1.0.0");
    expect(rubyAnalyzers[0]?.packLanguages).toEqual(["ruby"]);
    expect(rubyAnalyzers[0]?.packFrameworks).toEqual(["openai"]);
    expect(rubyAnalyzers[0]?.ruleIds).toEqual(["ci-ruby-llm-tool-argument-command-execution"]);

    const firebaseAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "firebase");
    expect(firebaseAnalyzers).toHaveLength(1);
    expect(firebaseAnalyzers[0]?.packVersion).toBe("1.0.0");
    expect(firebaseAnalyzers[0]?.packLanguages).toEqual(["firebase-rules", "json"]);
    expect(firebaseAnalyzers[0]?.packFrameworks).toEqual([]);
    expect(firebaseAnalyzers[0]?.packPlatforms).toEqual(["firebase"]);
    expect(firebaseAnalyzers[0]?.ruleIds).toEqual([
      "ci-firebase-firestore-public-write",
      "ci-firebase-storage-public-write",
      "ci-firebase-realtime-database-public-write",
    ]);
    const githubActionsAnalyzers = analyzers.filter((analyzer) => analyzer.packId === "github-actions");
    expect(githubActionsAnalyzers).toHaveLength(1);
    expect(githubActionsAnalyzers[0]?.packVersion).toBe("1.0.0");
    expect(githubActionsAnalyzers[0]?.packLanguages).toEqual(["yaml"]);
    expect(githubActionsAnalyzers[0]?.packFrameworks).toEqual([]);
    expect(githubActionsAnalyzers[0]?.packPlatforms).toEqual(["github-actions"]);
    expect(githubActionsAnalyzers[0]?.ruleIds).toEqual([
      "ci-github-actions-untrusted-expression-command",
      "ci-github-actions-pwn-request",
    ]);
  });

  test("exposes installed inventory and explicit not-run coverage without executing analyzers", () => {
    const inventory = nativePackInventory();
    expect(inventory).toEqual([
      expect.objectContaining({
        pack_id: "javascript-typescript",
        analyzers: { registered: 8 },
        rules: { registered: 22 },
      }),
      expect.objectContaining({
        pack_id: "flutter",
        analyzers: { registered: 6 },
        rules: { registered: 6 },
      }),
      expect.objectContaining({
        pack_id: "android",
        platforms: ["android"],
        analyzers: { registered: 1 },
        rules: { registered: 4 },
      }),
      expect.objectContaining({
        pack_id: "ios",
        platforms: ["ios"],
        analyzers: { registered: 1 },
        rules: { registered: 4 },
      }),
      expect.objectContaining({
        pack_id: "react-native",
        frameworks: ["react-native"],
        analyzers: { registered: 4 },
        rules: { registered: 4 },
      }),
      expect.objectContaining({
        pack_id: "expo",
        frameworks: ["expo"],
        analyzers: { registered: 2 },
        rules: { registered: 2 },
      }),
      expect.objectContaining({
        pack_id: "python-ai-api",
        languages: ["python"],
        analyzers: { registered: 10 },
        rules: { registered: 10 },
      }),
      expect.objectContaining({
        pack_id: "javascript-baseline",
        scanner_kind: "sast",
        analyzers: { registered: 1 },
        rules: { registered: 2 },
      }),
      expect.objectContaining({
        pack_id: "go-ai",
        languages: ["go"],
        frameworks: ["openai"],
        analyzers: { registered: 1 },
        rules: { registered: 1 },
      }),
      expect.objectContaining({
        pack_id: "java-ai",
        languages: ["java"],
        frameworks: ["openai"],
        analyzers: { registered: 1 },
        rules: { registered: 1 },
      }),
      expect.objectContaining({
        pack_id: "csharp-ai",
        languages: ["csharp"],
        frameworks: ["openai"],
        analyzers: { registered: 1 },
        rules: { registered: 1 },
      }),
      expect.objectContaining({
        pack_id: "php-ai",
        languages: ["php"],
        frameworks: ["openai"],
        analyzers: { registered: 1 },
        rules: { registered: 1 },
      }),
      expect.objectContaining({
        pack_id: "rust-ai",
        languages: ["rust"],
        frameworks: ["openai"],
        analyzers: { registered: 1 },
        rules: { registered: 1 },
      }),
      expect.objectContaining({
        pack_id: "ruby-ai",
        languages: ["ruby"],
        frameworks: ["openai"],
        analyzers: { registered: 1 },
        rules: { registered: 1 },
      }),
      expect.objectContaining({
        pack_id: "firebase",
        frameworks: [],
        platforms: ["firebase"],
        analyzers: { registered: 1 },
        rules: { registered: 3 },
      }),
      expect.objectContaining({
        pack_id: "github-actions",
        platforms: ["github-actions"],
        analyzers: { registered: 1 },
        rules: { registered: 2 },
      }),
    ]);
    expect(inventory[0]?.limitations.join(" ")).toMatch(/not complete coverage/i);
    expect(inventory[1]?.limitations.join(" ")).toMatch(/source-ordered|does not claim complete/i);

    expect(nativePackNotRunCoverage()).toEqual([
      expect.objectContaining({
        pack_id: "javascript-typescript",
        state: "not_run",
        analyzers: { registered: 8, ran: 0 },
        rules: { registered: 22, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "flutter",
        state: "not_run",
        analyzers: { registered: 6, ran: 0 },
        rules: { registered: 6, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "android",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 4, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "ios",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 4, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "react-native",
        state: "not_run",
        analyzers: { registered: 4, ran: 0 },
        rules: { registered: 4, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "expo",
        state: "not_run",
        analyzers: { registered: 2, ran: 0 },
        rules: { registered: 2, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "python-ai-api",
        state: "not_run",
        analyzers: { registered: 10, ran: 0 },
        rules: { registered: 10, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "javascript-baseline",
        scanner_kind: "sast",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 2, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "go-ai",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 1, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "java-ai",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 1, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "csharp-ai",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 1, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "php-ai",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 1, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "rust-ai",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 1, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "ruby-ai",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 1, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "firebase",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 3, ran: 0 },
      }),
      expect.objectContaining({
        pack_id: "github-actions",
        state: "not_run",
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 2, ran: 0 },
      }),
    ]);
  });

  test("accounts for every native rule in the shipped detection manifest", async () => {
    const manifest = JSON.parse(
      await readFile(join(process.cwd(), "detection-db", "manifest.json"), "utf8"),
    ) as { custom_rules: Array<{ id: string; engine: string }> };
    const manifestRuleIds = manifest.custom_rules
      .filter((rule) => rule.engine === "codeinspectus-ai")
      .map((rule) => rule.id)
      .sort();
    const registeredRuleIds = registeredNativeAnalyzers("/tmp/codeinspectus-pack-registry")
      .flatMap((analyzer) => analyzer.ruleIds)
      .sort();

    expect(registeredRuleIds).toEqual(manifestRuleIds);
  });

  test("keeps rule ownership aligned with provenance components", () => {
    const analyzers = registeredNativeAnalyzers("/tmp/codeinspectus-pack-registry");
    for (const analyzer of analyzers) {
      expect(() => aiSignaturesForComponents(analyzer.components)).not.toThrow();
      for (const ruleId of analyzer.ruleIds) {
        const detectorComponent = aiFindingComponents(ruleId, analyzer.packScannerKind).find(
          (component) => component.startsWith(analyzer.packScannerKind === "sast" ? "sast:" : "ai:"),
        );
        expect(analyzer.components).toContain(detectorComponent);
      }
    }
  });
});

describe("native detector pack execution accounting", () => {
  test("scanner kinds select SAST and AI packs independently", async () => {
    const aiRun = vi.fn(async () => ({ findings: [] }));
    const sastRun = vi.fn(async () => ({ findings: [] }));
    const aiPack = { ...testPack(aiRun, aiRun), id: "ai-pack" };
    const sastPack: NativeDetectorPack = {
      ...testPack(sastRun, sastRun),
      id: "sast-pack",
      scannerKind: "sast",
    };

    const sastOnly = await runAiChecks("/not-read", {
      packs: [aiPack, sastPack],
      scannerKinds: ["sast"],
      detectedTechnologies: [],
    });
    expect(aiRun).not.toHaveBeenCalled();
    expect(sastRun).toHaveBeenCalledTimes(2);
    expect(sastOnly.packCoverage.map((pack) => [pack.pack_id, pack.state])).toEqual([
      ["ai-pack", "not_run"],
      ["sast-pack", "ran"],
    ]);
  });

  test("executes an applicable pack against the supplied technology detection", async () => {
    const promptRun = vi.fn(async () => ({ findings: [testFinding()] }));
    const apiRun = vi.fn(async () => ({ findings: [] }));
    const applicability = vi.fn((technologies: readonly DetectedTechnology[]) =>
      technologies.some((technology) => technology.id === "flutter")
    );
    const pack = testPack(promptRun, apiRun, applicability);

    const result = await runAiChecks("/not-read", {
      detectedTechnologies: [{
        id: "flutter",
        kind: "framework",
        confidence: "high",
        evidence: ["pubspec.yaml"],
      }],
      packs: [pack],
    });

    expect(applicability).toHaveBeenCalledOnce();
    expect(promptRun).toHaveBeenCalledOnce();
    expect(apiRun).toHaveBeenCalledOnce();
    expect(result.packCoverage[0]).toMatchObject({
      state: "ran",
      analyzers: { registered: 2, ran: 2 },
      rules: { registered: 5, ran: 5 },
    });
  });

  test("inventories a non-applicable pack without executing any analyzer", async () => {
    const promptRun = vi.fn(async () => ({ findings: [testFinding()] }));
    const apiRun = vi.fn(async () => ({ findings: [] }));
    const pack = testPack(
      promptRun,
      apiRun,
      (technologies) => technologies.some((technology) => technology.id === "flutter"),
    );

    const result = await runAiChecks("/not-read", {
      detectedTechnologies: [{
        id: "dart",
        kind: "language",
        confidence: "high",
        evidence: ["lib/tool.dart"],
      }],
      packs: [pack],
    });

    expect(promptRun).not.toHaveBeenCalled();
    expect(apiRun).not.toHaveBeenCalled();
    expect(result.findings).toEqual([]);
    expect(result.securityControlEvidence).toEqual([]);
    expect(result.info).toMatchObject({ available: true, ran: false, finding_count: 0 });
    expect(result.packCoverage).toEqual([{
      pack_id: "test-pack",
      version: "1.0.0-test",
      scanner_kind: "ai",
      state: "not_applicable",
      languages: ["typescript"],
      frameworks: ["test-framework"],
      platforms: [],
      analyzers: { registered: 2, ran: 0 },
      rules: { registered: 5, ran: 0 },
      limitations: ["Test limitation."],
      note: "No detected project technology matched this native pack; its analyzers did not run.",
    }]);
  });

  test("detects technologies itself when a direct caller omits detectedTechnologies", async () => {
    const project = await temporaryProject();
    await writeFile(join(project, "tool.dart"), "void main() {}\n", "utf8");
    const promptRun = vi.fn(async () => ({ findings: [] }));
    const apiRun = vi.fn(async () => ({ findings: [] }));
    const pack = testPack(
      promptRun,
      apiRun,
      (technologies) => technologies.some((technology) => technology.id === "dart"),
    );

    const result = await runAiChecks(project, { packs: [pack] });

    expect(promptRun).toHaveBeenCalledOnce();
    expect(apiRun).toHaveBeenCalledOnce();
    expect(result.packCoverage[0]?.state).toBe("ran");
  });

  test("keeps a no-options direct runAiChecks call working", async () => {
    const project = await temporaryProject();
    await writeFile(join(project, "index.ts"), "export const value = true;\n", "utf8");

    const result = await runAiChecks(project);

    expect(result.packCoverage.find((pack) => pack.pack_id === "javascript-typescript"))
      .toMatchObject({ state: "ran" });
    expect(result.packCoverage.find((pack) => pack.pack_id === "flutter"))
      .toMatchObject({
        state: "not_applicable",
        analyzers: { registered: 6, ran: 0 },
        rules: { registered: 6, ran: 0 },
      });
    for (const platform of ["android", "ios"]) {
      expect(result.packCoverage.find((pack) => pack.pack_id === platform)).toMatchObject({
        state: "not_applicable",
        platforms: [platform],
        analyzers: { registered: 1, ran: 0 },
        rules: { registered: 4, ran: 0 },
      });
    }
  });

  test("statically proven Expo evidence activates both Expo and React Native packs", async () => {
    const project = await temporaryProject();
    await writeFile(
      join(project, "app.json"),
      JSON.stringify({ expo: { name: "Mobile", slug: "mobile" } }),
      "utf8",
    );

    const result = await runAiChecks(project);

    expect(result.packCoverage.find((pack) => pack.pack_id === "react-native")).toMatchObject({
      state: "ran",
      analyzers: { registered: 4, ran: 4 },
      rules: { registered: 4, ran: 4 },
    });
    expect(result.packCoverage.find((pack) => pack.pack_id === "expo")).toMatchObject({
      state: "ran",
      analyzers: { registered: 2, ran: 2 },
      rules: { registered: 2, ran: 2 },
    });
  });

  test("scanner-filter coverage stays not_run for every pack without evaluating applicability", () => {
    const applicability = vi.fn(() => false);
    const first = testPack(async () => ({ findings: [] }), async () => ({ findings: [] }), applicability);
    const second = {
      ...testPack(async () => ({ findings: [] }), async () => ({ findings: [] }), applicability),
      id: "second-test-pack",
    };

    const coverage = nativePackNotRunCoverage("scanner excluded", [first, second]);

    expect(applicability).not.toHaveBeenCalled();
    expect(coverage).toEqual([
      expect.objectContaining({
        pack_id: "test-pack",
        state: "not_run",
        analyzers: { registered: 2, ran: 0 },
        rules: { registered: 5, ran: 0 },
        note: "scanner excluded",
      }),
      expect.objectContaining({
        pack_id: "second-test-pack",
        state: "not_run",
        analyzers: { registered: 2, ran: 0 },
        rules: { registered: 5, ran: 0 },
        note: "scanner excluded",
      }),
    ]);
  });

  test("all successful analyzers report the full analyzer and rule counts", async () => {
    const pack = testPack(
      async () => ({ findings: [testFinding()] }),
      async () => ({ findings: [] }),
    );
    const result = await runAiChecks("/not-read", { packs: [pack] });

    expect(result.packCoverage).toEqual([
      {
        pack_id: "test-pack",
        version: "1.0.0-test",
        scanner_kind: "ai",
        state: "ran",
        languages: ["typescript"],
        frameworks: ["test-framework"],
        platforms: [],
        analyzers: { registered: 2, ran: 2 },
        rules: { registered: 5, ran: 5 },
        limitations: ["Test limitation."],
      },
    ]);
    expect(result.info).toMatchObject({ available: true, ran: true, finding_count: 1 });
    expect(result.info.note).toBeUndefined();
  });

  test("fulfilled zero-finding analyzers still count as ran", async () => {
    const pack = testPack(
      async () => ({ findings: [] }),
      async () => ({ findings: [] }),
    );
    const result = await runAiChecks("/not-read", { packs: [pack] });

    expect(result.findings).toEqual([]);
    expect(result.info).toMatchObject({ available: true, ran: true, finding_count: 0 });
    expect(result.packCoverage[0]).toMatchObject({
      state: "ran",
      analyzers: { registered: 2, ran: 2 },
      rules: { registered: 5, ran: 5 },
    });
  });

  test("one rejected analyzer reports partial coverage and excludes its rules and signatures", async () => {
    const warn = vi.spyOn(log, "warn").mockImplementation(() => {});
    const pack = testPack(
      async () => ({ findings: [] }),
      async () => Promise.reject(new Error("expected analyzer failure")),
    );
    const result = await runAiChecks("/not-read", { packs: [pack] });

    expect(warn).toHaveBeenCalledTimes(1);
    expect(result.info).toMatchObject({ available: true, ran: true, finding_count: 0 });
    expect(result.info.note).toBe("1 of 2 native analyzers failed.");
    expect(result.packCoverage[0]).toMatchObject({
      state: "partial",
      analyzers: { registered: 2, ran: 1 },
      rules: { registered: 5, ran: 1 },
      note: "1 of 2 native analyzers failed; 4 of 5 registered rules did not run.",
    });
    expect(result.componentSignatures).toHaveProperty("ai:prompt-injection");
    expect(result.componentSignatures).not.toHaveProperty("ai:client-error-leak");
  });

  test("all rejected analyzers report unavailable while the installed engine remains available", async () => {
    const warn = vi.spyOn(log, "warn").mockImplementation(() => {});
    const pack = testPack(
      async () => Promise.reject(new Error("expected prompt failure")),
      async () => Promise.reject(new Error("expected API failure")),
    );
    const result = await runAiChecks("/not-read", { packs: [pack] });

    expect(warn).toHaveBeenCalledTimes(2);
    expect(result.info).toMatchObject({
      available: true,
      ran: false,
      finding_count: 0,
      note: "2 of 2 native analyzers failed.",
    });
    expect(result.packCoverage[0]).toMatchObject({
      state: "unavailable",
      analyzers: { registered: 2, ran: 0 },
      rules: { registered: 5, ran: 0 },
      note: "2 of 2 native analyzers failed; 5 of 5 registered rules did not run.",
    });
    expect(Object.keys(result.componentSignatures)).toEqual([
      "codeinspectus:pipeline",
      "codeinspectus-ai:invocation",
    ]);
  });
});
