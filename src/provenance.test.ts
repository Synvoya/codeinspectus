import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import {
  AI_INVOCATION_COMPONENT,
  ANDROID_PACK_DISPATCH_COMPONENT,
  ANDROID_XML_PARSER_COMPONENT,
  FLUTTER_DART_PARSER_COMPONENT,
  FLUTTER_PACK_DISPATCH_COMPONENT,
  PIPELINE_COMPONENT,
  IOS_PACK_DISPATCH_COMPONENT,
  IOS_PLIST_PARSER_COMPONENT,
  REACT_NATIVE_PACK_DISPATCH_COMPONENT,
  REACT_NATIVE_JAVASCRIPT_PARSER_COMPONENT,
  EXPO_PACK_DISPATCH_COMPONENT,
  EXPO_CONFIG_PARSER_COMPONENT,
  PYTHON_AI_API_PACK_DISPATCH_COMPONENT,
  PYTHON_LEZER_PARSER_COMPONENT,
  aiFindingComponents,
  aiSignaturesForComponents,
  invocationSignature,
  rulesetSignature,
  sha256FileStreaming,
  signature,
} from "./provenance.js";
import { runAiChecks } from "./ai-checks/index.js";

const dirs: string[] = [];

const LEGACY_JS_RULE_IDS = [
  "ci-ai-client-hardcoded-secret",
  "ci-ai-secret-in-bundle",
  "ci-ai-public-env-secret",
  "ci-ai-supabase-service-role-client",
  "ci-ai-llm-key-browser-exposed",
  "ci-ai-rls-using-true",
  "ci-ai-rls-missing",
  "ci-ai-rls-inverted-auth",
  "ci-ai-edge-fn-no-auth",
  "ci-ai-storage-rls-public",
  "ci-ai-prompt-injection-sink",
  "ci-ai-client-metadata-authz",
  "ci-ai-llm-output-dangerous-html",
  "ci-ai-client-error-leak",
  "ci-ai-sensitive-api-response",
  "ci-ai-unvalidated-request-write",
  "ci-ai-sensitive-log",
  "ci-ai-security-header-disabled",
  "ci-ai-unsafe-production-csp",
  "ci-ai-insecure-session-cookie",
  "ci-ai-supabase-captcha-token-missing",
] as const;

const FLUTTER_RULES = [
  {
    id: "ci-flutter-tls-verification-disabled",
    component: "ai:flutter-tls-verification",
    cwe: ["CWE-295"],
    severity: "high",
  },
  {
    id: "ci-flutter-sensitive-shared-preferences",
    component: "ai:flutter-sensitive-preferences",
    cwe: ["CWE-312"],
    severity: "high",
  },
  {
    id: "ci-flutter-webview-untrusted-content",
    component: "ai:flutter-webview-untrusted-content",
    cwe: ["CWE-20", "CWE-346"],
    severity: "medium",
  },
  {
    id: "ci-flutter-sensitive-log",
    component: "ai:flutter-sensitive-log",
    cwe: ["CWE-532"],
    severity: "medium",
  },
  {
    id: "ci-flutter-supabase-privileged-key-client",
    component: "ai:flutter-supabase-privileged-key",
    cwe: ["CWE-798", "CWE-312", "CWE-285"],
    severity: "critical",
  },
  {
    id: "ci-flutter-cleartext-network",
    component: "ai:flutter-cleartext-network",
    cwe: ["CWE-319"],
    severity: "medium",
  },
] as const;

const PLATFORM_RULES = [
  { id: "ci-android-debuggable-release", dispatch: ANDROID_PACK_DISPATCH_COMPONENT, parser: ANDROID_XML_PARSER_COMPONENT, component: "ai:android-debuggable" },
  { id: "ci-android-cleartext-traffic", dispatch: ANDROID_PACK_DISPATCH_COMPONENT, parser: ANDROID_XML_PARSER_COMPONENT, component: "ai:android-cleartext-traffic" },
  { id: "ci-android-user-ca-trust", dispatch: ANDROID_PACK_DISPATCH_COMPONENT, parser: ANDROID_XML_PARSER_COMPONENT, component: "ai:android-user-ca-trust" },
  { id: "ci-android-exported-file-provider", dispatch: ANDROID_PACK_DISPATCH_COMPONENT, parser: ANDROID_XML_PARSER_COMPONENT, component: "ai:android-exported-file-provider" },
  { id: "ci-ios-ats-global-arbitrary-loads", dispatch: IOS_PACK_DISPATCH_COMPONENT, parser: IOS_PLIST_PARSER_COMPONENT, component: "ai:ios-ats-global-arbitrary-loads" },
  { id: "ci-ios-ats-insecure-domain-exception", dispatch: IOS_PACK_DISPATCH_COMPONENT, parser: IOS_PLIST_PARSER_COMPONENT, component: "ai:ios-ats-insecure-domain-exception" },
  { id: "ci-ios-ats-weak-tls", dispatch: IOS_PACK_DISPATCH_COMPONENT, parser: IOS_PLIST_PARSER_COMPONENT, component: "ai:ios-ats-weak-tls" },
  { id: "ci-ios-data-protection-disabled", dispatch: IOS_PACK_DISPATCH_COMPONENT, parser: IOS_PLIST_PARSER_COMPONENT, component: "ai:ios-data-protection" },
] as const;

const REACT_NATIVE_EXPO_RULES = [
  { id: "ci-react-native-sensitive-async-storage", dispatch: REACT_NATIVE_PACK_DISPATCH_COMPONENT, parser: REACT_NATIVE_JAVASCRIPT_PARSER_COMPONENT, component: "ai:react-native-sensitive-async-storage" },
  { id: "ci-react-native-webview-untrusted-content", dispatch: REACT_NATIVE_PACK_DISPATCH_COMPONENT, parser: REACT_NATIVE_JAVASCRIPT_PARSER_COMPONENT, component: "ai:react-native-webview-untrusted-content" },
  { id: "ci-react-native-webview-mixed-content", dispatch: REACT_NATIVE_PACK_DISPATCH_COMPONENT, parser: REACT_NATIVE_JAVASCRIPT_PARSER_COMPONENT, component: "ai:react-native-webview-mixed-content" },
  { id: "ci-react-native-webview-universal-file-access", dispatch: REACT_NATIVE_PACK_DISPATCH_COMPONENT, parser: REACT_NATIVE_JAVASCRIPT_PARSER_COMPONENT, component: "ai:react-native-webview-universal-file-access" },
  { id: "ci-expo-secret-in-public-config", dispatch: EXPO_PACK_DISPATCH_COMPONENT, parser: EXPO_CONFIG_PARSER_COMPONENT, component: "ai:expo-secret-in-public-config" },
  { id: "ci-expo-unsigned-cleartext-updates", dispatch: EXPO_PACK_DISPATCH_COMPONENT, parser: EXPO_CONFIG_PARSER_COMPONENT, component: "ai:expo-unsigned-cleartext-updates" },
] as const;

const PYTHON_AI_API_RULES = [
  { id: "ci-python-hardcoded-signing-secret", component: "ai:python-hardcoded-signing-secret" },
  { id: "ci-python-credentialed-cors-all-origins", component: "ai:python-credentialed-cors" },
  { id: "ci-python-untrusted-file-response", component: "ai:python-untrusted-file-response" },
  { id: "ci-python-untrusted-redirect", component: "ai:python-untrusted-redirect" },
  { id: "ci-python-untrusted-template-source", component: "ai:python-untrusted-template-source" },
  { id: "ci-python-llm-output-dangerous-html", component: "ai:python-llm-output-dangerous-html" },
] as const;

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("component signatures", () => {
  test("Flutter findings use pack/parser/specific provenance without the JavaScript invocation", () => {
    for (const rule of FLUTTER_RULES) {
      const components = aiFindingComponents(rule.id);
      expect(components).toEqual([
        PIPELINE_COMPONENT,
        FLUTTER_PACK_DISPATCH_COMPONENT,
        FLUTTER_DART_PARSER_COMPONENT,
        rule.component,
      ]);
      expect(components).not.toContain(AI_INVOCATION_COMPONENT);
      expect(Object.keys(aiSignaturesForComponents(components))).toEqual(components);
    }
  });

  test("Android and iOS findings use platform-pack provenance without the JavaScript invocation", () => {
    for (const rule of PLATFORM_RULES) {
      const components = aiFindingComponents(rule.id);
      expect(components).toEqual([
        PIPELINE_COMPONENT,
        rule.dispatch,
        rule.parser,
        rule.component,
      ]);
      expect(components).not.toContain(AI_INVOCATION_COMPONENT);
      expect(Object.keys(aiSignaturesForComponents(components))).toEqual(components);
    }
  });

  test("React Native and Expo findings use their pack/parser provenance", () => {
    for (const rule of REACT_NATIVE_EXPO_RULES) {
      const components = aiFindingComponents(rule.id);
      expect(components).toEqual([
        PIPELINE_COMPONENT,
        rule.dispatch,
        rule.parser,
        rule.component,
      ]);
      expect(components).not.toContain(AI_INVOCATION_COMPONENT);
      expect(Object.keys(aiSignaturesForComponents(components))).toEqual(components);
    }
  });

  test("Python AI/API findings use their pack and bounded parser provenance", () => {
    for (const rule of PYTHON_AI_API_RULES) {
      const components = aiFindingComponents(rule.id);
      expect(components).toEqual([
        PIPELINE_COMPONENT,
        PYTHON_AI_API_PACK_DISPATCH_COMPONENT,
        PYTHON_LEZER_PARSER_COMPONENT,
        rule.component,
      ]);
      expect(components).not.toContain(AI_INVOCATION_COMPONENT);
      expect(Object.keys(aiSignaturesForComponents(components))).toEqual(components);
    }
  });

  test("the existing 21 JavaScript mappings remain stable under the intentional pipeline revision", () => {
    const compatibilityProjection = LEGACY_JS_RULE_IDS.map((ruleId) => {
      const components = aiFindingComponents(ruleId);
      return [ruleId, components, aiSignaturesForComponents(components)];
    });

    expect(signature(JSON.stringify(compatibilityProjection))).toBe(
      "sha256:ffb98a9322a87de3161318dd943ac3e64b883509eb1c43a82928395615dc416f",
    );
    expect(compatibilityProjection.every(([, components]) =>
      (components as string[]).includes(AI_INVOCATION_COMPONENT))).toBe(true);
  });

  test("four RLS reducer rules share one component while edge auth remains separate", () => {
    for (const rule of [
      "ci-ai-rls-missing",
      "ci-ai-rls-using-true",
      "ci-ai-storage-rls-public",
      "ci-ai-rls-inverted-auth",
    ]) {
      expect(aiFindingComponents(rule)).toContain("ai:supabase-rls-policy-state");
      expect(aiFindingComponents(rule)).not.toContain("ai:supabase-edge-auth");
    }
    expect(aiFindingComponents("ci-ai-edge-fn-no-auth")).toContain("ai:supabase-edge-auth");
    expect(aiFindingComponents("ci-ai-edge-fn-no-auth")).not.toContain("ai:supabase-rls-policy-state");
  });

  test("ruleset signature changes with detector content but ignores non-rule documentation", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-provenance-rules-"));
    dirs.push(dir);
    await writeFile(join(dir, "rules.yaml"), "rules: []\n", "utf8");
    await writeFile(join(dir, "README.md"), "first\n", "utf8");
    const first = await rulesetSignature(dir);
    await writeFile(join(dir, "README.md"), "second\n", "utf8");
    expect(await rulesetSignature(dir)).toBe(first);
    await writeFile(join(dir, "rules.yaml"), "rules:\n  - id: changed\n", "utf8");
    expect(await rulesetSignature(dir)).not.toBe(first);
  });

  test("Trivy DB helper computes a content digest and invocation signatures include flags", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-provenance-db-"));
    dirs.push(dir);
    const db = join(dir, "trivy.db");
    await writeFile(db, "db-content", "utf8");
    expect(await sha256FileStreaming(db)).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(invocationSignature("trivy", ["--offline-scan"]))
      .not.toBe(invocationSignature("trivy", ["--offline-scan", "--skip-check-update"]));
  });

  test("a successful zero-finding AI pass still records every analyzer component", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-provenance-ai-"));
    dirs.push(dir);
    const result = await runAiChecks(dir);
    expect(result.findings).toEqual([]);
    expect(Object.keys(result.componentSignatures)).toEqual(expect.arrayContaining([
      "codeinspectus:pipeline",
      "codeinspectus-ai:invocation",
      "ai:client-secrets",
      "ai:supabase-rls-policy-state",
      "ai:supabase-edge-auth",
      "ai:prompt-injection",
      "ai:client-metadata-authz",
      "ai:llm-dangerous-html",
      "ai:client-error-leak",
      "ai:sensitive-api-response",
      "ai:unvalidated-request-write",
      "ai:sensitive-log",
      "ai:security-header-config",
      "ai:csp-config",
      "ai:session-cookie-config",
      "ai:supabase-captcha-integration",
    ]));
  });

  test("each API-boundary rule has a dedicated rescan component", () => {
    expect(aiFindingComponents("ci-ai-client-error-leak")).toContain("ai:client-error-leak");
    expect(aiFindingComponents("ci-ai-sensitive-api-response")).toContain("ai:sensitive-api-response");
    expect(aiFindingComponents("ci-ai-unvalidated-request-write")).toContain("ai:unvalidated-request-write");
    expect(aiFindingComponents("ci-ai-sensitive-log")).toContain("ai:sensitive-log");
  });

  test("each Enhancement 2 rule has a dedicated rescan component", () => {
    expect(aiFindingComponents("ci-ai-security-header-disabled")).toContain("ai:security-header-config");
    expect(aiFindingComponents("ci-ai-unsafe-production-csp")).toContain("ai:csp-config");
    expect(aiFindingComponents("ci-ai-insecure-session-cookie")).toContain("ai:session-cookie-config");
    expect(aiFindingComponents("ci-ai-supabase-captcha-token-missing")).toContain(
      "ai:supabase-captcha-integration",
    );
  });
});

describe("Flutter detection manifest", () => {
  test("catalogues the six Flutter rules with exact ownership, severity, and CWE metadata", async () => {
    const manifest = JSON.parse(
      await readFile(join(process.cwd(), "detection-db", "manifest.json"), "utf8"),
    ) as {
      version: string;
      date: string;
      custom_rules: Array<{
        id: string;
        engine: string;
        pack_id?: string;
        severity?: string;
        cwe: string[];
      }>;
    };
    const flutterRules = manifest.custom_rules.filter((rule) => rule.pack_id === "flutter");

    expect(manifest.version).toBe("1.0.0");
    expect(manifest.date).toBe("2026-07-27");
    expect(manifest.custom_rules).toHaveLength(70);
    expect(flutterRules).toHaveLength(6);
    expect(flutterRules.map((rule) => ({
      id: rule.id,
      engine: rule.engine,
      pack_id: rule.pack_id,
      severity: rule.severity,
      cwe: rule.cwe,
    }))).toEqual(FLUTTER_RULES.map((rule) => ({
      id: rule.id,
      engine: "codeinspectus-ai",
      pack_id: "flutter",
      severity: rule.severity,
      cwe: [...rule.cwe],
    })));
  });
});
