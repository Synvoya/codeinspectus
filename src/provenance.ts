/**
 * Detection-component provenance for conservative rescan classification.
 * Signatures identify detector inputs, not user findings or secret contents.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";

import { MANAGED_PROVENANCE, MANAGED_TRIVY_DB, MANAGED_TRIVY_DB_PROVENANCE } from "./config.js";
import type { Engine, FindingKind } from "./types.js";

export const PIPELINE_COMPONENT = "codeinspectus:pipeline";
export const AI_INVOCATION_COMPONENT = "codeinspectus-ai:invocation";
export const FLUTTER_PACK_DISPATCH_COMPONENT = "pack:flutter:dispatch";
export const FLUTTER_DART_PARSER_COMPONENT = "flutter:dart-structural-parser";
export const ANDROID_PACK_DISPATCH_COMPONENT = "pack:android:dispatch";
export const ANDROID_XML_PARSER_COMPONENT = "android:xml-config-parser";
export const IOS_PACK_DISPATCH_COMPONENT = "pack:ios:dispatch";
export const IOS_PLIST_PARSER_COMPONENT = "ios:xml-plist-parser";
export const REACT_NATIVE_PACK_DISPATCH_COMPONENT = "pack:react-native:dispatch";
export const REACT_NATIVE_JAVASCRIPT_PARSER_COMPONENT = "react-native:javascript-structural-parser";
export const EXPO_PACK_DISPATCH_COMPONENT = "pack:expo:dispatch";
export const EXPO_CONFIG_PARSER_COMPONENT = "expo:static-config-parser";
export const PYTHON_AI_API_PACK_DISPATCH_COMPONENT = "pack:python-ai-api:dispatch";
export const PYTHON_LEZER_PARSER_COMPONENT = "python:lezer-structural-parser";
export const GO_AI_PACK_DISPATCH_COMPONENT = "pack:go-ai:dispatch";
export const GO_STRUCTURAL_PARSER_COMPONENT = "go:bounded-structural-parser";
export const JAVA_AI_PACK_DISPATCH_COMPONENT = "pack:java-ai:dispatch";
export const JAVA_STRUCTURAL_PARSER_COMPONENT = "java:bounded-structural-parser";
export const CSHARP_AI_PACK_DISPATCH_COMPONENT = "pack:csharp-ai:dispatch";
export const CSHARP_STRUCTURAL_PARSER_COMPONENT = "csharp:bounded-structural-parser";
export const PHP_AI_PACK_DISPATCH_COMPONENT = "pack:php-ai:dispatch";
export const PHP_STRUCTURAL_PARSER_COMPONENT = "php:bounded-structural-parser";
export const RUST_AI_PACK_DISPATCH_COMPONENT = "pack:rust-ai:dispatch";
export const RUST_STRUCTURAL_PARSER_COMPONENT = "rust:bounded-structural-parser";
export const RUBY_AI_PACK_DISPATCH_COMPONENT = "pack:ruby-ai:dispatch";
export const RUBY_STRUCTURAL_PARSER_COMPONENT = "ruby:bounded-structural-parser";
export const FIREBASE_PACK_DISPATCH_COMPONENT = "pack:firebase:dispatch";
export const FIREBASE_RULES_PARSER_COMPONENT = "firebase:bounded-rules-parser";
export const GITHUB_ACTIONS_PACK_DISPATCH_COMPONENT = "pack:github-actions:dispatch";
export const GITHUB_ACTIONS_YAML_PARSER_COMPONENT = "github-actions:yaml-workflow-parser";
export const JAVASCRIPT_BASELINE_PACK_DISPATCH_COMPONENT = "pack:javascript-baseline:dispatch";
export const JAVASCRIPT_BASELINE_PARSER_COMPONENT = "javascript:bounded-structural-parser";
export const NATIVE_SAST_RECONCILIATION_COMPONENT = "native-sast:opengrep-reconciliation";
export const PUB_LOCKFILE_PARSER_COMPONENT = "codeinspectus-pub:lockfile-parser";
export const PUB_SNAPSHOT_COMPONENT = "codeinspectus-pub:osv-snapshot";
export const PUB_MATCHER_COMPONENT = "codeinspectus-pub:exact-version-matcher";

const COMPONENT_REVISIONS: Record<string, string> = {
  [PIPELINE_COMPONENT]: "3:normalize-alias-dedup-direct-target-routing-envelope",
  [AI_INVOCATION_COMPONENT]: "1:all-analyzers-no-target-flags",
  "ai:client-secrets": "3:source-built-and-oversized-bundle-secret-state",
  "ai:supabase-rls-policy-state": "2:effective-migration-state",
  "ai:supabase-edge-auth": "2:edge-scan-independent-of-sql-project-gate",
  "ai:prompt-injection": "2:prompt-sink-analysis-cwe-1427",
  "ai:unsafe-tool-execution": "1:proven-model-tool-arguments-to-node-shell",
  "ai:client-metadata-authz": "1:client-metadata-authz",
  "ai:llm-dangerous-html": "1:dangerous-html-flow",
  "ai:client-error-leak": "1:client-response-error-detail",
  "ai:sensitive-api-response": "1:explicit-sensitive-response-fields",
  "ai:unvalidated-request-write": "1:request-object-write-flow",
  "ai:sensitive-log": "1:sensitive-log-flow",
  "ai:security-header-config": "1:explicit-effective-header-disablement",
  "ai:csp-config": "1:production-script-source-policy",
  "ai:session-cookie-config": "1:explicit-auth-cookie-attributes",
  "ai:supabase-captcha-integration": "1:enabled-config-auth-call-token",
  [FLUTTER_PACK_DISPATCH_COMPONENT]: "1:flutter-pack-dispatch",
  [FLUTTER_DART_PARSER_COMPONENT]: "1:dart-structural-parser",
  "ai:flutter-tls-verification": "1:unconditional-bad-certificate-callback",
  "ai:flutter-sensitive-preferences": "1:sensitive-value-shared-preferences-write",
  "ai:flutter-webview-untrusted-content": "1:untrusted-content-webview-flow",
  "ai:flutter-sensitive-log": "1:sensitive-data-log-sink",
  "ai:flutter-supabase-privileged-key": "1:privileged-supabase-key-client-exposure",
  "ai:flutter-cleartext-network": "1:production-cleartext-network-use",
  [ANDROID_PACK_DISPATCH_COMPONENT]: "1:android-pack-dispatch",
  [ANDROID_XML_PARSER_COMPONENT]: "1:bounded-android-xml-config-parser",
  "ai:android-debuggable": "1:explicit-release-manifest-debuggable",
  "ai:android-cleartext-traffic": "1:effective-explicit-cleartext-configuration",
  "ai:android-user-ca-trust": "1:production-user-installed-ca-trust",
  "ai:android-exported-file-provider": "1:explicit-exported-androidx-file-provider",
  [IOS_PACK_DISPATCH_COMPONENT]: "1:ios-pack-dispatch",
  [IOS_PLIST_PARSER_COMPONENT]: "1:bounded-ios-xml-plist-parser",
  "ai:ios-ats-global-arbitrary-loads": "1:effective-global-ats-arbitrary-loads",
  "ai:ios-ats-insecure-domain-exception": "1:concrete-production-domain-http-exception",
  "ai:ios-ats-weak-tls": "1:concrete-production-domain-weak-tls-exception",
  "ai:ios-data-protection": "1:explicit-default-file-protection-none",
  [REACT_NATIVE_PACK_DISPATCH_COMPONENT]: "1:react-native-pack-dispatch",
  [REACT_NATIVE_JAVASCRIPT_PARSER_COMPONENT]: "1:bounded-javascript-typescript-jsx-structural-parser",
  "ai:react-native-sensitive-async-storage": "1:proven-async-storage-sensitive-write",
  "ai:react-native-webview-untrusted-content": "1:proven-untrusted-webview-content-flow",
  "ai:react-native-webview-mixed-content": "1:explicit-production-webview-mixed-content",
  "ai:react-native-webview-universal-file-access": "1:explicit-file-webview-universal-origin-access",
  [EXPO_PACK_DISPATCH_COMPONENT]: "1:expo-pack-dispatch",
  [EXPO_CONFIG_PARSER_COMPONENT]: "1:bounded-nonexecuting-static-expo-config-parser",
  "ai:expo-secret-in-public-config": "1:sensitive-server-env-in-public-expo-config",
  "ai:expo-unsigned-cleartext-updates": "1:unsigned-cleartext-production-expo-updates",
  [PYTHON_AI_API_PACK_DISPATCH_COMPONENT]: "1:python-ai-api-pack-dispatch",
  [PYTHON_LEZER_PARSER_COMPONENT]: "2:bounded-lezer-gated-python-structural-parser-opaque-format-strings",
  [JAVASCRIPT_BASELINE_PACK_DISPATCH_COMPONENT]: "1:javascript-baseline-pack-dispatch",
  [JAVASCRIPT_BASELINE_PARSER_COMPONENT]: "1:bounded-javascript-typescript-structural-parser",
  [NATIVE_SAST_RECONCILIATION_COMPONENT]: "1:exact-opengrep-pre-dedup-reconciliation",
  "sast:javascript-weak-hash": "1:weak-hash-md5-sha1",
  "sast:javascript-weak-cipher": "1:weak-cipher-and-deprecated-create-cipher",
  "ai:python-hardcoded-signing-secret": "1:literal-framework-signing-secret",
  "ai:python-credentialed-cors": "1:credentialed-universal-origin-policy",
  "ai:python-untrusted-file-response": "1:request-controlled-file-response-path",
  "ai:python-untrusted-redirect": "1:request-controlled-complete-redirect-target",
  "ai:python-untrusted-template-source": "1:request-controlled-template-compilation",
  "ai:python-llm-output-dangerous-html": "1:proven-sdk-output-html-response-flow",
  "ai:python-faiss-dangerous-deserialization": "1:proven-langchain-faiss-pickle-opt-in",
  "ai:python-langchain-web-loader-ssrf": "1:request-controlled-complete-url-proven-web-loader-fetch",
  "ai:python-prompt-injection": "2:request-controlled-privileged-prompt-or-tool-enabled-input-cwe-1427",
  "ai:python-unsafe-tool-execution": "1:proven-model-tool-arguments-to-python-shell",
  [GO_AI_PACK_DISPATCH_COMPONENT]: "1:go-ai-pack-dispatch",
  [GO_STRUCTURAL_PARSER_COMPONENT]: "1:bounded-source-ordered-go-structural-parser",
  "ai:go-unsafe-tool-execution": "1:proven-openai-tool-arguments-to-go-shell",
  [JAVA_AI_PACK_DISPATCH_COMPONENT]: "1:java-ai-pack-dispatch",
  [JAVA_STRUCTURAL_PARSER_COMPONENT]: "1:bounded-source-ordered-java-structural-parser",
  "ai:java-unsafe-tool-execution": "1:proven-openai-tool-arguments-to-started-java-shell",
  [CSHARP_AI_PACK_DISPATCH_COMPONENT]: "1:csharp-ai-pack-dispatch",
  [CSHARP_STRUCTURAL_PARSER_COMPONENT]: "2:bounded-source-ordered-csharp-structural-parser-with-typed-tool-parameters",
  "ai:csharp-unsafe-tool-execution": "2:proven-openai-tool-arguments-to-started-csharp-shell-direct-deserialization",
  [PHP_AI_PACK_DISPATCH_COMPONENT]: "1:php-ai-pack-dispatch",
  [PHP_STRUCTURAL_PARSER_COMPONENT]: "1:bounded-php-structural-parser",
  "ai:php-unsafe-tool-execution": "1:proven-openai-php-tool-arguments-to-command-execution",
  [RUST_AI_PACK_DISPATCH_COMPONENT]: "1:rust-ai-pack-dispatch",
  [RUST_STRUCTURAL_PARSER_COMPONENT]: "1:bounded-source-ordered-rust-structural-parser-multiline-strings",
  "ai:rust-unsafe-tool-execution": "1:proven-async-openai-tool-arguments-to-rust-shell",
  [RUBY_AI_PACK_DISPATCH_COMPONENT]: "1:ruby-ai-pack-dispatch",
  [RUBY_STRUCTURAL_PARSER_COMPONENT]: "1:bounded-ruby-structural-parser-string-masked",
  "ai:ruby-unsafe-tool-execution": "1:proven-official-openai-ruby-tool-arguments-to-shell",
  [FIREBASE_PACK_DISPATCH_COMPONENT]: "1:firebase-pack-dispatch",
  [FIREBASE_RULES_PARSER_COMPONENT]: "1:bounded-firestore-storage-rules-and-strict-rtdb-json-parser",
  "ai:firebase-firestore-public-write": "1:literal-unconditional-firestore-write-grant",
  "ai:firebase-storage-public-write": "1:literal-unconditional-storage-write-grant",
  "ai:firebase-realtime-database-public-write": "1:literal-unconditional-rtdb-write-grant",
  [GITHUB_ACTIONS_PACK_DISPATCH_COMPONENT]: "1:github-actions-pack-dispatch",
  [GITHUB_ACTIONS_YAML_PARSER_COMPONENT]: "1:bounded-strict-yaml12-workflow-parser",
  "ai:github-actions-expression-injection": "1:documented-untrusted-context-direct-run-interpolation",
  "ai:github-actions-pwn-request": "1:pre-v7-privileged-untrusted-checkout-and-workspace-execution",
  [PUB_LOCKFILE_PARSER_COMPONENT]: "1:bounded-pub-lockfile-parser",
  [PUB_MATCHER_COMPONENT]: "1:exact-enumerated-osv-version-membership",
};

const AI_RULE_COMPONENT: Record<string, string> = {
  "ci-ai-client-hardcoded-secret": "ai:client-secrets",
  "ci-ai-secret-in-bundle": "ai:client-secrets",
  "ci-ai-public-env-secret": "ai:client-secrets",
  "ci-ai-llm-key-browser-exposed": "ai:client-secrets",
  "ci-ai-supabase-service-role-client": "ai:client-secrets",
  "ci-ai-rls-missing": "ai:supabase-rls-policy-state",
  "ci-ai-rls-using-true": "ai:supabase-rls-policy-state",
  "ci-ai-storage-rls-public": "ai:supabase-rls-policy-state",
  "ci-ai-rls-inverted-auth": "ai:supabase-rls-policy-state",
  "ci-ai-edge-fn-no-auth": "ai:supabase-edge-auth",
  "ci-ai-prompt-injection-sink": "ai:prompt-injection",
  "ci-ai-llm-tool-argument-command-execution": "ai:unsafe-tool-execution",
  "ci-ai-client-metadata-authz": "ai:client-metadata-authz",
  "ci-ai-llm-output-dangerous-html": "ai:llm-dangerous-html",
  "ci-ai-client-error-leak": "ai:client-error-leak",
  "ci-ai-sensitive-api-response": "ai:sensitive-api-response",
  "ci-ai-unvalidated-request-write": "ai:unvalidated-request-write",
  "ci-ai-sensitive-log": "ai:sensitive-log",
  "ci-ai-security-header-disabled": "ai:security-header-config",
  "ci-ai-unsafe-production-csp": "ai:csp-config",
  "ci-ai-insecure-session-cookie": "ai:session-cookie-config",
  "ci-ai-supabase-captcha-token-missing": "ai:supabase-captcha-integration",
};

const FLUTTER_RULE_COMPONENT: Record<string, string> = {
  "ci-flutter-tls-verification-disabled": "ai:flutter-tls-verification",
  "ci-flutter-sensitive-shared-preferences": "ai:flutter-sensitive-preferences",
  "ci-flutter-webview-untrusted-content": "ai:flutter-webview-untrusted-content",
  "ci-flutter-sensitive-log": "ai:flutter-sensitive-log",
  "ci-flutter-supabase-privileged-key-client": "ai:flutter-supabase-privileged-key",
  "ci-flutter-cleartext-network": "ai:flutter-cleartext-network",
};

const ANDROID_RULE_COMPONENT: Record<string, string> = {
  "ci-android-debuggable-release": "ai:android-debuggable",
  "ci-android-cleartext-traffic": "ai:android-cleartext-traffic",
  "ci-android-user-ca-trust": "ai:android-user-ca-trust",
  "ci-android-exported-file-provider": "ai:android-exported-file-provider",
};

const IOS_RULE_COMPONENT: Record<string, string> = {
  "ci-ios-ats-global-arbitrary-loads": "ai:ios-ats-global-arbitrary-loads",
  "ci-ios-ats-insecure-domain-exception": "ai:ios-ats-insecure-domain-exception",
  "ci-ios-ats-weak-tls": "ai:ios-ats-weak-tls",
  "ci-ios-data-protection-disabled": "ai:ios-data-protection",
};

const REACT_NATIVE_RULE_COMPONENT: Record<string, string> = {
  "ci-react-native-sensitive-async-storage": "ai:react-native-sensitive-async-storage",
  "ci-react-native-webview-untrusted-content": "ai:react-native-webview-untrusted-content",
  "ci-react-native-webview-mixed-content": "ai:react-native-webview-mixed-content",
  "ci-react-native-webview-universal-file-access": "ai:react-native-webview-universal-file-access",
};

const EXPO_RULE_COMPONENT: Record<string, string> = {
  "ci-expo-secret-in-public-config": "ai:expo-secret-in-public-config",
  "ci-expo-unsigned-cleartext-updates": "ai:expo-unsigned-cleartext-updates",
};

const PYTHON_AI_API_RULE_COMPONENT: Record<string, string> = {
  "ci-python-hardcoded-signing-secret": "ai:python-hardcoded-signing-secret",
  "ci-python-credentialed-cors-all-origins": "ai:python-credentialed-cors",
  "ci-python-untrusted-file-response": "ai:python-untrusted-file-response",
  "ci-python-untrusted-redirect": "ai:python-untrusted-redirect",
  "ci-python-untrusted-template-source": "ai:python-untrusted-template-source",
  "ci-python-llm-output-dangerous-html": "ai:python-llm-output-dangerous-html",
  "ci-python-faiss-dangerous-deserialization": "ai:python-faiss-dangerous-deserialization",
  "ci-python-langchain-web-loader-ssrf": "ai:python-langchain-web-loader-ssrf",
  "ci-python-prompt-injection-sink": "ai:python-prompt-injection",
  "ci-python-llm-tool-argument-command-execution": "ai:python-unsafe-tool-execution",
};

const GO_AI_RULE_COMPONENT: Record<string, string> = {
  "ci-go-llm-tool-argument-command-execution": "ai:go-unsafe-tool-execution",
};

const JAVA_AI_RULE_COMPONENT: Record<string, string> = {
  "ci-java-llm-tool-argument-command-execution": "ai:java-unsafe-tool-execution",
};

const CSHARP_AI_RULE_COMPONENT: Record<string, string> = {
  "ci-csharp-llm-tool-argument-command-execution": "ai:csharp-unsafe-tool-execution",
};

const PHP_AI_RULE_COMPONENT: Record<string, string> = {
  "ci-php-llm-tool-argument-command-execution": "ai:php-unsafe-tool-execution",
};

const RUST_AI_RULE_COMPONENT: Record<string, string> = {
  "ci-rust-llm-tool-argument-command-execution": "ai:rust-unsafe-tool-execution",
};

const RUBY_AI_RULE_COMPONENT: Record<string, string> = {
  "ci-ruby-llm-tool-argument-command-execution": "ai:ruby-unsafe-tool-execution",
};

const FIREBASE_RULE_COMPONENT: Record<string, string> = {
  "ci-firebase-firestore-public-write": "ai:firebase-firestore-public-write",
  "ci-firebase-storage-public-write": "ai:firebase-storage-public-write",
  "ci-firebase-realtime-database-public-write": "ai:firebase-realtime-database-public-write",
};

const GITHUB_ACTIONS_RULE_COMPONENT: Record<string, string> = {
  "ci-github-actions-untrusted-expression-command": "ai:github-actions-expression-injection",
  "ci-github-actions-pwn-request": "ai:github-actions-pwn-request",
};

export function signature(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export async function fileSignature(path: string): Promise<string> {
  return signature(await readFile(path));
}

/** Stable digest of detector-rule files: normalized relative path + content digest. */
export async function rulesetSignature(root: string): Promise<string> {
  const entries: string[] = [];
  async function walk(dir: string): Promise<void> {
    const children = await readdir(dir, { withFileTypes: true });
    for (const child of children.sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = join(dir, child.name);
      if (child.isDirectory()) await walk(abs);
      else if (child.isFile() && [".yaml", ".yml", ".json"].includes(extname(child.name).toLowerCase())) {
        const rel = relative(root, abs).replace(/\\/g, "/");
        entries.push(`${rel}\0${await fileSignature(abs)}`);
      }
    }
  }
  await walk(root);
  return signature(entries.join("\n"));
}

export function invocationSignature(producer: string, semanticArgs: readonly string[]): string {
  return signature(JSON.stringify({ producer, args: semanticArgs }));
}

export function staticComponentSignatures(componentIds: readonly string[]): Record<string, string> {
  return Object.fromEntries(componentIds.map((id) => {
    const revision = COMPONENT_REVISIONS[id];
    if (!revision) throw new Error(`No semantic revision registered for detector component '${id}'.`);
    return [id, signature(`${id}\0${revision}`)];
  }));
}

export function aiComponentForRule(ruleId: string): string {
  return AI_RULE_COMPONENT[ruleId] ?? FLUTTER_RULE_COMPONENT[ruleId] ??
    ANDROID_RULE_COMPONENT[ruleId] ?? IOS_RULE_COMPONENT[ruleId] ??
    REACT_NATIVE_RULE_COMPONENT[ruleId] ?? EXPO_RULE_COMPONENT[ruleId] ??
    PYTHON_AI_API_RULE_COMPONENT[ruleId] ?? GO_AI_RULE_COMPONENT[ruleId] ??
    JAVA_AI_RULE_COMPONENT[ruleId] ?? CSHARP_AI_RULE_COMPONENT[ruleId] ??
    PHP_AI_RULE_COMPONENT[ruleId] ?? RUST_AI_RULE_COMPONENT[ruleId] ??
    RUBY_AI_RULE_COMPONENT[ruleId] ?? FIREBASE_RULE_COMPONENT[ruleId] ??
    GITHUB_ACTIONS_RULE_COMPONENT[ruleId] ?? "ai:unmapped-rule";
}

export function aiFindingComponents(ruleId: string, scannerKind: "ai" | "sast" = "ai"): string[] {
  if (scannerKind === "sast") {
    const detector = ruleId === "ci-baseline-weak-hash"
      ? "sast:javascript-weak-hash"
      : ruleId === "ci-baseline-weak-cipher"
        ? "sast:javascript-weak-cipher"
        : "sast:unmapped-rule";
    return [
      PIPELINE_COMPONENT,
      JAVASCRIPT_BASELINE_PACK_DISPATCH_COMPONENT,
      JAVASCRIPT_BASELINE_PARSER_COMPONENT,
      NATIVE_SAST_RECONCILIATION_COMPONENT,
      detector,
    ];
  }
  const flutterComponent = FLUTTER_RULE_COMPONENT[ruleId];
  if (flutterComponent) {
    return [
      PIPELINE_COMPONENT,
      FLUTTER_PACK_DISPATCH_COMPONENT,
      FLUTTER_DART_PARSER_COMPONENT,
      flutterComponent,
    ];
  }
  const androidComponent = ANDROID_RULE_COMPONENT[ruleId];
  if (androidComponent) {
    return [
      PIPELINE_COMPONENT,
      ANDROID_PACK_DISPATCH_COMPONENT,
      ANDROID_XML_PARSER_COMPONENT,
      androidComponent,
    ];
  }
  const iosComponent = IOS_RULE_COMPONENT[ruleId];
  if (iosComponent) {
    return [
      PIPELINE_COMPONENT,
      IOS_PACK_DISPATCH_COMPONENT,
      IOS_PLIST_PARSER_COMPONENT,
      iosComponent,
    ];
  }
  const reactNativeComponent = REACT_NATIVE_RULE_COMPONENT[ruleId];
  if (reactNativeComponent) {
    return [
      PIPELINE_COMPONENT,
      REACT_NATIVE_PACK_DISPATCH_COMPONENT,
      REACT_NATIVE_JAVASCRIPT_PARSER_COMPONENT,
      reactNativeComponent,
    ];
  }
  const expoComponent = EXPO_RULE_COMPONENT[ruleId];
  if (expoComponent) {
    return [
      PIPELINE_COMPONENT,
      EXPO_PACK_DISPATCH_COMPONENT,
      EXPO_CONFIG_PARSER_COMPONENT,
      expoComponent,
    ];
  }
  const pythonComponent = PYTHON_AI_API_RULE_COMPONENT[ruleId];
  if (pythonComponent) {
    return [
      PIPELINE_COMPONENT,
      PYTHON_AI_API_PACK_DISPATCH_COMPONENT,
      PYTHON_LEZER_PARSER_COMPONENT,
      pythonComponent,
    ];
  }
  const goComponent = GO_AI_RULE_COMPONENT[ruleId];
  if (goComponent) {
    return [
      PIPELINE_COMPONENT,
      GO_AI_PACK_DISPATCH_COMPONENT,
      GO_STRUCTURAL_PARSER_COMPONENT,
      goComponent,
    ];
  }
  const javaComponent = JAVA_AI_RULE_COMPONENT[ruleId];
  if (javaComponent) {
    return [
      PIPELINE_COMPONENT,
      JAVA_AI_PACK_DISPATCH_COMPONENT,
      JAVA_STRUCTURAL_PARSER_COMPONENT,
      javaComponent,
    ];
  }
  const csharpComponent = CSHARP_AI_RULE_COMPONENT[ruleId];
  if (csharpComponent) {
    return [
      PIPELINE_COMPONENT,
      CSHARP_AI_PACK_DISPATCH_COMPONENT,
      CSHARP_STRUCTURAL_PARSER_COMPONENT,
      csharpComponent,
    ];
  }
  const phpComponent = PHP_AI_RULE_COMPONENT[ruleId];
  if (phpComponent) {
    return [
      PIPELINE_COMPONENT,
      PHP_AI_PACK_DISPATCH_COMPONENT,
      PHP_STRUCTURAL_PARSER_COMPONENT,
      phpComponent,
    ];
  }
  const rustComponent = RUST_AI_RULE_COMPONENT[ruleId];
  if (rustComponent) {
    return [
      PIPELINE_COMPONENT,
      RUST_AI_PACK_DISPATCH_COMPONENT,
      RUST_STRUCTURAL_PARSER_COMPONENT,
      rustComponent,
    ];
  }
  const rubyComponent = RUBY_AI_RULE_COMPONENT[ruleId];
  if (rubyComponent) {
    return [
      PIPELINE_COMPONENT,
      RUBY_AI_PACK_DISPATCH_COMPONENT,
      RUBY_STRUCTURAL_PARSER_COMPONENT,
      rubyComponent,
    ];
  }
  const firebaseComponent = FIREBASE_RULE_COMPONENT[ruleId];
  if (firebaseComponent) {
    return [
      PIPELINE_COMPONENT,
      FIREBASE_PACK_DISPATCH_COMPONENT,
      FIREBASE_RULES_PARSER_COMPONENT,
      firebaseComponent,
    ];
  }
  const githubActionsComponent = GITHUB_ACTIONS_RULE_COMPONENT[ruleId];
  if (githubActionsComponent) {
    return [
      PIPELINE_COMPONENT,
      GITHUB_ACTIONS_PACK_DISPATCH_COMPONENT,
      GITHUB_ACTIONS_YAML_PARSER_COMPONENT,
      githubActionsComponent,
    ];
  }
  return [PIPELINE_COMPONENT, AI_INVOCATION_COMPONENT, aiComponentForRule(ruleId)];
}

export function aiSignaturesForComponents(componentIds: readonly string[]): Record<string, string> {
  return staticComponentSignatures([...new Set(componentIds)]);
}

export function pubFindingComponents(): string[] {
  return [
    PIPELINE_COMPONENT,
    PUB_LOCKFILE_PARSER_COMPONENT,
    PUB_SNAPSHOT_COMPONENT,
    PUB_MATCHER_COMPONENT,
  ];
}

export function pubStaticComponentSignatures(snapshotSignature: string): Record<string, string> {
  if (!/^sha256:[a-f0-9]{64}$/.test(snapshotSignature)) {
    throw new Error("Invalid bundled OSV Pub snapshot signature.");
  }
  return {
    ...staticComponentSignatures([
      PIPELINE_COMPONENT,
      PUB_LOCKFILE_PARSER_COMPONENT,
      PUB_MATCHER_COMPONENT,
    ]),
    [PUB_SNAPSHOT_COMPONENT]: snapshotSignature,
  };
}

export function externalFindingComponents(engine: Engine, kind: FindingKind): string[] {
  const base = [PIPELINE_COMPONENT, `${engine}:binary`, `${engine}:invocation`];
  if (engine === "opengrep") return [...base, "opengrep:ruleset"];
  if (engine === "gitleaks") return [...base, "gitleaks:config", "gitleaks:effective-ignore"];
  if (engine === "trivy") {
    const components = [...base, "trivy:checks"];
    if (kind === "vulnerability") components.push("trivy:vulnerability-db");
    return components;
  }
  return base;
}

export async function sha256FileStreaming(path: string): Promise<string> {
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return `sha256:${hash.digest("hex")}`;
}

/** Atomically persist a precomputed DB signature after the staged DB is installed. */
export async function writeTrivyDbContentDigest(digest: string): Promise<void> {
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error("Invalid Trivy DB content signature.");
  await mkdir(join(MANAGED_PROVENANCE, "trivy"), { recursive: true });
  const tmp = `${MANAGED_TRIVY_DB_PROVENANCE}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(
    tmp,
    JSON.stringify({ component: "trivy:vulnerability-db", signature: digest, recorded_at: new Date().toISOString() }),
    "utf8",
  );
  try {
    await rename(tmp, MANAGED_TRIVY_DB_PROVENANCE);
  } finally {
    await rm(tmp, { force: true }).catch(() => {});
  }
}

/** Called only after a DB download; never hashes the 1.1GB DB during scans. */
export async function recordTrivyDbContentDigest(dbPath = MANAGED_TRIVY_DB): Promise<string> {
  const digest = await sha256FileStreaming(dbPath);
  await writeTrivyDbContentDigest(digest);
  return digest;
}

/** Small metadata read at scan time. Missing metadata means DB equivalence cannot be proven. */
export async function readTrivyDbContentDigest(): Promise<string | undefined> {
  try {
    const parsed = JSON.parse(await readFile(MANAGED_TRIVY_DB_PROVENANCE, "utf8")) as { signature?: unknown };
    return typeof parsed.signature === "string" && /^sha256:[a-f0-9]{64}$/.test(parsed.signature)
      ? parsed.signature
      : undefined;
  } catch {
    return undefined;
  }
}
