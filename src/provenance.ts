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
  "ai:prompt-injection": "1:prompt-sink-analysis",
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
  [PYTHON_LEZER_PARSER_COMPONENT]: "1:bounded-lezer-gated-python-structural-parser",
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
    PYTHON_AI_API_RULE_COMPONENT[ruleId] ?? "ai:unmapped-rule";
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
