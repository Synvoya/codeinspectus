/**
 * CodeInspectus eval suite (PRD §13). Drives the BUILT server over real MCP stdio
 * and asserts on structuredContent. ≥10 evals against fixtures/vulnerable-app:
 * each independent, read-only, verifiable, stable.
 *
 * Engine-dependent evals (Opengrep SQLi, Trivy SCA) are SKIPPED (not failed) when
 * the engine binary / Trivy DB is unavailable, so the suite is stable in any
 * environment; the AI-code evals are pure-TS and always run.
 *
 * Run: npm run eval
 */

import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { cp, mkdir, mkdtemp, readdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { runOpengrepShadowParity } from "../src/shadow/opengrep-parity.js";
import {
  buildOpengrepArgs,
  effectiveOpengrepIgnoreList,
  OPENGREP_EFFECTIVE_IGNORE_NAME,
  OPENGREP_IGNORE_FILE,
  opengrepExecEnvironment,
  opengrepRuleSets,
  runOpengrep,
} from "../src/engines/opengrep.js";
import { resolveEngine } from "../src/engines/resolve.js";
import { execBinary } from "../src/engines/exec.js";
import { normalizeEngineOutput } from "../src/sarif/normalize.js";

const FIXTURE = resolve(process.cwd(), "fixtures/vulnerable-app");
const CORS_FIXTURE = resolve(process.cwd(), "fixtures/cors-corpus");
const API_BOUNDARY_FIXTURE = resolve(process.cwd(), "fixtures/api-boundary-corpus");
const SECURITY_CONTROLS_FIXTURE = resolve(process.cwd(), "fixtures/security-controls-corpus");
const SUPABASE_EDGE_AUTH_FIXTURE = resolve(process.cwd(), "fixtures/supabase-edge-auth-corpus");
const NEXTJS_ADMIN_ROUTE_FIXTURE = resolve(process.cwd(), "fixtures/nextjs-admin-route-corpus");
const FLUTTER_FIXTURE = resolve(process.cwd(), "fixtures/flutter-corpus");
const FLUTTER_TP_FIXTURE = resolve(FLUTTER_FIXTURE, "tp");
const FLUTTER_FP_FIXTURE = resolve(FLUTTER_FIXTURE, "fp");
const FLUTTER_FIXED_FIXTURE = resolve(FLUTTER_FIXTURE, "fixed");
const MOBILE_CONFIG_FIXTURE = resolve(process.cwd(), "fixtures/mobile-config-corpus");
const ANDROID_CONFIG_FIXTURE = resolve(MOBILE_CONFIG_FIXTURE, "android");
const IOS_CONFIG_FIXTURE = resolve(MOBILE_CONFIG_FIXTURE, "ios");
const PUB_SCA_FIXTURE = resolve(process.cwd(), "fixtures/pub-sca-corpus");
const PUB_TP_FIXTURE = resolve(PUB_SCA_FIXTURE, "tp");
const PUB_FP_FIXTURE = resolve(PUB_SCA_FIXTURE, "fp");
const PUB_FIXED_FIXTURE = resolve(PUB_SCA_FIXTURE, "fixed");
const REACT_NATIVE_EXPO_FIXTURE = resolve(process.cwd(), "fixtures/react-native-expo-corpus");
const REACT_NATIVE_EXPO_TP_FIXTURE = resolve(REACT_NATIVE_EXPO_FIXTURE, "tp");
const REACT_NATIVE_EXPO_FP_FIXTURE = resolve(REACT_NATIVE_EXPO_FIXTURE, "fp");
const REACT_NATIVE_EXPO_FIXED_FIXTURE = resolve(REACT_NATIVE_EXPO_FIXTURE, "fixed");
const PYTHON_AI_API_FIXTURE = resolve(process.cwd(), "fixtures/python-ai-api-corpus");
const PYTHON_AI_API_TP_FIXTURE = resolve(PYTHON_AI_API_FIXTURE, "tp");
const PYTHON_AI_API_FP_FIXTURE = resolve(PYTHON_AI_API_FIXTURE, "fp");
const PYTHON_AI_API_FIXED_FIXTURE = resolve(PYTHON_AI_API_FIXTURE, "fixed");
const GO_AI_FIXTURE = resolve(process.cwd(), "fixtures/go-ai-corpus");
const GO_AI_TP_FIXTURE = resolve(GO_AI_FIXTURE, "tp");
const GO_AI_FP_FIXTURE = resolve(GO_AI_FIXTURE, "fp");
const GO_AI_FIXED_FIXTURE = resolve(GO_AI_FIXTURE, "fixed");
const JAVA_AI_FIXTURE = resolve(process.cwd(), "fixtures/java-ai-corpus");
const JAVA_AI_TP_FIXTURE = resolve(JAVA_AI_FIXTURE, "tp");
const JAVA_AI_FP_FIXTURE = resolve(JAVA_AI_FIXTURE, "fp");
const JAVA_AI_FIXED_FIXTURE = resolve(JAVA_AI_FIXTURE, "fixed");
const CSHARP_AI_FIXTURE = resolve(process.cwd(), "fixtures/csharp-ai-corpus");
const CSHARP_AI_TP_FIXTURE = resolve(CSHARP_AI_FIXTURE, "tp");
const CSHARP_AI_FP_FIXTURE = resolve(CSHARP_AI_FIXTURE, "fp");
const CSHARP_AI_FIXED_FIXTURE = resolve(CSHARP_AI_FIXTURE, "fixed");
const PHP_AI_FIXTURE = resolve(process.cwd(), "fixtures/php-ai-corpus");
const PHP_AI_TP_FIXTURE = resolve(PHP_AI_FIXTURE, "tp");
const PHP_AI_FP_FIXTURE = resolve(PHP_AI_FIXTURE, "fp");
const PHP_AI_FIXED_FIXTURE = resolve(PHP_AI_FIXTURE, "fixed");
const RUST_AI_FIXTURE = resolve(process.cwd(), "fixtures/rust-ai-corpus");
const RUST_AI_TP_FIXTURE = resolve(RUST_AI_FIXTURE, "tp");
const RUST_AI_FP_FIXTURE = resolve(RUST_AI_FIXTURE, "fp");
const RUST_AI_FIXED_FIXTURE = resolve(RUST_AI_FIXTURE, "fixed");
const RUBY_AI_FIXTURE = resolve(process.cwd(), "fixtures/ruby-ai-corpus");
const RUBY_AI_TP_FIXTURE = resolve(RUBY_AI_FIXTURE, "tp");
const RUBY_AI_FP_FIXTURE = resolve(RUBY_AI_FIXTURE, "fp");
const RUBY_AI_FIXED_FIXTURE = resolve(RUBY_AI_FIXTURE, "fixed");
const FIREBASE_CONFIG_FIXTURE = resolve(process.cwd(), "fixtures/firebase-config-corpus");
const FIREBASE_CONFIG_TP_FIXTURE = resolve(FIREBASE_CONFIG_FIXTURE, "tp");
const FIREBASE_CONFIG_FP_FIXTURE = resolve(FIREBASE_CONFIG_FIXTURE, "fp");
const FIREBASE_CONFIG_FIXED_FIXTURE = resolve(FIREBASE_CONFIG_FIXTURE, "fixed");
const GITHUB_ACTIONS_FIXTURE = resolve(process.cwd(), "fixtures/github-actions-corpus");
const GITHUB_ACTIONS_TP_FIXTURE = resolve(GITHUB_ACTIONS_FIXTURE, "tp");
const GITHUB_ACTIONS_FP_FIXTURE = resolve(GITHUB_ACTIONS_FIXTURE, "fp");
const GITHUB_ACTIONS_FIXED_FIXTURE = resolve(GITHUB_ACTIONS_FIXTURE, "fixed");
const OSV_PYPI_FIXTURE = resolve(process.cwd(), "fixtures/osv-pypi");
const OSV_PYPI_VULNERABLE_FIXTURE = resolve(OSV_PYPI_FIXTURE, "vulnerable");
const OSV_PYPI_FIXED_FIXTURE = resolve(OSV_PYPI_FIXTURE, "fixed");
const OSV_PYPI_SUPPRESSED_FIXTURE = resolve(OSV_PYPI_FIXTURE, "suppressed");
const OSV_CARGO_NO_DB_FIXTURE = resolve(process.cwd(), "fixtures/osv-cargo-no-db");
const OPENGREP_SHADOW_FIXTURE = resolve(process.cwd(), "fixtures/opengrep-shadow-corpus");
const COVERAGE_HONESTY_FIXTURE = resolve(process.cwd(), "fixtures/coverage-honesty-corpus");
const OPENGREP_RULES_FIXTURE = resolve(COVERAGE_HONESTY_FIXTURE, "opengrep-rules");
const SYNVOYA_EVAL_FIXTURES = resolve(process.cwd(), "fixtures/synvoya/evals");
const SYNVOYA_GAP_DECLARATIONS_FIXTURE = resolve(SYNVOYA_EVAL_FIXTURES, "gap-declarations");
const SYNVOYA_TRIVY_COVERED_FIXTURE = resolve(SYNVOYA_EVAL_FIXTURES, "trivy-covered");
const SYNVOYA_FLOATING_TAG_FIXTURE = resolve(SYNVOYA_EVAL_FIXTURES, "floating-tag");
const SYNVOYA_VENDORED_FIXTURE = resolve(SYNVOYA_EVAL_FIXTURES, "vendored-libraries");
const SYNVOYA_GO_TOOLCHAIN_FIXTURE = resolve(SYNVOYA_EVAL_FIXTURES, "go-toolchain");
const SYNVOYA_PHP_FIXTURES = resolve(process.cwd(), "fixtures/synvoya-php");
const SYNVOYA_NODE_FIXTURE = resolve(process.cwd(), "fixtures/synvoya-node-corpus");
// INTENTIONAL FAKE TEST DATA (planted fixture value; the evals below assert it is
// detected and redacted) -- not a real credential; allowlisted in /.gitleaks.toml.
const RAW_SECRET = "sk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP1rE5wB9mNqK7";
const FLUTTER_REDACTION_SENTINEL = "CI_FLUTTER_REDACTION_SENTINEL";
const REACT_NATIVE_EXPO_REDACTION_SENTINEL = "CI_RN_EXPO_REDACTION_SENTINEL";
const PYTHON_REDACTION_SENTINEL = "CI_PYTHON_REDACTION_SENTINEL";

const FLUTTER_RULES = [
  {
    file: "lib/01_tls_verification.dart",
    id: "ci-flutter-tls-verification-disabled",
    severity: "high",
    cwe: ["CWE-295"],
    component: "ai:flutter-tls-verification",
  },
  {
    file: "lib/02_sensitive_preferences.dart",
    id: "ci-flutter-sensitive-shared-preferences",
    severity: "high",
    cwe: ["CWE-312"],
    component: "ai:flutter-sensitive-preferences",
  },
  {
    file: "lib/03_untrusted_webview.dart",
    id: "ci-flutter-webview-untrusted-content",
    severity: "medium",
    cwe: ["CWE-20", "CWE-346"],
    component: "ai:flutter-webview-untrusted-content",
  },
  {
    file: "lib/04_sensitive_log.dart",
    id: "ci-flutter-sensitive-log",
    severity: "medium",
    cwe: ["CWE-532"],
    component: "ai:flutter-sensitive-log",
  },
  {
    file: "lib/05_supabase_privileged_key.dart",
    id: "ci-flutter-supabase-privileged-key-client",
    severity: "critical",
    cwe: ["CWE-798", "CWE-312", "CWE-285"],
    component: "ai:flutter-supabase-privileged-key",
  },
  {
    file: "lib/06_cleartext_network.dart",
    id: "ci-flutter-cleartext-network",
    severity: "medium",
    cwe: ["CWE-319"],
    component: "ai:flutter-cleartext-network",
  },
] as const;

const MOBILE_CONFIG_RULES = [
  { id: "ci-android-debuggable-release", pack: "android", file: "app/src/release/AndroidManifest.xml", severity: "medium", cwe: ["CWE-489"], component: "ai:android-debuggable" },
  { id: "ci-android-cleartext-traffic", pack: "android", file: "app/src/main/res/xml/network_security_config.xml", severity: "medium", cwe: ["CWE-319"], component: "ai:android-cleartext-traffic" },
  { id: "ci-android-user-ca-trust", pack: "android", file: "app/src/main/res/xml/network_security_config.xml", severity: "medium", cwe: ["CWE-295"], component: "ai:android-user-ca-trust" },
  { id: "ci-android-exported-file-provider", pack: "android", file: "app/src/main/AndroidManifest.xml", severity: "high", cwe: ["CWE-926"], component: "ai:android-exported-file-provider" },
  { id: "ci-ios-ats-global-arbitrary-loads", pack: "ios", file: "Runner/Info.plist", severity: "medium", cwe: ["CWE-319"], component: "ai:ios-ats-global-arbitrary-loads" },
  { id: "ci-ios-ats-insecure-domain-exception", pack: "ios", file: "Runner/Info.plist", severity: "medium", cwe: ["CWE-319"], component: "ai:ios-ats-insecure-domain-exception" },
  { id: "ci-ios-ats-weak-tls", pack: "ios", file: "Runner/Info.plist", severity: "medium", cwe: ["CWE-327"], component: "ai:ios-ats-weak-tls" },
  { id: "ci-ios-data-protection-disabled", pack: "ios", file: "Runner/Runner.entitlements", severity: "medium", cwe: ["CWE-311"], component: "ai:ios-data-protection" },
] as const;

const REACT_NATIVE_EXPO_RULES = [
  {
    file: "src/01_sensitive_storage.ts",
    id: "ci-react-native-sensitive-async-storage",
    pack: "react-native",
    severity: "high",
    kind: "ai",
    cwe: ["CWE-312"],
    component: "ai:react-native-sensitive-async-storage",
  },
  {
    file: "src/02_untrusted_webview.tsx",
    id: "ci-react-native-webview-untrusted-content",
    pack: "react-native",
    severity: "medium",
    kind: "ai",
    cwe: ["CWE-20", "CWE-346"],
    component: "ai:react-native-webview-untrusted-content",
  },
  {
    file: "src/03_mixed_content.tsx",
    id: "ci-react-native-webview-mixed-content",
    pack: "react-native",
    severity: "medium",
    kind: "ai",
    cwe: ["CWE-319"],
    component: "ai:react-native-webview-mixed-content",
  },
  {
    file: "src/04_universal_file_access.tsx",
    id: "ci-react-native-webview-universal-file-access",
    pack: "react-native",
    severity: "high",
    kind: "ai",
    cwe: ["CWE-200", "CWE-942"],
    component: "ai:react-native-webview-universal-file-access",
  },
  {
    file: "app.config.ts",
    id: "ci-expo-secret-in-public-config",
    pack: "expo",
    severity: "high",
    kind: "secret",
    cwe: ["CWE-798", "CWE-312"],
    component: "ai:expo-secret-in-public-config",
  },
  {
    file: "app.config.ts",
    id: "ci-expo-unsigned-cleartext-updates",
    pack: "expo",
    severity: "high",
    kind: "ai",
    cwe: ["CWE-494", "CWE-319"],
    component: "ai:expo-unsigned-cleartext-updates",
  },
] as const;

const PYTHON_AI_API_RULES = [
  { file: "config/settings.py", id: "ci-python-hardcoded-signing-secret", severity: "high", kind: "secret", cwe: ["CWE-798", "CWE-321"], confidence: "high", component: "ai:python-hardcoded-signing-secret" },
  { file: "src/02_credentialed_cors.py", id: "ci-python-credentialed-cors-all-origins", severity: "high", kind: "ai", cwe: ["CWE-942", "CWE-346"], confidence: "high", component: "ai:python-credentialed-cors" },
  { file: "src/03_file_response.py", id: "ci-python-untrusted-file-response", severity: "high", kind: "ai", cwe: ["CWE-22", "CWE-73"], confidence: "high", component: "ai:python-untrusted-file-response" },
  { file: "src/04_redirect.py", id: "ci-python-untrusted-redirect", severity: "medium", kind: "ai", cwe: ["CWE-601"], confidence: "high", component: "ai:python-untrusted-redirect" },
  { file: "src/05_template_source.py", id: "ci-python-untrusted-template-source", severity: "high", kind: "ai", cwe: ["CWE-1336", "CWE-94"], confidence: "high", component: "ai:python-untrusted-template-source" },
  { file: "src/06_llm_html.py", id: "ci-python-llm-output-dangerous-html", severity: "high", kind: "ai", cwe: ["CWE-79", "CWE-116"], confidence: "high", component: "ai:python-llm-output-dangerous-html" },
  { file: "src/07_faiss_deserialization.py", id: "ci-python-faiss-dangerous-deserialization", severity: "high", kind: "ai", cwe: ["CWE-502"], confidence: "high", component: "ai:python-faiss-dangerous-deserialization" },
  { file: "src/08_langchain_web_loader_ssrf.py", id: "ci-python-langchain-web-loader-ssrf", severity: "high", kind: "ai", cwe: ["CWE-918"], confidence: "high", component: "ai:python-langchain-web-loader-ssrf" },
  { file: "src/09_prompt_injection.py", id: "ci-python-prompt-injection-sink", severity: "high", kind: "ai", cwe: ["CWE-1427"], confidence: "medium", component: "ai:python-prompt-injection" },
  { file: "src/10_unsafe_tool_execution.py", id: "ci-python-llm-tool-argument-command-execution", severity: "high", kind: "ai", cwe: ["CWE-78", "CWE-1426"], confidence: "medium", component: "ai:python-unsafe-tool-execution" },
] as const;

const PUB_TP_ADVISORIES = [
  "GHSA-3hpf-ff72-j67p",
  "GHSA-4xh4-v2pq-jvhm",
  "GHSA-9v85-q87q-g4vg",
  "GHSA-fmj7-7gfw-64pg",
  "GHSA-r285-q736-9v95",
  "GHSA-vm9r-h74p-hg97",
] as const;

const FLUTTER_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:flutter:dispatch": "sha256:dd7a82ca5ce49accb0f5d903aaca56bf9785388b3e58c352466a9bd729233f4b",
  "flutter:dart-structural-parser": "sha256:87cb980e5c38f12d8413ecd826a16a00b00662efe7ef6fc5f358d492e5296a9f",
  "ai:flutter-tls-verification": "sha256:722e83e70e16b98875482d3dabde531562e85b2953970f7917d6ed5253e4972a",
  "ai:flutter-sensitive-preferences": "sha256:9050cea99534ada1789015c48c7e9dffcdcb7ed3e942694e488eaa2c7f0f166a",
  "ai:flutter-webview-untrusted-content": "sha256:60c6f2c59bf27a7481fc37992530776c3e27f7f985f9e6b46398cff5e68de8ac",
  "ai:flutter-sensitive-log": "sha256:d29aa52f8d9be52e5c5c23d01450c880d64fb131cb670552ce8f6417a1145b3a",
  "ai:flutter-supabase-privileged-key": "sha256:a6e842c74dd651af3cc82d5a81a493eecd0fc250bfc70250dcd3500c571de586",
  "ai:flutter-cleartext-network": "sha256:84d344056e50ef21f7cd0f16d183d31dcf1af9927c4376afa62ac3f0c476cbc2",
};

const FLUTTER_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Dart analysis; it has no type resolution or path-sensitive branch merge and does not claim complete Flutter security coverage.",
  "Generated files and test/example corpora are excluded from project-root scans unless scanned directly.",
  "Unreadable Dart files, files over 2 MiB, and source beyond the 10,000-file/64 MiB project bounds are skipped and reported in pack coverage.",
  "The pack analyzes repository evidence only and does not replace runtime mobile security testing.",
] as const;

const ANDROID_PACK_LIMITATIONS = [
  "Parses explicit repository AndroidManifest.xml and referenced Network Security Config XML, with bounded main-to-release overlay handling for the supported attributes and resources; it does not run Gradle or model arbitrary product flavors, build-type DSL, placeholders, the full manifest merger, runtime behavior, or complete Android security coverage.",
  "Directory scans inspect only root, main, and release manifests; non-production demo, sample, example, debug, profile, test, dependency, generated, build, vendor, and cache trees are excluded.",
  "Only literal @xml/... networkSecurityConfig references are resolved; unreferenced configurations are not claimed.",
  "XML files over 1 MiB, discovery beyond 20,000 entries, 500 manifests, or 24 levels, and malformed or unreadable files are skipped and reported in pack coverage.",
  "Symbolic links are skipped and never followed; the structured parser never resolves external or DTD-defined XML entities and never executes target content.",
] as const;

const IOS_PACK_LIMITATIONS = [
  "Parses explicit repository XML property lists and entitlements and resolves only literal Release/AppStore INFOPLIST_FILE and CODE_SIGN_ENTITLEMENTS project settings; it does not run Xcode, expand xcconfig/preprocessing/dynamic variables, inspect provisioning profiles, or claim complete iOS security coverage.",
  "Non-production demo, sample, example, debug, profile, test, macOS/OS X, dependency, generated, build, Pods, and DerivedData trees are excluded from directory scans.",
  "Binary, malformed, unreadable, or oversized configuration is skipped and reported; discovery is bounded to 50,000 entries, Xcode projects to 4 MiB each and 16 MiB total, and selected property lists to 256 files, 512 KiB each, and 8 MiB total.",
  "Symbolic links are skipped and never followed; the structured parser never resolves external or DTD-defined XML entities and never executes target content.",
] as const;

const MOBILE_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:android:dispatch": "sha256:1bae739b2ab006e02ef14153a5ce74cf02afc7680ba3aaf8232b548cec27b58a",
  "android:xml-config-parser": "sha256:830ca59f1a42c411a28623d8c031f20f72cbad0613f1cb102ba48bd128605c2a",
  "ai:android-debuggable": "sha256:7fa4f7caa6995a1d684446b1bc385cd729921806983fecea78b437d18f222850",
  "ai:android-cleartext-traffic": "sha256:114225b82081704f606a2cc902ed5e0ccd94dbb2bfd0ed3b7435a6447c4fde99",
  "ai:android-user-ca-trust": "sha256:ca1d428633319865fc62a9a38ed9809be339033fcdef0ff83726865d93c8b1c8",
  "ai:android-exported-file-provider": "sha256:413ef5b898cebaabf07821eb3dd6169dd5e4cb9a41f2fcc214fba90821914746",
  "pack:ios:dispatch": "sha256:eda28c4a3455fd33025c49171c177714fb274b27b328555f8c871a948e7854fa",
  "ios:xml-plist-parser": "sha256:1a52ab357205e1e995da78443c246c514320f04d9f380bd8fe91580479f98f2f",
  "ai:ios-ats-global-arbitrary-loads": "sha256:73c3b26ded2edad8740f87758cc71d059ebd4f232328f7919f8e7ca01c0bcdd9",
  "ai:ios-ats-insecure-domain-exception": "sha256:f65c000a1858daa3fc589f88c6e25f2659c80e3ca46db372e0cf5ded9cf585fa",
  "ai:ios-ats-weak-tls": "sha256:925a3be9f0dcf3b1cadfa44247ae3f7891a50d547fdd8908b025ea92877cc78f",
  "ai:ios-data-protection": "sha256:380aaa201867fcc488a783a22f0282aaacaea9f6c9cafc24e5db969d519c171f",
};

const REACT_NATIVE_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile JavaScript/TypeScript/JSX analysis; it has no type checker, module graph, interprocedural state flow, or path-sensitive branch merge and does not claim complete React Native security coverage.",
  "Only receivers and components proven by static imports/requires and bounded source-ordered aliases are analyzed; computed properties, dynamic imports, JSX spread props, and unresolved dynamic security values fail closed.",
  "Generated, dependency, build, test, fixture, demo, sample, and example trees are excluded from project-root scans unless a supported source file is scanned directly.",
  "Unreadable, malformed, symbolic-link, over-2 MiB, over-200,000-token, or over-64-level structurally nested files and source beyond the 50,000-entry/10,000-file/64 MiB/1,000,000-token/32-level project bounds are skipped and reported in pack coverage.",
  "The pack analyzes repository evidence only, never executes target code, and does not replace runtime mobile security testing.",
  "Each file is read with a full parser (@babel/parser); a file it cannot parse is skipped as the gap native-parse-errors. The rules are intrafile token and syntax patterns, so code written to avoid a pattern (an alias, a wrapper, a computed call) can still avoid it.",
] as const;

const EXPO_PACK_LIMITATIONS = [
  "Parses app.json/app.config.json and direct static app.config JavaScript/TypeScript object exports at the scan root and bounded nested package roots; it never imports, evaluates, transpiles, or executes target configuration.",
  "Comments and trailing commas are supported, but spreads, functions, computed keys, branches, unresolved aliases, duplicate keys, ambiguous config files, and unsupported or malformed syntax encountered in the exported static-object subset suppress findings and are reported as coverage notes; unrelated module statements are not fully syntax-validated.",
  "The secret rule covers sensitive non-EXPO_PUBLIC process.env references and one-hop const aliases in public Expo config paths; Expo's hooks, ios.config, android.config, and update code-signing fields are excluded.",
  "The update rule covers explicit enabled/default-enabled non-local production HTTP URLs without a literal signing certificate; dynamic fields, HTTPS, local/private/reserved/example URLs, disabled updates, and signed updates are excluded.",
  "Symbolic links and generated/corpus trees are skipped; discovery is bounded to 20,000 entries, 500 package roots, and 24 levels. Individual configs are limited to 1 MiB/100,000 tokens; aggregate package/config reads are limited to 4,096 files/4 MiB and static parsing to 250,000 tokens/25,000 properties.",
] as const;

const REACT_NATIVE_EXPO_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:react-native:dispatch": "sha256:b34edc998d094867fbb5e76edc81ada50a9e80bedcb6c23972f34da589c5b521",
  "react-native:javascript-structural-parser": "sha256:f72c111621c233cc77fcfdddf781b5cbe6c72edf85e5fe6c55471bfb2086840a",
  "ai:react-native-sensitive-async-storage": "sha256:d8be985dfb0232afbba8fa5f698ec82e271d1971791d2c031ebcaad75f200f43",
  "ai:react-native-webview-untrusted-content": "sha256:4471ca3c31a6b5e77f15707fcfca7a6d8e20572c09a33dcfdf5efbe47e64d292",
  "ai:react-native-webview-mixed-content": "sha256:661de986f2b1babf01d9f4f2c15f3e7b316a56e2ebbdcd0f19b28034bd2c11bd",
  "ai:react-native-webview-universal-file-access": "sha256:92edbb521406c3e69736e5f41d9b85dde5e2203f8950e53c5a6cefc80eafc498",
  "pack:expo:dispatch": "sha256:b3512fceb46f52fc07d84c68957386ca497631f91535848e6cbbc5ae90d8359a",
  "expo:static-config-parser": "sha256:0da5406f9f222fa22bff539f7647e5d89f43c2a616c0b2ffd3fd548d5d11724b",
  "ai:expo-secret-in-public-config": "sha256:6fbdeeac774e54bc354deb7f33ebb9ddbceaa04b6f6d3f4d33404c2665162274",
  "ai:expo-unsigned-cleartext-updates": "sha256:48f2e9f3dfa399b787fda2a0b6c2c2d5787fcbcc48be3029015c2a5926226f11",
};

const PYTHON_AI_API_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Python analysis with a bounded Lezer syntax gate; it has no type checker, module graph, interprocedural flow, path-sensitive branch merge, or claim of complete Python security coverage.",
  "The ten rules cover exact Django, Flask, FastAPI, Starlette, Jinja, OpenAI, Anthropic, LangChain, and Python OS-command source/sink shapes only; unsupported aliases, computed values, dynamic imports, spreads, generic dispatch, and flows beyond the documented bounded aliases fail closed.",
  "Lezer-validated format strings are tokenized as opaque dynamic strings, so replacement expressions are not inspected; leading tab indentation remains unsupported and mixed tab-stop indentation is skipped and reported rather than risking conditional bindings being analyzed as executable direct scope.",
  "Generated, migration, dependency, build, test, fixture, demo, sample, and example trees and conventional test files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, generated headers, unreadable or malformed files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/1,000,000-token/1,000,000-node/32-level project bounds are skipped and reported in pack coverage.",
  "The pack parses repository evidence only, never imports or executes target Python, and does not replace dependency, runtime, or penetration testing.",
] as const;

const PYTHON_AI_API_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:python-ai-api:dispatch": "sha256:25fc9425b3ffcf2bc1f15178e39000687fb2e261d1cb938f0a77a59828a1b9dd",
  "python:lezer-structural-parser": "sha256:9de9056123c716b9615c231183379140d60e3805f6d6be6709159eeb0839dea5",
  "ai:python-hardcoded-signing-secret": "sha256:9381fb56d3598c1f478fba84a9b0db960f879d0b6aa8bda021a57c016d601c3a",
  "ai:python-credentialed-cors": "sha256:46477b8b3f9abff6ce4e771aaf3830721e26c31481ccce82751278930b584adf",
  "ai:python-untrusted-file-response": "sha256:f77122fe93de07f380fca77b64f72cd7860c61c5a5255e48e928cb269e186d54",
  "ai:python-untrusted-redirect": "sha256:ab6e8662a4039b7138c0468d779db948a1ef40271b0d6d700fb569166275b3b5",
  "ai:python-untrusted-template-source": "sha256:0592921975193cdb4ca77cf885051efad80b327bc78fc2cbaa90c19e4524806e",
  "ai:python-llm-output-dangerous-html": "sha256:c0ad9bab6d078faf4f2946b384ad8ce31c44729fee65049d38d41d26271da1d4",
  "ai:python-faiss-dangerous-deserialization": "sha256:43c272019a5f1b55134069fd78a86cd2a2e3f7e7cd40d3f5b5c81f9f5d7ca6ad",
  "ai:python-langchain-web-loader-ssrf": "sha256:fc0a8cb494a013673039c15cc7b510626512beab2ec8271c81a63335c42366d0",
  "ai:python-prompt-injection": "sha256:81e7a02901ab455dd89ba8fb60a5c8366ee8b98ba6bf4a54b3d909bbd524ba20",
  "ai:python-unsafe-tool-execution": "sha256:2edfb092c8fab55b2e1ebdf11c1d13c576597a5018cfcb0ebe802d2c55bc0203",
};

const GO_AI_RULE = {
  file: "src/main.go",
  id: "ci-go-llm-tool-argument-command-execution",
  severity: "high",
  kind: "ai",
  cwe: ["CWE-78", "CWE-1426"],
  confidence: "medium",
  owaspLlm: ["LLM05:2025", "LLM06:2025"],
  component: "ai:go-unsafe-tool-execution",
} as const;

const GO_AI_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Go analysis without a type checker, module graph, path-sensitive branch merge, or claim of complete Go security coverage.",
  "The rule covers exact official OpenAI Go Chat Completions tool-call arguments reaching import-proven os/exec shell interpreters; Anthropic, Gemini, custom model types, generic dispatch, renamed external wrappers, and cross-module flow fail closed.",
  "Dataflow is bounded to direct aliases, encoding/json unmarshal, one local JSON parsing helper, and one local command wrapper; checked approval/allowlist rejection and validated replacement values suppress findings.",
  "Generated, dependency, build, test, fixture, demo, sample, and example trees and conventional _test.go/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; individual structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never builds or executes target Go, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

const GO_AI_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:go-ai:dispatch": "sha256:6cbbc85ac343288606d333f362e0efa10d98fae6e10ee4f39ac2ec3e09289d24",
  "go:bounded-structural-parser": "sha256:6e8f71ff7992a99bf8f56e0b565de70bb97c1cf758e9640a19b610417f9254fb",
  "ai:go-unsafe-tool-execution": "sha256:147e1bf42da903fd3f25a9f1ca4bc87fd0a49344429d6ce65432dd2caa1ee606",
};

const JAVA_AI_RULE = {
  file: "src/main/java/example/Agent.java",
  id: "ci-java-llm-tool-argument-command-execution",
  severity: "high",
  kind: "ai",
  cwe: ["CWE-78", "CWE-1426"],
  confidence: "medium",
  owaspLlm: ["LLM05:2025", "LLM06:2025"],
  component: "ai:java-unsafe-tool-execution",
} as const;

const JAVA_AI_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Java analysis without a type checker, module graph, path-sensitive branch merge, or claim of complete Java security coverage.",
  "The rule covers exact official OpenAI Java tool-call argument types reaching an actually-started recognized ProcessBuilder or Runtime shell interpreter; Spring AI, LangChain4j, Azure OpenAI, other model types, generic dispatch, and cross-module flow fail closed.",
  "Dataflow is bounded to direct aliases, one local parsing helper, and one local command wrapper; checked approval/allowlist rejection and validated replacement values suppress findings.",
  "Generated, dependency, build, test, fixture, demo, sample, and top-level example trees and conventional Java test/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, malformed strings/comments, Java text blocks, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; individual structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never builds or executes target Java, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

const JAVA_AI_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:java-ai:dispatch": "sha256:53b46f20e876320207801dd71b2d50798445213de2a166381e729998e541cd05",
  "java:bounded-structural-parser": "sha256:aaacb6ad72981025fd5dfeb36b069be7501a8b7c6e5f9a543d677e49090bd912",
  "ai:java-unsafe-tool-execution": "sha256:687fdfc3620ba571e5a4107a4d2ed1b9bb438cc082fbc5c3da26c8266f37dfdd",
};

const CSHARP_AI_RULE = {
  file: "Agent.cs",
  id: "ci-csharp-llm-tool-argument-command-execution",
  severity: "high",
  kind: "ai",
  cwe: ["CWE-78", "CWE-1426"],
  confidence: "medium",
  owaspLlm: ["LLM05:2025", "LLM06:2025"],
  component: "ai:csharp-unsafe-tool-execution",
} as const;

const CSHARP_AI_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile C# analysis without a compiler, semantic model, project graph, path-sensitive branch merge, or claim of complete .NET security coverage.",
  "The rule covers exact official OpenAI .NET ChatToolCall FunctionArguments reaching an actually-started recognized System.Diagnostics.Process shell; Azure OpenAI, Semantic Kernel, Microsoft.Extensions.AI, other model types, generic dispatch, and cross-project flow fail closed.",
  "Dataflow is bounded to direct aliases, System.Text.Json dictionary/property extraction, one local parsing helper, and one local command wrapper; checked approval/allowlist rejection and validated replacement values suppress findings.",
  "Generated, dependency, build, publish, test, fixture, demo, sample, and example trees and conventional C# test/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; raw string contents are treated as opaque and individual structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never restores, builds, or executes target .NET code, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

const CSHARP_AI_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:csharp-ai:dispatch": "sha256:21f516ef1895a1191e8ac4a6b4675f96999fe8d780c56300ce6debc745ce3819",
  "csharp:bounded-structural-parser": "sha256:2f3cc2240e2ee15030469d80fafc72f001eb8d3d19d91f0e1d7aac6950a4051f",
  "ai:csharp-unsafe-tool-execution": "sha256:92191655ff218b54dc31c16e26f04d3544e3a94f409b6909bfb3c3ea7f85c2f9",
};

const PHP_AI_RULE = {
  file: "Agent.php",
  id: "ci-php-llm-tool-argument-command-execution",
  severity: "high",
  kind: "ai",
  cwe: ["CWE-78", "CWE-1426"],
  confidence: "medium",
  owaspLlm: ["LLM05:2025", "LLM06:2025"],
  component: "ai:php-unsafe-tool-execution",
} as const;

const PHP_AI_PACK_LIMITATIONS = [
  "Bounded intrafile PHP analysis without a PHP parser, type resolver, Composer graph, path-sensitive branch merge, or claim of complete PHP security coverage.",
  "The rule covers exact openai-php/client or openai-php/laravel package evidence and tool-call function arguments reaching exec, system, shell_exec, or passthru; other clients, generic callables, and cross-file flow fail closed.",
  "Dataflow is bounded to direct aliases, associative json_decode extraction, one local parsing helper, one local command wrapper, and one exact mapped variadic method dispatch; checked approval/full-command allowlists and validated replacement values suppress findings.",
  "Custom validation helpers are not assumed safe; first-token executable checks do not neutralize shell metacharacters in the remaining command string.",
  "Generated, dependency, cache, build, test, fixture, demo, sample, and example trees and conventional PHP test/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, heredoc/nowdoc or malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never installs dependencies or executes target PHP, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

const PHP_AI_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:php-ai:dispatch": "sha256:44aa9fa34f5c0b53c491c771952d84ab1aaa178798025dd47102a13ff2b39e69",
  "php:bounded-structural-parser": "sha256:fb4f8ef79ec4a77caa4a6ce45371baba2cb82f158b12c1f15ea6c3aef9473eb3",
  "ai:php-unsafe-tool-execution": "sha256:30f1d918b42fb730c688da0737617e621df0f5ff1384c763ed62b55ec83ec361",
};

const RUST_AI_RULE = {
  file: "src/main.rs",
  id: "ci-rust-llm-tool-argument-command-execution",
  severity: "high",
  kind: "ai",
  cwe: ["CWE-78", "CWE-1426"],
  confidence: "medium",
  owaspLlm: ["LLM05:2025", "LLM06:2025"],
  component: "ai:rust-unsafe-tool-execution",
} as const;

const RUST_AI_PACK_LIMITATIONS = [
  "Token-aware, source-ordered intrafile Rust analysis without rustc, a Rust parser, type resolution, a Cargo graph, path-sensitive branch merge, or claim of complete Rust security coverage.",
  "The rule covers exact community async-openai package evidence and recognized tool-call arguments reaching an import-proven standard/tokio process shell or a literal bollard Docker exec shell vector; other clients, generic dispatch, renamed external wrappers, and cross-crate flow fail closed.",
  "Dataflow is bounded to direct aliases, serde_json extraction, one recognized generate_function_call result, and one local command wrapper; checked approval/allowlist rejection and validated replacement values suppress findings.",
  "Generated, dependency, build, benchmark, test, fixture, demo, sample, and example trees and conventional Rust test/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; individual structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never fetches crates, builds, or executes target Rust, and does not replace dependency, runtime, sandbox, container-isolation, or penetration testing.",
] as const;

const RUST_AI_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:rust-ai:dispatch": "sha256:0834394e6a589b909a47a7ab34802df959354e2dc1258d9ea8700ad3076a4ece",
  "rust:bounded-structural-parser": "sha256:4939aeeeb022c79e485dcdc45bfdd73980ec9b2a940fd1b45e75d856507dd1b2",
  "ai:rust-unsafe-tool-execution": "sha256:b63a5bce3f237ab50aa2c3b134431ffe4ee30a95d8239e1ad91d216b8a5bb1f8",
};

const RUBY_AI_RULE = {
  file: "agent.rb",
  id: "ci-ruby-llm-tool-argument-command-execution",
  severity: "high",
  kind: "ai",
  cwe: ["CWE-78", "CWE-1426"],
  confidence: "medium",
  owaspLlm: ["LLM05:2025", "LLM06:2025"],
  component: "ai:ruby-unsafe-tool-execution",
} as const;

const RUBY_AI_PACK_LIMITATIONS = [
  "Source-ordered intrafile Ruby analysis without a Ruby parser, type resolver, Bundler graph, path-sensitive branch merge, or claim of complete Ruby security coverage.",
  "The rule requires exact official openai production Gemfile or runtime gemspec evidence and covers Chat tool-call function arguments or explicitly typed Responses function-tool arguments reaching system, exec, IO.popen, or import-proven Open3 shell execution; lockfile-only and development-only dependencies, other clients, generic argument objects, backticks, percent-x literals, spawn APIs, and cross-file flow fail closed.",
  "Dataflow is bounded to direct aliases, JSON.parse command extraction, one local parsing helper, and one local command wrapper; checked approval/full-command allowlists and validated replacement values suppress findings.",
  "Generated, dependency, cache, build, test, spec, fixture, demo, sample, and example trees and conventional Ruby test/spec/generated files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, heredocs, malformed strings/comments, unreadable files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/32-level project bounds are skipped; structural expressions are capped at 64 KiB.",
  "The pack parses repository evidence only, never installs gems or executes target Ruby, and does not replace dependency, runtime, sandbox, or penetration testing.",
] as const;

const RUBY_AI_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:ruby-ai:dispatch": "sha256:1465e634819da647c7b359ee15c53480aab71876b938a4122ad4c1e55a17dfd5",
  "ruby:bounded-structural-parser": "sha256:282b5d4d8c11046396b4ac1cd978168aef82534ee31cdc3db86910424d155d20",
  "ai:ruby-unsafe-tool-execution": "sha256:44b95fb03e402cfc02447f1a54ba0cbe7be625bcb549b97c43c5dda22b41cf07",
};

const FIREBASE_CONFIG_RULES = [
  { file: "database.rules.json", id: "ci-firebase-realtime-database-public-write", component: "ai:firebase-realtime-database-public-write", line: 6 },
  { file: "firestore.rules", id: "ci-firebase-firestore-public-write", component: "ai:firebase-firestore-public-write", line: 6 },
  { file: "storage.rules", id: "ci-firebase-storage-public-write", component: "ai:firebase-storage-public-write", line: 5 },
] as const;

const FIREBASE_PACK_LIMITATIONS = [
  "Detects only literal unconditional public write grants in checked-in Cloud Firestore, Cloud Storage, and Realtime Database Security Rules; public reads, semantic helper functions, runtime policy state, IAM, App Check, and complete Firebase security coverage are outside this pack.",
  "Cloud Firestore and Cloud Storage analysis requires exact service declarations and literal allow write/create/update/delete statements with no condition or a condition that is exactly true; other expressions fail closed.",
  "Realtime Database analysis requires strict JSON and recognizes only .write values that are boolean true or the exact string true; dynamic expressions are not evaluated.",
  "Directory scans inspect .rules files and database.rules.json while excluding test, example, sample, dependency, generated, build, vendor, and cache trees; custom non-.rules filenames are not discovered.",
  "Files over 1 MiB and discovery beyond 1,000 rule files, 32 MiB total, 50,000 entries, or 32 levels are skipped and reported in pack coverage.",
  "Symbolic links and symbolic-link ancestors are skipped and never followed; target code and Firebase tooling are never executed.",
] as const;

const FIREBASE_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:firebase:dispatch": "sha256:6dd4579434dbe4aea4ad1447622635672bd31b17b8f9f144e8d4b4aeb820f56d",
  "firebase:bounded-rules-parser": "sha256:8e5d2044f2d1e09ff06d3fecae9a82b760247df1b7f12e5e5ae8016209443765",
  "ai:firebase-firestore-public-write": "sha256:bda1ab89f677e74ccc5ee4b914173fd2e8fb6c1decfaa10c8e4de4d2a08ee4e3",
  "ai:firebase-storage-public-write": "sha256:c6fb9ed52de8f3d7a4083319f9a55080be354dd3857e66f9455080875a6059ee",
  "ai:firebase-realtime-database-public-write": "sha256:afd70f134a2a1acddac482a26289251c25b2a51aeab4ed88b75bdb8500fd3098",
};

const GITHUB_ACTIONS_RULES = [
  {
    file: ".github/workflows/pwn.yml",
    line: 11,
    id: "ci-github-actions-pwn-request",
    severity: "critical",
    cwe: ["CWE-94", "CWE-829"],
    owaspWeb: ["A03:2021", "A08:2021"],
    component: "ai:github-actions-pwn-request",
  },
  {
    file: ".github/workflows/expression.yml",
    line: 10,
    id: "ci-github-actions-untrusted-expression-command",
    severity: "high",
    cwe: ["CWE-78", "CWE-94"],
    owaspWeb: ["A03:2021"],
    component: "ai:github-actions-expression-injection",
  },
] as const;

const GITHUB_ACTIONS_PACK_LIMITATIONS = [
  "Detects two exact GitHub Actions workflow risks: attacker-controlled GitHub context expressions embedded directly in run scripts, and pull_request_target workflows that check out and execute untrusted pull request code.",
  "Expression injection covers a documented static set of issue, pull request, comment, review, page, commit, email, name, and head-ref properties; bracket notation, aliases, custom actions, generated scripts, and inter-step dataflow are outside this pack.",
  "Pwn-request analysis requires pull_request_target, a recognized untrusted actions/checkout ref, checkout v1-v6 or explicit allow-unsafe-pr-checkout, the default workspace, and a subsequent recognized build/test/script command or local action.",
  "workflow_run, issue_comment code fetches, downloaded artifacts, non-checkout git/gh fetches, non-default checkout paths, self-hosted runner isolation, deployed repository settings, organization policy, and complete CI/CD security coverage are outside this pack.",
  "Only direct .github/workflows/*.yml and *.yaml files are parsed as strict YAML 1.2; malformed, unsupported, unreadable, symbolic-link, or oversized workflows fail closed and are reported in pack coverage.",
  "Workflow reads are bounded to 1 MiB per file, 512 files, and 16 MiB total; target actions, expressions, scripts, and repository code are never evaluated or executed.",
] as const;

const GITHUB_ACTIONS_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:github-actions:dispatch": "sha256:4c6d22343e56aed91e1e60bf8bed705215611289ee544be2469f955eacfa2277",
  "github-actions:yaml-workflow-parser": "sha256:0dd39cf27e0ea7e5a74307c358d5331277c0487b37ffb1c3a4a7c1688f979508",
  "ai:github-actions-expression-injection": "sha256:9ce6f791745bca7b121eb230a1fb5953348b3bcf94b933286ed5a7820dc0bcbc",
  "ai:github-actions-pwn-request": "sha256:b9edf2d17656fe46595ed64e77e978e69c6fc9901ed0146ed9c7050c92e4f15e",
};

// ── Minimal MCP stdio client ────────────────────────────────────────────────
class McpClient {
  private child: ChildProcessWithoutNullStreams;
  private buf = "";
  private pending = new Map<number, (v: any) => void>();
  private nextId = 1;

  constructor(envOverrides: NodeJS.ProcessEnv = {}, entry = "dist/index.js") {
    this.child = spawn("node", [entry], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, CODEINSPECTUS_INTERNAL_DISABLE_SCAN_PERSISTENCE: "1", CODEINSPECTUS_INTERNAL_DISABLE_TRIAGE_PERSISTENCE: "1", ...envOverrides },
    });
    this.child.stdout.on("data", (d) => this.onData(d.toString()));
    this.child.stderr.on("data", () => {});
  }
  private onData(s: string) {
    this.buf += s;
    let i;
    while ((i = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, i).trim();
      this.buf = this.buf.slice(i + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id && this.pending.has(msg.id)) {
          this.pending.get(msg.id)!(msg);
          this.pending.delete(msg.id);
        }
      } catch {
        throw new Error(`STDOUT POLLUTION (not JSON-RPC): ${line}`);
      }
    }
  }
  private send(method: string, params: unknown, id?: number) {
    this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...(id ? { id } : {}), method, params }) + "\n");
  }
  private request(method: string, params: unknown, timeoutMs = 120000): Promise<any> {
    const id = this.nextId++;
    return new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error(`timeout: ${method}`)), timeoutMs);
      this.pending.set(id, (v) => {
        clearTimeout(t);
        res(v);
      });
      this.send(method, params, id);
    });
  }
  async init() {
    await this.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "ci-evals", version: "1.0.0" },
    });
    this.send("notifications/initialized", {});
  }
  async callTool(name: string, args: Record<string, unknown>): Promise<any> {
    const r = await this.request("tools/call", { name, arguments: args });
    if (r.error) throw new Error(`tool ${name} error: ${JSON.stringify(r.error)}`);
    return r.result;
  }
  close() {
    this.child.kill();
  }
}

// ── Eval framework ──────────────────────────────────────────────────────────
type Status = "pass" | "fail" | "skip";
interface EvalResult {
  id: string;
  status: Status;
  detail: string;
}
const results: EvalResult[] = [];
function record(id: string, status: Status, detail: string) {
  results.push({ id, status, detail });
}
function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

function assertExactJson(actual: unknown, expected: unknown, message: string): void {
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
  );
}

function assertFlutterExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  assert(technologies.has("dart"), `${label}: Dart technology detection missing`);
  assert(technologies.has("flutter"), `${label}: Flutter framework detection missing`);

  const flutter = result.pack_coverage?.find((pack: any) => pack.pack_id === "flutter");
  assert(flutter?.state === "ran", `${label}: Flutter pack did not report ran`);
  assert(
    flutter.analyzers.registered === 6 && flutter.analyzers.ran === 6,
    `${label}: Flutter analyzer coverage was not 6/6`,
  );
  assert(
    flutter.rules.registered === 6 && flutter.rules.ran === 6,
    `${label}: Flutter rule coverage was not 6/6`,
  );
  assertExactJson(
    flutter.limitations,
    FLUTTER_PACK_LIMITATIONS,
    `${label}: Flutter limitations changed`,
  );
  assert(flutter.note === undefined, `${label}: unexpected Flutter execution limitation: ${flutter.note}`);

  const javascript = result.pack_coverage?.find(
    (pack: any) => pack.pack_id === "javascript-typescript",
  );
  assert(javascript?.state === "ran", `${label}: JavaScript/TypeScript pack did not report ran`);
  assert(
    javascript.analyzers.registered === 12 && javascript.analyzers.ran === 12,
    `${label}: JavaScript/TypeScript analyzer coverage was not 12/12`,
  );
  assert(
    javascript.rules.registered === 29 && javascript.rules.ran === 29,
    `${label}: JavaScript/TypeScript rule coverage was not 29/29`,
  );

  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter(
    (engine: any) => engine.engine === "codeinspectus-ai",
  );
  assert(aiEngines.length === 1, `${label}: expected exactly one AI engine run record`);
  assert(
    aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected codeinspectus-ai@5.20.0 to run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertExactFlutterRuleIds(findings: any[], label: string): void {
  assert(findings.length === FLUTTER_RULES.length, `${label}: expected six Flutter findings, got ${findings.length}`);
  const actual = findings.map((finding) => finding.rule_id).sort();
  const expected = FLUTTER_RULES.map((rule) => rule.id).sort();
  assertExactJson(actual, expected, `${label}: Flutter rule IDs changed`);
}

function assertFlutterTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertExactFlutterRuleIds(findings, label);
  assert(
    result.summary?.total === 6 &&
      result.summary.critical === 1 &&
      result.summary.high === 2 &&
      result.summary.medium === 3 &&
      result.summary.low === 0 &&
      result.summary.info === 0,
    `${label}: expected severity totals 1 critical / 2 high / 3 medium`,
  );

  for (const expected of FLUTTER_RULES) {
    const matches = findings.filter((finding) =>
      finding.location?.file === expected.file && finding.rule_id === expected.id
    );
    assert(matches.length === 1, `${label}: expected exactly one ${expected.id} at ${expected.file}`);
    const finding = matches[0];
    assert(finding.severity === expected.severity, `${label}: ${expected.id} severity changed`);
    assertExactJson(finding.cwe, expected.cwe, `${label}: ${expected.id} CWE mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: ${expected.id} engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: ${expected.id} producer engines changed`);
    assert(finding.finding_kind === "ai", `${label}: ${expected.id} finding kind changed`);
    assert(finding.confidence === "high", `${label}: ${expected.id} confidence changed`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: ${expected.id} remediation is incomplete`,
    );

    const components = [
      "codeinspectus:pipeline",
      "pack:flutter:dispatch",
      "flutter:dart-structural-parser",
      expected.component,
    ];
    assertExactJson(
      finding.producer_components,
      components,
      `${label}: ${expected.id} producer components changed`,
    );
    for (const component of components) {
      assert(
        result.component_signatures?.[component] === FLUTTER_COMPONENT_SIGNATURES[component],
        `${label}: ${component} signature changed or is missing`,
      );
    }
  }

  const flutterSignatureKeys = Object.keys(result.component_signatures ?? {})
    .filter((component) =>
      component === "pack:flutter:dispatch" ||
      component === "flutter:dart-structural-parser" ||
      component.startsWith("ai:flutter-")
    )
    .sort();
  const expectedFlutterSignatureKeys = Object.keys(FLUTTER_COMPONENT_SIGNATURES)
    .filter((component) => component !== "codeinspectus:pipeline")
    .sort();
  assertExactJson(
    flutterSignatureKeys,
    expectedFlutterSignatureKeys,
    `${label}: Flutter component-signature inventory changed`,
  );
  assert(
    !JSON.stringify(result).includes(FLUTTER_REDACTION_SENTINEL),
    `${label}: planted Flutter redaction sentinel leaked in the MCP response`,
  );
}

function mobilePackLimitations(platform: "android" | "ios"): readonly string[] {
  return platform === "android" ? ANDROID_PACK_LIMITATIONS : IOS_PACK_LIMITATIONS;
}

function mobilePackComponents(platform: "android" | "ios", component: string): string[] {
  return [
    "codeinspectus:pipeline",
    `pack:${platform}:dispatch`,
    platform === "android" ? "android:xml-config-parser" : "ios:xml-plist-parser",
    component,
  ];
}

function assertMobileExecutionEnvelope(
  result: any,
  platform: "android" | "ios",
  label: string,
  expectEngineDetails = true,
): void {
  assert(
    (result.detected_technologies ?? []).some((technology: any) => technology.id === platform),
    `${label}: ${platform} technology detection missing`,
  );
  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === platform);
  assert(pack?.state === "ran", `${label}: ${platform} pack did not report ran`);
  assert(
    pack.analyzers.registered === 1 && pack.analyzers.ran === 1,
    `${label}: ${platform} analyzer coverage was not 1/1`,
  );
  assert(
    pack.rules.registered === 4 && pack.rules.ran === 4,
    `${label}: ${platform} rule coverage was not 4/4`,
  );
  assertExactJson(pack.platforms, [platform], `${label}: ${platform} platform metadata changed`);
  assertExactJson(
    pack.limitations,
    mobilePackLimitations(platform),
    `${label}: ${platform} limitations changed`,
  );
  assert(pack.note === undefined, `${label}: unexpected ${platform} execution limitation: ${pack.note}`);
  const javascript = result.pack_coverage?.find(
    (candidate: any) => candidate.pack_id === "javascript-typescript",
  );
  assert(
    javascript?.state === "ran" &&
      javascript.analyzers.ran === 12 &&
      javascript.rules.ran === 29,
    `${label}: unconditional JavaScript/TypeScript pack coverage changed`,
  );
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter(
    (engine: any) => engine.engine === "codeinspectus-ai",
  );
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertMobileTpScan(
  result: any,
  platform: "android" | "ios",
  label: string,
  pathPrefix = "",
  allowAdditionalFindings = false,
): void {
  const expectedRules = MOBILE_CONFIG_RULES.filter((rule) => rule.pack === platform);
  const allFindings: any[] = result.findings ?? [];
  const expectedIds = new Set(expectedRules.map((rule) => rule.id));
  const findings = allFindings.filter((finding) => expectedIds.has(finding.rule_id));
  assert(findings.length === 4, `${label}: expected four findings, got ${findings.length}`);
  if (!allowAdditionalFindings) {
    assert(allFindings.length === 4, `${label}: unexpected non-${platform} findings were present`);
  }
  assertExactJson(
    findings.map((finding) => finding.rule_id).sort(),
    expectedRules.map((rule) => rule.id).sort(),
    `${label}: rule IDs changed`,
  );
  const expectedHigh = platform === "android" ? 1 : 0;
  const severityCount = (severity: string) =>
    findings.filter((finding) => finding.severity === severity).length;
  assert(
    severityCount("high") === expectedHigh &&
      severityCount("medium") === 4 - expectedHigh &&
      severityCount("critical") === 0 &&
      severityCount("low") === 0 &&
      severityCount("info") === 0,
    `${label}: severity summary changed`,
  );
  for (const expected of expectedRules) {
    const file = `${pathPrefix}${expected.file}`;
    const matches = findings.filter((finding) =>
      finding.rule_id === expected.id && finding.location?.file === file
    );
    assert(matches.length === 1, `${label}: expected exactly one ${expected.id} at ${file}`);
    const finding = matches[0];
    assert(finding.severity === expected.severity, `${label}: ${expected.id} severity changed`);
    assertExactJson(finding.cwe, expected.cwe, `${label}: ${expected.id} CWE mapping changed`);
    assert(finding.confidence === "high", `${label}: ${expected.id} confidence changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: ${expected.id} engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: ${expected.id} engines changed`);
    assert(finding.finding_kind === "ai", `${label}: ${expected.id} finding kind changed`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: ${expected.id} remediation is incomplete`,
    );
    const components = mobilePackComponents(platform, expected.component);
    assertExactJson(
      finding.producer_components,
      components,
      `${label}: ${expected.id} producer components changed`,
    );
    for (const component of components) {
      assert(
        result.component_signatures?.[component] === MOBILE_COMPONENT_SIGNATURES[component],
        `${label}: ${component} signature changed or is missing`,
      );
    }
  }
  assert(
    !JSON.stringify(result).includes("CI_IOS_REDACTION_SENTINEL"),
    `${label}: planted iOS redaction sentinel leaked in the MCP response`,
  );
}

function reactNativeExpoPackLimitations(packId: "react-native" | "expo"): readonly string[] {
  return packId === "react-native" ? REACT_NATIVE_PACK_LIMITATIONS : EXPO_PACK_LIMITATIONS;
}

function reactNativeExpoComponents(
  packId: "react-native" | "expo",
  component: string,
): string[] {
  return [
    "codeinspectus:pipeline",
    `pack:${packId}:dispatch`,
    packId === "react-native"
      ? "react-native:javascript-structural-parser"
      : "expo:static-config-parser",
    component,
  ];
}

function assertReactNativeExpoExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  for (const technology of ["typescript", "react-native", "expo"]) {
    assert(technologies.has(technology), `${label}: ${technology} technology detection missing`);
  }

  for (const [packId, analyzerCount, ruleCount] of [
    ["react-native", 4, 4],
    ["expo", 2, 2],
  ] as const) {
    const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(pack?.state === "ran", `${label}: ${packId} pack did not report ran`);
    assert(
      pack.analyzers.registered === analyzerCount && pack.analyzers.ran === analyzerCount,
      `${label}: ${packId} analyzer coverage was not ${analyzerCount}/${analyzerCount}`,
    );
    assert(
      pack.rules.registered === ruleCount && pack.rules.ran === ruleCount,
      `${label}: ${packId} rule coverage was not ${ruleCount}/${ruleCount}`,
    );
    assertExactJson(pack.frameworks, [packId], `${label}: ${packId} framework metadata changed`);
    assertExactJson(
      pack.limitations,
      reactNativeExpoPackLimitations(packId),
      `${label}: ${packId} limitations changed`,
    );
    assert(pack.note === undefined, `${label}: unexpected ${packId} execution limitation: ${pack.note}`);
  }

  const javascript = result.pack_coverage?.find(
    (candidate: any) => candidate.pack_id === "javascript-typescript",
  );
  assert(
    javascript?.state === "ran" &&
      javascript.analyzers.ran === 12 &&
      javascript.rules.ran === 29,
    `${label}: JavaScript/TypeScript pack coverage changed`,
  );
  for (const packId of ["flutter", "android", "ios"]) {
    const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(pack?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }

  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter(
    (engine: any) => engine.engine === "codeinspectus-ai",
  );
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertExactReactNativeExpoRuleIds(findings: any[], label: string): void {
  assert(
    findings.length === REACT_NATIVE_EXPO_RULES.length,
    `${label}: expected six React Native/Expo findings, got ${findings.length}`,
  );
  assertExactJson(
    findings.map((finding) => finding.rule_id).sort(),
    REACT_NATIVE_EXPO_RULES.map((rule) => rule.id).sort(),
    `${label}: React Native/Expo rule IDs changed`,
  );
}

function assertReactNativeExpoTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertExactReactNativeExpoRuleIds(findings, label);
  assert(
    result.summary?.total === 6 &&
      result.summary.critical === 0 &&
      result.summary.high === 4 &&
      result.summary.medium === 2 &&
      result.summary.low === 0 &&
      result.summary.info === 0,
    `${label}: expected severity totals 4 high / 2 medium`,
  );

  for (const expected of REACT_NATIVE_EXPO_RULES) {
    const matches = findings.filter((finding) =>
      finding.location?.file === expected.file && finding.rule_id === expected.id
    );
    assert(matches.length === 1, `${label}: expected exactly one ${expected.id} at ${expected.file}`);
    const finding = matches[0];
    assert(finding.severity === expected.severity, `${label}: ${expected.id} severity changed`);
    assertExactJson(finding.cwe, expected.cwe, `${label}: ${expected.id} CWE mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: ${expected.id} engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: ${expected.id} engines changed`);
    assert(
      finding.finding_kind === expected.kind,
      `${label}: ${expected.id} finding kind changed`,
    );
    assert(finding.confidence === "high", `${label}: ${expected.id} confidence changed`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: ${expected.id} remediation is incomplete`,
    );

    const components = reactNativeExpoComponents(expected.pack, expected.component);
    assertExactJson(
      finding.producer_components,
      components,
      `${label}: ${expected.id} producer components changed`,
    );
    for (const component of components) {
      assert(
        result.component_signatures?.[component] === REACT_NATIVE_EXPO_COMPONENT_SIGNATURES[component],
        `${label}: ${component} signature changed or is missing`,
      );
    }
  }

  const signatureKeys = Object.keys(result.component_signatures ?? {})
    .filter((component) =>
      component === "pack:react-native:dispatch" ||
      component === "react-native:javascript-structural-parser" ||
      component === "pack:expo:dispatch" ||
      component === "expo:static-config-parser" ||
      component.startsWith("ai:react-native-") ||
      component.startsWith("ai:expo-")
    )
    .sort();
  const expectedSignatureKeys = Object.keys(REACT_NATIVE_EXPO_COMPONENT_SIGNATURES)
    .filter((component) => component !== "codeinspectus:pipeline")
    .sort();
  assertExactJson(
    signatureKeys,
    expectedSignatureKeys,
    `${label}: React Native/Expo component-signature inventory changed`,
  );
  assert(
    !JSON.stringify(result).includes(REACT_NATIVE_EXPO_REDACTION_SENTINEL),
    `${label}: planted React Native/Expo redaction sentinel leaked in the MCP response`,
  );
}

function assertPythonAiApiExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  for (const technology of [
    "python", "fastapi", "starlette", "flask", "django", "jinja2", "openai", "anthropic", "langchain",
  ]) assert(technologies.has(technology), `${label}: ${technology} technology detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "python-ai-api");
  assert(pack?.state === "ran", `${label}: Python AI/API pack did not report ran`);
  assert(
    pack.analyzers.registered === 10 && pack.analyzers.ran === 10,
    `${label}: Python AI/API analyzer coverage was not 10/10`,
  );
  assert(
    pack.rules.registered === 10 && pack.rules.ran === 10,
    `${label}: Python AI/API rule coverage was not 10/10`,
  );
  assertExactJson(pack.languages, ["python"], `${label}: Python language metadata changed`);
  assertExactJson(pack.limitations, PYTHON_AI_API_PACK_LIMITATIONS, `${label}: Python limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected Python execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter(
    (engine: any) => engine.engine === "codeinspectus-ai",
  );
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertExactPythonAiApiRuleIds(findings: any[], label: string): void {
  assert(findings.length === 10, `${label}: expected ten Python AI/API findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id).sort(),
    PYTHON_AI_API_RULES.map((rule) => rule.id).sort(),
    `${label}: Python AI/API rule IDs changed`,
  );
}

function assertPythonAiApiTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertExactPythonAiApiRuleIds(findings, label);
  assert(
    result.summary?.total === 10 && result.summary.high === 9 && result.summary.medium === 1 &&
      result.summary.critical === 0 && result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 9 high / 1 medium`,
  );
  for (const expected of PYTHON_AI_API_RULES) {
    const matches = findings.filter((finding) =>
      finding.location?.file === expected.file && finding.rule_id === expected.id
    );
    assert(matches.length === 1, `${label}: expected exactly one ${expected.id} at ${expected.file}`);
    const finding = matches[0];
    assert(finding.severity === expected.severity, `${label}: ${expected.id} severity changed`);
    assertExactJson(finding.cwe, expected.cwe, `${label}: ${expected.id} CWE mapping changed`);
    assert(finding.finding_kind === expected.kind, `${label}: ${expected.id} finding kind changed`);
    assert(finding.confidence === expected.confidence, `${label}: ${expected.id} confidence changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: ${expected.id} engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: ${expected.id} engines changed`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: ${expected.id} remediation is incomplete`,
    );
    const components = [
      "codeinspectus:pipeline",
      "pack:python-ai-api:dispatch",
      "python:lezer-structural-parser",
      expected.component,
    ];
    assertExactJson(finding.producer_components, components, `${label}: ${expected.id} components changed`);
    for (const component of components) {
      assert(
        result.component_signatures?.[component] === PYTHON_AI_API_COMPONENT_SIGNATURES[component],
        `${label}: ${component} signature changed or is missing`,
      );
    }
  }
  const secret = findings.find((finding) => finding.rule_id === "ci-python-hardcoded-signing-secret");
  assert(secret?.is_secret === true && /^sha256:[a-f0-9]{64}$/.test(secret.secret_value_hash ?? ""), `${label}: signing-secret redaction metadata missing`);
  assert(!findings.some((finding) => /(?:^|\/)(?:tests|examples)\//.test(finding.location?.file ?? "")), `${label}: excluded corpus content produced a finding`);
  assert(!JSON.stringify(result).includes(PYTHON_REDACTION_SENTINEL), `${label}: Python redaction sentinel leaked`);
}

function assertGoAiExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  assert(technologies.has("go"), `${label}: Go technology detection missing`);
  assert(technologies.has("openai"), `${label}: OpenAI framework detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "go-ai");
  assert(pack?.state === "ran", `${label}: Go AI pack did not report ran`);
  assert(
    pack.analyzers.registered === 1 && pack.analyzers.ran === 1,
    `${label}: Go AI analyzer coverage was not 1/1`,
  );
  assert(
    pack.rules.registered === 1 && pack.rules.ran === 1,
    `${label}: Go AI rule coverage was not 1/1`,
  );
  assertExactJson(pack.languages, ["go"], `${label}: Go language metadata changed`);
  assertExactJson(pack.frameworks, ["openai"], `${label}: Go framework metadata changed`);
  assertExactJson(pack.limitations, GO_AI_PACK_LIMITATIONS, `${label}: Go limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected Go execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo", "python-ai-api"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter(
    (engine: any) => engine.engine === "codeinspectus-ai",
  );
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertGoAiFindings(findings: any[], label: string): void {
  assert(findings.length === 3, `${label}: expected three Go AI findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id),
    [GO_AI_RULE.id, GO_AI_RULE.id, GO_AI_RULE.id],
    `${label}: Go AI rule IDs changed`,
  );
  assertExactJson(
    findings.map((finding) => finding.location?.start_line),
    [22, 36, 50],
    `${label}: Go AI source identities changed`,
  );
  for (const finding of findings) {
    assert(finding.location?.file === GO_AI_RULE.file, `${label}: Go AI file changed`);
    assert(finding.severity === GO_AI_RULE.severity, `${label}: Go AI severity changed`);
    assert(finding.finding_kind === GO_AI_RULE.kind, `${label}: Go AI finding kind changed`);
    assert(finding.confidence === GO_AI_RULE.confidence, `${label}: Go AI confidence changed`);
    assertExactJson(finding.cwe, GO_AI_RULE.cwe, `${label}: Go AI CWE mapping changed`);
    assertExactJson(finding.owasp_llm, GO_AI_RULE.owaspLlm, `${label}: Go AI OWASP LLM mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: Go AI engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: Go AI engines changed`);
    assert(
      finding.location?.snippet?.includes("[VALUE REDACTED]"),
      `${label}: Go AI source value was not redacted`,
    );
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: Go AI remediation is incomplete`,
    );
    const components = [
      "codeinspectus:pipeline",
      "pack:go-ai:dispatch",
      "go:bounded-structural-parser",
      GO_AI_RULE.component,
    ];
    assertExactJson(finding.producer_components, components, `${label}: Go AI components changed`);
  }
}

function assertGoAiTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertGoAiFindings(findings, label);
  assert(
    result.summary?.total === 3 && result.summary.high === 3 &&
      result.summary.critical === 0 && result.summary.medium === 0 &&
      result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 3 high`,
  );
  for (const [component, signature] of Object.entries(GO_AI_COMPONENT_SIGNATURES)) {
    assert(
      result.component_signatures?.[component] === signature,
      `${label}: ${component} signature changed or is missing`,
    );
  }
}

function assertJavaAiExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  assert(technologies.has("java"), `${label}: Java technology detection missing`);
  assert(technologies.has("openai"), `${label}: OpenAI framework detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "java-ai");
  assert(pack?.state === "ran", `${label}: Java AI pack did not report ran`);
  assert(
    pack.analyzers.registered === 1 && pack.analyzers.ran === 1,
    `${label}: Java AI analyzer coverage was not 1/1`,
  );
  assert(
    pack.rules.registered === 1 && pack.rules.ran === 1,
    `${label}: Java AI rule coverage was not 1/1`,
  );
  assertExactJson(pack.languages, ["java"], `${label}: Java language metadata changed`);
  assertExactJson(pack.frameworks, ["openai"], `${label}: Java framework metadata changed`);
  assertExactJson(pack.limitations, JAVA_AI_PACK_LIMITATIONS, `${label}: Java limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected Java execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo", "python-ai-api", "go-ai"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter(
    (engine: any) => engine.engine === "codeinspectus-ai",
  );
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertJavaAiFindings(findings: any[], label: string): void {
  assert(findings.length === 3, `${label}: expected three Java AI findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id),
    [JAVA_AI_RULE.id, JAVA_AI_RULE.id, JAVA_AI_RULE.id],
    `${label}: Java AI rule IDs changed`,
  );
  assertExactJson(
    findings.map((finding) => finding.location?.start_line),
    [12, 17, 23],
    `${label}: Java AI source identities changed`,
  );
  for (const finding of findings) {
    assert(finding.location?.file === JAVA_AI_RULE.file, `${label}: Java AI file changed`);
    assert(finding.severity === JAVA_AI_RULE.severity, `${label}: Java AI severity changed`);
    assert(finding.finding_kind === JAVA_AI_RULE.kind, `${label}: Java AI finding kind changed`);
    assert(finding.confidence === JAVA_AI_RULE.confidence, `${label}: Java AI confidence changed`);
    assertExactJson(finding.cwe, JAVA_AI_RULE.cwe, `${label}: Java AI CWE mapping changed`);
    assertExactJson(finding.owasp_llm, JAVA_AI_RULE.owaspLlm, `${label}: Java AI OWASP LLM mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: Java AI engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: Java AI engines changed`);
    assert(
      finding.location?.snippet?.includes("[VALUE REDACTED]"),
      `${label}: Java AI source value was not redacted`,
    );
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: Java AI remediation is incomplete`,
    );
    const components = [
      "codeinspectus:pipeline",
      "pack:java-ai:dispatch",
      "java:bounded-structural-parser",
      JAVA_AI_RULE.component,
    ];
    assertExactJson(finding.producer_components, components, `${label}: Java AI components changed`);
  }
}

function assertJavaAiTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertJavaAiFindings(findings, label);
  assert(
    result.summary?.total === 3 && result.summary.high === 3 &&
      result.summary.critical === 0 && result.summary.medium === 0 &&
      result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 3 high`,
  );
  for (const [component, signature] of Object.entries(JAVA_AI_COMPONENT_SIGNATURES)) {
    assert(
      result.component_signatures?.[component] === signature,
      `${label}: ${component} signature changed or is missing`,
    );
  }
}

function assertCsharpAiExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  assert(technologies.has("csharp"), `${label}: C# technology detection missing`);
  assert(technologies.has("openai"), `${label}: OpenAI framework detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "csharp-ai");
  assert(pack?.state === "ran", `${label}: C# AI pack did not report ran`);
  assert(pack.analyzers.registered === 1 && pack.analyzers.ran === 1, `${label}: C# AI analyzer coverage was not 1/1`);
  assert(pack.rules.registered === 1 && pack.rules.ran === 1, `${label}: C# AI rule coverage was not 1/1`);
  assertExactJson(pack.languages, ["csharp"], `${label}: C# language metadata changed`);
  assertExactJson(pack.frameworks, ["openai"], `${label}: C# framework metadata changed`);
  assertExactJson(pack.limitations, CSHARP_AI_PACK_LIMITATIONS, `${label}: C# limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected C# execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo", "python-ai-api", "go-ai", "java-ai"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter((engine: any) => engine.engine === "codeinspectus-ai");
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertCsharpAiFindings(findings: any[], label: string): void {
  assert(findings.length === 3, `${label}: expected three C# AI findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id),
    [CSHARP_AI_RULE.id, CSHARP_AI_RULE.id, CSHARP_AI_RULE.id],
    `${label}: C# AI rule IDs changed`,
  );
  assertExactJson(
    findings.map((finding) => finding.location?.start_line),
    [9, 12, 25],
    `${label}: C# AI source identities changed`,
  );
  for (const finding of findings) {
    assert(finding.location?.file === CSHARP_AI_RULE.file, `${label}: C# AI file changed`);
    assert(finding.severity === CSHARP_AI_RULE.severity, `${label}: C# AI severity changed`);
    assert(finding.finding_kind === CSHARP_AI_RULE.kind, `${label}: C# AI finding kind changed`);
    assert(finding.confidence === CSHARP_AI_RULE.confidence, `${label}: C# AI confidence changed`);
    assertExactJson(finding.cwe, CSHARP_AI_RULE.cwe, `${label}: C# AI CWE mapping changed`);
    assertExactJson(finding.owasp_llm, CSHARP_AI_RULE.owaspLlm, `${label}: C# AI OWASP LLM mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: C# AI engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: C# AI engines changed`);
    assert(finding.location?.snippet?.includes("[VALUE REDACTED]"), `${label}: C# AI source value was not redacted`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: C# AI remediation is incomplete`,
    );
    const components = [
      "codeinspectus:pipeline",
      "pack:csharp-ai:dispatch",
      "csharp:bounded-structural-parser",
      CSHARP_AI_RULE.component,
    ];
    assertExactJson(finding.producer_components, components, `${label}: C# AI components changed`);
  }
}

function assertCsharpAiTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertCsharpAiFindings(findings, label);
  assert(
    result.summary?.total === 3 && result.summary.high === 3 &&
      result.summary.critical === 0 && result.summary.medium === 0 &&
      result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 3 high`,
  );
  for (const [component, signature] of Object.entries(CSHARP_AI_COMPONENT_SIGNATURES)) {
    assert(result.component_signatures?.[component] === signature, `${label}: ${component} signature changed or is missing`);
  }
}

function assertPhpAiExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  assert(technologies.has("php"), `${label}: PHP technology detection missing`);
  assert(technologies.has("openai"), `${label}: OpenAI framework detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "php-ai");
  assert(pack?.state === "ran", `${label}: PHP AI pack did not report ran`);
  assert(pack.analyzers.registered === 1 && pack.analyzers.ran === 1, `${label}: PHP AI analyzer coverage was not 1/1`);
  assert(pack.rules.registered === 1 && pack.rules.ran === 1, `${label}: PHP AI rule coverage was not 1/1`);
  assertExactJson(pack.languages, ["php"], `${label}: PHP language metadata changed`);
  assertExactJson(pack.frameworks, ["openai"], `${label}: PHP framework metadata changed`);
  assertExactJson(pack.limitations, PHP_AI_PACK_LIMITATIONS, `${label}: PHP limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected PHP execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo", "python-ai-api", "go-ai", "java-ai", "csharp-ai"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter((engine: any) => engine.engine === "codeinspectus-ai");
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertPhpAiFindings(findings: any[], label: string): void {
  assert(findings.length === 3, `${label}: expected three PHP AI findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id),
    [PHP_AI_RULE.id, PHP_AI_RULE.id, PHP_AI_RULE.id],
    `${label}: PHP AI rule IDs changed`,
  );
  assertExactJson(
    findings.map((finding) => finding.location?.start_line),
    [7, 19, 42],
    `${label}: PHP AI source identities changed`,
  );
  for (const finding of findings) {
    assert(finding.location?.file === PHP_AI_RULE.file, `${label}: PHP AI file changed`);
    assert(finding.severity === PHP_AI_RULE.severity, `${label}: PHP AI severity changed`);
    assert(finding.finding_kind === PHP_AI_RULE.kind, `${label}: PHP AI finding kind changed`);
    assert(finding.confidence === PHP_AI_RULE.confidence, `${label}: PHP AI confidence changed`);
    assertExactJson(finding.cwe, PHP_AI_RULE.cwe, `${label}: PHP AI CWE mapping changed`);
    assertExactJson(finding.owasp_llm, PHP_AI_RULE.owaspLlm, `${label}: PHP AI OWASP LLM mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: PHP AI engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: PHP AI engines changed`);
    assert(finding.location?.snippet?.includes("[VALUE REDACTED]"), `${label}: PHP AI source value was not redacted`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: PHP AI remediation is incomplete`,
    );
    const components = [
      "codeinspectus:pipeline",
      "pack:php-ai:dispatch",
      "php:bounded-structural-parser",
      PHP_AI_RULE.component,
    ];
    assertExactJson(finding.producer_components, components, `${label}: PHP AI components changed`);
  }
}

function assertPhpAiTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertPhpAiFindings(findings, label);
  assert(
    result.summary?.total === 3 && result.summary.high === 3 &&
      result.summary.critical === 0 && result.summary.medium === 0 &&
      result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 3 high`,
  );
  for (const [component, signature] of Object.entries(PHP_AI_COMPONENT_SIGNATURES)) {
    assert(result.component_signatures?.[component] === signature, `${label}: ${component} signature changed or is missing`);
  }
}

function assertRustAiExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  assert(technologies.has("rust"), `${label}: Rust technology detection missing`);
  assert(technologies.has("openai"), `${label}: OpenAI framework detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "rust-ai");
  assert(pack?.state === "ran", `${label}: Rust AI pack did not report ran`);
  assert(pack.analyzers.registered === 1 && pack.analyzers.ran === 1, `${label}: Rust AI analyzer coverage was not 1/1`);
  assert(pack.rules.registered === 1 && pack.rules.ran === 1, `${label}: Rust AI rule coverage was not 1/1`);
  assertExactJson(pack.languages, ["rust"], `${label}: Rust language metadata changed`);
  assertExactJson(pack.frameworks, ["openai"], `${label}: Rust framework metadata changed`);
  assertExactJson(pack.limitations, RUST_AI_PACK_LIMITATIONS, `${label}: Rust limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected Rust execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo", "python-ai-api", "go-ai", "java-ai", "csharp-ai", "php-ai"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter((engine: any) => engine.engine === "codeinspectus-ai");
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertRustAiFindings(findings: any[], label: string): void {
  assert(findings.length === 3, `${label}: expected three Rust AI findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id),
    [RUST_AI_RULE.id, RUST_AI_RULE.id, RUST_AI_RULE.id],
    `${label}: Rust AI rule IDs changed`,
  );
  assertExactJson(
    findings.map((finding) => finding.location?.start_line),
    [8, 12, 25],
    `${label}: Rust AI source identities changed`,
  );
  for (const finding of findings) {
    assert(finding.location?.file === RUST_AI_RULE.file, `${label}: Rust AI file changed`);
    assert(finding.severity === RUST_AI_RULE.severity, `${label}: Rust AI severity changed`);
    assert(finding.finding_kind === RUST_AI_RULE.kind, `${label}: Rust AI finding kind changed`);
    assert(finding.confidence === RUST_AI_RULE.confidence, `${label}: Rust AI confidence changed`);
    assertExactJson(finding.cwe, RUST_AI_RULE.cwe, `${label}: Rust AI CWE mapping changed`);
    assertExactJson(finding.owasp_llm, RUST_AI_RULE.owaspLlm, `${label}: Rust AI OWASP LLM mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: Rust AI engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: Rust AI engines changed`);
    assert(finding.location?.snippet?.includes("[VALUE REDACTED]"), `${label}: Rust AI source value was not redacted`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: Rust AI remediation is incomplete`,
    );
    const components = [
      "codeinspectus:pipeline",
      "pack:rust-ai:dispatch",
      "rust:bounded-structural-parser",
      RUST_AI_RULE.component,
    ];
    assertExactJson(finding.producer_components, components, `${label}: Rust AI components changed`);
  }
}

function assertRustAiTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertRustAiFindings(findings, label);
  assert(
    result.summary?.total === 3 && result.summary.high === 3 &&
      result.summary.critical === 0 && result.summary.medium === 0 &&
      result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 3 high`,
  );
  for (const [component, signature] of Object.entries(RUST_AI_COMPONENT_SIGNATURES)) {
    assert(result.component_signatures?.[component] === signature, `${label}: ${component} signature changed or is missing`);
  }
}

function assertRubyAiExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  assert(technologies.has("ruby"), `${label}: Ruby technology detection missing`);
  assert(technologies.has("openai"), `${label}: OpenAI framework detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "ruby-ai");
  assert(pack?.state === "ran", `${label}: Ruby AI pack did not report ran`);
  assert(pack.analyzers.registered === 1 && pack.analyzers.ran === 1, `${label}: Ruby AI analyzer coverage was not 1/1`);
  assert(pack.rules.registered === 1 && pack.rules.ran === 1, `${label}: Ruby AI rule coverage was not 1/1`);
  assertExactJson(pack.languages, ["ruby"], `${label}: Ruby language metadata changed`);
  assertExactJson(pack.frameworks, ["openai"], `${label}: Ruby framework metadata changed`);
  assertExactJson(pack.limitations, RUBY_AI_PACK_LIMITATIONS, `${label}: Ruby limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected Ruby execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo", "python-ai-api", "go-ai", "java-ai", "csharp-ai", "php-ai", "rust-ai"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter((engine: any) => engine.engine === "codeinspectus-ai");
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertRubyAiFindings(findings: any[], label: string): void {
  assert(findings.length === 3, `${label}: expected three Ruby AI findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id),
    [RUBY_AI_RULE.id, RUBY_AI_RULE.id, RUBY_AI_RULE.id],
    `${label}: Ruby AI rule IDs changed`,
  );
  assertExactJson(
    findings.map((finding) => finding.location?.start_line),
    [8, 12, 30],
    `${label}: Ruby AI source identities changed`,
  );
  for (const finding of findings) {
    assert(finding.location?.file === RUBY_AI_RULE.file, `${label}: Ruby AI file changed`);
    assert(finding.severity === RUBY_AI_RULE.severity, `${label}: Ruby AI severity changed`);
    assert(finding.finding_kind === RUBY_AI_RULE.kind, `${label}: Ruby AI finding kind changed`);
    assert(finding.confidence === RUBY_AI_RULE.confidence, `${label}: Ruby AI confidence changed`);
    assertExactJson(finding.cwe, RUBY_AI_RULE.cwe, `${label}: Ruby AI CWE mapping changed`);
    assertExactJson(finding.owasp_llm, RUBY_AI_RULE.owaspLlm, `${label}: Ruby AI OWASP LLM mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: Ruby AI engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: Ruby AI engines changed`);
    assert(finding.location?.snippet?.includes("[VALUE REDACTED]"), `${label}: Ruby AI source value was not redacted`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: Ruby AI remediation is incomplete`,
    );
    const components = [
      "codeinspectus:pipeline",
      "pack:ruby-ai:dispatch",
      "ruby:bounded-structural-parser",
      RUBY_AI_RULE.component,
    ];
    assertExactJson(finding.producer_components, components, `${label}: Ruby AI components changed`);
  }
}

function assertRubyAiTpScan(result: any, label: string): void {
  const findings: any[] = result.findings ?? [];
  assertRubyAiFindings(findings, label);
  assert(
    result.summary?.total === 3 && result.summary.high === 3 &&
      result.summary.critical === 0 && result.summary.medium === 0 &&
      result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 3 high`,
  );
  for (const [component, signature] of Object.entries(RUBY_AI_COMPONENT_SIGNATURES)) {
    assert(result.component_signatures?.[component] === signature, `${label}: ${component} signature changed or is missing`);
  }
}

function assertFirebaseExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technologies = new Set(
    (result.detected_technologies ?? []).map((technology: any) => technology.id),
  );
  assert(technologies.has("firebase"), `${label}: Firebase technology detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "firebase");
  assert(pack?.state === "ran", `${label}: Firebase pack did not report ran`);
  assert(pack.analyzers.registered === 1 && pack.analyzers.ran === 1, `${label}: Firebase analyzer coverage was not 1/1`);
  assert(pack.rules.registered === 3 && pack.rules.ran === 3, `${label}: Firebase rule coverage was not 3/3`);
  assertExactJson(pack.languages, ["firebase-rules", "json"], `${label}: Firebase language metadata changed`);
  assertExactJson(pack.frameworks, [], `${label}: Firebase framework metadata changed`);
  assertExactJson(pack.platforms, ["firebase"], `${label}: Firebase platform metadata changed`);
  assertExactJson(pack.limitations, FIREBASE_PACK_LIMITATIONS, `${label}: Firebase limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected Firebase execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo", "python-ai-api", "go-ai", "java-ai", "csharp-ai", "php-ai", "rust-ai", "ruby-ai"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter((engine: any) => engine.engine === "codeinspectus-ai");
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertFirebaseFindings(findings: any[], label: string): void {
  assert(findings.length === 3, `${label}: expected three Firebase findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id),
    FIREBASE_CONFIG_RULES.map((rule) => rule.id),
    `${label}: Firebase rule IDs changed`,
  );
  for (let index = 0; index < findings.length; index++) {
    const finding = findings[index];
    const expected = FIREBASE_CONFIG_RULES[index]!;
    assert(finding.location?.file === expected.file, `${label}: ${expected.id} file changed`);
    assert(finding.location?.start_line === expected.line, `${label}: ${expected.id} line changed`);
    assert(finding.severity === "critical", `${label}: ${expected.id} severity changed`);
    assert(finding.finding_kind === "ai", `${label}: ${expected.id} finding kind changed`);
    assert(finding.confidence === "high", `${label}: ${expected.id} confidence changed`);
    assertExactJson(finding.cwe, ["CWE-862", "CWE-285"], `${label}: ${expected.id} CWE mapping changed`);
    assertExactJson(finding.owasp_web, ["A01:2021"], `${label}: ${expected.id} OWASP mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: ${expected.id} engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: ${expected.id} engines changed`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: ${expected.id} remediation is incomplete`,
    );
    assertExactJson(finding.producer_components, [
      "codeinspectus:pipeline",
      "pack:firebase:dispatch",
      "firebase:bounded-rules-parser",
      expected.component,
    ], `${label}: ${expected.id} components changed`);
  }
}

function assertFirebaseTpScan(result: any, label: string): void {
  assertFirebaseFindings(result.findings ?? [], label);
  assert(
    result.summary?.total === 3 && result.summary.critical === 3 &&
      result.summary.high === 0 && result.summary.medium === 0 &&
      result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 3 critical`,
  );
  for (const [component, signature] of Object.entries(FIREBASE_COMPONENT_SIGNATURES)) {
    assert(result.component_signatures?.[component] === signature, `${label}: ${component} signature changed or is missing`);
  }
}

function assertGithubActionsExecutionEnvelope(
  result: any,
  label: string,
  expectEngineDetails = true,
): void {
  const technology = (result.detected_technologies ?? []).find(
    (candidate: any) => candidate.id === "github-actions",
  );
  assert(technology?.kind === "platform", `${label}: GitHub Actions platform detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "github-actions");
  assert(pack?.state === "ran", `${label}: GitHub Actions pack did not report ran`);
  assert(pack.analyzers.registered === 1 && pack.analyzers.ran === 1, `${label}: GitHub Actions analyzer coverage was not 1/1`);
  assert(pack.rules.registered === 2 && pack.rules.ran === 2, `${label}: GitHub Actions rule coverage was not 2/2`);
  assertExactJson(pack.languages, ["yaml"], `${label}: GitHub Actions language metadata changed`);
  assertExactJson(pack.frameworks, [], `${label}: GitHub Actions framework metadata changed`);
  assertExactJson(pack.platforms, ["github-actions"], `${label}: GitHub Actions platform metadata changed`);
  assertExactJson(pack.limitations, GITHUB_ACTIONS_PACK_LIMITATIONS, `${label}: GitHub Actions limitations changed`);
  assert(pack.note === undefined, `${label}: unexpected GitHub Actions execution limitation: ${pack.note}`);

  for (const packId of ["flutter", "android", "ios", "react-native", "expo", "python-ai-api", "go-ai", "java-ai", "csharp-ai", "php-ai", "rust-ai", "ruby-ai", "firebase"]) {
    const other = result.pack_coverage?.find((candidate: any) => candidate.pack_id === packId);
    assert(other?.state === "not_applicable", `${label}: unexpectedly activated the ${packId} pack`);
  }
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter((engine: any) => engine.engine === "codeinspectus-ai");
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.20.0",
    `${label}: expected exactly one codeinspectus-ai@5.20.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertGithubActionsFindings(findings: any[], label: string): void {
  assert(findings.length === 2, `${label}: expected two GitHub Actions findings, got ${findings.length}`);
  assertExactJson(
    findings.map((finding) => finding.rule_id),
    GITHUB_ACTIONS_RULES.map((rule) => rule.id),
    `${label}: GitHub Actions rule IDs changed`,
  );
  for (let index = 0; index < findings.length; index++) {
    const finding = findings[index];
    const expected = GITHUB_ACTIONS_RULES[index]!;
    assert(finding.location?.file === expected.file, `${label}: ${expected.id} file changed`);
    assert(finding.location?.start_line === expected.line, `${label}: ${expected.id} line changed`);
    assert(finding.severity === expected.severity, `${label}: ${expected.id} severity changed`);
    assert(finding.finding_kind === "ai", `${label}: ${expected.id} finding kind changed`);
    assert(finding.confidence === "high", `${label}: ${expected.id} confidence changed`);
    assertExactJson(finding.cwe, expected.cwe, `${label}: ${expected.id} CWE mapping changed`);
    assertExactJson(finding.owasp_web, expected.owaspWeb, `${label}: ${expected.id} OWASP mapping changed`);
    assert(finding.engine === "codeinspectus-ai", `${label}: ${expected.id} engine changed`);
    assertExactJson(finding.engines, ["codeinspectus-ai"], `${label}: ${expected.id} engines changed`);
    assert(
      typeof finding.remediation?.summary === "string" && finding.remediation.summary.length > 0 &&
        Array.isArray(finding.remediation.steps) && finding.remediation.steps.length > 0 &&
        Array.isArray(finding.remediation.references) && finding.remediation.references.length > 0,
      `${label}: ${expected.id} remediation is incomplete`,
    );
    assertExactJson(finding.producer_components, [
      "codeinspectus:pipeline",
      "pack:github-actions:dispatch",
      "github-actions:yaml-workflow-parser",
      expected.component,
    ], `${label}: ${expected.id} components changed`);
  }
}

function assertGithubActionsTpScan(result: any, label: string): void {
  assertGithubActionsFindings(result.findings ?? [], label);
  assert(
    result.summary?.total === 2 && result.summary.critical === 1 &&
      result.summary.high === 1 && result.summary.medium === 0 &&
      result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 1 critical and 1 high`,
  );
  for (const [component, signature] of Object.entries(GITHUB_ACTIONS_COMPONENT_SIGNATURES)) {
    assert(result.component_signatures?.[component] === signature, `${label}: ${component} signature changed or is missing`);
  }
}

async function replaceFixtureDirectory(source: string, target: string): Promise<void> {
  await rm(target, { recursive: true, force: true });
  await cp(source, target, { recursive: true });
}

// The OSV evals run against the live OSV PyPI database, which changes daily. They pin the targeted
// advisories (identity, package and shape), never a total, so unrelated new advisories cannot break them.
const OSV_MALWARE_ID = "MAL-2026-2144";
const OSV_BROTLI_ID = "CVE-2026-111497";
const OSV_BROTLI_ALIAS = "GHSA-9v8h-qqgm-4m35";

function osvAdvisoryMatches(finding: any, id: string): boolean {
  return finding.rule_id === id || (finding.vulnerability_aliases ?? []).includes(id);
}

function osvTargetedFindings(findings: any[], ids: readonly string[]): any[] {
  return findings.filter((finding) => ids.some((id) => osvAdvisoryMatches(finding, id)));
}

function assertOsvPypiTargetedFindings(findings: any[], label: string): void {
  const malware = findings.filter((finding) => osvAdvisoryMatches(finding, OSV_MALWARE_ID));
  assert(malware.length === 1, `${label}: expected exactly one ${OSV_MALWARE_ID} finding, got ${malware.length}`);
  const [litellm] = malware;
  assert(
    litellm.package?.ecosystem === "PyPI" && litellm.package.name === "litellm" && litellm.package.version === "1.107.0",
    `${label}: ${OSV_MALWARE_ID} was not reported on PyPI litellm 1.107.0: ${JSON.stringify(litellm.package)}`,
  );
  assert(litellm.engines?.includes("osv-scanner"), `${label}: ${OSV_MALWARE_ID} did not come from osv-scanner`);

  // The same advisory on two different packages must stay two findings (package-aware dedup).
  const brotli = findings.filter((finding) => osvAdvisoryMatches(finding, OSV_BROTLI_ID));
  assertExactJson(
    brotli.map((finding) => `${finding.package?.ecosystem}:${String(finding.package?.name).toLowerCase()}@${finding.package?.version}`).sort(),
    ["PyPI:brotli@1.2.0", "PyPI:brotlicffi@1.2.0.2"],
    `${label}: ${OSV_BROTLI_ID} must be two separate package findings`,
  );
  assert(new Set(brotli.map((finding) => finding.fingerprint)).size === 2, `${label}: ${OSV_BROTLI_ID} findings share a fingerprint`);
  assert(
    brotli.every((finding) => finding.engines?.includes("osv-scanner")),
    `${label}: every ${OSV_BROTLI_ID} finding must carry osv-scanner in engines`,
  );
}

function assertNoOsvPypiTargetedFindings(findings: any[], label: string): void {
  const stale = osvTargetedFindings(findings, [OSV_MALWARE_ID, OSV_BROTLI_ID, OSV_BROTLI_ALIAS]);
  assert(stale.length === 0, `${label}: targeted advisories still reported: ${stale.map((finding) => finding.rule_id).join(", ")}`);
}

/** A check that cannot exercise its scenario in this environment (recorded as a skip, never a pass). */
class EvalSkip extends Error {}

/**
 * A throwaway copy of the built package (dist, data, detection-db, the lockfile of engines) that a test may alter,
 * so the Synvoya dataset can be tampered with without ever touching the repository's own files. node_modules
 * is linked, not copied. Returns the copy's server entry point.
 */
async function copyBuiltPackage(root: string): Promise<string> {
  for (const name of ["dist", "data", "detection-db"]) await cp(resolve(process.cwd(), name), join(root, name), { recursive: true });
  for (const name of ["package.json", "engines.lock.json"]) await cp(resolve(process.cwd(), name), join(root, name));
  await symlink(resolve(process.cwd(), "node_modules"), join(root, "node_modules"), "junction");
  return join(root, "dist", "index.js");
}

/** Edits one advisory of the copy's dataset without updating manifest.json, so its SHA-256 digest no longer matches. */
async function tamperSynvoyaDataset(root: string): Promise<void> {
  const file = join(root, "detection-db", "synvoya", "advisories.json");
  const data = JSON.parse(await readFile(file, "utf8"));
  data.advisories[0].title = `${data.advisories[0].title} (edited)`;
  await writeFile(file, `${JSON.stringify(data, null, 2)}\n`, "utf8");
}

/** Runs `fn` with a server that serves the intact package's tools over a Synvoya dataset that fails its integrity check. */
async function withTamperedSynvoya<T>(fn: (server: { entry: string; client: McpClient }) => Promise<T>, env: NodeJS.ProcessEnv = {}): Promise<T> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-tampered-"));
  let client: McpClient | undefined;
  try {
    const entry = await copyBuiltPackage(root);
    await tamperSynvoyaDataset(root);
    client = new McpClient(env, entry);
    await client.init();
    return await fn({ entry, client });
  } finally {
    client?.close();
    await rm(root, { recursive: true, force: true });
  }
}

/** A home directory of its own with scan persistence on, so a scan and a later rescan can run in different servers. */
const isolatedHome = (home: string): NodeJS.ProcessEnv => ({
  HOME: home,
  USERPROFILE: home,
  CODEINSPECTUS_INTERNAL_DISABLE_SCAN_PERSISTENCE: undefined,
});

const synvoyaFindings = (findings: any[]): any[] => findings.filter((finding) => finding.engines.includes("synvoya"));

/** A workflow with a clean action, the given tj-actions/changed-files ref (line 7), a v4 tag with a fix and a branch ref. */
const ACTIONS_WORKFLOW = (ref: string): string =>
  "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n" +
  `      - uses: tj-actions/changed-files@${ref}\n      - uses: rlespinasse/github-slug-action@v4\n      - uses: tj-actions/changed-files@main\n`;

/** Skips an eval when the OSV GitHub Actions database is not installed in this HOME (setup offers it). */
function requireActionsDb(result: any): void {
  const note = result.engine_details?.find((engine: any) => engine.engine === "synvoya")?.note ?? "";
  if (!/checked against the OSV GitHub Actions database/.test(note)) {
    throw new EvalSkip('OSV GitHub Actions database not installed (setup --select osv-scanner --osv-ecosystems "GitHub Actions")');
  }
}

async function replaceMobileFixture(target: string, state: "tp" | "fixed"): Promise<void> {
  await rm(target, { recursive: true, force: true });
  // Model a normal Flutter mobile repository so one MCP scan proves that the
  // Flutter, Android, and iOS packs activate together without cross-pack noise.
  await cp(FLUTTER_FP_FIXTURE, target, { recursive: true });
  await cp(resolve(ANDROID_CONFIG_FIXTURE, state), join(target, "android"), { recursive: true });
  await cp(resolve(IOS_CONFIG_FIXTURE, state), join(target, "ios"), { recursive: true });
}

function nativePubFindings(result: any): any[] {
  return (result.findings ?? []).filter((finding: any) =>
    finding.producer_components?.includes("codeinspectus-pub:osv-snapshot")
  );
}

function assertPubAdvisorySet(findings: any[], label: string): void {
  assert(findings.length === 6, `${label}: expected six native Pub findings, got ${findings.length}`);
  const identitySets = findings.map((finding: any) =>
    new Set([finding.rule_id, ...(finding.vulnerability_aliases ?? [])])
  );
  for (const advisory of PUB_TP_ADVISORIES) {
    assert(
      identitySets.filter((identities) => identities.has(advisory)).length === 1,
      `${label}: expected exactly one finding carrying advisory identity ${advisory}`,
    );
  }
}

function assertPubTpScan(result: any, label: string): void {
  const findings = nativePubFindings(result);
  assertPubAdvisorySet(findings, label);
  for (const finding of findings) {
    assert(finding.engines.includes("codeinspectus-pub"), `${label}: native Pub producer identity missing`);
    assert(finding.finding_kind === "vulnerability", `${label}: Pub finding kind changed`);
    assert(finding.confidence === "high", `${label}: Pub finding confidence changed`);
    assert(finding.cwe.includes("CWE-1395"), `${label}: vulnerable-component CWE missing`);
    assert(finding.location.file === "pubspec.lock", `${label}: Pub finding came from the wrong lockfile`);
    assert(finding.location.start_line > 0, `${label}: Pub version line missing`);
    for (const component of [
      "codeinspectus:pipeline",
      "codeinspectus-pub:lockfile-parser",
      "codeinspectus-pub:exact-version-matcher",
      "codeinspectus-pub:osv-snapshot",
    ]) {
      assert(finding.producer_components.includes(component), `${label}: missing ${component}`);
      assert(/^sha256:[a-f0-9]{64}$/.test(result.component_signatures?.[component] ?? ""), `${label}: missing ${component} signature`);
    }
  }
  const coverage = result.dependency_coverage?.find(
    (item: any) => item.engine === "codeinspectus-pub",
  );
  assert(coverage?.state === "partial", `${label}: expected explicit partial coverage for excluded non-official packages`);
  assert(
    coverage.lockfiles.discovered === 1 && coverage.lockfiles.analyzed === 1,
    `${label}: Pub lockfile coverage changed`,
  );
  assert(
    // skipped = unverifiable git/custom-hosted packages only; SDK/path packages are not applicable.
    coverage.packages.resolved === 9 && coverage.packages.eligible === 5 && coverage.packages.skipped === 2,
    `${label}: Pub package coverage changed`,
  );
  assert(coverage.matching === "exact-enumerated-versions", `${label}: Pub matching mode changed`);
  const engine = result.engine_details?.find((item: any) => item.engine === "codeinspectus-pub");
  assert(engine?.available === true && engine.ran === true && engine.finding_count === 6, `${label}: Pub engine run record changed`);
}

async function main() {
  const client = new McpClient();
  await client.init();

  // One full scan, reused across evals.
  const scanRes = await client.callTool("codeinspectus_scan", { path: FIXTURE });
  const scan = scanRes.structuredContent;
  const findings: any[] = scan.findings;
  const engineRan = (e: string) => scan.engine_details.some((d: any) => d.engine === e && d.ran);
  const has = (pred: (f: any) => boolean) => findings.some(pred);
  const find = (pred: (f: any) => boolean) => findings.find(pred);

  // The OSV evals need osv-scanner, and E59/E60 the PyPI OSV database too. The shared scan above cannot say so
  // (its npm lockfile needs the npm database), so one probe scan of the clean PyPI fixture reports readiness.
  let osvProbe: Promise<any> | undefined;
  const osvProbeScan = (): Promise<any> => {
    osvProbe ??= client.callTool("codeinspectus_scan", { path: OSV_PYPI_FIXED_FIXTURE, scanners: ["vuln"] })
      .then((response: any) => response.structuredContent);
    return osvProbe;
  };
  const osvNotInstalled = async (): Promise<string | undefined> =>
    (await osvProbeScan()).engine_details.some((d: any) => d.engine === "osv-scanner" && d.available)
      ? undefined
      : "osv-scanner not installed (repair-engines)";
  let osvPypiBlocker: Promise<string | undefined> | undefined;
  const osvPypiNotReady = (): Promise<string | undefined> => {
    osvPypiBlocker ??= (async () => {
      const notInstalled = await osvNotInstalled();
      if (notInstalled) return notInstalled;
      const probe = await osvProbeScan();
      // Skip only when the database is missing. Any other state (a failed run, no PyPI entry) must reach the
      // eval and fail it, not be reported as a missing database.
      const pypi = probe.dependency_coverage?.find((c: any) => c.engine === "osv-scanner" && c.ecosystem === "PyPI");
      if (pypi?.state === "unavailable") {
        return "OSV PyPI database not installed (repair-engines osv-scanner --osv-ecosystems PyPI)";
      }
      return undefined;
    })();
    return osvPypiBlocker;
  };

  type Check = { id: string; engineDep?: string; fn: () => Promise<void> | void };
  const checks: Check[] = [
    {
      id: "E01 scan returns a valid envelope with explicit technology and native-pack coverage",
      fn: () => {
        assert(typeof scan.scan_id === "string" && scan.scan_id.length > 0, "missing scan_id");
        assert(scan.offline === true, "offline must be true");
        assert(/not an audit or certification/i.test(scan.disclaimer), "missing standing disclaimer");
        assert(scan.detected_technologies.some((technology: any) => technology.id === "typescript"), "fixture TypeScript was not detected");
        const nativePack = scan.pack_coverage.find((pack: any) => pack.pack_id === "javascript-typescript");
        assert(nativePack?.state === "ran", `expected JavaScript/TypeScript pack to run, got ${nativePack?.state}`);
        assert(nativePack.analyzers.registered === 12 && nativePack.analyzers.ran === 12, "native analyzer execution counts are wrong");
        assert(nativePack.rules.registered === 29 && nativePack.rules.ran === 29, "native rule execution counts are wrong");
        const flutterPack = scan.pack_coverage.find((pack: any) => pack.pack_id === "flutter");
        assert(flutterPack?.state === "not_applicable", `expected Flutter pack to be not_applicable, got ${flutterPack?.state}`);
        assert(flutterPack.analyzers.registered === 6 && flutterPack.analyzers.ran === 0, "non-applicable Flutter analyzer counts are wrong");
        assert(flutterPack.rules.registered === 6 && flutterPack.rules.ran === 0, "non-applicable Flutter rule counts are wrong");
        for (const platform of ["android", "ios"]) {
          const platformPack = scan.pack_coverage.find((pack: any) => pack.pack_id === platform);
          assert(platformPack?.state === "not_applicable", `expected ${platform} pack to be not_applicable, got ${platformPack?.state}`);
          assertExactJson(platformPack.platforms, [platform], `${platform} pack platform metadata changed`);
        }
        for (const [packId, analyzers, rules] of [["react-native", 4, 4], ["expo", 2, 2]] as const) {
          const frameworkPack = scan.pack_coverage.find((pack: any) => pack.pack_id === packId);
          assert(frameworkPack?.state === "not_applicable", `expected ${packId} pack to be not_applicable, got ${frameworkPack?.state}`);
          assert(
            frameworkPack.analyzers.registered === analyzers && frameworkPack.analyzers.ran === 0 &&
              frameworkPack.rules.registered === rules && frameworkPack.rules.ran === 0,
            `non-applicable ${packId} coverage counts are wrong`,
          );
        }
        const pubCoverage = scan.dependency_coverage?.find((item: any) => item.engine === "codeinspectus-pub");
        assert(pubCoverage?.state === "not_applicable", "non-Dart fixture must report native Pub as not_applicable");
      },
    },
    {
      id: "E02 hard-coded live secret detected at config.ts (CWE-798)",
      fn: () => {
        const f = find((x) => x.location.file === "src/config.ts" && x.cwe.includes("CWE-798"));
        assert(!!f, "no CWE-798 finding at src/config.ts");
        assert(f.severity === "critical", `expected critical, got ${f.severity}`);
      },
    },
    {
      id: "E03 secret VALUE is redacted everywhere (guardrail §5)",
      fn: () => {
        const leaked = findings.some(
          (f) => JSON.stringify(f).includes(RAW_SECRET),
        );
        assert(!leaked, "raw secret value leaked into output — redaction failed");
      },
    },
    {
      id: "E04 USING (true) RLS policy detected as critical CWE-863",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-rls-using-true");
        assert(!!f, "USING (true) not detected");
        assert(f.severity === "critical" && f.cwe.includes("CWE-863"), "wrong severity/CWE for USING(true)");
        assert(f.owasp_web?.includes("A01:2021"), "USING(true) should map to OWASP A01:2021");
      },
    },
    {
      id: "E05 USING(true) inside a SQL COMMENT is NOT flagged (precision)",
      fn: () => {
        const fps = findings.filter((x) => x.rule_id === "ci-ai-rls-using-true");
        assert(fps.length === 1, `expected exactly 1 USING(true) finding, got ${fps.length} (comment false positive?)`);
        assert(fps[0].location.start_line === 18, `expected the real policy at line 18, got ${fps[0].location.start_line}`);
      },
    },
    {
      id: "E06 public table without RLS detected (CWE-862, payments)",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-rls-missing");
        assert(!!f, "missing-RLS not detected");
        assert(/payments/.test(f.title), "expected payments table");
        assert(f.cwe.includes("CWE-862"), "expected CWE-862");
      },
    },
    {
      id: "E07 correctly-secured table (accounts) NOT flagged (precision)",
      fn: () => {
        const bad = findings.some((x) => /'accounts'/.test(x.title) && x.rule_id.startsWith("ci-ai-rls"));
        assert(!bad, "accounts table (RLS + auth.uid policies) wrongly flagged");
      },
    },
    {
      id: "E08 prompt-injection sink + excessive agency (LLM01+LLM06, CWE-1427)",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-prompt-injection-sink");
        assert(!!f, "prompt-injection sink not detected");
        assert(f.cwe.includes("CWE-1427"), "expected CWE-1427");
        assert(f.owasp_llm?.includes("LLM01:2025") && f.owasp_llm?.includes("LLM06:2025"), "expected LLM01 + LLM06");
        assert(f.confidence === "medium", "prompt-injection must be medium confidence (honest scope)");
      },
    },
    {
      id: "E08b model-produced tool argument reaches shell execution (LLM05+LLM06)",
      fn: () => {
        const matches = findings.filter((x) => x.rule_id === "ci-ai-llm-tool-argument-command-execution");
        assert(matches.length === 1, `expected one unsafe tool-execution finding, got ${matches.length}`);
        const f = matches[0];
        assert(f.location.file === "src/agent.ts" && f.location.start_line === 9, "unsafe tool-execution sink location drifted");
        assert(f.severity === "high" && f.confidence === "medium", "unsafe tool-execution severity/confidence drifted");
        assert(f.cwe.includes("CWE-78") && f.cwe.includes("CWE-1426"), "expected CWE-78 + CWE-1426");
        assert(f.owasp_llm?.includes("LLM05:2025") && f.owasp_llm?.includes("LLM06:2025"), "expected LLM05 + LLM06");
      },
    },
    {
      id: "E09 secret behind client-exposed env prefix detected; publishable key NOT",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-public-env-secret");
        assert(!!f, "public-env-secret not detected");
        // publishable() uses NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY — must NOT be flagged
        const fpCount = findings.filter((x) => x.rule_id === "ci-ai-public-env-secret").length;
        assert(fpCount === 1, `expected exactly 1 public-env-secret finding, got ${fpCount}`);
      },
    },
    {
      id: "E10 compliance_report: ISO27001 code-visible denominator shown; no '% compliant'",
      fn: async () => {
        const rep = (await client.callTool("codeinspectus_compliance_report", { scan_id: scan.scan_id, framework: "ISO27001:2022" })).structuredContent;
        const iso = rep.frameworks.find((f: any) => f.framework === "ISO27001:2022");
        assert(!!iso, "no ISO27001 framework in report");
        assert(iso.code_visible_controls === 7, `expected 7 code-visible ISO controls, got ${iso.code_visible_controls}`);
        assert(iso.scope === "code-visible subset only", "scope label missing");
        assert(/not an iso 27001 audit/i.test(iso.disclaimer), "ISO disclaimer missing");
        const blob = JSON.stringify(rep).toLowerCase();
        assert(!/%\s*compliant/.test(blob) && !/you pass/.test(blob), "forbidden '% compliant' / 'you pass' language present");
      },
    },
    {
      id: "E11 posture score is its own 0-100 view, never labeled percent-compliant",
      fn: async () => {
        const rep = (await client.callTool("codeinspectus_compliance_report", { scan_id: scan.scan_id })).structuredContent;
        assert(typeof rep.posture_score === "number" && rep.posture_score >= 0 && rep.posture_score <= 100, "posture_score out of range");
        assert(/not a percent-compliant/i.test(rep.posture_note), "posture_note must disclaim '% compliant'");
      },
    },
    {
      id: "E12 explain_finding returns remediation steps + references for a finding",
      fn: async () => {
        const target = find((x) => x.rule_id === "ci-ai-rls-using-true");
        const ex = (await client.callTool("codeinspectus_explain_finding", { scan_id: scan.scan_id, finding_id: target.id })).structuredContent;
        assert(ex.remediation.steps.length > 0, "no remediation steps");
        assert(ex.remediation.references.length > 0, "no references");
        assert(ex.why_it_matters.length > 0, "no why_it_matters");
      },
    },
    {
      id: "E13 rescan with no changes: all remaining, zero resolved, zero introduced",
      fn: async () => {
        // Use the deterministic pure-TS analyzers as the baseline so the diff
        // logic is tested without engine/DB nondeterminism.
        const base = (await client.callTool("codeinspectus_scan", { path: FIXTURE, scanners: ["ai"] })).structuredContent;
        const re = (await client.callTool("codeinspectus_rescan", { path: FIXTURE, prior_scan_id: base.scan_id, scanners: ["ai"] })).structuredContent;
        assert(re.summary.resolved === 0, `expected 0 resolved, got ${re.summary.resolved}`);
        assert(re.summary.introduced === 0, `expected 0 introduced, got ${re.summary.introduced}`);
        assert(re.summary.remaining > 0, "expected findings to remain");
        assert(re.detected_technologies.some((technology: any) => technology.id === "typescript"), "rescan lost detected technologies");
        const coverage = re.pack_coverage.find((pack: any) => pack.pack_id === "javascript-typescript");
        assert(coverage?.state === "ran" && coverage.analyzers.ran === 12 && coverage.rules.ran === 29, "rescan lost native-pack execution coverage");
        const flutterCoverage = re.pack_coverage.find((pack: any) => pack.pack_id === "flutter");
        assert(flutterCoverage?.state === "not_applicable" && flutterCoverage.rules.ran === 0, "rescan lost non-applicable Flutter-pack coverage");
        for (const packId of ["react-native", "expo"]) {
          const frameworkCoverage = re.pack_coverage.find((pack: any) => pack.pack_id === packId);
          assert(frameworkCoverage?.state === "not_applicable" && frameworkCoverage.rules.ran === 0, `rescan lost non-applicable ${packId} coverage`);
        }
      },
    },
    {
      id: "E14 list_rules exposes the AI-code moat rules + DB version",
      fn: async () => {
        const lr = (await client.callTool("codeinspectus_list_rules", {})).structuredContent;
        assert(lr.custom_rule_count === 126, `expected 126 custom rules, got ${lr.custom_rule_count}`);
        assert(lr.detection_db_version === "2.0.0", `expected detection DB 2.0.0, got ${lr.detection_db_version}`);
        assert(lr.detection_db_date === "2026-11-05", `unexpected detection DB date ${lr.detection_db_date}`);
        assert(lr.custom_rules.some((r: any) => r.id === "ci-ai-rls-using-true"), "missing ci-ai-rls-using-true in list_rules");
        const boundary = lr.custom_rules.find((r: any) => r.id === "ci-ai-client-error-leak");
        assert(boundary?.owasp_web?.includes("A05:2021") && boundary?.owasp_api?.includes("API8:2023"), "new rules must expose OWASP Web/API mappings");
        const nativeRules = lr.custom_rules.filter((rule: any) => rule.engine === "codeinspectus-ai");
        assert(nativeRules.length === 72, `expected 72 native rules, got ${nativeRules.length}`);
        assert(nativeRules.filter((rule: any) => rule.pack_id === "javascript-typescript").length === 29, "JavaScript/TypeScript native rule ownership is wrong");
        const unsafeTool = nativeRules.find((rule: any) => rule.id === "ci-ai-llm-tool-argument-command-execution");
        assert(unsafeTool?.owasp_llm?.includes("LLM05:2025") && unsafeTool?.owasp_llm?.includes("LLM06:2025"), "unsafe tool execution rule metadata is missing");
        const dynamicExecution = nativeRules.find((rule: any) => rule.id === "ci-ai-llm-output-dynamic-execution");
        assert(dynamicExecution?.owasp_llm?.includes("LLM05:2025") && dynamicExecution?.cwe?.includes("CWE-94") && dynamicExecution?.cwe?.includes("CWE-78"), "dynamic execution rule metadata is missing");
        const adminRoute = nativeRules.find((rule: any) => rule.id === "ci-ai-nextjs-admin-route-no-authz");
        assert(adminRoute?.owasp_web?.includes("A01:2021") && adminRoute?.owasp_api?.includes("API5:2023") && adminRoute?.cwe?.includes("CWE-862"), "Next.js admin route rule metadata is missing");
        const expressRoute = nativeRules.find((rule: any) => rule.id === "ci-ai-express-admin-route-no-authz");
        assert(expressRoute?.owasp_web?.includes("A01:2021") && expressRoute?.owasp_api?.includes("API5:2023") && expressRoute?.cwe?.includes("CWE-863"), "Express admin route rule metadata is missing");
        const privilegedEdge = nativeRules.find((rule: any) => rule.id === "ci-ai-edge-fn-privileged-no-authz");
        assert(privilegedEdge?.owasp_web?.includes("A01:2021") && privilegedEdge?.cwe?.includes("CWE-863"), "Supabase privileged Edge authz rule metadata is missing");
        const flutterRules = nativeRules.filter((rule: any) => rule.pack_id === "flutter");
        assert(flutterRules.length === 6, "Flutter native rule ownership is wrong");
        assertExactJson(
          flutterRules.map((rule: any) => rule.id).sort(),
          FLUTTER_RULES.map((rule) => rule.id).sort(),
          "list_rules Flutter rule IDs changed",
        );
        for (const expected of FLUTTER_RULES) {
          const rule = flutterRules.find((candidate: any) => candidate.id === expected.id);
          assert(rule?.engine === "codeinspectus-ai" && rule.pack_id === "flutter", `${expected.id} ownership is wrong`);
          assert(rule.severity === expected.severity, `${expected.id} catalog severity changed`);
          assertExactJson(rule.cwe, expected.cwe, `${expected.id} catalog CWE mapping changed`);
        }
        const nativePack = lr.native_packs.find((pack: any) => pack.id === "javascript-typescript");
        assert(nativePack?.version === "1.10.0", "expected JavaScript/TypeScript pack 1.10.0");
        assert(nativePack?.analyzer_count === 12 && nativePack.rule_count === 29, "list_rules JavaScript/TypeScript pack inventory is wrong");
        const baselinePack = lr.native_packs.find((pack: any) => pack.id === "javascript-baseline");
        assert(baselinePack?.scanner_kind === "sast" && baselinePack.analyzer_count === 1 && baselinePack.rule_count === 2, "list_rules JavaScript baseline pack inventory is wrong");
        const promotedRules = nativeRules.filter((rule: any) => rule.pack_id === "javascript-baseline");
        assert(promotedRules.length === 2 && promotedRules.every((rule: any) => rule.kind === "sast" && rule.fallback_engine === "opengrep"), "promoted rule ownership/fallback is wrong");
        const flutterPack = lr.native_packs.find((pack: any) => pack.id === "flutter");
        assert(flutterPack?.analyzer_count === 6 && flutterPack.rule_count === 6, "list_rules Flutter pack inventory is wrong");
        assert(flutterPack.version === "1.1.0", `expected Flutter pack 1.1.0, got ${flutterPack.version}`);
        assertExactJson(flutterPack.languages, ["dart"], "list_rules Flutter languages changed");
        assertExactJson(flutterPack.frameworks, ["flutter"], "list_rules Flutter frameworks changed");
        assertExactJson(flutterPack.limitations, FLUTTER_PACK_LIMITATIONS, "list_rules Flutter limitations changed");
        for (const packId of ["android", "ios"] as const) {
          const pack = lr.native_packs.find((candidate: any) => candidate.id === packId);
          assert(pack?.version === "1.0.0", `expected ${packId} pack 1.0.0`);
          assert(pack.analyzer_count === 1 && pack.rule_count === 4, `${packId} pack inventory changed`);
          assertExactJson(pack.languages, ["xml"], `${packId} pack languages changed`);
          assertExactJson(pack.frameworks, [], `${packId} pack frameworks changed`);
          assertExactJson(pack.platforms, [packId], `${packId} pack platforms changed`);
          assertExactJson(
            pack.limitations,
            mobilePackLimitations(packId),
            `${packId} pack limitations changed`,
          );
          const rules = nativeRules.filter((rule: any) => rule.pack_id === packId);
          assert(rules.length === 4, `expected four ${packId} rules`);
          for (const expected of MOBILE_CONFIG_RULES.filter((rule) => rule.pack === packId)) {
            const rule = rules.find((candidate: any) => candidate.id === expected.id);
            assert(rule?.severity === expected.severity, `${expected.id} catalog severity changed`);
            assertExactJson(rule.cwe, expected.cwe, `${expected.id} catalog CWE mapping changed`);
          }
        }
        for (const [packId, analyzerCount, ruleCount] of [["react-native", 4, 4], ["expo", 2, 2]] as const) {
          const pack = lr.native_packs.find((candidate: any) => candidate.id === packId);
          const expectedVersion = packId === "react-native" ? "1.1.0" : "1.0.0";
          assert(pack?.version === expectedVersion, `expected ${packId} pack ${expectedVersion}`);
          assert(pack.analyzer_count === analyzerCount && pack.rule_count === ruleCount, `${packId} pack inventory changed`);
          assertExactJson(
            pack.languages,
            packId === "react-native" ? ["javascript", "typescript"] : ["javascript", "typescript", "json"],
            `${packId} language metadata changed`,
          );
          assertExactJson(pack.frameworks, [packId], `${packId} framework metadata changed`);
          assertExactJson(pack.platforms, [], `${packId} must not claim native platform-configuration coverage`);
          assertExactJson(
            pack.limitations,
            packId === "react-native" ? REACT_NATIVE_PACK_LIMITATIONS : EXPO_PACK_LIMITATIONS,
            `${packId} limitations changed`,
          );
          const rules = nativeRules.filter((rule: any) => rule.pack_id === packId);
          assert(rules.length === ruleCount, `${packId} rule ownership changed`);
          const expectedRules = REACT_NATIVE_EXPO_RULES.filter((rule) => rule.pack === packId);
          assertExactJson(
            rules.map((rule: any) => rule.id).sort(),
            expectedRules.map((rule) => rule.id).sort(),
            `${packId} rule IDs changed`,
          );
          for (const expected of expectedRules) {
            const rule = rules.find((candidate: any) => candidate.id === expected.id);
            assert(rule?.severity === expected.severity, `${expected.id} catalog severity changed`);
            assertExactJson(rule.cwe, expected.cwe, `${expected.id} catalog CWE mapping changed`);
          }
        }
        const pythonPack = lr.native_packs.find((pack: any) => pack.id === "python-ai-api");
        assert(pythonPack?.version === "1.5.0", "expected Python AI/API pack 1.5.0");
        assert(
          pythonPack.analyzer_count === 10 && pythonPack.rule_count === 10,
          "list_rules Python AI/API pack inventory is wrong",
        );
        assertExactJson(pythonPack.languages, ["python"], "list_rules Python languages changed");
        assertExactJson(
          pythonPack.frameworks,
          ["fastapi", "starlette", "flask", "django", "jinja2", "openai", "anthropic", "langchain"],
          "list_rules Python frameworks changed",
        );
        assertExactJson(pythonPack.platforms, [], "Python pack must not claim platform coverage");
        assertExactJson(
          pythonPack.limitations,
          PYTHON_AI_API_PACK_LIMITATIONS,
          "list_rules Python limitations changed",
        );
        const pythonRules = nativeRules.filter((rule: any) => rule.pack_id === "python-ai-api");
        assertExactJson(
          pythonRules.map((rule: any) => rule.id).sort(),
          PYTHON_AI_API_RULES.map((rule) => rule.id).sort(),
          "Python AI/API rule ownership changed",
        );
        for (const expected of PYTHON_AI_API_RULES) {
          const rule = pythonRules.find((candidate: any) => candidate.id === expected.id);
          assert(rule?.severity === expected.severity, `${expected.id} catalog severity changed`);
          assertExactJson(rule.cwe, expected.cwe, `${expected.id} catalog CWE mapping changed`);
        }
        const goPack = lr.native_packs.find((pack: any) => pack.id === "go-ai");
        assert(goPack?.version === "1.0.0", "expected Go AI pack 1.0.0");
        assert(goPack.analyzer_count === 1 && goPack.rule_count === 1, "list_rules Go AI pack inventory is wrong");
        assertExactJson(goPack.languages, ["go"], "list_rules Go languages changed");
        assertExactJson(goPack.frameworks, ["openai"], "list_rules Go frameworks changed");
        assertExactJson(goPack.platforms, [], "Go pack must not claim platform coverage");
        assertExactJson(goPack.limitations, GO_AI_PACK_LIMITATIONS, "list_rules Go limitations changed");
        const goRules = nativeRules.filter((rule: any) => rule.pack_id === "go-ai");
        assert(goRules.length === 1, "Go AI rule ownership changed");
        const goRule = goRules[0];
        assert(goRule.id === GO_AI_RULE.id, "Go AI rule ID changed");
        assert(goRule.severity === GO_AI_RULE.severity, "Go AI catalog severity changed");
        assertExactJson(goRule.cwe, GO_AI_RULE.cwe, "Go AI catalog CWE mapping changed");
        assertExactJson(goRule.owasp_llm, GO_AI_RULE.owaspLlm, "Go AI catalog OWASP LLM mapping changed");
        const javaPack = lr.native_packs.find((pack: any) => pack.id === "java-ai");
        assert(javaPack?.version === "1.0.0", "expected Java AI pack 1.0.0");
        assert(javaPack.analyzer_count === 1 && javaPack.rule_count === 1, "list_rules Java AI pack inventory is wrong");
        assertExactJson(javaPack.languages, ["java"], "list_rules Java languages changed");
        assertExactJson(javaPack.frameworks, ["openai"], "list_rules Java frameworks changed");
        assertExactJson(javaPack.platforms, [], "Java pack must not claim platform coverage");
        assertExactJson(javaPack.limitations, JAVA_AI_PACK_LIMITATIONS, "list_rules Java limitations changed");
        const javaRules = nativeRules.filter((rule: any) => rule.pack_id === "java-ai");
        assert(javaRules.length === 1, "Java AI rule ownership changed");
        const javaRule = javaRules[0];
        assert(javaRule.id === JAVA_AI_RULE.id, "Java AI rule ID changed");
        assert(javaRule.severity === JAVA_AI_RULE.severity, "Java AI catalog severity changed");
        assertExactJson(javaRule.cwe, JAVA_AI_RULE.cwe, "Java AI catalog CWE mapping changed");
        assertExactJson(javaRule.owasp_llm, JAVA_AI_RULE.owaspLlm, "Java AI catalog OWASP LLM mapping changed");
        const csharpPack = lr.native_packs.find((pack: any) => pack.id === "csharp-ai");
        assert(csharpPack?.version === "1.0.0", "expected C# AI pack 1.0.0");
        assert(csharpPack.analyzer_count === 1 && csharpPack.rule_count === 1, "list_rules C# AI pack inventory is wrong");
        assertExactJson(csharpPack.languages, ["csharp"], "list_rules C# languages changed");
        assertExactJson(csharpPack.frameworks, ["openai"], "list_rules C# frameworks changed");
        assertExactJson(csharpPack.platforms, [], "C# pack must not claim platform coverage");
        assertExactJson(csharpPack.limitations, CSHARP_AI_PACK_LIMITATIONS, "list_rules C# limitations changed");
        const csharpRules = nativeRules.filter((rule: any) => rule.pack_id === "csharp-ai");
        assert(csharpRules.length === 1, "C# AI rule ownership changed");
        const csharpRule = csharpRules[0];
        assert(csharpRule.id === CSHARP_AI_RULE.id, "C# AI rule ID changed");
        assert(csharpRule.severity === CSHARP_AI_RULE.severity, "C# AI catalog severity changed");
        assertExactJson(csharpRule.cwe, CSHARP_AI_RULE.cwe, "C# AI catalog CWE mapping changed");
        assertExactJson(csharpRule.owasp_llm, CSHARP_AI_RULE.owaspLlm, "C# AI catalog OWASP LLM mapping changed");
        const phpPack = lr.native_packs.find((pack: any) => pack.id === "php-ai");
        assert(phpPack?.version === "1.0.0", "expected PHP AI pack 1.0.0");
        assert(phpPack.analyzer_count === 1 && phpPack.rule_count === 1, "list_rules PHP AI pack inventory is wrong");
        assertExactJson(phpPack.languages, ["php"], "list_rules PHP languages changed");
        assertExactJson(phpPack.frameworks, ["openai"], "list_rules PHP frameworks changed");
        assertExactJson(phpPack.platforms, [], "PHP pack must not claim platform coverage");
        assertExactJson(phpPack.limitations, PHP_AI_PACK_LIMITATIONS, "list_rules PHP limitations changed");
        const phpRules = nativeRules.filter((rule: any) => rule.pack_id === "php-ai");
        assert(phpRules.length === 1, "PHP AI rule ownership changed");
        const phpRule = phpRules[0];
        assert(phpRule.id === PHP_AI_RULE.id, "PHP AI rule ID changed");
        assert(phpRule.severity === PHP_AI_RULE.severity, "PHP AI catalog severity changed");
        assertExactJson(phpRule.cwe, PHP_AI_RULE.cwe, "PHP AI catalog CWE mapping changed");
        assertExactJson(phpRule.owasp_llm, PHP_AI_RULE.owaspLlm, "PHP AI catalog OWASP LLM mapping changed");
        const rustPack = lr.native_packs.find((pack: any) => pack.id === "rust-ai");
        assert(rustPack?.version === "1.0.0", "expected Rust AI pack 1.0.0");
        assert(rustPack.analyzer_count === 1 && rustPack.rule_count === 1, "list_rules Rust AI pack inventory is wrong");
        assertExactJson(rustPack.languages, ["rust"], "list_rules Rust languages changed");
        assertExactJson(rustPack.frameworks, ["openai"], "list_rules Rust frameworks changed");
        assertExactJson(rustPack.platforms, [], "Rust pack must not claim platform coverage");
        assertExactJson(rustPack.limitations, RUST_AI_PACK_LIMITATIONS, "list_rules Rust limitations changed");
        const rustRules = nativeRules.filter((rule: any) => rule.pack_id === "rust-ai");
        assert(rustRules.length === 1, "Rust AI rule ownership changed");
        const rustRule = rustRules[0];
        assert(rustRule.id === RUST_AI_RULE.id, "Rust AI rule ID changed");
        assert(rustRule.severity === RUST_AI_RULE.severity, "Rust AI catalog severity changed");
        assertExactJson(rustRule.cwe, RUST_AI_RULE.cwe, "Rust AI catalog CWE mapping changed");
        assertExactJson(rustRule.owasp_llm, RUST_AI_RULE.owaspLlm, "Rust AI catalog OWASP LLM mapping changed");
        const rubyPack = lr.native_packs.find((pack: any) => pack.id === "ruby-ai");
        assert(rubyPack?.version === "1.0.0", "expected Ruby AI pack 1.0.0");
        assert(rubyPack.analyzer_count === 1 && rubyPack.rule_count === 1, "list_rules Ruby AI pack inventory is wrong");
        assertExactJson(rubyPack.languages, ["ruby"], "list_rules Ruby languages changed");
        assertExactJson(rubyPack.frameworks, ["openai"], "list_rules Ruby frameworks changed");
        assertExactJson(rubyPack.platforms, [], "Ruby pack must not claim platform coverage");
        assertExactJson(rubyPack.limitations, RUBY_AI_PACK_LIMITATIONS, "list_rules Ruby limitations changed");
        const rubyRules = nativeRules.filter((rule: any) => rule.pack_id === "ruby-ai");
        assert(rubyRules.length === 1, "Ruby AI rule ownership changed");
        const rubyRule = rubyRules[0];
        assert(rubyRule.id === RUBY_AI_RULE.id, "Ruby AI rule ID changed");
        assert(rubyRule.severity === RUBY_AI_RULE.severity, "Ruby AI catalog severity changed");
        assertExactJson(rubyRule.cwe, RUBY_AI_RULE.cwe, "Ruby AI catalog CWE mapping changed");
        assertExactJson(rubyRule.owasp_llm, RUBY_AI_RULE.owaspLlm, "Ruby AI catalog OWASP LLM mapping changed");
        const firebasePack = lr.native_packs.find((pack: any) => pack.id === "firebase");
        assert(firebasePack?.version === "1.0.0", "expected Firebase pack 1.0.0");
        assert(firebasePack.analyzer_count === 1 && firebasePack.rule_count === 3, "list_rules Firebase pack inventory is wrong");
        assertExactJson(firebasePack.languages, ["firebase-rules", "json"], "list_rules Firebase languages changed");
        assertExactJson(firebasePack.frameworks, [], "list_rules Firebase frameworks changed");
        assertExactJson(firebasePack.platforms, ["firebase"], "list_rules Firebase platforms changed");
        assertExactJson(firebasePack.limitations, FIREBASE_PACK_LIMITATIONS, "list_rules Firebase limitations changed");
        const firebaseRules = nativeRules.filter((rule: any) => rule.pack_id === "firebase");
        assert(firebaseRules.length === 3, "Firebase rule ownership changed");
        assertExactJson(
          firebaseRules.map((rule: any) => rule.id).sort(),
          FIREBASE_CONFIG_RULES.map((rule) => rule.id).sort(),
          "Firebase rule IDs changed",
        );
        assert(firebaseRules.every((rule: any) => rule.severity === "critical"), "Firebase catalog severity changed");
        assert(firebaseRules.every((rule: any) => JSON.stringify(rule.cwe) === JSON.stringify(["CWE-862", "CWE-285"])), "Firebase catalog CWE mapping changed");
        assert(firebaseRules.every((rule: any) => JSON.stringify(rule.owasp_web) === JSON.stringify(["A01:2021"])), "Firebase catalog OWASP mapping changed");
        const githubActionsPack = lr.native_packs.find((pack: any) => pack.id === "github-actions");
        assert(githubActionsPack?.version === "1.0.0", "expected GitHub Actions pack 1.0.0");
        assert(githubActionsPack.analyzer_count === 1 && githubActionsPack.rule_count === 2, "list_rules GitHub Actions pack inventory is wrong");
        assertExactJson(githubActionsPack.languages, ["yaml"], "list_rules GitHub Actions languages changed");
        assertExactJson(githubActionsPack.frameworks, [], "list_rules GitHub Actions frameworks changed");
        assertExactJson(githubActionsPack.platforms, ["github-actions"], "list_rules GitHub Actions platforms changed");
        assertExactJson(githubActionsPack.limitations, GITHUB_ACTIONS_PACK_LIMITATIONS, "list_rules GitHub Actions limitations changed");
        const githubActionsRules = nativeRules.filter((rule: any) => rule.pack_id === "github-actions");
        assert(githubActionsRules.length === 2, "GitHub Actions rule ownership changed");
        assertExactJson(
          githubActionsRules.map((rule: any) => rule.id).sort(),
          GITHUB_ACTIONS_RULES.map((rule) => rule.id).sort(),
          "GitHub Actions rule IDs changed",
        );
        const pubEngine = lr.engines.find((engine: any) => engine.engine === "codeinspectus-pub");
        assert(pubEngine?.version === "1.0.0" && pubEngine.available === true, "native Pub engine inventory is unavailable");
        const pubDb = lr.advisory_databases?.find((database: any) => database.engine === "codeinspectus-pub");
        assert(["current", "stale"].includes(pubDb?.state), `unexpected Pub database state ${pubDb?.state}`);
        assert(pubDb.active_advisories === 12 && pubDb.affected_packages === 11, "Pub database inventory changed");
        assert(pubDb.matching === "exact-enumerated-versions" && pubDb.license === "CC-BY-4.0", "Pub database provenance changed");
        assert(/^sha256:[a-f0-9]{64}$/.test(pubDb.content_digest), "Pub database content digest missing");
      },
    },
    {
      id: "E15 severity_threshold filters out lower-severity findings",
      fn: async () => {
        const hi = (await client.callTool("codeinspectus_scan", { path: FIXTURE, severity_threshold: "high", scanners: ["ai"] })).structuredContent;
        assert(hi.findings.every((f: any) => ["critical", "high"].includes(f.severity)), "threshold leaked lower severities");
        assert(hi.summary.medium === 0 && hi.summary.low === 0, "threshold summary should have no medium/low");
      },
    },
    {
      id: "E16 [engine] Opengrep detects SQL injection (CWE-89) and NOT the parameterized query",
      engineDep: "opengrep",
      fn: () => {
        const sqli = find((x) => x.cwe.includes("CWE-89") && x.location.file === "src/db.ts");
        assert(!!sqli, "SQLi not detected by Opengrep");
        assert(sqli.location.start_line === 11, `expected SQLi at the unsafe line 11, got ${sqli.location.start_line}`);
        // safe parameterized query is on line 16 — must not be flagged
        const safe = findings.some((x) => x.cwe.includes("CWE-89") && x.location.start_line >= 15);
        assert(!safe, "parameterized query wrongly flagged as SQLi");
      },
    },
    {
      id: "E17 [engine] Trivy detects the outdated vulnerable dependency (lodash/minimist)",
      engineDep: "trivy-vuln",
      fn: () => {
        const dep = find(
          (x) => x.engine === "trivy" && /^(cve-|ghsa-)/i.test(x.rule_id) && /lodash|minimist/i.test(JSON.stringify(x.location) + x.message + x.title),
        );
        assert(!!dep, "no Trivy SCA finding for lodash/minimist");
        assert(dep.frameworks.some((t: any) => t.framework === "EssentialEight"), "vuln dep should map to Essential Eight Patch Applications");
      },
    },
    {
      id: "E18 [engine] CORS rules distinguish invalid wildcard from credentialed arbitrary-origin exposure",
      engineDep: "opengrep",
      fn: async () => {
        const corsScan = (await client.callTool("codeinspectus_scan", { path: CORS_FIXTURE, scanners: ["sast"] })).structuredContent;
        const corsFindings: any[] = corsScan.findings;
        assert(corsScan.detected_technologies.some((technology: any) => technology.id === "typescript"), "technology detection must run on external-engine-only scans");
        const nativeCoverage = corsScan.pack_coverage;
        assert(nativeCoverage.length === 16, `SAST-filtered scan must inventory all sixteen installed native packs, got ${nativeCoverage.length}`);
        assert(nativeCoverage.filter((pack: any) => pack.scanner_kind === "ai").every((pack: any) => pack.state === "not_run" && pack.rules.ran === 0), "SAST-filtered scan must report every AI pack as not_run");
        const baselineCoverage = nativeCoverage.find((pack: any) => pack.pack_id === "javascript-baseline");
        assert(baselineCoverage?.state === "ran" && baselineCoverage.rules.ran === 2, "SAST-filtered scan did not run the JavaScript baseline pack");
        const wildcard = corsFindings.filter((x) => x.rule_id === "ci-baseline-cors-wildcard-credentials");
        const arbitrary = corsFindings.filter((x) => x.rule_id === "ci-baseline-cors-arbitrary-origin-credentials");
        assert(wildcard.length === 3, `expected three invalid wildcard findings, got ${wildcard.length}`);
        assert(/browsers reject/i.test(wildcard[0].message), "wildcard rule must explain browser rejection, not claim data exposure");
        assert(wildcard.every((x) => x.severity === "medium"), "invalid wildcard combination should be medium, below actual arbitrary-origin exposure");
        assert(wildcard.every((x) => x.owasp_web?.includes("A05:2021") && x.owasp_api?.includes("API8:2023")), "wildcard CORS findings need OWASP Web/API mappings");
        assert(arbitrary.length === 6, `expected six arbitrary-origin findings, got ${arbitrary.length}`);
        assert(arbitrary.every((x) => x.severity === "high"), "credentialed arbitrary-origin exposure should remain high");
        assert(arbitrary.every((x) => x.confidence === "high"), "credentialed arbitrary-origin exposure should retain high rule confidence");
        assert(arbitrary.every((x) => x.finding_kind === "sast" && !x.is_secret), "CORS findings must remain SAST, not secrets");
        assert(arbitrary.every((x) => x.owasp_web?.includes("A05:2021") && x.owasp_api?.includes("API8:2023")), "CORS findings need OWASP Web/API mappings");
        assert(arbitrary.every((x) => /allowlist/i.test(x.remediation.summary + " " + x.remediation.steps.join(" "))), "CORS remediation must require an origin allowlist");
        assert(arbitrary.every((x) => x.location.file.startsWith("tp/")), "safe CORS near-miss produced a finding");
      },
    },
    {
      id: "E19 API-boundary rules survive the full MCP scan envelope with redaction and provenance",
      fn: async () => {
        const boundaryScan = (await client.callTool("codeinspectus_scan", { path: API_BOUNDARY_FIXTURE, scanners: ["ai"] })).structuredContent;
        const boundaryFindings: any[] = boundaryScan.findings;
        const counts = (ruleId: string) => boundaryFindings.filter((x) => x.rule_id === ruleId).length;
        assert(boundaryFindings.length === 18, `expected 18 API-boundary findings, got ${boundaryFindings.length}`);
        assert(counts("ci-ai-client-error-leak") === 8, "expected eight internal-error findings");
        assert(counts("ci-ai-sensitive-api-response") === 1, "expected one sensitive-response finding");
        assert(counts("ci-ai-unvalidated-request-write") === 6, "expected six unsafe-write findings");
        assert(counts("ci-ai-sensitive-log") === 3, "expected three sensitive-log findings");
        assert(boundaryFindings.every((x) => x.location.file.startsWith("tp/")), "API-boundary safe near-miss produced a finding");
        assert(boundaryFindings.every((x) => x.owasp_api?.length > 0), "API-boundary finding missing OWASP API mapping");
        assert(boundaryFindings.every((x) => x.producer_components?.some((component: string) => component.startsWith("ai:"))), "API-boundary finding missing detector provenance");
        const serialized = JSON.stringify(boundaryScan);
        assert(!serialized.includes("provider failure") && !serialized.includes("database unavailable"), "API-boundary output leaked planted internal detail");
        assert(boundaryScan.engine_details.some((x: any) => x.engine === "codeinspectus-ai" && x.version === "5.20.0"), "AI engine version was not bumped for expanded multi-pack coverage");
      },
    },
    {
      id: "E20 Enhancement 2 explicit header/CSP/cookie/CAPTCHA configurations emit only evidence-gated findings",
      fn: async () => {
        const scenarios = [
          ["tp/headers-next", "ci-ai-security-header-disabled", 1, "http.header.strict-transport-security"],
          ["tp/headers-route-mixed", "ci-ai-security-header-disabled", 1, "http.header.strict-transport-security"],
          ["tp/csp-vercel", "ci-ai-unsafe-production-csp", 1, "http.header.content-security-policy"],
          ["tp/referrer-next", "ci-ai-unsafe-referrer-policy", 1, "http.header.referrer-policy"],
          ["tp/permissions-nginx", "ci-ai-overbroad-permissions-policy", 1, "http.header.permissions-policy"],
          ["tp/cookies", "ci-ai-insecure-session-cookie", 3, "http.cookie.session-security"],
          ["tp/cookies-mixed", "ci-ai-insecure-session-cookie", 1, "http.cookie.session-security"],
          ["tp/captcha", "ci-ai-supabase-captcha-token-missing", 3, "supabase.auth.captcha-token"],
          ["tp/captcha-mixed", "ci-ai-supabase-captcha-token-missing", 1, "supabase.auth.captcha-token"],
        ] as const;
        for (const [rel, ruleId, count, controlId] of scenarios) {
          const result = (await client.callTool("codeinspectus_scan", {
            path: resolve(SECURITY_CONTROLS_FIXTURE, rel),
            scanners: ["ai"],
          })).structuredContent;
          assert(result.findings.filter((x: any) => x.rule_id === ruleId).length === count, `${rel}: expected ${count} ${ruleId} finding(s)`);
          const evidence = result.security_control_evidence.find((x: any) => x.control_id === controlId);
          assert(evidence?.state === "insecure_configuration_found", `${rel}: insecure evidence state missing`);
          assert(result.findings.every((x: any) => x.owasp_web?.includes("A05:2021") && x.owasp_api?.includes("API8:2023")), `${rel}: finding missing OWASP context`);
        }
      },
    },
    {
      id: "E21 Enhancement 2 safe, hosted-unknown, and conflicting runtime controls remain non-findings",
      fn: async () => {
        const safe = (await client.callTool("codeinspectus_scan", {
          path: resolve(SECURITY_CONTROLS_FIXTURE, "safe/next"),
          scanners: ["ai"],
        })).structuredContent;
        assert(safe.findings.length === 0, "safe Next.js headers produced a finding");
        assert(safe.security_control_evidence.filter((x: any) => x.control_id.startsWith("http.header.")).every((x: any) => x.state === "verified_in_repository"), "safe Next.js header evidence was not verified");

        const headerUnknown = (await client.callTool("codeinspectus_scan", {
          path: resolve(SECURITY_CONTROLS_FIXTURE, "near-miss/header-policy-lookalikes"),
          scanners: ["ai"],
        })).structuredContent;
        assert(headerUnknown.findings.length === 0, "lookalike or removed policy configuration produced a finding");
        for (const controlId of ["http.header.referrer-policy", "http.header.permissions-policy"]) {
          assert(
            headerUnknown.security_control_evidence.find((x: any) => x.control_id === controlId)?.state === "not_verifiable_from_repository",
            `${controlId}: removal/lookalike evidence must remain unknown`,
          );
        }

        const hostedUnknown = (await client.callTool("codeinspectus_scan", {
          path: resolve(SECURITY_CONTROLS_FIXTURE, "near-miss/captcha-hosted-unknown"),
          scanners: ["ai"],
        })).structuredContent;
        assert(hostedUnknown.findings.length === 0, "dashboard-only/hosted CAPTCHA absence produced a finding");
        assert(hostedUnknown.security_control_evidence.find((x: any) => x.control_id === "supabase.auth.captcha-token")?.state === "not_verifiable_from_repository", "hosted CAPTCHA state must remain not verifiable");

        const nonProduction = (await client.callTool("codeinspectus_scan", {
          path: resolve(SECURITY_CONTROLS_FIXTURE, "near-miss/non-production-paths"),
          scanners: ["ai"],
        })).structuredContent;
        assert(nonProduction.findings.length === 0, "test/example/development configuration produced a finding");
        assert(nonProduction.security_control_evidence.every((x: any) => x.state === "not_verifiable_from_repository"), "non-production paths must not contribute runtime-control evidence");

        const conflict = (await client.callTool("codeinspectus_scan", {
          path: resolve(SECURITY_CONTROLS_FIXTURE, "conflict/headers"),
          scanners: ["ai"],
        })).structuredContent;
        assert(conflict.findings.length === 0, "conflicting repository layers produced a vulnerability finding");
        assert(conflict.security_control_evidence.find((x: any) => x.control_id === "http.header.strict-transport-security")?.state === "not_verifiable_from_repository", "conflicting HSTS layers must resolve to not verifiable");
      },
    },
    {
      id: "E22 Supabase Edge deployment auth/authz uses effective config and handler proof",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", {
          path: SUPABASE_EDGE_AUTH_FIXTURE,
          scanners: ["ai"],
        })).structuredContent;
        const unauthenticated = result.findings.filter((x: any) => x.rule_id === "ci-ai-edge-fn-no-auth");
        const unauthorizedAdmin = result.findings.filter((x: any) => x.rule_id === "ci-ai-edge-fn-privileged-no-authz");
        assert(unauthenticated.length === 18, `expected 18 unauthenticated privileged Edge findings, got ${unauthenticated.length}`);
        assert(unauthorizedAdmin.length === 13, `expected 13 privileged Edge authz findings, got ${unauthorizedAdmin.length}`);
        assert(unauthenticated.some((x: any) => x.location.file.endsWith("public-admin/index.ts")), "Edge no-auth rule missed a public privileged sink");
        assert(unauthorizedAdmin.some((x: any) => x.location.file.endsWith("mixed-user-secret-admin/index.ts")), "Edge authz rule missed the user-reachable mixed-mode sink");
        assert(
          [...unauthenticated, ...unauthorizedAdmin].every(
            (finding: any) =>
              finding.producer_components?.includes("ai:supabase-edge-auth") &&
              finding.producer_components?.includes("javascript:bounded-structural-parser"),
          ),
          "Edge auth finding lost detector or parser provenance",
        );
        assert(!result.findings.some((x: any) => x.location.file.endsWith("stripe-webhook/index.ts") || x.location.file.endsWith("with-none-stripe-official/index.ts")), "verified signed webhook produced a finding");
        assert(result.pack_coverage.find((pack: any) => pack.pack_id === "javascript-typescript")?.note?.includes("intent is not statically verifiable"), "public Edge uncertainty was not surfaced in pack coverage");
      },
    },
    {
      id: "E23 Flutter pack exact MCP findings, precision, coverage, provenance, and redaction",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: FLUTTER_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: FLUTTER_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: FLUTTER_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        const tpScan = tp.structuredContent;
        const fpScan = fp.structuredContent;
        const fixedScan = fixed.structuredContent;

        assertFlutterExecutionEnvelope(tpScan, "Flutter TP scan");
        assertFlutterExecutionEnvelope(fpScan, "Flutter FP scan");
        assertFlutterExecutionEnvelope(fixedScan, "Flutter fixed scan");
        assertFlutterTpScan(tpScan, "Flutter TP scan");
        assert(fpScan.findings.length === 0 && fpScan.summary.total === 0, "Flutter FP corpus produced a finding");
        assert(fixedScan.findings.length === 0 && fixedScan.summary.total === 0, "Flutter fixed corpus produced a finding");
        for (const scanResult of [tpScan, fpScan, fixedScan]) {
          for (const platform of ["android", "ios"] as const) {
            const platformPack = scanResult.pack_coverage.find(
              (pack: any) => pack.pack_id === platform,
            );
            assert(
              platformPack?.state === "not_applicable",
              `Flutter corpus unexpectedly activated the ${platform} pack`,
            );
          }
          for (const packId of ["react-native", "expo"]) {
            const frameworkPack = scanResult.pack_coverage.find((pack: any) => pack.pack_id === packId);
            assert(frameworkPack?.state === "not_applicable", `Flutter corpus unexpectedly activated the ${packId} pack`);
          }
        }
      },
    },
    {
      id: "E24 Flutter same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(tmpdir(), "codeinspectus-flutter-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(FLUTTER_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          })).structuredContent;
          assertFlutterExecutionEnvelope(baseline, "Flutter rescan TP baseline");
          assertFlutterTpScan(baseline, "Flutter rescan TP baseline");

          await replaceFixtureDirectory(FLUTTER_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertFlutterExecutionEnvelope(resolved, "Flutter fixed rescan", false);
          assert(
            resolved.summary.resolved === 6 &&
              resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 &&
              resolved.summary.not_rechecked === 0,
            `Flutter fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assert(resolved.partial === false, "Flutter fixed rescan unexpectedly reported a partial comparison");
          assert(resolved.not_rechecked.length === 0, "Flutter fixed rescan contained not_rechecked findings");
          assertExactFlutterRuleIds(resolved.resolved, "Flutter fixed rescan resolved bucket");

          await replaceFixtureDirectory(FLUTTER_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertFlutterExecutionEnvelope(introduced, "Flutter reintroduced TP rescan", false);
          assert(
            introduced.summary.resolved === 0 &&
              introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 6 &&
              introduced.summary.not_rechecked === 0,
            `Flutter reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assert(introduced.partial === false, "Flutter reintroduced rescan unexpectedly reported a partial comparison");
          assert(introduced.not_rechecked.length === 0, "Flutter reintroduced rescan contained not_rechecked findings");
          assertExactFlutterRuleIds(introduced.introduced, "Flutter reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E25 Android and iOS packs exact MCP findings, precision, coverage, provenance, and redaction",
      fn: async () => {
        for (const platform of ["android", "ios"] as const) {
          const root = platform === "android" ? ANDROID_CONFIG_FIXTURE : IOS_CONFIG_FIXTURE;
          const [tp, fp, fixed] = await Promise.all([
            client.callTool("codeinspectus_scan", { path: resolve(root, "tp"), scanners: ["ai"] }),
            client.callTool("codeinspectus_scan", { path: resolve(root, "fp"), scanners: ["ai"] }),
            client.callTool("codeinspectus_scan", { path: resolve(root, "fixed"), scanners: ["ai"] }),
          ]);
          const tpScan = tp.structuredContent;
          const fpScan = fp.structuredContent;
          const fixedScan = fixed.structuredContent;
          assertMobileExecutionEnvelope(tpScan, platform, `${platform} TP scan`);
          assertMobileExecutionEnvelope(fpScan, platform, `${platform} FP scan`);
          assertMobileExecutionEnvelope(fixedScan, platform, `${platform} fixed scan`);
          assertMobileTpScan(tpScan, platform, `${platform} TP scan`);
          assert(
            fpScan.findings.length === 0 && fpScan.summary.total === 0,
            `${platform} FP corpus produced a finding`,
          );
          assert(
            fixedScan.findings.length === 0 && fixedScan.summary.total === 0,
            `${platform} fixed corpus produced a finding`,
          );
          const other = platform === "android" ? "ios" : "android";
          for (const scanResult of [tpScan, fpScan, fixedScan]) {
            const otherPack = scanResult.pack_coverage.find(
              (pack: any) => pack.pack_id === other,
            );
            assert(
              otherPack?.state === "not_applicable",
              `${platform} corpus unexpectedly activated the ${other} pack`,
            );
            const flutterPack = scanResult.pack_coverage.find(
              (pack: any) => pack.pack_id === "flutter",
            );
            assert(
              flutterPack?.state === "not_applicable",
              `${platform} corpus unexpectedly activated the Flutter pack`,
            );
            for (const packId of ["react-native", "expo"]) {
              const frameworkPack = scanResult.pack_coverage.find((pack: any) => pack.pack_id === packId);
              assert(frameworkPack?.state === "not_applicable", `${platform} corpus unexpectedly activated the ${packId} pack`);
            }
          }
        }
      },
    },
    {
      id: "E26 Flutter, Android, and iOS compose through same-path TP-to-fixed-to-TP rescan",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(tmpdir(), "codeinspectus-mobile-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceMobileFixture(target, "tp");
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          })).structuredContent;
          assertFlutterExecutionEnvelope(baseline, "mobile rescan TP Flutter");
          assertMobileExecutionEnvelope(baseline, "android", "mobile rescan TP Android");
          assertMobileExecutionEnvelope(baseline, "ios", "mobile rescan TP iOS");
          assertMobileTpScan(baseline, "android", "mobile rescan TP Android", "android/", true);
          assertMobileTpScan(baseline, "ios", "mobile rescan TP iOS", "ios/", true);
          assert(baseline.findings.length === 8, "mobile rescan baseline did not contain eight findings");

          await replaceMobileFixture(target, "fixed");
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertFlutterExecutionEnvelope(resolved, "mobile fixed rescan Flutter", false);
          assertMobileExecutionEnvelope(resolved, "android", "mobile fixed rescan Android", false);
          assertMobileExecutionEnvelope(resolved, "ios", "mobile fixed rescan iOS", false);
          assert(
            resolved.summary.resolved === 8 &&
              resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 &&
              resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `mobile fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertExactJson(
            resolved.resolved.map((finding: any) => finding.rule_id).sort(),
            MOBILE_CONFIG_RULES.map((rule) => rule.id).sort(),
            "mobile fixed rescan resolved rule IDs changed",
          );
          assert(resolved.not_rechecked.length === 0, "mobile fixed rescan contained not_rechecked findings");

          await replaceMobileFixture(target, "tp");
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertFlutterExecutionEnvelope(introduced, "mobile TP reintroduction Flutter", false);
          assertMobileExecutionEnvelope(introduced, "android", "mobile TP reintroduction Android", false);
          assertMobileExecutionEnvelope(introduced, "ios", "mobile TP reintroduction iOS", false);
          assert(
            introduced.summary.resolved === 0 &&
              introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 8 &&
              introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `mobile reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertExactJson(
            introduced.introduced.map((finding: any) => finding.rule_id).sort(),
            MOBILE_CONFIG_RULES.map((rule) => rule.id).sort(),
            "mobile reintroduced rule IDs changed",
          );
          assert(introduced.not_rechecked.length === 0, "mobile reintroduced rescan contained not_rechecked findings");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E27 native Pub SCA exact MCP findings, exclusions, fixed boundaries, and provenance",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: PUB_TP_FIXTURE, scanners: ["vuln"] }),
          client.callTool("codeinspectus_scan", { path: PUB_FP_FIXTURE, scanners: ["vuln"] }),
          client.callTool("codeinspectus_scan", { path: PUB_FIXED_FIXTURE, scanners: ["vuln"] }),
        ]);
        const tpScan = tp.structuredContent;
        const fpScan = fp.structuredContent;
        const fixedScan = fixed.structuredContent;
        assertPubTpScan(tpScan, "Pub TP scan");
        assert(nativePubFindings(fpScan).length === 0, "Pub FP corpus produced a native advisory finding");
        assert(nativePubFindings(fixedScan).length === 0, "Pub fixed corpus produced a native advisory finding");
        for (const [label, result] of [["FP", fpScan], ["fixed", fixedScan]] as const) {
          const coverage = result.dependency_coverage?.find((item: any) => item.engine === "codeinspectus-pub");
          // FP has git and custom-hosted dependencies (unverifiable → partial); fixed has only the
          // Flutter SDK package, which has no Pub advisories, so its coverage is complete.
          assert(coverage?.state === (label === "FP" ? "partial" : "ran"), `Pub ${label} scan coverage state changed`);
          assert(coverage.lockfiles.analyzed === 1, `Pub ${label} lockfile was not analyzed`);
          assert(result.detected_technologies.some((technology: any) => technology.id === "dart"), `Pub ${label} Dart detection missing`);
        }
      },
    },
    {
      id: "E28 native Pub same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(tmpdir(), "codeinspectus-pub-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(PUB_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["vuln"],
          })).structuredContent;
          assertPubTpScan(baseline, "Pub rescan TP baseline");

          await replaceFixtureDirectory(PUB_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["vuln"],
          })).structuredContent;
          const resolvedPub = resolved.resolved.filter((finding: any) =>
            finding.producer_components?.includes("codeinspectus-pub:osv-snapshot")
          );
          assertPubAdvisorySet(resolvedPub, "Pub fixed rescan resolved advisory identities");
          assert(
            resolved.remaining.filter((finding: any) => finding.engines?.includes("codeinspectus-pub")).length === 0 &&
              resolved.not_rechecked.filter((finding: any) => finding.engines?.includes("codeinspectus-pub")).length === 0,
            `Pub fixed rescan was not provably resolved: ${JSON.stringify(resolved.summary)}`,
          );

          await replaceFixtureDirectory(PUB_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["vuln"],
          })).structuredContent;
          const introducedPub = introduced.introduced.filter((finding: any) =>
            finding.producer_components?.includes("codeinspectus-pub:osv-snapshot")
          );
          assertPubAdvisorySet(introducedPub, "Pub reintroduced advisory identities");
          assert(
            introduced.not_rechecked.filter((finding: any) => finding.engines?.includes("codeinspectus-pub")).length === 0,
            "Pub reintroduced rescan contained not_rechecked native findings",
          );
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E29 native Pub CycloneDX/SPDX SBOM generation works with Trivy merge or fallback",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(tmpdir(), "codeinspectus-pub-sbom-"));
        try {
          for (const format of ["cyclonedx", "spdx"] as const) {
            const outputPath = join(temporaryRoot, `pub.${format}.json`);
            const result = (await client.callTool("codeinspectus_generate_sbom", {
              path: PUB_FIXED_FIXTURE,
              format,
              output_path: outputPath,
            })).structuredContent;
            assert(result.generated === true && result.offline === true, `${format}: SBOM was not generated offline`);
            assert(result.providers.includes("codeinspectus-pub"), `${format}: native Pub provider missing`);
            assert(["combined", "native_only"].includes(result.coverage_state), `${format}: unexpected coverage state ${result.coverage_state}`);
            assert(result.lockfiles_analyzed === 1 && result.component_count >= 5, `${format}: Pub inventory count changed`);
            assert(result.ecosystems.includes("Pub"), `${format}: Pub ecosystem metadata missing`);
            const document = JSON.parse(await readFile(outputPath, "utf8"));
            if (format === "cyclonedx") {
              assert(document.bomFormat === "CycloneDX", "CycloneDX document marker missing");
              assert(document.components.some((component: any) => component.purl === "pkg:pub/jose@0.3.5%2B1"), "CycloneDX encoded jose purl missing");
            } else {
              assert(document.spdxVersion === "SPDX-2.3", "SPDX document marker missing");
              assert(document.packages.some((pkg: any) => pkg.externalRefs?.some((reference: any) => reference.referenceLocator === "pkg:pub/jose@0.3.5%2B1")), "SPDX encoded jose purl missing");
            }
          }
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E30 React Native and Expo exact MCP findings, precision, coverage, provenance, and redaction",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: REACT_NATIVE_EXPO_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: REACT_NATIVE_EXPO_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: REACT_NATIVE_EXPO_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        const tpScan = tp.structuredContent;
        const fpScan = fp.structuredContent;
        const fixedScan = fixed.structuredContent;
        assertReactNativeExpoExecutionEnvelope(tpScan, "React Native/Expo TP scan");
        assertReactNativeExpoExecutionEnvelope(fpScan, "React Native/Expo FP scan");
        assertReactNativeExpoExecutionEnvelope(fixedScan, "React Native/Expo fixed scan");
        assertReactNativeExpoTpScan(tpScan, "React Native/Expo TP scan");
        assert(
          fpScan.findings.length === 0 && fpScan.summary.total === 0,
          "React Native/Expo FP corpus produced a finding",
        );
        assert(
          fixedScan.findings.length === 0 && fixedScan.summary.total === 0,
          "React Native/Expo fixed corpus produced a finding",
        );
      },
    },
    {
      id: "E31 React Native and Expo same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(tmpdir(), "codeinspectus-react-native-expo-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(REACT_NATIVE_EXPO_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          })).structuredContent;
          assertReactNativeExpoExecutionEnvelope(baseline, "React Native/Expo rescan TP baseline");
          assertReactNativeExpoTpScan(baseline, "React Native/Expo rescan TP baseline");

          await replaceFixtureDirectory(REACT_NATIVE_EXPO_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertReactNativeExpoExecutionEnvelope(resolved, "React Native/Expo fixed rescan", false);
          assert(
            resolved.summary.resolved === 6 &&
              resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 &&
              resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `React Native/Expo fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertExactReactNativeExpoRuleIds(
            resolved.resolved,
            "React Native/Expo fixed rescan resolved bucket",
          );
          assert(resolved.not_rechecked.length === 0, "React Native/Expo fixed rescan contained not_rechecked findings");

          await replaceFixtureDirectory(REACT_NATIVE_EXPO_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertReactNativeExpoExecutionEnvelope(introduced, "React Native/Expo TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 &&
              introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 6 &&
              introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `React Native/Expo reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertExactReactNativeExpoRuleIds(
            introduced.introduced,
            "React Native/Expo reintroduced rescan introduced bucket",
          );
          assert(introduced.not_rechecked.length === 0, "React Native/Expo reintroduced rescan contained not_rechecked findings");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E32 Python AI/API exact MCP findings, precision, coverage, provenance, and redaction",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: PYTHON_AI_API_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: PYTHON_AI_API_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: PYTHON_AI_API_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        const tpScan = tp.structuredContent;
        const fpScan = fp.structuredContent;
        const fixedScan = fixed.structuredContent;

        assertPythonAiApiExecutionEnvelope(tpScan, "Python AI/API TP scan");
        assertPythonAiApiExecutionEnvelope(fpScan, "Python AI/API FP scan");
        assertPythonAiApiExecutionEnvelope(fixedScan, "Python AI/API fixed scan");
        assertPythonAiApiTpScan(tpScan, "Python AI/API TP scan");
        assert(
          fpScan.findings.length === 0 && fpScan.summary.total === 0,
          "Python AI/API FP corpus produced a finding",
        );
        assert(
          fixedScan.findings.length === 0 && fixedScan.summary.total === 0,
          "Python AI/API fixed corpus produced a finding",
        );
      },
    },
    {
      id: "E33 Python AI/API same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        // macOS exposes os.tmpdir() through /var, which is a symlink to /private/var.
        // Use the canonical parent so the Python pack's ancestor-symlink guard can
        // distinguish the harness path from a target-selected symlink escape.
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-python-ai-api-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(PYTHON_AI_API_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          })).structuredContent;
          assertPythonAiApiExecutionEnvelope(baseline, "Python AI/API rescan TP baseline");
          assertPythonAiApiTpScan(baseline, "Python AI/API rescan TP baseline");

          await replaceFixtureDirectory(PYTHON_AI_API_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertPythonAiApiExecutionEnvelope(resolved, "Python AI/API fixed rescan", false);
          assert(
            resolved.summary.resolved === 10 &&
              resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 &&
              resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `Python AI/API fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertExactPythonAiApiRuleIds(
            resolved.resolved,
            "Python AI/API fixed rescan resolved bucket",
          );
          assert(resolved.not_rechecked.length === 0, "Python AI/API fixed rescan contained not_rechecked findings");

          await replaceFixtureDirectory(PYTHON_AI_API_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertPythonAiApiExecutionEnvelope(introduced, "Python AI/API TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 &&
              introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 10 &&
              introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `Python AI/API reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertExactPythonAiApiRuleIds(
            introduced.introduced,
            "Python AI/API reintroduced rescan introduced bucket",
          );
          assert(introduced.not_rechecked.length === 0, "Python AI/API reintroduced rescan contained not_rechecked findings");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E34 Opengrep/native JavaScript baseline shadow parity is exact",
      engineDep: "opengrep",
      fn: async () => {
        const [tp, fp, fixed, direct] = await Promise.all([
          runOpengrepShadowParity(resolve(OPENGREP_SHADOW_FIXTURE, "tp")),
          runOpengrepShadowParity(resolve(OPENGREP_SHADOW_FIXTURE, "fp")),
          runOpengrepShadowParity(resolve(OPENGREP_SHADOW_FIXTURE, "fixed")),
          runOpengrepShadowParity(resolve(OPENGREP_SHADOW_FIXTURE, "tp", "01_hash.js")),
        ]);
        assert(tp.passed, `shadow TP parity failed: ${JSON.stringify(tp.comparison)}`);
        assert(fp.passed, `shadow FP parity failed: ${JSON.stringify(fp.comparison)}`);
        assert(fixed.passed, `shadow fixed parity failed: ${JSON.stringify(fixed.comparison)}`);
        assert(direct.passed, `shadow direct-file parity failed: ${JSON.stringify(direct.comparison)}`);
        assert(
          tp.comparison.reference_count === 6 && tp.comparison.candidate_count === 6 &&
            tp.comparison.matched_count === 6,
          `shadow TP multiplicity changed: ${JSON.stringify(tp.comparison)}`,
        );
        assert(
          fp.comparison.reference_count === 0 && fixed.comparison.reference_count === 0,
          "shadow FP/fixed corpus produced selected findings",
        );
        assert(
          direct.comparison.reference_count === 1 && direct.comparison.candidate_count === 1,
          `shadow direct-file identity changed: ${JSON.stringify(direct.comparison)}`,
        );
      },
    },
    {
      id: "E35 promoted JavaScript baseline surfaces native-only provenance with Opengrep fallback active",
      engineDep: "opengrep",
      fn: async () => {
        const scan = (await client.callTool("codeinspectus_scan", {
          path: resolve(OPENGREP_SHADOW_FIXTURE, "tp"),
          scanners: ["sast"],
          max_findings: 50,
        })).structuredContent;
        const promoted = scan.findings.filter((finding: any) =>
          finding.rule_id === "ci-baseline-weak-hash" || finding.rule_id === "ci-baseline-weak-cipher"
        );
        assert(promoted.length === 5, `expected 5 post-dedup promoted findings, got ${promoted.length}`);
        assert(
          promoted.every((finding: any) =>
            finding.engine === "codeinspectus-ai" &&
            finding.engines.length === 1 && finding.engines[0] === "codeinspectus-ai" &&
            finding.finding_kind === "sast" &&
            finding.producer_components.includes("native-sast:opengrep-reconciliation") &&
            !finding.producer_components.some((component: string) => component.startsWith("opengrep:"))
          ),
          "promoted findings carried mixed or non-native provenance",
        );
        const baseline = scan.pack_coverage.find((pack: any) => pack.pack_id === "javascript-baseline");
        assert(
          baseline?.scanner_kind === "sast" && baseline.state === "ran" &&
          baseline.analyzers.ran === 1 && baseline.rules.ran === 2,
          `JavaScript baseline coverage was wrong: ${JSON.stringify(baseline)}`,
        );
        assert(
          scan.pack_coverage.filter((pack: any) => pack.scanner_kind === "ai").every((pack: any) => pack.state === "not_run"),
          "SAST-only scan executed an AI pack",
        );
      },
    },
    {
      id: "E36 promoted JavaScript baseline same-path rescan proves fixed and reintroduced states",
      engineDep: "opengrep",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-javascript-baseline-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(resolve(OPENGREP_SHADOW_FIXTURE, "tp"), target);
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["sast"],
            max_findings: 50,
          })).structuredContent;
          assert(baseline.summary.total === 5, `promotion rescan baseline changed: ${JSON.stringify(baseline.summary)}`);

          await replaceFixtureDirectory(resolve(OPENGREP_SHADOW_FIXTURE, "fixed"), target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["sast"],
            max_findings: 50,
          })).structuredContent;
          assert(
            resolved.summary.resolved === 5 && resolved.summary.remaining === 0 &&
            resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
            resolved.partial === false,
            `promotion fixed rescan was wrong: ${JSON.stringify(resolved.summary)}`,
          );

          await replaceFixtureDirectory(resolve(OPENGREP_SHADOW_FIXTURE, "tp"), target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["sast"],
            max_findings: 50,
          })).structuredContent;
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
            introduced.summary.introduced === 5 && introduced.summary.not_rechecked === 0 &&
            introduced.partial === false,
            `promotion reintroduction rescan was wrong: ${JSON.stringify(introduced.summary)}`,
          );
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E37 Go AI corpus is exact through the built MCP server",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: GO_AI_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: GO_AI_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: GO_AI_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        for (const [label, response] of [["TP", tp], ["FP", fp], ["fixed", fixed]] as const) {
          assertGoAiExecutionEnvelope(response.structuredContent, `Go AI ${label}`);
        }
        assertGoAiTpScan(tp.structuredContent, "Go AI TP");
        assert(fp.structuredContent.findings.length === 0, "Go AI FP corpus produced a finding");
        assert(fixed.structuredContent.findings.length === 0, "Go AI fixed corpus produced a finding");
      },
    },
    {
      id: "E38 Go AI same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-go-ai-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(GO_AI_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          })).structuredContent;
          assertGoAiExecutionEnvelope(baseline, "Go AI rescan TP baseline");
          assertGoAiTpScan(baseline, "Go AI rescan TP baseline");

          await replaceFixtureDirectory(GO_AI_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertGoAiExecutionEnvelope(resolved, "Go AI fixed rescan", false);
          assert(
            resolved.summary.resolved === 3 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `Go AI fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertGoAiFindings(resolved.resolved, "Go AI fixed rescan resolved bucket");

          await replaceFixtureDirectory(GO_AI_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertGoAiExecutionEnvelope(introduced, "Go AI TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 3 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `Go AI reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertGoAiFindings(introduced.introduced, "Go AI reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E39 Java AI corpus is exact through the built MCP server",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: JAVA_AI_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: JAVA_AI_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: JAVA_AI_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        for (const [label, response] of [["TP", tp], ["FP", fp], ["fixed", fixed]] as const) {
          assertJavaAiExecutionEnvelope(response.structuredContent, `Java AI ${label}`);
        }
        assertJavaAiTpScan(tp.structuredContent, "Java AI TP");
        assert(fp.structuredContent.findings.length === 0, "Java AI FP corpus produced a finding");
        assert(fixed.structuredContent.findings.length === 0, "Java AI fixed corpus produced a finding");
      },
    },
    {
      id: "E40 Java AI same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-java-ai-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(JAVA_AI_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          })).structuredContent;
          assertJavaAiExecutionEnvelope(baseline, "Java AI rescan TP baseline");
          assertJavaAiTpScan(baseline, "Java AI rescan TP baseline");

          await replaceFixtureDirectory(JAVA_AI_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertJavaAiExecutionEnvelope(resolved, "Java AI fixed rescan", false);
          assert(
            resolved.summary.resolved === 3 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `Java AI fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertJavaAiFindings(resolved.resolved, "Java AI fixed rescan resolved bucket");

          await replaceFixtureDirectory(JAVA_AI_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertJavaAiExecutionEnvelope(introduced, "Java AI TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 3 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `Java AI reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertJavaAiFindings(introduced.introduced, "Java AI reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E41 C# AI corpus is exact through the built MCP server",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: CSHARP_AI_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: CSHARP_AI_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: CSHARP_AI_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        for (const [label, response] of [["TP", tp], ["FP", fp], ["fixed", fixed]] as const) {
          assertCsharpAiExecutionEnvelope(response.structuredContent, `C# AI ${label}`);
        }
        assertCsharpAiTpScan(tp.structuredContent, "C# AI TP");
        assert(fp.structuredContent.findings.length === 0, "C# AI FP corpus produced a finding");
        assert(fixed.structuredContent.findings.length === 0, "C# AI fixed corpus produced a finding");
      },
    },
    {
      id: "E42 C# AI same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-csharp-ai-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(CSHARP_AI_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["ai"] })).structuredContent;
          assertCsharpAiExecutionEnvelope(baseline, "C# AI rescan TP baseline");
          assertCsharpAiTpScan(baseline, "C# AI rescan TP baseline");

          await replaceFixtureDirectory(CSHARP_AI_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertCsharpAiExecutionEnvelope(resolved, "C# AI fixed rescan", false);
          assert(
            resolved.summary.resolved === 3 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `C# AI fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertCsharpAiFindings(resolved.resolved, "C# AI fixed rescan resolved bucket");

          await replaceFixtureDirectory(CSHARP_AI_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertCsharpAiExecutionEnvelope(introduced, "C# AI TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 3 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `C# AI reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertCsharpAiFindings(introduced.introduced, "C# AI reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E43 PHP AI corpus is exact through the built MCP server",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: PHP_AI_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: PHP_AI_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: PHP_AI_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        for (const [label, response] of [["TP", tp], ["FP", fp], ["fixed", fixed]] as const) {
          assertPhpAiExecutionEnvelope(response.structuredContent, `PHP AI ${label}`);
        }
        assertPhpAiTpScan(tp.structuredContent, "PHP AI TP");
        assert(fp.structuredContent.findings.length === 0, "PHP AI FP corpus produced a finding");
        assert(fixed.structuredContent.findings.length === 0, "PHP AI fixed corpus produced a finding");
      },
    },
    {
      id: "E44 PHP AI same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-php-ai-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(PHP_AI_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["ai"] })).structuredContent;
          assertPhpAiExecutionEnvelope(baseline, "PHP AI rescan TP baseline");
          assertPhpAiTpScan(baseline, "PHP AI rescan TP baseline");

          await replaceFixtureDirectory(PHP_AI_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertPhpAiExecutionEnvelope(resolved, "PHP AI fixed rescan", false);
          assert(
            resolved.summary.resolved === 3 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `PHP AI fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertPhpAiFindings(resolved.resolved, "PHP AI fixed rescan resolved bucket");

          await replaceFixtureDirectory(PHP_AI_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertPhpAiExecutionEnvelope(introduced, "PHP AI TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 3 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `PHP AI reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertPhpAiFindings(introduced.introduced, "PHP AI reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E45 Rust AI corpus is exact through the built MCP server",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: RUST_AI_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: RUST_AI_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: RUST_AI_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        for (const [label, response] of [["TP", tp], ["FP", fp], ["fixed", fixed]] as const) {
          assertRustAiExecutionEnvelope(response.structuredContent, `Rust AI ${label}`);
        }
        assertRustAiTpScan(tp.structuredContent, "Rust AI TP");
        assert(fp.structuredContent.findings.length === 0, "Rust AI FP corpus produced a finding");
        assert(fixed.structuredContent.findings.length === 0, "Rust AI fixed corpus produced a finding");
      },
    },
    {
      id: "E46 Rust AI same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-rust-ai-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(RUST_AI_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["ai"] })).structuredContent;
          assertRustAiExecutionEnvelope(baseline, "Rust AI rescan TP baseline");
          assertRustAiTpScan(baseline, "Rust AI rescan TP baseline");

          await replaceFixtureDirectory(RUST_AI_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertRustAiExecutionEnvelope(resolved, "Rust AI fixed rescan", false);
          assert(
            resolved.summary.resolved === 3 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `Rust AI fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertRustAiFindings(resolved.resolved, "Rust AI fixed rescan resolved bucket");

          await replaceFixtureDirectory(RUST_AI_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertRustAiExecutionEnvelope(introduced, "Rust AI TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 3 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `Rust AI reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertRustAiFindings(introduced.introduced, "Rust AI reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E47 Ruby AI corpus is exact through the built MCP server",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: RUBY_AI_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: RUBY_AI_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: RUBY_AI_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        for (const [label, response] of [["TP", tp], ["FP", fp], ["fixed", fixed]] as const) {
          assertRubyAiExecutionEnvelope(response.structuredContent, `Ruby AI ${label}`);
        }
        assertRubyAiTpScan(tp.structuredContent, "Ruby AI TP");
        assert(fp.structuredContent.findings.length === 0, "Ruby AI FP corpus produced a finding");
        assert(fixed.structuredContent.findings.length === 0, "Ruby AI fixed corpus produced a finding");
      },
    },
    {
      id: "E48 Ruby AI same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-ruby-ai-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(RUBY_AI_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["ai"] })).structuredContent;
          assertRubyAiExecutionEnvelope(baseline, "Ruby AI rescan TP baseline");
          assertRubyAiTpScan(baseline, "Ruby AI rescan TP baseline");

          await replaceFixtureDirectory(RUBY_AI_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertRubyAiExecutionEnvelope(resolved, "Ruby AI fixed rescan", false);
          assert(
            resolved.summary.resolved === 3 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `Ruby AI fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertRubyAiFindings(resolved.resolved, "Ruby AI fixed rescan resolved bucket");

          await replaceFixtureDirectory(RUBY_AI_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertRubyAiExecutionEnvelope(introduced, "Ruby AI TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 3 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `Ruby AI reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertRubyAiFindings(introduced.introduced, "Ruby AI reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E49 Firebase configuration corpus is exact through the built MCP server",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: FIREBASE_CONFIG_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: FIREBASE_CONFIG_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: FIREBASE_CONFIG_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        for (const [label, response] of [["TP", tp], ["FP", fp], ["fixed", fixed]] as const) {
          assertFirebaseExecutionEnvelope(response.structuredContent, `Firebase ${label}`);
        }
        assertFirebaseTpScan(tp.structuredContent, "Firebase TP");
        assert(fp.structuredContent.findings.length === 0, "Firebase FP corpus produced a finding");
        assert(fixed.structuredContent.findings.length === 0, "Firebase fixed corpus produced a finding");
      },
    },
    {
      id: "E50 Firebase same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-firebase-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(FIREBASE_CONFIG_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["ai"] })).structuredContent;
          assertFirebaseExecutionEnvelope(baseline, "Firebase rescan TP baseline");
          assertFirebaseTpScan(baseline, "Firebase rescan TP baseline");

          await replaceFixtureDirectory(FIREBASE_CONFIG_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertFirebaseExecutionEnvelope(resolved, "Firebase fixed rescan", false);
          assert(
            resolved.summary.resolved === 3 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `Firebase fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertFirebaseFindings(resolved.resolved, "Firebase fixed rescan resolved bucket");

          await replaceFixtureDirectory(FIREBASE_CONFIG_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertFirebaseExecutionEnvelope(introduced, "Firebase TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 3 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `Firebase reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertFirebaseFindings(introduced.introduced, "Firebase reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E51 GitHub Actions workflow corpus is exact through the built MCP server",
      fn: async () => {
        const [tp, fp, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: GITHUB_ACTIONS_TP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: GITHUB_ACTIONS_FP_FIXTURE, scanners: ["ai"] }),
          client.callTool("codeinspectus_scan", { path: GITHUB_ACTIONS_FIXED_FIXTURE, scanners: ["ai"] }),
        ]);
        for (const [label, response] of [["TP", tp], ["FP", fp], ["fixed", fixed]] as const) {
          assertGithubActionsExecutionEnvelope(response.structuredContent, `GitHub Actions ${label}`);
        }
        assertGithubActionsTpScan(tp.structuredContent, "GitHub Actions TP");
        assert(fp.structuredContent.findings.length === 0, "GitHub Actions FP corpus produced a finding");
        assert(fixed.structuredContent.findings.length === 0, "GitHub Actions fixed corpus produced a finding");
      },
    },
    {
      id: "E52 GitHub Actions same-path TP-to-fixed-to-TP rescan proves resolution and introduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-github-actions-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(GITHUB_ACTIONS_TP_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["ai"] })).structuredContent;
          assertGithubActionsExecutionEnvelope(baseline, "GitHub Actions rescan TP baseline");
          assertGithubActionsTpScan(baseline, "GitHub Actions rescan TP baseline");

          await replaceFixtureDirectory(GITHUB_ACTIONS_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertGithubActionsExecutionEnvelope(resolved, "GitHub Actions fixed rescan", false);
          assert(
            resolved.summary.resolved === 2 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `GitHub Actions fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertGithubActionsFindings(resolved.resolved, "GitHub Actions fixed rescan resolved bucket");

          await replaceFixtureDirectory(GITHUB_ACTIONS_TP_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assertGithubActionsExecutionEnvelope(introduced, "GitHub Actions TP reintroduction", false);
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 2 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `GitHub Actions reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertGithubActionsFindings(introduced.introduced, "GitHub Actions reintroduced rescan introduced bucket");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E53 Next.js admin authorization corpus is exact through the built MCP server",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", {
          path: NEXTJS_ADMIN_ROUTE_FIXTURE,
          scanners: ["ai"],
        })).structuredContent;
        const findings = result.findings.filter(
          (finding: any) => finding.rule_id === "ci-ai-nextjs-admin-route-no-authz",
        );
        assert(findings.length === 81, `expected 81 Next.js admin-route findings, got ${findings.length}`);
        assert(
          findings.every(
            (finding: any) =>
              finding.location.file.startsWith("tp/") &&
              finding.producer_components?.includes("ai:nextjs-admin-route") &&
              finding.producer_components?.includes("javascript:bounded-structural-parser"),
          ),
          "Next.js admin-route precision or provenance changed",
        );
        assert(
          !result.findings.some(
            (finding: any) =>
              finding.rule_id === "ci-ai-nextjs-admin-route-no-authz" &&
              /^(?:fp|fixed)\//.test(finding.location.file),
          ),
          "Next.js FP/fixed corpus produced an admin-route finding",
        );
        const pack = result.pack_coverage.find(
          (candidate: any) => candidate.pack_id === "javascript-typescript",
        );
        // Pre-release field validation item 3: the deliberate limits are declared, acceptable gaps.
        const gapFiles = (id: string) => result.coverage_gaps?.find((gap: any) => gap.id === id)?.files;
        assert(
          pack?.state === "ran" && pack.analyzers.ran === 12 && pack.rules.ran === 29 &&
            gapFiles("nextjs-routes-unresolved") === 5 && gapFiles("native-parse-errors") === 2,
          "Next.js adversarial corpus did not expose its deliberate JavaScript/TypeScript coverage limits",
        );
      },
    },
    {
      id: "E54 Express admin authorization survives built-MCP dedup and same-path rescans",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-express-auth-rescan-"));
        const target = join(temporaryRoot, "admin.ts");
        const vulnerable = [
          'import express from "express";',
          "const app = express();",
          "app.delete('/api/admin/users', async (_req, res) => {",
          "  await db.users.deleteMany();",
          "  return res.sendStatus(204);",
          "});",
        ].join("\n");
        const fixed = [
          'import express from "express";',
          "const app = express();",
          "app.delete('/api/admin/users', async (req, res) => {",
          "  if (!req.user) return res.sendStatus(401);",
          "  if (req.user.role !== 'admin') return res.sendStatus(403);",
          "  await db.users.deleteMany();",
          "  return res.sendStatus(204);",
          "});",
        ].join("\n");
        try {
          await writeFile(target, vulnerable);
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          })).structuredContent;
          const baselineFindings = baseline.findings.filter(
            (finding: any) => finding.rule_id === "ci-ai-express-admin-route-no-authz",
          );
          assert(baselineFindings.length === 1, `expected one Express baseline finding, got ${baselineFindings.length}`);
          assert(
            baselineFindings[0].producer_components?.includes("ai:express-admin-route") &&
              baselineFindings[0].producer_components?.includes("javascript:bounded-structural-parser"),
            "Express finding lost detector or parser provenance",
          );

          await writeFile(target, fixed);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assert(
            resolved.summary.resolved === 1 && resolved.summary.remaining === 0 &&
              resolved.summary.introduced === 0 && resolved.summary.not_rechecked === 0 &&
              resolved.partial === false,
            `Express fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assert(
            resolved.resolved[0]?.rule_id === "ci-ai-express-admin-route-no-authz",
            "Express fixed rescan resolved the wrong finding",
          );

          await writeFile(target, vulnerable);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assert(
            introduced.summary.resolved === 0 && introduced.summary.remaining === 0 &&
              introduced.summary.introduced === 1 && introduced.summary.not_rechecked === 0 &&
              introduced.partial === false,
            `Express reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assert(
            introduced.introduced[0]?.rule_id === "ci-ai-express-admin-route-no-authz",
            "Express reintroduced rescan surfaced the wrong finding",
          );
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E55 source-integrity markers are exact, bounded, and vendor-neutral through built MCP",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-source-integrity-"));
        const target = join(temporaryRoot, "integrity.ts");
        const source = [
          `const admin\u200BRole = "owner";`,
          `const allowed = true; // \u202E } hidden branch`,
          `const heart = "❤️";`,
          `// \u2067مرحبا بالعالم\u2069`,
        ].join("\n");
        try {
          await writeFile(target, source, "utf8");
          const response = await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          });
          const result = response.structuredContent;
          const trust = result.repository_trust;
          const sourceCoverage = trust.coverage.capabilities.find(
            (capability: any) => capability.capability === "source_integrity",
          );
          assert(
            sourceCoverage?.state === "ran" &&
              sourceCoverage.validators?.includes("codeinspectus-source-integrity@1.0.0"),
            `source-integrity coverage was not complete: ${JSON.stringify(sourceCoverage)}`,
          );
          assert(trust.coverage.state === "partial", "unimplemented provenance capabilities were not fail-closed");
          assert(trust.artifacts.length === 2, `expected two source-integrity artifacts, got ${trust.artifacts.length}`);
          const markerClasses = trust.artifacts.map((artifact: any) => artifact.marker_class).sort();
          assert(
            JSON.stringify(markerClasses) === JSON.stringify(["unicode_bidi_override", "unicode_zero_width_token"]),
            `unexpected marker classes: ${JSON.stringify(markerClasses)}`,
          );
          assert(
            trust.artifacts.every(
              (artifact: any) =>
                artifact.kind === "source_integrity" && artifact.state === "verified" &&
                artifact.location.file === "integrity.ts" && artifact.location.start_line > 0 &&
                artifact.location.start_column > 0 && artifact.remediation.requires_approval === true &&
                artifact.remediation.reversible === true,
            ),
            "source-integrity artifacts lost exact location or approval-gated remediation metadata",
          );
          assert(
            trust.artifacts.every((artifact: any) =>
              artifact.evidence.attributes.some((attribute: any) => attribute.name === "escaped_sequence") &&
              artifact.evidence.attributes.some((attribute: any) => attribute.name === "utf8_byte_offset") &&
              artifact.evidence.attributes.some((attribute: any) => attribute.name === "proposed_action")
            ),
            "source-integrity artifacts lost independently inspectable evidence",
          );
          assert(
            !/claude|anthropic|vendor.watermark|ai.generated/i.test(JSON.stringify(trust)),
            "source-integrity evidence was mislabeled as vendor or AI attribution",
          );
          const humanText = response.content.map((item: any) => item.text ?? "").join("\n");
          assert(/U\+200B/.test(humanText), "human output omitted the escaped code point");
          assert(!humanText.includes("\u200B"), "human output emitted the raw invisible marker");
          assert(/approval required before cleanup/i.test(humanText), "human output omitted the approval gate");
          assert((await readFile(target, "utf8")) === source, "the read-only scan mutated its target");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E56 source-integrity same-path rescan proves resolution and reintroduction",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-source-rescan-"));
        const target = join(temporaryRoot, "integrity.ts");
        const marked = `const admin\u200BRole = "owner";\n`;
        const fixed = `const adminRole = "owner";\n`;
        try {
          await writeFile(target, marked, "utf8");
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["ai"],
          })).structuredContent;
          assert(baseline.repository_trust.artifacts.length === 1, "source-integrity baseline was not exact");

          await writeFile(target, fixed, "utf8");
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assert(
            resolved.repository_trust_changes.summary.resolved === 1 &&
              resolved.repository_trust_changes.summary.remaining === 0 &&
              resolved.repository_trust_changes.summary.introduced === 0 &&
              resolved.repository_trust_changes.summary.not_rechecked === 0 &&
              resolved.repository_trust_changes.partial === false,
            `source-integrity fixed rescan diff was wrong: ${JSON.stringify(resolved.repository_trust_changes)}`,
          );

          await writeFile(target, marked, "utf8");
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assert(
            introduced.repository_trust_changes.summary.resolved === 0 &&
              introduced.repository_trust_changes.summary.remaining === 0 &&
              introduced.repository_trust_changes.summary.introduced === 1 &&
              introduced.repository_trust_changes.summary.not_rechecked === 0 &&
              introduced.repository_trust_changes.partial === false,
            `source-integrity reintroduction diff was wrong: ${JSON.stringify(introduced.repository_trust_changes)}`,
          );
          assert(
            introduced.repository_trust_changes.introduced[0]?.marker_class === "unicode_zero_width_token",
            "source-integrity reintroduction surfaced the wrong artifact",
          );
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E57 V3.2 explicit attribution and media metadata survive built MCP and rescan",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-ai-provenance-"));
        const source = join(temporaryRoot, "generated.ts");
        const image = join(temporaryRoot, "generated.png");
        const marked = `// Generated by Claude Code\nexport const value = 1;\n`;
        const fixed = `export const value = 1;\n`;
        const pngWithMetadata = Buffer.from(
          "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAFHRFWHRTb2Z0d2FyZQBDbGF1ZGUgQ29kZUU+WAAAAAAASUVORK5CYII=",
          "base64",
        );
        try {
          await writeFile(source, marked, "utf8");
          await writeFile(image, pngWithMetadata);
          const response = await client.callTool("codeinspectus_scan", {
            path: temporaryRoot,
            scanners: ["ai"],
          });
          const baseline = response.structuredContent;
          const explicitCoverage = baseline.repository_trust.coverage.capabilities.find(
            (capability: any) => capability.capability === "explicit_ai_attribution",
          );
          assert(
            explicitCoverage?.state === "ran" &&
              explicitCoverage.validators?.includes("codeinspectus-explicit-ai-attribution@1.0.0") &&
              explicitCoverage.validators?.includes("codeinspectus-media-metadata@1.0.0"),
            `V3.2 explicit-attribution coverage was wrong: ${JSON.stringify(explicitCoverage)}`,
          );
          const explicitArtifacts = baseline.repository_trust.artifacts.filter(
            (artifact: any) => artifact.kind === "explicit_ai_attribution",
          );
          assert(explicitArtifacts.length === 2, `expected two explicit-attribution artifacts, got ${explicitArtifacts.length}`);
          assert(
            explicitArtifacts.some((artifact: any) =>
              artifact.marker_class === "explicit_generator_attribution" && artifact.location.file === "generated.ts"
            ),
            "source attribution was not surfaced through built MCP",
          );
          assert(
            explicitArtifacts.some((artifact: any) =>
              artifact.marker_class === "explicit_generator_metadata" && artifact.location.file === "generated.png"
            ),
            "media generator metadata was not surfaced through built MCP",
          );
          assert(
            explicitArtifacts.every((artifact: any) =>
              artifact.state === "verified" && artifact.remediation.eligible === true &&
              artifact.remediation.reversible === true && artifact.remediation.requires_approval === true
            ),
            "V3.3 attribution artifacts lost approval-gated remediation boundaries",
          );
          const humanText = response.content.map((item: any) => item.text ?? "").join("\n");
          assert(/explicit_ai_attribution: ran/.test(humanText), "human summary omitted V3.2 capability coverage");

          await writeFile(source, fixed, "utf8");
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: temporaryRoot,
            prior_scan_id: baseline.scan_id,
            scanners: ["ai"],
          })).structuredContent;
          assert(
            resolved.repository_trust_changes.resolved.some(
              (artifact: any) => artifact.marker_class === "explicit_generator_attribution",
            ) &&
              resolved.repository_trust_changes.remaining.some(
                (artifact: any) => artifact.marker_class === "explicit_generator_metadata",
              ) &&
              resolved.repository_trust_changes.summary.not_rechecked === 0,
            `V3.2 attribution rescan diff was wrong: ${JSON.stringify(resolved.repository_trust_changes)}`,
          );
          assert((await readFile(image)).equals(pngWithMetadata), "the read-only provenance scan mutated media bytes");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E58 V3.3 built MCP plans, applies, verifies, and rolls back exact source cleanup",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-verified-cleanup-"));
        const source = join(temporaryRoot, "app.ts");
        const marked = `// Generated by Claude Code\nconst user\u200Bname = true;\n`;
        let auditDirectory: string | undefined;
        try {
          await writeFile(source, marked, "utf8");
          const baseline = (await client.callTool("codeinspectus_scan", {
            path: temporaryRoot,
            scanners: ["ai"],
          })).structuredContent;
          const artifactIds = baseline.repository_trust.artifacts
            .filter((artifact: any) => artifact.location.file === "app.ts" && artifact.remediation.eligible)
            .map((artifact: any) => artifact.artifact_id);
          assert(artifactIds.length === 2, `expected two V3.3 cleanup artifacts, got ${artifactIds.length}`);

          const planned = (await client.callTool("codeinspectus_plan_cleanup", {
            path: temporaryRoot,
            artifact_ids: artifactIds,
          })).structuredContent;
          assert(planned.outcome === "ready" && planned.operations.length === 1, `V3.3 cleanup plan was not ready: ${JSON.stringify(planned)}`);
          assert(planned.approval.exact_artifact_ids.length === 2 && planned.checkpoint.strategy === "managed_content_backup", "V3.3 plan omitted approval/checkpoint contract");

          const appliedResponse = await client.callTool("codeinspectus_apply_cleanup", {
            plan_id: planned.plan_id,
            approved_artifact_ids: artifactIds,
            confirm_cleanup: true,
            confirm_rights_to_modify: true,
          });
          const applied = appliedResponse.structuredContent;
          auditDirectory = dirname(applied.audit_log_path);
          assert(applied.outcome === "incomplete" && applied.operations.every((operation: any) => operation.status === "applied"), `V3.3 cleanup mutation state was wrong: ${JSON.stringify(applied)}`);
          assert(applied.verification.same_validators_ran === true && applied.verification.targeted_artifacts_resolved === true, "V3.3 cleanup lacked same-validator proof");
          assert(applied.verification.repository_checks.state === "not_run" && applied.verification.repository_checks.required === true, "V3.3 cleanup overclaimed repository verification");
          assert((await readFile(source, "utf8")) === "const username = true;\n", "V3.3 cleanup changed unexpected source bytes");

          const rolledBack = (await client.callTool("codeinspectus_rollback_cleanup", {
            cleanup_id: applied.cleanup_id,
            confirm_rollback: true,
          })).structuredContent;
          assert(rolledBack.outcome === "rolled_back", `V3.3 rollback failed: ${JSON.stringify(rolledBack)}`);
          assert((await readFile(source, "utf8")) === marked, "V3.3 rollback did not restore the exact preimage");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
          if (auditDirectory) await rm(auditDirectory, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E59 OSV PyPI corpus is exact through the built MCP server",
      engineDep: "osv-pypi",
      fn: async () => {
        const [vulnerable, fixed] = await Promise.all([
          client.callTool("codeinspectus_scan", { path: OSV_PYPI_VULNERABLE_FIXTURE, scanners: ["vuln"] }),
          client.callTool("codeinspectus_scan", { path: OSV_PYPI_FIXED_FIXTURE, scanners: ["vuln"] }),
        ]);
        for (const [label, response] of [["vulnerable", vulnerable], ["fixed", fixed]] as const) {
          const result = response.structuredContent;
          assert(
            result.engines_run.some((engine: string) => engine.startsWith("osv-scanner@")),
            `OSV ${label}: osv-scanner did not run`,
          );
          const pypi = result.dependency_coverage.find((c: any) => c.engine === "osv-scanner" && c.ecosystem === "PyPI");
          assert(
            pypi?.state === "ran" && pypi.packages.resolved === 3 && pypi.packages.eligible === 3 && pypi.packages.skipped === 0,
            `OSV ${label}: PyPI coverage was not 3/3: ${JSON.stringify(pypi)}`,
          );
        }
        assertOsvPypiTargetedFindings(vulnerable.structuredContent.findings, "OSV vulnerable corpus");
        assertNoOsvPypiTargetedFindings(fixed.structuredContent.findings, "OSV fixed corpus");

        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-osv-rescan-"));
        const target = join(temporaryRoot, "project");
        try {
          await replaceFixtureDirectory(OSV_PYPI_VULNERABLE_FIXTURE, target);
          const baseline = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["vuln"] })).structuredContent;
          assertOsvPypiTargetedFindings(baseline.findings, "OSV rescan baseline");

          await replaceFixtureDirectory(OSV_PYPI_FIXED_FIXTURE, target);
          const resolved = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: baseline.scan_id,
            scanners: ["vuln"],
          })).structuredContent;
          assert(
            resolved.summary.resolved >= 3 &&
              resolved.summary.not_rechecked === 0 && resolved.partial === false,
            `OSV fixed rescan diff was wrong: ${JSON.stringify(resolved.summary)}`,
          );
          assertOsvPypiTargetedFindings(resolved.resolved, "OSV fixed rescan resolved bucket");
          assertNoOsvPypiTargetedFindings([...resolved.remaining, ...resolved.introduced], "OSV fixed rescan remaining/introduced");

          await replaceFixtureDirectory(OSV_PYPI_VULNERABLE_FIXTURE, target);
          const introduced = (await client.callTool("codeinspectus_rescan", {
            path: target,
            prior_scan_id: resolved.scan_id,
            scanners: ["vuln"],
          })).structuredContent;
          assert(
            introduced.summary.introduced >= 3 &&
              introduced.summary.not_rechecked === 0 && introduced.partial === false,
            `OSV reintroduced rescan diff was wrong: ${JSON.stringify(introduced.summary)}`,
          );
          assertOsvPypiTargetedFindings(introduced.introduced, "OSV reintroduced rescan introduced bucket");
          assertNoOsvPypiTargetedFindings([...introduced.resolved, ...introduced.remaining], "OSV reintroduced rescan resolved/remaining");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E62 [engine] Opengrep runs under a UTF-8 locale when the host sets none",
      engineDep: "opengrep",
      fn: async () => {
        const localeless = new McpClient({ LANG: undefined, LC_ALL: undefined, LC_CTYPE: undefined });
        try {
          await localeless.init();
          const result = (await localeless.callTool("codeinspectus_scan", {
            path: join(COVERAGE_HONESTY_FIXTURE, "opengrep-utf8"),
            scanners: ["sast"],
          })).structuredContent;
          const opengrep = result.engine_details.find((engine: any) => engine.engine === "opengrep");
          assert(opengrep?.ran === true, `Opengrep did not run without a host locale: ${opengrep?.note}`);
          const planted = result.findings.find((finding: any) =>
            finding.rule_id === "ci-baseline-dangerous-eval" && finding.location.file === "src/app.js");
          assert(planted?.location.start_line === 4 && planted.engines.includes("opengrep"), "the planted eval() was not reported by Opengrep");
          assert(planted.location.snippet?.includes("caf\u00e9 \u2014"), `non-ASCII snippet text was not decoded as UTF-8: ${planted.location.snippet}`);
        } finally {
          localeless.close();
        }
      },
    },
    {
      id: "E60 OSV cannot be silenced by the scanned repo",
      engineDep: "osv-pypi",
      fn: async () => {
        // The fixture's root and nested osv-scanner.toml both ignore the advisory. The .gitignore that hides
        // both lockfiles is written into a temp copy at run time (a committed one would make git skip the
        // fixture's own requirements files); osv-scanner must still read them and report the advisory.
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-osv-suppressed-"));
        const target = join(temporaryRoot, "project");
        let suppressed: any;
        try {
          await replaceFixtureDirectory(OSV_PYPI_SUPPRESSED_FIXTURE, target);
          await writeFile(join(target, ".gitignore"), "requirements.txt\n", "utf8");
          suppressed = (await client.callTool("codeinspectus_scan", {
            path: target,
            scanners: ["vuln"],
          })).structuredContent;
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
        const malware = suppressed.findings.filter((f: any) => osvAdvisoryMatches(f, OSV_MALWARE_ID));
        assertExactJson(
          malware.map((f: any) => f.location.file).sort(),
          ["nested/requirements.txt", "requirements.txt"],
          `a repo-planted osv-scanner.toml or .gitignore hid ${OSV_MALWARE_ID}`,
        );
        assert(
          malware.every((f: any) =>
            f.package?.ecosystem === "PyPI" && f.package.name === "litellm" && f.package.version === "1.107.0" &&
            f.engines?.includes("osv-scanner")),
          `suppressed fixture findings were not osv-scanner litellm 1.107.0: ${JSON.stringify(malware.map((f: any) => f.package))}`,
        );
      },
    },
    {
      id: "E61 OSV never reports a missing ecosystem database as clean",
      engineDep: "osv-scanner",
      fn: async () => {
        // A lockfile whose ecosystem database is absent is "not checked", never an empty (clean) result.
        const noDb = (await client.callTool("codeinspectus_scan", {
          path: OSV_CARGO_NO_DB_FIXTURE,
          scanners: ["vuln"],
        })).structuredContent;
        const crates = noDb.dependency_coverage.find((c: any) => c.engine === "osv-scanner" && c.ecosystem === "crates.io");
        if (crates && crates.state !== "unavailable") {
          // CI installs only the PyPI database; a maintainer machine with crates.io installed cannot show this case.
          throw new EvalSkip(`OSV crates.io database is installed here (coverage ${crates.state}), so the missing-database case cannot run`);
        }
        assert(
          crates?.state === "unavailable" && crates.lockfiles.analyzed === 0 && crates.packages.eligible === 0 &&
            crates.packages.resolved > 0 && crates.packages.skipped === crates.packages.resolved,
          `a missing OSV crates.io database was not reported as unavailable coverage: ${JSON.stringify(crates)}`,
        );
        assert(
          noDb.warnings.some((w: string) => w.includes("crates.io") && w.includes("codeinspectus setup")),
          `missing OSV crates.io database produced no \`codeinspectus setup\` warning: ${JSON.stringify(noDb.warnings)}`,
        );
        assert(
          !noDb.engines_run.some((engine: string) => engine.startsWith("osv-scanner@")) &&
            !noDb.findings.some((f: any) => f.engines?.includes("osv-scanner")),
          "osv-scanner was reported as having checked crates.io packages without their database",
        );
      },
    },
    {
      id: "E63 [engine] a repository .semgrepignore cannot remove files from Opengrep's scan",
      engineDep: "opengrep",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", {
          path: join(COVERAGE_HONESTY_FIXTURE, "opengrep-ignore-suppress"),
          scanners: ["sast"],
        })).structuredContent;
        const opengrep = result.engine_details.find((engine: any) => engine.engine === "opengrep");
        assert(opengrep?.ran === true, `Opengrep did not run: ${opengrep?.note}`);
        const evals = result.findings.filter((finding: any) => finding.rule_id === "ci-baseline-dangerous-eval");
        assert(
          evals.some((finding: any) => finding.location.file === "src/app.js" && finding.engines.includes("opengrep")),
          "the repository .semgrepignore (src/) hid the planted eval() from Opengrep",
        );
        assert(
          !evals.some((finding: any) => finding.location.file === "public/app.min.js"),
          "Opengrep's default ignores (*.min.js) no longer applied",
        );
      },
    },
    {
      id: "E64 [engine] Trivy dependency findings name the package and its fixed version",
      engineDep: "trivy-vuln",
      fn: () => {
        const dependencies = findings.filter((x) => x.engines.includes("trivy") && x.finding_kind === "vulnerability");
        assert(dependencies.length > 0, "no Trivy dependency finding in the vulnerable-app scan");
        for (const finding of dependencies) {
          if (finding.engine !== "trivy") {
            // Merged into another engine's finding for the same package (osv-scanner): the survivor's own
            // text applies, and it must still name the package and an upgrade of it.
            const pkg = finding.package;
            assert(!!pkg?.name && !!pkg.version, `${finding.rule_id}: merged ${finding.engine} finding has no package`);
            assert(finding.title.includes(` (${pkg.name}@${pkg.version}`), `${finding.rule_id}: title does not name ${pkg.name}@${pkg.version}`);
            assert(finding.remediation.summary.startsWith(`Upgrade ${pkg.name} `), `${finding.rule_id}: remediation is "${finding.remediation.summary}"`);
            continue;
          }
          const name = /^Package: (\S+)$/m.exec(finding.message)?.[1];
          const installed = /^Installed Version: (\S+)$/m.exec(finding.message)?.[1];
          const fixed = /^Fixed Version: *(\S.*)$/m.exec(finding.message)?.[1];
          assert(!!name && !!installed, `${finding.rule_id}: Trivy message lost its package fields`);
          assert(finding.title.endsWith(` (${name}@${installed})`), `${finding.rule_id}: title does not name ${name}@${installed}`);
          if (fixed) {
            assert(
              finding.remediation.summary.startsWith(`Upgrade ${name} from ${installed} to `),
              `${finding.rule_id}: Trivy supplied fixed version ${fixed} but remediation is "${finding.remediation.summary}"`,
            );
          }
        }
      },
    },
    {
      id: "E65 valid JSX text with an apostrophe or a bare slash keeps JavaScript coverage complete",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", {
          path: join(COVERAGE_HONESTY_FIXTURE, "jsx-text"),
          scanners: ["ai", "sast"],
        })).structuredContent;
        for (const packId of ["javascript-typescript", "javascript-baseline"]) {
          const pack = result.pack_coverage.find((coverage: any) => coverage.pack_id === packId);
          assert(pack?.state === "ran", `${packId} read ${pack?.state}: ${pack?.note}`);
          assert(!/malformed/i.test(pack.note ?? ""), `${packId} still skips valid JSX: ${pack.note}`);
        }
        assert(!result.warnings.some((warning: string) => /malformed/i.test(warning)), "a malformed-source warning remained");
      },
    },
    {
      id: "E66 [engine] only a .gitleaksignore entry Gitleaks can match lowers secret coverage",
      engineDep: "gitleaks",
      fn: async () => {
        const relative = (await client.callTool("codeinspectus_scan", {
          path: join(COVERAGE_HONESTY_FIXTURE, "gitleaksignore-relative"),
          scanners: ["secret"],
        })).structuredContent;
        assert(
          relative.findings.some((x: any) => x.engines.includes("gitleaks") && x.location.file === "config.yml" && x.location.start_line === 3),
          "Gitleaks did not report the key a relative .gitleaksignore entry names",
        );
        assert(relative.secret_coverage === "verified", `a relative .gitleaksignore entry lowered secret coverage to ${relative.secret_coverage}`);
        assert(relative.secret_suppression?.channels[0]?.handling === "ignored_by_codeinspectus", "relative .gitleaksignore not disclosed as inert");

        const temporaryRoot = await mkdtemp(join(tmpdir(), "codeinspectus-e66-"));
        try {
          const target = await realpath(temporaryRoot);
          await cp(join(COVERAGE_HONESTY_FIXTURE, "gitleaksignore-relative", "config.yml"), join(target, "config.yml"));
          await writeFile(join(target, ".gitleaksignore"), `${join(target, "config.yml")}:generic-api-key:3\n`, "utf8");
          const absolute = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["secret"] })).structuredContent;
          assert(
            !absolute.findings.some((x: any) => x.engines.includes("gitleaks") && x.location.file === "config.yml"),
            "an absolute .gitleaksignore entry no longer hides the finding; revisit the classifier",
          );
          assert(absolute.secret_coverage === "unverified", "an absolute .gitleaksignore entry hid a finding but coverage read verified");
          // Gitleaks trims with Go's TrimSpace, which also strips U+0085 (NEL).
          await writeFile(join(target, ".gitleaksignore"), `\u0085${join(target, "config.yml")}:generic-api-key:3\n`, "utf8");
          const nel = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["secret"] })).structuredContent;
          assert(
            !nel.findings.some((x: any) => x.engines.includes("gitleaks") && x.location.file === "config.yml"),
            "a NEL-prefixed absolute .gitleaksignore entry no longer hides the finding; revisit the classifier",
          );
          assert(nel.secret_coverage === "unverified", "a NEL-prefixed .gitleaksignore entry hid a finding but coverage read verified");
          // Review C2: Gitleaks looks up the whole absolute "<file>:<rule>:<line>", so ':' in the path
          // (a `colon:target` checkout or a `sub:dir/` folder) does not stop an absolute entry.
          // Windows forbids ':' in file names, so these folders cannot exist there.
          for (const [folder, sub] of process.platform === "win32" ? [] : [["colon:target", ""], ["plain", "sub:dir"]] as const) {
            const colonTarget = join(target, folder);
            await mkdir(join(colonTarget, sub), { recursive: true });
            const secretFile = join(colonTarget, sub, "config.yml");
            await cp(join(COVERAGE_HONESTY_FIXTURE, "gitleaksignore-relative", "config.yml"), secretFile);
            await writeFile(join(colonTarget, ".gitleaksignore"), `${secretFile}:generic-api-key:3\n`, "utf8");
            const colon = (await client.callTool("codeinspectus_scan", { path: colonTarget, scanners: ["secret"] })).structuredContent;
            assert(!colon.findings.some((x: any) => x.engines.includes("gitleaks")), `${folder}/${sub}: the absolute entry no longer hides the finding; revisit the classifier`);
            assert(colon.secret_coverage === "unverified", `${folder}/${sub}: an absolute entry with ':' in its path hid a finding but coverage read verified`);
          }
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E67 a committed Yarn release bundle is vendored tooling, not an oversized source",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e67-"));
        try {
          await cp(join(COVERAGE_HONESTY_FIXTURE, "jsx-text"), temporaryRoot, { recursive: true });
          await mkdir(join(temporaryRoot, ".yarn", "releases"), { recursive: true });
          await writeFile(join(temporaryRoot, ".yarn", "releases", "yarn-4.6.0.cjs"), `/*${"x".repeat(2_800_000)}*/\n`, "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: temporaryRoot, scanners: ["ai", "sast"] })).structuredContent;
          for (const packId of ["javascript-typescript", "javascript-baseline"]) {
            const pack = result.pack_coverage.find((coverage: any) => coverage.pack_id === packId);
            assert(pack?.state === "ran" && !/oversized/i.test(pack.note ?? ""), `${packId} read ${pack?.state}: ${pack?.note}`);
          }
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E68 [engine] a scanned repository's trivy.yaml, .trivyignore and trivy-secret.yaml do not configure Trivy",
      engineDep: "trivy-vuln",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e68-"));
        try {
          await mkdir(join(temporaryRoot, "src"));
          for (const file of ["package.json", "package-lock.json", "src/config.ts"]) {
            await cp(join(FIXTURE, file), join(temporaryRoot, file));
          }
          await writeFile(join(temporaryRoot, "Dockerfile"), "FROM node:latest\nRUN echo build\n", "utf8");
          // Each of these hid findings on the real Trivy 0.76.1 binary when Trivy ran inside the target.
          await writeFile(join(temporaryRoot, "trivy.yaml"), "severity:\n  - CRITICAL\n", "utf8");
          await writeFile(join(temporaryRoot, ".trivyignore"), "CVE-2019-10744\nDS-0002\nstripe-secret-token\n", "utf8");
          await writeFile(join(temporaryRoot, "trivy-secret.yaml"), "disable-rules:\n  - stripe-secret-token\n", "utf8");
          const result = (await client.callTool("codeinspectus_scan", {
            path: temporaryRoot,
            scanners: ["vuln", "misconfig", "secret"],
          })).structuredContent;
          const trivy = result.findings.filter((x: any) => x.engines.includes("trivy"));
          for (const id of ["CVE-2019-10744", "CVE-2020-8203", "DS-0002"]) {
            assert(trivy.some((x: any) => x.rule_id === id), `${id} was hidden by repository Trivy configuration`);
          }
          assert(trivy.some((x: any) => x.is_secret && x.location.file === "src/config.ts"), "repository trivy-secret.yaml disabled a Trivy secret rule");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E69 [engine] a single-file scan ignores the .gitleaksignore beside the file",
      engineDep: "gitleaks",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e69-"));
        try {
          const file = join(temporaryRoot, "config.yml");
          await cp(join(COVERAGE_HONESTY_FIXTURE, "gitleaksignore-relative", "config.yml"), file);
          // Gitleaks 8.30.1 run from the file's directory applied this entry and hid the finding.
          await writeFile(join(temporaryRoot, ".gitleaksignore"), `${file}:generic-api-key:3\n`, "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: file, scanners: ["secret"] })).structuredContent;
          assert(
            result.findings.some((x: any) => x.engines.includes("gitleaks") && x.location.file === "config.yml"),
            `the neighbouring .gitleaksignore hid the finding while secret coverage read ${result.secret_coverage}`,
          );
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // Ruling 14: a parse error is the acceptable gap sast-parse-errors, not the non-acceptable warning.
      id: "E70 [engine] files Opengrep skips for size or cannot parse make SAST coverage partial",
      engineDep: "opengrep",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e70-"));
        try {
          await cp(join(COVERAGE_HONESTY_FIXTURE, "opengrep-utf8", "src"), join(temporaryRoot, "src"), { recursive: true });
          // Over Opengrep's 1,000,000-byte target limit, and a syntax error: both used to read as covered.
          await writeFile(join(temporaryRoot, "src", "generated.js"), `const data = [${"0,".repeat(600_000)}];\neval(location.hash);\n`, "utf8");
          await writeFile(join(temporaryRoot, "src", "broken.js"), "function broken( {\n  return eval(x;\n", "utf8");
          // A non-source file over the limit (field run 2026-11-05) is an informational note, never partial.
          await writeFile(join(temporaryRoot, "src", "logo.png"), Buffer.alloc(1_100_000, 0x89));
          const result = (await client.callTool("codeinspectus_scan", { path: temporaryRoot, scanners: ["sast"] })).structuredContent;
          assert(result.engine_details.some((engine: any) => engine.engine === "opengrep" && engine.ran), "Opengrep did not run");
          const note = result.warnings.find((warning: string) => warning.startsWith("Opengrep SAST coverage partial"));
          assert(!!note, `no Opengrep partial-coverage warning: ${JSON.stringify(result.warnings)}`);
          assert(/1 over Opengrep's file size limit/.test(note) && note.includes("src/generated.js"), `size skip not reported: ${note}`);
          assert(!note.includes("logo.png"), `a non-source size skip made SAST coverage partial: ${note}`);
          assert(result.coverage_notes?.some((entry: any) => entry.component === "engine:opengrep" && /non-source file\(s\) over its file size limit.*src\/logo\.png/.test(entry.detail)),
            `no informational note for the non-source size skip: ${JSON.stringify(result.coverage_notes)}`);
          assert(!note.includes("src/broken.js"), `a parse error was reported as a non-acceptable warning: ${note}`);
          const parse = result.coverage_gaps?.find((gap: any) => gap.id === "sast-parse-errors");
          assertExactJson(parse, { id: "sast-parse-errors", files: 1, examples: ["src/broken.js"] }, "parse error not declared as a gap");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE is internal to Opengrep: this fails if a bump drops it.
      id: "E71 [engine] Opengrep's ignore list applies inside the target, never to the folders above it",
      engineDep: "opengrep",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e71-"));
        try {
          for (const parent of ["build", "tests", "node_modules"]) {
            const target = join(temporaryRoot, parent, "app");
            await cp(join(COVERAGE_HONESTY_FIXTURE, "opengrep-ignore-suppress"), target, { recursive: true });
            const result = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["sast"] })).structuredContent;
            const evals = result.findings.filter((x: any) => x.rule_id === "ci-baseline-dangerous-eval" && x.engines.includes("opengrep"));
            assert(evals.some((x: any) => x.location.file === "src/app.js"), `a checkout under ${parent}/ (or its .semgrepignore) hid the planted eval()`);
            assert(!evals.some((x: any) => x.location.file === "public/app.min.js"), `Opengrep's default *.min.js exclusion stopped applying under ${parent}/`);
          }
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E72 [engine] Opengrep scans git-ignored files in the target like the other engines",
      engineDep: "opengrep",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e72-"));
        try {
          const planted = await readFile(join(COVERAGE_HONESTY_FIXTURE, "opengrep-ignore-suppress", "src", "app.js"), "utf8");
          await mkdir(join(temporaryRoot, "generated"));
          await writeFile(join(temporaryRoot, ".gitignore"), "generated/\n", "utf8");
          await writeFile(join(temporaryRoot, "generated", "forced.js"), planted, "utf8");
          await writeFile(join(temporaryRoot, "generated", "local.js"), planted, "utf8");
          const git = (...args: string[]) => execFileSync("git", [
            "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
            "-c", "user.name=CodeInspectus eval", "-c", "user.email=eval@example.invalid", ...args,
          ], { cwd: temporaryRoot, stdio: "ignore" });
          git("init", "-q");
          git("add", ".gitignore");
          git("add", "-f", "generated/forced.js"); // committed although .gitignore matches it
          git("commit", "-q", "-m", "fixture");
          const result = (await client.callTool("codeinspectus_scan", { path: temporaryRoot, scanners: ["sast"] })).structuredContent;
          const files = result.findings
            .filter((x: any) => x.rule_id === "ci-baseline-dangerous-eval" && x.engines.includes("opengrep"))
            .map((x: any) => x.location.file);
          assert(files.includes("generated/forced.js"), "Opengrep skipped a committed file that .gitignore matches");
          assert(files.includes("generated/local.js"), "Opengrep silently skipped an untracked git-ignored file the other engines scan");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // Task 5 (Hibi, 2026-10-31): declared gaps are partial coverage with stable ids; accept_gaps is
      // an explicit opt-in that keeps them listed, and an unknown id is an input error.
      id: "E73 declared coverage gaps are listed by stable id and can only be accepted by name",
      fn: async () => {
        const path = join(COVERAGE_HONESTY_FIXTURE, "coverage-gaps");
        const plain = (await client.callTool("codeinspectus_scan", { path })).structuredContent;
        assertExactJson(
          plain.coverage_gaps.map((gap: any) => [gap.id, gap.files, gap.examples]),
          [["php-sast", 1, ["src/page.html.twig"]], ["deno-lock", 1, ["deno.lock"]],
            ["no-lockfile-npm", 1, ["package.json"]], ["no-lockfile-composer", 1, ["composer.json"]]],
          "declared coverage gaps changed",
        );
        assert(plain.accepted_gaps === undefined, "gaps were accepted without accept_gaps");
        const accepted = (await client.callTool("codeinspectus_scan", { path, accept_gaps: ["php-sast", "deno-lock"] })).structuredContent;
        assertExactJson(accepted.accepted_gaps, ["php-sast", "deno-lock"], "accepted gaps not listed");
        assert(accepted.coverage_gaps.length === 4, "an accepted gap disappeared from coverage_gaps");
        let rejected = false;
        try {
          const response = await client.callTool("codeinspectus_scan", { path, accept_gaps: ["everything"] });
          rejected = response.isError === true;
        } catch {
          rejected = true;
        }
        assert(rejected, "an unknown accept_gaps id was not rejected as an input error");
      },
    },
    {
      // Review C-1: host or CI settings such as Semgrep's diff-aware SEMGREP_BASELINE_REF or a team's
      // TRIVY_SEVERITY must not narrow a scan while coverage reads complete.
      id: "E74 [engine] inherited SEMGREP_*, TRIVY_* and GITLEAKS_* settings do not narrow a scan",
      engineDep: "trivy-vuln",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e74-"));
        try {
          const target = join(temporaryRoot, "repo");
          await cp(FIXTURE, target, { recursive: true });
          const git = (...args: string[]) => execFileSync("git", [
            "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
            "-c", "user.name=CodeInspectus eval", "-c", "user.email=eval@example.invalid", ...args,
          ], { cwd: target, stdio: "ignore" });
          git("init", "-q");
          git("add", "-A");
          git("commit", "-q", "-m", "fixture");
          await writeFile(join(temporaryRoot, "trivy.yaml"), "severity:\n  - CRITICAL\n", "utf8");
          await writeFile(join(temporaryRoot, "gitleaks.toml"), "[allowlist]\npaths = ['.*']\n", "utf8");
          const inherited = new McpClient({
            SEMGREP_BASELINE_REF: "HEAD",
            TRIVY_SEVERITY: "CRITICAL",
            TRIVY_CONFIG: join(temporaryRoot, "trivy.yaml"),
            GITLEAKS_CONFIG: join(temporaryRoot, "gitleaks.toml"),
          });
          let findings: any[] = [];
          try {
            await inherited.init();
            findings = (await inherited.callTool("codeinspectus_scan", { path: target })).structuredContent.findings;
          } finally {
            inherited.close();
          }
          if (engineRan("opengrep")) {
            assert(findings.some((x) => x.engines.includes("opengrep") && x.cwe.includes("CWE-89") && x.location.file === "src/db.ts"),
              "SEMGREP_BASELINE_REF narrowed Opengrep to changed files");
          }
          assert(findings.some((x) => x.engines.includes("trivy") && x.rule_id === "CVE-2020-8203"),
            "TRIVY_SEVERITY or TRIVY_CONFIG hid a non-critical Trivy finding");
          if (engineRan("gitleaks")) {
            assert(findings.some((x) => x.engines.includes("gitleaks") && x.location.file === "src/config.ts"),
              "GITLEAKS_CONFIG replaced the bundled Gitleaks config");
          }
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // Ruling 13: a rule arm that binds a metavariable another clause needs makes Opengrep report an
      // "Internal matching error" for the whole file. Every bundled rule has a folder here named by its
      // id; tp/ must fire that rule, fp/ and known-gap/ must stay quiet, and no file may error.
      id: "E75 [engine] every bundled Opengrep rule fires on its fixtures and none errors while matching",
      engineDep: "opengrep",
      fn: async () => {
        const rulesDir = resolve(process.cwd(), "detection-db/opengrep-rules/security-baseline");
        const ruleIds: string[] = [];
        for (const name of (await readdir(rulesDir)).filter((x) => x.endsWith(".yaml"))) {
          for (const match of (await readFile(join(rulesDir, name), "utf8")).matchAll(/^ {2}- id: (\S+)$/gm)) ruleIds.push(match[1] ?? "");
        }
        const folders = await readdir(OPENGREP_RULES_FIXTURE);
        assertExactJson([...folders].sort(), [...ruleIds].sort(), "fixture folders and bundled Opengrep rule ids differ");
        const result = (await client.callTool("codeinspectus_scan", { path: OPENGREP_RULES_FIXTURE, scanners: ["sast"] })).structuredContent;
        assert(result.engine_details.some((engine: any) => engine.engine === "opengrep" && engine.ran), "Opengrep did not run");
        const partial = result.warnings.filter((warning: string) => warning.startsWith("Opengrep SAST coverage partial"));
        assert(partial.length === 0, `Opengrep reported skipped or failed files: ${JSON.stringify(partial)}`);
        assert(!result.coverage_gaps?.some((gap: any) => gap.id === "sast-parse-errors"), "Opengrep could not parse a rule fixture");
        const hits = new Set<string>();
        // By rule id, not engine: native SAST reconciliation reports some rules (e.g. JS weak-hash) as its own.
        for (const finding of result.findings.filter((x: any) => ruleIds.includes(x.rule_id))) {
          const [folder, kind] = finding.location.file.split("/");
          assert(folder === finding.rule_id && kind === "tp", `${finding.rule_id} fired at ${finding.location.file}:${finding.location.start_line}`);
          hits.add(finding.location.file);
        }
        for (const id of ruleIds) {
          for (const file of await readdir(join(OPENGREP_RULES_FIXTURE, id, "tp"))) {
            assert(hits.has(`${id}/tp/${file}`), `${id} missed ${id}/tp/${file}`);
          }
        }
      },
    },
    {
      // Review I-7: Gitleaks 8.30.1 applies its default allowlist to absolute paths, so a target under
      // node_modules/ or site-packages/ reported no secrets while secret coverage read verified.
      id: "E76 [engine] a target under a folder Gitleaks allowlists still gets its secrets scanned",
      engineDep: "gitleaks",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e76-"));
        try {
          for (const parent of ["node_modules/pkg", "bower_components/lib", "vendor/bundle/gem", "lib/python3.12/site-packages/pkg"]) {
            const target = join(temporaryRoot, ...parent.split("/"));
            await mkdir(target, { recursive: true });
            await cp(join(COVERAGE_HONESTY_FIXTURE, "gitleaksignore-relative", "config.yml"), join(target, "config.yml"));
            const result = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["secret"] })).structuredContent;
            if (process.platform === "win32") {
              // Windows scans the real path (no link), so the allowlist applies and must be disclosed.
              assert(result.secret_coverage === "unverified", `secret coverage under ${parent} read ${result.secret_coverage} on Windows`);
              assert(result.warnings.some((warning: string) => warning.startsWith("Secret coverage unverified: Gitleaks' default allowlist")),
                `the allowlisted target under ${parent} was not disclosed on Windows`);
              continue;
            }
            assert(
              result.findings.some((x: any) => x.engines.includes("gitleaks") && x.location.file === "config.yml" && x.location.start_line === 3),
              `Gitleaks reported nothing for a target under ${parent}`,
            );
            assert(result.secret_coverage === "verified", `secret coverage under ${parent} read ${result.secret_coverage}`);
          }
          // A single file cannot be scanned through a link (Gitleaks skips symlinked files).
          const single = (await client.callTool("codeinspectus_scan", {
            path: join(temporaryRoot, "node_modules", "pkg", "config.yml"), scanners: ["secret"],
          })).structuredContent;
          assert(single.secret_coverage === "unverified", `a single file under node_modules/ read ${single.secret_coverage}`);
          assert(single.warnings.some((warning: string) => warning.startsWith("Secret coverage unverified: Gitleaks' default allowlist")),
            "the allowlisted single-file target was not disclosed");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // Fix round 3: build output is skipped only in BUILD_DIRS, where file routing drops Opengrep
      // findings anyway; committed code in .vercel/output is the repository's own and is kept.
      id: "E77 [engine] Opengrep scans committed code under .vercel/output",
      engineDep: "opengrep",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e77-"));
        try {
          const planted = await readFile(join(COVERAGE_HONESTY_FIXTURE, "opengrep-ignore-suppress", "src", "app.js"), "utf8");
          const functionDir = join(temporaryRoot, ".vercel", "output", "functions", "api.func");
          await mkdir(functionDir, { recursive: true });
          await writeFile(join(functionDir, "index.js"), planted, "utf8");
          await mkdir(join(temporaryRoot, ".next"));
          await writeFile(join(temporaryRoot, ".next", "server.js"), planted, "utf8");
          const git = (...args: string[]) => execFileSync("git", [
            "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
            "-c", "user.name=CodeInspectus eval", "-c", "user.email=eval@example.invalid", ...args,
          ], { cwd: temporaryRoot, stdio: "ignore" });
          git("init", "-q");
          git("add", "-A");
          git("commit", "-q", "-m", "fixture");
          const result = (await client.callTool("codeinspectus_scan", { path: temporaryRoot, scanners: ["sast"] })).structuredContent;
          const files = result.findings
            .filter((x: any) => x.rule_id === "ci-baseline-dangerous-eval" && x.engines.includes("opengrep"))
            .map((x: any) => x.location.file);
          assert(files.includes(".vercel/output/functions/api.func/index.js"), `committed .vercel/output code was not scanned: ${JSON.stringify(files)}`);
          assert(!files.some((file: string) => file.startsWith(".next/")), "an Opengrep finding in .next/ (BUILD_DIRS) was reported");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // Pre-release field validation item 1: without --include-dev-deps Trivy dropped devDependencies
      // and Composer packages-dev with no trace (a Nuxt app declaring everything as dev read 0 findings).
      id: "E78 [engine] development dependencies are analysed and named as such",
      engineDep: "trivy-vuln",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", { path: join(COVERAGE_HONESTY_FIXTURE, "dev-deps"), scanners: ["vuln"] })).structuredContent;
        const trivy = result.findings.filter((x: any) => x.engines.includes("trivy"));
        const about = (name: string) => trivy.filter((x: any) => x.title.includes(`(${name}@`));
        for (const name of ["handlebars", "phpunit/phpunit"]) {
          assert(about(name).length > 0, `no finding for the development dependency ${name}`);
          assert(about(name).every((x: any) => x.title.endsWith(", dev dependency)") && x.message.includes("Dependency scope: development only")),
            `${name} findings are not named as a development dependency`);
        }
        for (const name of ["lodash", "guzzlehttp/guzzle"]) {
          assert(about(name).length > 0, `no finding for the production dependency ${name}`);
          assert(about(name).every((x: any) => !x.title.includes("dev dependency")), `${name} is production but was named dev`);
        }
      },
    },
    {
      // Pre-release field validation item 3 and recheck items 7-8: native-pack limits, WordPress plugins
      // and third-party Actions are declared gaps with stable ids that accept_gaps can name.
      id: "E79 native limits, WordPress plugins and GitHub Actions are declared, acceptable gaps",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e79-"));
        try {
          await mkdir(join(root, "src", "real"), { recursive: true });
          await mkdir(join(root, ".github", "workflows"), { recursive: true });
          await writeFile(join(root, "package.json"), "{}\n", "utf8");
          await writeFile(join(root, "src", "app.ts"), "export const ok = 1;\n", "utf8");
          await writeFile(join(root, "src", "broken.ts"), "function broken( {\n  return eval(x;\n", "utf8");
          await writeFile(join(root, "src", "real", "util.ts"), "export const u = 1;\n", "utf8");
          await symlink(join(root, "src", "real"), join(root, "src", "linked"));
          await writeFile(join(root, "composer.lock"), JSON.stringify({ packages: [{ name: "wpackagist-plugin/contact-form-7", version: "5.1.1" }] }), "utf8");
          // A branch of an action that has advisories stays in the gap with or without the OSV GitHub Actions database.
          await writeFile(join(root, ".github", "workflows", "ci.yml"), "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@main\n", "utf8");
          const ids = ["native-parse-errors", "symlinked-paths", "wordpress-plugins", "actions-unchecked"];
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["sast", "ai", "vuln"], accept_gaps: ids })).structuredContent;
          const gaps = Object.fromEntries(result.coverage_gaps.map((gap: any) => [gap.id, gap.examples]));
          assertExactJson(gaps["native-parse-errors"], ["src/broken.ts"], "native-parse-errors gap missing");
          assertExactJson(gaps["symlinked-paths"], ["src/linked"], "symlinked-paths gap missing");
          assertExactJson(gaps["wordpress-plugins"], ["composer.lock: wpackagist-plugin/contact-form-7"], "wordpress-plugins gap missing");
          assertExactJson(gaps["actions-unchecked"], ["tj-actions/changed-files@main (.github/workflows/ci.yml)"], "actions-unchecked gap missing");
          assertExactJson(result.accepted_gaps, ids, "accepted gaps not listed");
          for (const pack of ["javascript-baseline", "javascript-typescript"]) {
            const state = result.pack_coverage.find((entry: any) => entry.pack_id === pack)?.state;
            assert(state === "ran", `${pack} read ${state}, so a gap-only limit still made it partial`);
          }
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Ruling 29: cap-collectif could never pass CI because of the 1,000,000-token project bound. Seven
      // 180,000-token files: the first five fit, the last two are the declared gap native-token-budget.
      id: "E80 files past the JavaScript/TypeScript token budget are a declared, acceptable gap",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e80-"));
        try {
          await writeFile(join(root, "package.json"), "{}\n", "utf8");
          for (let index = 0; index < 7; index++) await writeFile(join(root, `f${index}.js`), "a;\n".repeat(90_000), "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["sast", "ai"], accept_gaps: ["native-token-budget"] })).structuredContent;
          const gap = result.coverage_gaps?.find((entry: any) => entry.id === "native-token-budget");
          assertExactJson(gap, { id: "native-token-budget", files: 2, examples: ["f5.js", "f6.js"] }, "native-token-budget gap wrong");
          assertExactJson(result.accepted_gaps, ["native-token-budget"], "accepted gaps not listed");
          for (const pack of ["javascript-baseline", "javascript-typescript"]) {
            const state = result.pack_coverage.find((entry: any) => entry.pack_id === pack)?.state;
            assert(state === "ran", `${pack} read ${state}, so the token budget still made it partial`);
          }
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Review I-1: Trivy 0.76.1 drops Maven test/provided dependencies even with --include-dev-deps.
      id: "E81 test-scoped Maven dependencies are the declared gap dev-deps-unscanned",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e81-"));
        try {
          await writeFile(join(root, "pom.xml"), [
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>',
            "<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version><dependencies>",
            "<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.1</version><scope>test</scope></dependency>",
            "</dependencies></project>",
          ].join("\n"), "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["vuln"], accept_gaps: ["dev-deps-unscanned"] })).structuredContent;
          const gap = result.coverage_gaps?.find((entry: any) => entry.id === "dev-deps-unscanned");
          assertExactJson(gap, { id: "dev-deps-unscanned", files: 1, examples: ["pom.xml: com.fasterxml.jackson.core:jackson-databind (test)"] }, "dev-deps-unscanned gap wrong");
          assertExactJson(result.accepted_gaps, ["dev-deps-unscanned"], "accepted gaps not listed");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Synvoya M1: declared runtime pins, an image tag and an Adobe Commerce lock. Every finding is the
      // declared version (never "deployed"), carries a rebuild-and-redeploy fix, and is tagged engine_family.
      id: "E82 Synvoya reports Node.js, PHP and Adobe Commerce gap findings with fixes for declared versions",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", { path: SYNVOYA_GAP_DECLARATIONS_FIXTURE, scanners: ["vuln"] })).structuredContent;
        const engine = result.engine_details.find((entry: any) => entry.engine === "synvoya");
        assert(engine?.available === true && engine.ran === true, `Synvoya did not run: ${JSON.stringify(engine)}`);
        const found = synvoyaFindings(result.findings);
        const pick = (ruleId: string, file: string) => {
          const hit = found.find((finding) => finding.rule_id === ruleId && finding.location.file === file);
          assert(hit !== undefined, `no ${ruleId} finding in ${file}: ${found.map((x) => `${x.rule_id}@${x.location.file}`).join(", ")}`);
          return hit;
        };
        for (const finding of found) {
          assert(finding.engine === "synvoya" && finding.engine_family === "synvoya", `${finding.rule_id} is not engine synvoya / family synvoya`);
          assert(finding.message.includes("declare"), `${finding.rule_id} does not say the version is declared`);
        }
        // node:22.1.0-alpine: an exact image tag below the fixed release.
        const image = pick("SYN-2026-009", "Dockerfile");
        assert(image.severity === "critical" && image.confidence === "high" && image.location.start_line === 1, "Node image finding severity, confidence or line wrong");
        assert(image.title.includes("Node.js 22.1.0 declared in Dockerfile"), `Node image title wrong: ${image.title}`);
        assert(image.remediation.summary.includes("22.23.4") && image.remediation.summary.includes("rebuild and redeploy"), `Node image fix wrong: ${image.remediation.summary}`);
        // .nvmrc 20: a floating major on an end-of-life line is a high-confidence EOL finding with the supported fix.
        const nvm = pick("SYN-2026-013", ".nvmrc");
        assert(nvm.severity === "high" && nvm.confidence === "high" && nvm.title.includes("End-of-life Node.js"), `.nvmrc EOL finding wrong: ${nvm.title}`);
        assert(nvm.title.includes("Node.js 20 declared in .nvmrc") && nvm.remediation.summary.includes("rebuild and redeploy"), ".nvmrc declared version or fix wrong");
        // composer.json "php": "8.1.*": the 8.1 line is end of life.
        const php = pick("SYN-2026-015", "composer.json");
        assert(php.severity === "critical" && php.confidence === "high" && php.location.start_line === 4, "PHP EOL finding severity, confidence or line wrong");
        assert(php.title.includes("PHP 8.1.* declared in composer.json") && php.remediation.summary.includes("8.2.35"), `PHP EOL fix wrong: ${php.remediation.summary}`);
        // Magento EE 2.4.7-p2: a hotfix advisory, so the finding asks to verify it and never claims it proved.
        const adobe = pick("SYN-2026-084", "composer.lock");
        assert(adobe.severity === "medium" && adobe.title.startsWith("Verify APSB25-88 is applied to Adobe Commerce 2.4.7-p2"), `Adobe verify finding wrong: ${adobe.title}`);
        assert(adobe.remediation.summary.includes("2.4.7-p8"), `Adobe fix missing the patched release: ${adobe.remediation.summary}`);
        assert(adobe.message.includes("does not change the version string"), "Adobe finding does not explain why the version cannot prove it");
      },
    },
    {
      // Review focus 3: an edited dataset must never read as "no findings". It runs from a COPY of the built
      // package, never the repo's own files; the rescan half checks the prior Synvoya findings stay unconfirmed.
      id: "E83 a tampered Synvoya dataset makes the engine unavailable, warns, and never confirms a prior finding fixed",
      fn: async () => {
        await withTamperedSynvoya(async ({ client: tampered }) => {
          const result = (await tampered.callTool("codeinspectus_scan", { path: SYNVOYA_GAP_DECLARATIONS_FIXTURE, scanners: ["vuln"] })).structuredContent;
          const engine = result.engine_details.find((entry: any) => entry.engine === "synvoya");
          assert(engine?.available === false && engine.ran === false, `tampered dataset did not make Synvoya unavailable: ${JSON.stringify(engine)}`);
          assert(String(engine.note).includes("SHA-256 digest"), `unavailable note does not name the digest check: ${engine.note}`);
          assert(result.warnings.some((warning: string) => warning.startsWith("Synvoya gap advisories unavailable")), `no unavailable warning: ${JSON.stringify(result.warnings)}`);
          assert(!result.engines_run.includes("synvoya"), "synvoya listed in engines_run");
          assert(synvoyaFindings(result.findings).length === 0, "a tampered dataset still produced Synvoya findings");
        });
        const home = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e83-home-"));
        const intact = new McpClient(isolatedHome(home));
        try {
          await intact.init();
          const prior = (await intact.callTool("codeinspectus_scan", { path: SYNVOYA_GAP_DECLARATIONS_FIXTURE, scanners: ["vuln"] })).structuredContent;
          const priorSynvoya = synvoyaFindings(prior.findings);
          assert(priorSynvoya.length > 0, "the intact baseline scan produced no Synvoya findings");
          await withTamperedSynvoya(async ({ client: tampered }) => {
            const rescan = (await tampered.callTool("codeinspectus_rescan", {
              path: SYNVOYA_GAP_DECLARATIONS_FIXTURE,
              prior_scan_id: prior.scan_id,
              scanners: ["vuln"],
            })).structuredContent;
            assert(rescan.summary.resolved === 0, `an unavailable Synvoya confirmed ${rescan.summary.resolved} finding(s) fixed`);
            assert(rescan.partial === true, "the rescan with an unavailable Synvoya was not reported partial");
            const unconfirmed = synvoyaFindings(rescan.not_rechecked).map((finding: any) => finding.fingerprint).sort();
            assertExactJson(unconfirmed, priorSynvoya.map((finding: any) => finding.fingerprint).sort(), "prior Synvoya findings are not all not_rechecked");
          }, isolatedHome(home));
        } finally {
          intact.close();
          await rm(home, { recursive: true, force: true });
        }
      },
    },
    {
      // Enrich, never merge: the upstream finding is the only one; it keeps its id, fingerprint and producers and
      // gains Synvoya's fix. The baseline is the same scan with Synvoya unavailable (a tampered package copy).
      id: "E84 a package CVE Trivy or osv-scanner reports is one upstream finding enriched with the Synvoya fix",
      engineDep: "trivy-vuln",
      fn: async () => {
        const covered = ["CVE-2026-33894", "GHSA-86w9-cpqp-85rv"];
        const isCovered = (finding: any) => [finding.rule_id, ...(finding.vulnerability_aliases ?? [])].some((id: string) => covered.includes(id));
        const result = (await client.callTool("codeinspectus_scan", { path: SYNVOYA_TRIVY_COVERED_FIXTURE, scanners: ["vuln"] })).structuredContent;
        const upstream = result.findings.filter((finding: any) => !finding.engines.includes("synvoya") && finding.package?.name === "node-forge" && isCovered(finding));
        if (upstream.length === 0) throw new EvalSkip("the installed vulnerability database does not list the Synvoya-covered node-forge CVE yet (repair-engines)");
        assert(synvoyaFindings(result.findings).every((finding: any) => finding.rule_id !== "SYN-2026-057"), "SYN-2026-057 was reported beside the upstream finding it duplicates");
        assert(upstream.length === 1, `expected one upstream finding for the covered advisory, got ${upstream.map((finding: any) => finding.rule_id).join(", ")}`);
        const [enriched] = upstream;
        const synvoyaStep = enriched.remediation.steps.find((step: string) => step.startsWith("Synvoya SYN-2026-057:"));
        assert(synvoyaStep !== undefined && synvoyaStep.includes("1.4.1"), `the Synvoya fix is not in the upstream remediation: ${JSON.stringify(enriched.remediation.steps)}`);
        assert(enriched.producer_components.every((component: string) => !component.startsWith("synvoya:")), "the upstream finding gained Synvoya producer components");

        const baseline = await withTamperedSynvoya(async ({ client: tampered }) =>
          (await tampered.callTool("codeinspectus_scan", { path: SYNVOYA_TRIVY_COVERED_FIXTURE, scanners: ["vuln"] })).structuredContent);
        const before = baseline.findings.find((finding: any) => finding.rule_id === enriched.rule_id && finding.package?.name === "node-forge");
        assert(before !== undefined, "the baseline scan without Synvoya lost the upstream finding");
        for (const key of ["id", "fingerprint", "severity", "title", "engine", "engines", "producer_components", "location"]) {
          assertExactJson(enriched[key], before[key], `upstream ${key} changed once Synvoya enriched the finding`);
        }
        assert(before.remediation.steps.every((step: string) => enriched.remediation.steps.includes(step)), "enrichment dropped an upstream remediation step");
        assert(!before.remediation.steps.some((step: string) => step.startsWith("Synvoya ")), "the baseline already carried a Synvoya step");
      },
    },
    {
      // Design §8.4/§8.5: a floating tag on a supported line is a hygiene note, never a finding or a coverage gap.
      id: "E85 a floating node:22-alpine tag is an info note, not a finding or a coverage gap",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", { path: SYNVOYA_FLOATING_TAG_FIXTURE, scanners: ["vuln"] })).structuredContent;
        const engine = result.engine_details.find((entry: any) => entry.engine === "synvoya");
        assert(engine?.available === true && engine.ran === true, `Synvoya did not run: ${JSON.stringify(engine)}`);
        assert(synvoyaFindings(result.findings).length === 0, `a floating tag on a supported line produced findings: ${synvoyaFindings(result.findings).map((x: any) => x.rule_id).join(", ")}`);
        const notes = (result.coverage_notes ?? []).filter((note: any) => note.component === "engine:synvoya");
        assert(notes.length > 0 && notes.every((note: any) => note.detail.startsWith("Dockerfile:1:") && note.detail.includes("Node.js 22") && note.detail.includes("pin Node.js")),
          `expected only Dockerfile:1 Node.js 22 pin notes, got ${JSON.stringify(notes)}`);
        assert(!result.coverage_gaps?.length, `a floating tag lowered coverage: ${JSON.stringify(result.coverage_gaps)}`);
        assert(!result.warnings.some((warning: string) => warning.toLowerCase().includes("synvoya")), `a floating tag raised a Synvoya warning: ${JSON.stringify(result.warnings)}`);
      },
    },
    {
      // A reader that hit its wall-clock deadline never read the file, so a rescan must not call the prior finding
      // fixed. The deadline is forced with the internal override (0 ms = already expired) on the rescanning server.
      id: "E86 a rescan whose Synvoya reader deadline is hit reports the prior findings not_rechecked, never resolved",
      fn: async () => {
        const home = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e86-home-"));
        const normal = new McpClient(isolatedHome(home));
        const expired = new McpClient({ ...isolatedHome(home), CODEINSPECTUS_INTERNAL_SYNVOYA_DEADLINE_MS: "0" });
        try {
          await normal.init();
          await expired.init();
          const prior = (await normal.callTool("codeinspectus_scan", { path: SYNVOYA_GAP_DECLARATIONS_FIXTURE, scanners: ["vuln"] })).structuredContent;
          const priorSynvoya = synvoyaFindings(prior.findings);
          assert(priorSynvoya.length > 0, "the baseline scan produced no Synvoya findings");
          // Control: without the override the same rescan keeps every finding as remaining, so the deadline is what changes it.
          const control = (await normal.callTool("codeinspectus_rescan", {
            path: SYNVOYA_GAP_DECLARATIONS_FIXTURE,
            prior_scan_id: prior.scan_id,
            scanners: ["vuln"],
          })).structuredContent;
          assert(control.summary.remaining === priorSynvoya.length && control.summary.not_rechecked === 0 && control.partial === false,
            `the unchanged rescan did not keep every Synvoya finding: ${JSON.stringify(control.summary)}`);
          const rescan = (await expired.callTool("codeinspectus_rescan", {
            path: SYNVOYA_GAP_DECLARATIONS_FIXTURE,
            prior_scan_id: prior.scan_id,
            scanners: ["vuln"],
          })).structuredContent;
          assert(String(rescan.not_rechecked_note).includes("Synvoya gap layer"), `the rescan does not name the Synvoya gap layer as the reason: ${rescan.not_rechecked_note}`);
          assert(rescan.summary.resolved === 0, `a deadline-cut rescan confirmed ${rescan.summary.resolved} finding(s) fixed`);
          assert(rescan.partial === true, "the deadline-cut rescan was not reported partial");
          assertExactJson(
            synvoyaFindings(rescan.not_rechecked).map((finding: any) => finding.fingerprint).sort(),
            priorSynvoya.map((finding: any) => finding.fingerprint).sort(),
            "prior Synvoya findings are not all not_rechecked",
          );
        } finally {
          normal.close();
          expired.close();
          await rm(home, { recursive: true, force: true });
        }
      },
    },
    {
      // The real osv-scanner 2.7.0 binary reads the per-scan CycloneDX SBOM (`-L inventory.cdx.json`) offline, and
      // its findings point at the vendored file and line, never at the SBOM in the scan's temp dir.
      id: "E87 a vendored jQuery 1.12.4 is checked by osv-scanner through the per-scan SBOM and reported at its file and line",
      engineDep: "osv-scanner",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", { path: SYNVOYA_VENDORED_FIXTURE, scanners: ["vuln"] })).structuredContent;
        if (result.coverage_gaps?.some((gap: any) => gap.id === "vendored-js")) {
          throw new EvalSkip("OSV npm database not installed (repair-engines osv-scanner --osv-ecosystems npm)");
        }
        const file = "public/js/jquery-1.12.4.min.js";
        const vendored = result.findings.filter((finding: any) => finding.location.file === file);
        assert(vendored.length > 0, `no finding for ${file}: ${JSON.stringify(result.warnings)}`);
        for (const finding of vendored) {
          assert(finding.engine === "osv-scanner" && finding.engine_family === "synvoya", `unexpected engine/family: ${finding.engine}/${finding.engine_family}`);
          assert(finding.location.start_line === 1, `expected line 1 (the banner), got ${finding.location.start_line}`);
          assert(finding.package?.name === "jquery" && finding.package?.version === "1.12.4", `unexpected package ${JSON.stringify(finding.package)}`);
          assert(finding.producer_components.includes("synvoya:sbom:osv-scanner"), "the finding does not record the SBOM producer");
        }
        assert(
          vendored.some((finding: any) => [finding.rule_id, ...(finding.vulnerability_aliases ?? [])].some((id: string) => /^GHSA-/.test(id))),
          `no GHSA advisory among ${vendored.map((finding: any) => finding.rule_id).join(", ")}`,
        );
        const text = JSON.stringify(result);
        for (const leak of ["inventory.cdx.json", "synvoya-sbom", "osv-scanner-sbom.json", "ci-scan-"]) {
          assert(!text.includes(leak), `the scan result mentions the managed SBOM or temp dir (${leak})`);
        }
        assert(!result.warnings.some((warning: string) => warning.startsWith("Synvoya SBOM check")), `the SBOM check warned: ${JSON.stringify(result.warnings)}`);
        assert(!result.coverage_gaps?.length, `unexpected coverage gaps: ${JSON.stringify(result.coverage_gaps)}`);
      },
    },
    {
      // Task M2-5: third-party Actions against the installed OSV GitHub Actions database (real GHSA records), never
      // through osv-scanner. A tag in the affected range is a finding with its fix; a major tag with a fixed release is
      // a "pin to ≥ X" note; only the branch reference of an action with advisories stays in actions-unchecked.
      id: "E88 a tj-actions/changed-files tag in the affected range is a Synvoya finding with its fix; a v4 tag with a fix is a note",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e88-"));
        try {
          await mkdir(join(root, ".github", "workflows"), { recursive: true });
          await writeFile(join(root, ".github", "workflows", "ci.yml"), ACTIONS_WORKFLOW("v45.0.7"), "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["vuln"] })).structuredContent;
          requireActionsDb(result);
          const finding = result.findings.find((entry: any) => entry.rule_id === "GHSA-mrrh-fwg8-r2c3");
          assert(finding, `no GHSA-mrrh-fwg8-r2c3 finding: ${JSON.stringify(result.findings.map((entry: any) => entry.rule_id))}`);
          assert(finding.engine === "synvoya" && finding.engine_family === "synvoya", `unexpected engine/family ${finding.engine}/${finding.engine_family}`);
          assertExactJson([finding.location.file, finding.location.start_line], [".github/workflows/ci.yml", 7], "the finding is not at the uses: line");
          assert(finding.remediation.summary.includes("46.0.1"), `the remediation does not name the fixed release: ${finding.remediation.summary}`);
          assert(finding.producer_components.includes("synvoya:actions"), "the finding does not record the actions producer");
          assert((finding.vulnerability_aliases ?? []).includes("CVE-2025-30066"), "the CVE alias is missing");
          assert(!result.findings.some((entry: any) => entry.location.start_line === 8 && entry.engine === "synvoya"), "the v4 tag with a fixed release became a finding");
          const notes = (result.coverage_notes ?? []).map((note: any) => note.detail).join("\n");
          assert(/rlespinasse\/github-slug-action@v4 is a moving tag .*≥ 4\.4\.1/.test(notes), `no pin-to note for the v4 tag: ${notes}`);
          assert(/not pinned to a full commit SHA/.test(notes), "no SHA-pinning hygiene note");
          assertExactJson(result.coverage_gaps?.find((gap: any) => gap.id === "actions-unchecked")?.examples,
            ["tj-actions/changed-files@main (.github/workflows/ci.yml)"], "actions-unchecked does not hold exactly the unevaluated branch reference");
          assert(!(result.dependency_coverage ?? []).some((entry: any) => entry.ecosystem === "GitHub Actions"), "osv-scanner reported GitHub Actions packages");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Design §10.9: the 3.x lexer read `/` after `export default` as division, so the backtick opened a
      // template that swallowed the admin route until the comment's backtick and the file read parsed.
      id: "E130 the native parser reads an Express admin route the 3.x lexer hid behind a regex",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e130-"));
        try {
          await writeFile(join(root, "admin.mjs"), [
            'import express from "express";',
            "const app = express();",
            "export default /`/;",
            "app.delete('/api/admin/users', async (_req, res) => {",
            "  await db.users.deleteMany();",
            "  return res.sendStatus(204);",
            "});",
            "// `",
          ].join("\n"), "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["ai"] })).structuredContent;
          const findings = result.findings.filter((finding: any) => finding.rule_id === "ci-ai-express-admin-route-no-authz");
          assert(findings.length === 1 && findings[0].location.start_line === 4, `expected the hidden admin route at line 4, got ${JSON.stringify(findings.map((finding: any) => finding.location))}`);
          assert(!result.coverage_gaps?.some((gap: any) => gap.id === "native-parse-errors"), "a valid file was reported unparsed");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Review focus 4: a commit-pinned action is a finding only when the advisory data lists that commit; otherwise a
      // note, and the reference stays in actions-unchecked. Without the database every reference is in the gap.
      id: "E89 an unlisted commit pin is a note and stays a gap; without the GitHub Actions database every reference is a gap",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e89-"));
        const home = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e89-home-"));
        const bare = new McpClient(isolatedHome(home));
        try {
          await mkdir(join(root, ".github", "workflows"), { recursive: true });
          await writeFile(join(root, ".github", "workflows", "ci.yml"), ACTIONS_WORKFLOW("0e58ed8671d6b60d0890c21b07f8835ace038e67"), "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["vuln"] })).structuredContent;
          requireActionsDb(result);
          assert(!result.findings.some((entry: any) => entry.engine === "synvoya" && entry.location.start_line === 7), "an unlisted commit became a finding");
          const notes = (result.coverage_notes ?? []).map((note: any) => note.detail).join("\n");
          assert(/tj-actions\/changed-files@0e58ed8671d6 is pinned to a commit; GHSA-[a-z0-9-]+ has no commit list/.test(notes), `no commit-pin note: ${notes}`);
          const gap = result.coverage_gaps?.find((entry: any) => entry.id === "actions-unchecked");
          assert(gap?.examples.includes("tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67 (.github/workflows/ci.yml)"), `the commit pin is not in the gap: ${JSON.stringify(gap)}`);

          await bare.init();
          const without = (await bare.callTool("codeinspectus_scan", { path: root, scanners: ["vuln"] })).structuredContent;
          const row = without.engine_details.find((engine: any) => engine.engine === "synvoya");
          assert(/not checked \(the OSV GitHub Actions database is not installed\)/.test(row?.note ?? ""), `the engine note does not say the database is missing: ${row?.note}`);
          assert(!without.findings.some((entry: any) => /^GHSA-/.test(entry.rule_id) && entry.engine === "synvoya"), "a GitHub Actions finding without the database");
          assertExactJson(without.coverage_gaps?.find((entry: any) => entry.id === "actions-unchecked")?.files, 4, "without the database not every reference is a gap");
        } finally {
          bare.close();
          await rm(root, { recursive: true, force: true });
          await rm(home, { recursive: true, force: true });
        }
      },
    },
    {
      // Rescan honesty for the actions producer: a fixed tag resolves the prior finding; a commit pin the matcher cannot
      // judge leaves it not_rechecked, never resolved.
      id: "E90 a rescan resolves an Actions finding once the tag is fixed, and reports it not_rechecked when pinned to an unlisted commit",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e90-"));
        const workflow = join(root, ".github", "workflows", "ci.yml");
        const only = (ref: string) => `on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: tj-actions/changed-files@${ref}\n`;
        try {
          await mkdir(join(root, ".github", "workflows"), { recursive: true });
          await writeFile(workflow, only("v45.0.7"), "utf8");
          const prior = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["vuln"] })).structuredContent;
          requireActionsDb(prior);
          assert(prior.findings.some((entry: any) => entry.rule_id === "GHSA-mrrh-fwg8-r2c3"), "the prior scan has no Actions finding");
          await writeFile(workflow, only("0e58ed8671d6b60d0890c21b07f8835ace038e67"), "utf8");
          const pinned = (await client.callTool("codeinspectus_rescan", { path: root, prior_scan_id: prior.scan_id, scanners: ["vuln"] })).structuredContent;
          assert(pinned.not_rechecked.some((entry: any) => entry.rule_id === "GHSA-mrrh-fwg8-r2c3"), `the commit-pinned rescan did not report it not_rechecked: ${JSON.stringify(pinned.summary)}`);
          assert(!pinned.resolved.some((entry: any) => entry.rule_id === "GHSA-mrrh-fwg8-r2c3"), "an unjudgeable commit pin confirmed the fix");
          await writeFile(workflow, only("v46.0.1"), "utf8");
          const fixed = (await client.callTool("codeinspectus_rescan", { path: root, prior_scan_id: prior.scan_id, scanners: ["vuln"] })).structuredContent;
          assert(fixed.resolved.some((entry: any) => entry.rule_id === "GHSA-mrrh-fwg8-r2c3"), `the fixed tag did not resolve the finding: ${JSON.stringify(fixed.summary)} ${fixed.not_rechecked_note ?? ""}`);
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      id: "E131 a 100,000-deep nested file is the native-parse-errors gap, not a crash or a hang",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e131-"));
        try {
          await writeFile(join(root, "package.json"), "{}\n", "utf8");
          await writeFile(join(root, "deep.js"), ("[".repeat(10_000) + "\n").repeat(10) + ("]".repeat(10_000) + "\n").repeat(10), "utf8");
          await writeFile(join(root, "ok.js"), "export const ok = 1;\n", "utf8");
          const started = Date.now();
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["ai"], accept_gaps: ["native-parse-errors"] })).structuredContent;
          const gaps = Object.fromEntries((result.coverage_gaps ?? []).map((gap: any) => [gap.id, gap.examples]));
          assertExactJson(gaps["native-parse-errors"], ["deep.js"], "deep nesting was not reported as native-parse-errors");
          assert(Date.now() - started < 60_000, "the scan took over a minute");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // The real osv-scanner 2.7.0 binary and the OSV Go database: an exact go.mod toolchain line and an exact golang
      // image are checked as the Go standard library (`stdlib`) through the per-scan SBOM, at their own lines.
      id: "E92 an exact Go toolchain (go.mod toolchain, golang image) is checked against the OSV Go database as stdlib at its line",
      engineDep: "osv-scanner",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", { path: SYNVOYA_GO_TOOLCHAIN_FIXTURE, scanners: ["vuln"] })).structuredContent;
        if ((result.coverage_notes ?? []).some((note: any) => /OSV Go database is not installed/.test(note.detail ?? ""))) {
          throw new EvalSkip("OSV Go database not installed (repair-engines osv-scanner --osv-ecosystems Go)");
        }
        const stdlib = result.findings.filter((finding: any) => finding.package?.ecosystem === "Go" && finding.package?.name === "stdlib");
        for (const [file, line] of [["go.mod", 5], ["Dockerfile", 1]] as const) {
          const here = stdlib.filter((finding: any) => finding.location.file === file);
          assert(here.length > 0, `no stdlib finding for ${file}: ${JSON.stringify(result.warnings)}`);
          for (const finding of here) {
            assert(finding.location.start_line === line, `${file}: expected line ${line}, got ${finding.location.start_line}`);
            assert(finding.engine === "osv-scanner" && finding.engine_family === "synvoya", `${file}: unexpected engine/family ${finding.engine}/${finding.engine_family}`);
            assert(finding.package.version === "v1.22.5", `${file}: unexpected version ${finding.package.version}`);
            assert(finding.producer_components.includes("synvoya:sbom:osv-scanner"), `${file}: the finding does not record the SBOM producer`);
          }
          assert(
            here.some((finding: any) => [finding.rule_id, ...(finding.vulnerability_aliases ?? [])].some((id: string) => /^GO-\d{4}-\d+$/.test(id))),
            `${file}: no GO- advisory among ${here.map((finding: any) => finding.rule_id).join(", ")}`,
          );
        }
        // The `go 1.22` minimum (line 3) is not a toolchain: nothing from the SBOM points at it.
        assert(!stdlib.some((finding: any) => finding.location.file === "go.mod" && finding.location.start_line !== 5), "a stdlib finding points at the go minimum");
        const text = JSON.stringify(result);
        for (const leak of ["inventory.cdx.json", "synvoya-sbom", "osv-scanner-sbom.json"]) {
          assert(!text.includes(leak), `the scan result mentions the managed SBOM (${leak})`);
        }
        assert(!result.warnings.some((warning: string) => warning.startsWith("Synvoya SBOM check")), `the SBOM check warned: ${JSON.stringify(result.warnings)}`);
      },
    },
    {
      // The GitHub Actions database is offered only through setup consent, with its size, licence and reader; the plan
      // is offline.
      id: "E91 setup offers the OSV GitHub Actions database for a repository with workflows, with its size and GHSA CC-BY-4.0 licence",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e91-"));
        try {
          await mkdir(join(root, ".github", "workflows"), { recursive: true });
          await writeFile(join(root, ".github", "workflows", "ci.yml"), ACTIONS_WORKFLOW("v45.0.7"), "utf8");
          const response = await client.callTool("codeinspectus_setup", { action: "plan", path: root, components: ["osv-scanner"] });
          const database = response.structuredContent.plan.osv_databases.find((entry: any) => entry.ecosystem === "GitHub Actions");
          assert(database, `GitHub Actions is not offered: ${JSON.stringify(response.structuredContent.plan.osv_databases)}`);
          assert(database.estimated_download_bytes > 50_000 && database.estimated_download_bytes < 1_000_000, `implausible size estimate ${database.estimated_download_bytes}`);
          assert(/GHSA.*CC-BY-4\.0.*never by osv-scanner/.test(database.note ?? ""), `no licence note: ${database.note}`);
          const text = response.content.map((item: any) => item.text ?? "").join("\n");
          assert(text.includes("GitHub Actions:") && text.includes("CC-BY-4.0"), "the plan text does not show the database and its licence");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Synvoya PHP pack (design 4.5): every shipped syn-php-* rule fires on each of its tp/ fixtures and
      // nowhere else, no fixture errors or times out, findings carry the Synvoya family, and PHP source
      // no longer declares the php-sast gap. Fixtures named dot-env* are copied to .env* here because
      // the repository never commits .env files.
      id: "E100 [engine] every Synvoya PHP rule fires on its fixtures only, and PHP source is no longer a gap",
      engineDep: "opengrep",
      fn: async () => {
        const rulesDir = resolve(process.cwd(), "detection-db/opengrep-rules/synvoya-php");
        const ruleIds: string[] = [];
        for (const name of (await readdir(rulesDir)).filter((x) => x.endsWith(".yaml"))) {
          for (const match of (await readFile(join(rulesDir, name), "utf8")).matchAll(/^ {2}- id: (\S+)$/gm)) ruleIds.push(match[1] ?? "");
        }
        assertExactJson([...(await readdir(SYNVOYA_PHP_FIXTURES))].sort(), [...ruleIds].sort(), "fixture folders and Synvoya PHP rule ids differ");
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e100-"));
        try {
          const expected: string[] = [];
          const copy = async (from: string, to: string): Promise<void> => {
            for (const entry of await readdir(from, { withFileTypes: true })) {
              const name = entry.name.startsWith("dot-") ? `.${entry.name.slice(4)}` : entry.name;
              if (entry.isDirectory()) {
                await mkdir(join(to, name), { recursive: true });
                await copy(join(from, entry.name), join(to, name));
              } else {
                await cp(join(from, entry.name), join(to, name));
              }
            }
          };
          await copy(SYNVOYA_PHP_FIXTURES, root);
          const walk = async (dir: string, rel: string): Promise<void> => {
            for (const entry of await readdir(dir, { withFileTypes: true })) {
              if (entry.isDirectory()) await walk(join(dir, entry.name), `${rel}${entry.name}/`);
              else expected.push(`${rel}${entry.name}`);
            }
          };
          for (const id of ruleIds) await walk(join(root, id, "tp"), `${id}/tp/`);
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["sast"], max_findings: 1000 })).structuredContent;
          assert(result.engine_details.some((engine: any) => engine.engine === "opengrep" && engine.ran), "Opengrep did not run");
          const partial = result.warnings.filter((warning: string) => warning.startsWith("Opengrep SAST coverage partial"));
          assert(partial.length === 0, `Opengrep reported skipped or failed files: ${JSON.stringify(partial)}`);
          assert(!result.coverage_gaps?.some((gap: any) => gap.id === "sast-parse-errors" || gap.id === "php-sast"),
            `unexpected coverage gaps: ${JSON.stringify(result.coverage_gaps)}`);
          const hits = new Set<string>();
          for (const finding of result.findings.filter((x: any) => ruleIds.includes(x.rule_id))) {
            const [folder, kind] = finding.location.file.split("/");
            assert(folder === finding.rule_id && kind === "tp", `${finding.rule_id} fired at ${finding.location.file}:${finding.location.start_line}`);
            assert(finding.engine_family === "synvoya", `${finding.rule_id} has no Synvoya family`);
            hits.add(finding.location.file);
          }
          const missed = expected.filter((file) => !hits.has(file));
          assert(missed.length === 0, `tp fixtures without a finding: ${missed.join(", ")}`);
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Stream D review, Critical 1: as a CommonJS script `<!--` starts a comment and the route runs; as a
      // module a template opens and swallows it. A `.js` file can be either, so it must never read clean.
      id: "E132 an Express admin route behind an HTML-like comment is never a silent clean pass",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e132-"));
        try {
          await writeFile(join(root, "package.json"), "{}\n", "utf8");
          await writeFile(join(root, "admin.js"), [
            'const express = require("express");',
            "const app = express();",
            "var y = 0;",
            "app <!--y; `",
            'app.delete("/api/admin/users", async (_req, res) => {',
            "  await db.users.deleteMany();",
            "  return res.sendStatus(204);",
            "});",
            "// `",
          ].join("\n"), "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["ai"], accept_gaps: ["native-parse-errors"] })).structuredContent;
          const gaps = Object.fromEntries((result.coverage_gaps ?? []).map((gap: any) => [gap.id, gap.examples]));
          const findings = result.findings.filter((finding: any) => finding.rule_id === "ci-ai-express-admin-route-no-authz");
          assert(
            findings.length === 1 || (gaps["native-parse-errors"] ?? []).includes("admin.js"),
            `the hidden route read clean: findings=${findings.length} gaps=${JSON.stringify(gaps)}`,
          );
          assertExactJson(gaps["native-parse-errors"], ["admin.js"], "the script/module divergence was not reported as native-parse-errors");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // A committed Laravel APP_KEY is a secret (Gitleaks rule, value redacted); example env files are
      // documentation and never match. The key is generated at run time, so no key is committed.
      id: "E101 [engine] a Laravel APP_KEY in .env is a redacted Synvoya secret, and .env.example is not",
      engineDep: "gitleaks",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e101-"));
        try {
          const key = `base64:${randomBytes(32).toString("base64")}`;
          await writeFile(join(root, ".env"), `APP_NAME=Shop\nAPP_KEY=${key}\nAPP_ENV=production\n`, "utf8");
          await writeFile(join(root, ".env.example"), `APP_KEY=${key}\n`, "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["secret"] })).structuredContent;
          const hits = result.findings.filter((x: any) => x.rule_id === "codeinspectus-laravel-app-key");
          assert(hits.length === 1, `expected one APP_KEY finding, got ${JSON.stringify(hits.map((x: any) => x.location))}`);
          assert(hits[0].location.file === ".env" && hits[0].location.start_line === 2, `APP_KEY reported at ${hits[0].location.file}:${hits[0].location.start_line}`);
          assert(hits[0].is_secret === true && hits[0].engine_family === "synvoya", "APP_KEY finding is not a Synvoya secret");
          assert(!JSON.stringify(result).includes(key.slice(7, 30)), "the APP_KEY value leaked into the scan result");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Opengrep matches rule path excludes against the absolute target path: the PHP pack must still
      // fire for a project that sits under parent folders named vendor/, includes/ and example/.
      id: "E103 [engine] the Synvoya PHP pack fires for a target under vendor/includes/example parent folders",
      engineDep: "opengrep",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e103-"));
        try {
          const target = join(root, "vendor", "includes", "example", "app");
          await mkdir(target, { recursive: true });
          await cp(join(SYNVOYA_PHP_FIXTURES, "syn-php-sql-injection", "tp", "plain.php"), join(target, "plain.php"));
          await cp(join(SYNVOYA_PHP_FIXTURES, "syn-php-wp-debug-display-enabled", "tp", "wp-config.php"), join(target, "wp-config.php"));
          const result = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["sast"] })).structuredContent;
          assert(result.engine_details.some((engine: any) => engine.engine === "opengrep" && engine.ran), "Opengrep did not run");
          for (const [rule, file] of [["syn-php-sql-injection", "plain.php"], ["syn-php-wp-debug-display-enabled", "wp-config.php"]]) {
            assert(result.findings.some((x: any) => x.rule_id === rule && x.location.file === file), `${rule} did not fire under the vendor/includes/example parents`);
          }
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Design 4.6: licence findings were 47% of field findings and none was fixable, so they are opt-in.
      id: "E133 [engine] licence findings are opt-in: absent with an informational note by default, present and kept by a rescan with include_licenses",
      engineDep: "trivy-vuln",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e133-"));
        try {
          await mkdir(join(root, "node_modules", "gpl-pkg"), { recursive: true });
          await writeFile(join(root, "package.json"), JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "gpl-pkg": "1.0.0" } }), "utf8");
          await writeFile(join(root, "package-lock.json"), JSON.stringify({ name: "app", lockfileVersion: 3, packages: { "": { name: "app", version: "1.0.0", dependencies: { "gpl-pkg": "1.0.0" } }, "node_modules/gpl-pkg": { version: "1.0.0", license: "GPL-3.0" } } }), "utf8");
          await writeFile(join(root, "node_modules", "gpl-pkg", "package.json"), JSON.stringify({ name: "gpl-pkg", version: "1.0.0", license: "GPL-3.0" }), "utf8");
          const note = "Licence findings were not requested (use include_licenses / --licenses).";
          const off = (await client.callTool("codeinspectus_scan", { path: root })).structuredContent;
          assert(off.findings.every((x: any) => x.finding_kind !== "license"), "a licence finding appeared without include_licenses");
          assert(off.coverage_notes?.some((n: any) => n.component === "scanner:license" && n.detail === note), "the licence note is missing");
          const on = (await client.callTool("codeinspectus_scan", { path: root, include_licenses: true })).structuredContent;
          const licences = on.findings.filter((x: any) => x.finding_kind === "license");
          assert(licences.length > 0, "include_licenses produced no licence finding");
          assert(!on.coverage_notes?.some((n: any) => n.component === "scanner:license"), "the note stays although licences were requested");
          const rescan = (await client.callTool("codeinspectus_rescan", { path: root, prior_scan_id: on.scan_id })).structuredContent;
          assert(rescan.summary.resolved === 0 && rescan.remaining.some((x: any) => x.finding_kind === "license"), "a rescan did not follow the prior licence setting");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // M4 Task 4 (controller ruling): the Synvoya pack rules run in their own Opengrep pass that skips
      // minified bundles (taint rules time out on them); the baseline rules still scan the bundle. Skipped
      // files are the acceptable gap third-party-bundles. A long comment line keeps a first-party file in
      // the pack pass, and a rescan whose bundle set changed cannot resolve a pack finding.
      id: "E134 [engine] the Synvoya pack pass skips minified bundles as the acceptable gap third-party-bundles; baseline rules still scan them",
      engineDep: "opengrep",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e134-"));
        try {
          const handler = 'const cp=require("child_process");exports.ping=(req,res)=>{cp.exec("ping -c 1 "+req.query.host,(e,o)=>res.send(o))};exports.run=(code)=>eval(code);' +
            'exports.user=(req,res)=>db.query("SELECT * FROM users WHERE id = "+req.query.id);';
          const filler = Array.from({ length: 40 }, (_, index) => `function a${index}(e,t){return e&&t?e.call(t,n[${index}]):void 0};`).join("");
          const readable = [
            'const cp = require("child_process");',
            "exports.ping = (req, res) => {",
            '  const cmd = "ping -c 1 " + req.query.host;',
            "  cp.exec(cmd, (err, out) => res.send(out));",
            "};",
            'exports.user = (req, res) => db.query("SELECT * FROM users WHERE id = " + req.query.id);',
            `//# sourceMappingURL=data:application/json;base64,${"QUJD".repeat(5_000)}`,
            "",
          ].join("\n");
          await mkdir(join(root, "public", "js"), { recursive: true });
          await mkdir(join(root, "src"), { recursive: true });
          await writeFile(join(root, "public", "js", "editor.js"), `/*! Editor v1 | MIT */${handler}${filler}\n`, "utf8");
          await writeFile(join(root, "src", "ping.js"), readable, "utf8");

          const first = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["sast"], accept_gaps: ["third-party-bundles"] })).structuredContent;
          assert(first.engine_details.some((engine: any) => engine.engine === "opengrep" && engine.ran), "Opengrep did not run");
          const pack = first.findings.filter((x: any) => /^syn-(?:node|php)-/.test(x.rule_id));
          assert(pack.some((x: any) => x.rule_id === "syn-node-command-injection" && x.location.file === "src/ping.js"),
            `a long comment line took the first-party file out of the pack pass: ${JSON.stringify(first.findings.map((x: any) => [x.rule_id, x.location.file]))}`);
          assert(!pack.some((x: any) => x.location.file === "public/js/editor.js"), "the pack pass scanned the minified bundle");
          assert(first.findings.some((x: any) => x.rule_id === "ci-baseline-dangerous-eval" && x.location.file === "public/js/editor.js" && x.engines.includes("opengrep")),
            "the baseline rules no longer scan the minified bundle");
          // M4 perf fix: the taint-mode baseline SQL rule runs in the bundle-skipping pass.
          const sql = first.findings.filter((x: any) => x.rule_id === "ci-baseline-sql-injection-string-build").map((x: any) => x.location.file);
          assert(sql.includes("src/ping.js") && !sql.includes("public/js/editor.js"),
            `the taint baseline SQL rule should fire on src/ping.js only: ${JSON.stringify(sql)}`);
          assertExactJson(first.coverage_gaps?.find((gap: any) => gap.id === "third-party-bundles"),
            { id: "third-party-bundles", files: 1, examples: ["public/js/editor.js"] }, "the skipped bundle is not the declared gap");
          assert(first.accepted_gaps?.includes("third-party-bundles"), "third-party-bundles could not be accepted");
          assert(!first.warnings.some((warning: string) => warning.startsWith("Opengrep SAST coverage partial")),
            `the pack pass left a coverage warning: ${JSON.stringify(first.warnings)}`);

          // The first-party file is now minified too: the pack pass skips it, so its finding is not proven fixed.
          await writeFile(join(root, "src", "ping.js"), `${handler}${filler}\n`, "utf8");
          const rescan = (await client.callTool("codeinspectus_rescan", { path: root, prior_scan_id: first.scan_id })).structuredContent;
          assert(!rescan.resolved.some((x: any) => /^syn-(?:node|php)-/.test(x.rule_id)),
            `a pack finding resolved although the pack pass skipped its file: ${JSON.stringify(rescan.resolved.map((x: any) => x.rule_id))}`);
          assert(rescan.not_rechecked.some((x: any) => x.rule_id === "syn-node-command-injection"), "the skipped pack finding is not listed as not rechecked");
          assert(!rescan.resolved.some((x: any) => x.rule_id === "ci-baseline-sql-injection-string-build"),
            "the taint baseline SQL finding resolved although the bundle-skipping pass skipped its file");
          assert(rescan.not_rechecked.some((x: any) => x.rule_id === "ci-baseline-sql-injection-string-build"), "the skipped SQL finding is not listed as not rechecked");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // M4 Task 4 review Critical 1: Opengrep 1.33.1 reads `\*` and `\?` in an ignore line as wildcards (and
      // cannot name a literal `[`), so a minified file named with a glob character never goes on the pack
      // skip list: it stays in the pack pass, and its readable sibling keeps its pack finding.
      id: "E135 [engine] a minified file named with a glob character never hides its siblings from the Synvoya pack pass",
      engineDep: "opengrep",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e135-"));
        try {
          const handler = 'const cp=require("child_process");exports.ping=(req,res)=>{cp.exec("ping -c 1 "+req.query.host,(e,o)=>res.send(o))};';
          const filler = Array.from({ length: 40 }, (_, index) => `function a${index}(e,t){return e&&t?e.call(t,n[${index}]):void 0};`).join("");
          const readable = 'const cp = require("child_process");\nexports.ping = (req, res) => {\n  const cmd = "ping -c 1 " + req.query.host;\n  cp.exec(cmd, (err, out) => res.send(out));\n};\n';
          // Windows file names cannot hold `*` or `?`; `[` and `]` are glob characters too.
          const pairs = process.platform === "win32"
            ? [["c[X].js", "cX.js"], ["d]e.js", "de.js"]]
            : [["c*.js", "cX.js"], ["q?.js", "qA.js"], ["r[1].js", "r1.js"]];
          await mkdir(join(root, "src"), { recursive: true });
          for (const [bundle, sibling] of pairs) {
            await writeFile(join(root, "src", bundle!), `${handler}${filler}\n`, "utf8");
            await writeFile(join(root, "src", sibling!), readable, "utf8");
          }
          const result = (await client.callTool("codeinspectus_scan", { path: root, scanners: ["sast"] })).structuredContent;
          assert(result.engine_details.some((engine: any) => engine.engine === "opengrep" && engine.ran), "Opengrep did not run");
          const packFiles = new Set(result.findings.filter((x: any) => x.rule_id === "syn-node-command-injection").map((x: any) => x.location.file));
          for (const [bundle, sibling] of pairs) {
            assert(packFiles.has(`src/${sibling}`), `the minified src/${bundle} hid src/${sibling} from the pack pass: ${JSON.stringify([...packFiles])}`);
            assert(packFiles.has(`src/${bundle}`), `src/${bundle} left the pack pass although no ignore line can name it alone`);
          }
          assert(!result.coverage_gaps?.some((gap: any) => gap.id === "third-party-bundles"), `a file the pack pass scanned is listed as skipped: ${JSON.stringify(result.coverage_gaps)}`);
          assert(!result.warnings.some((warning: string) => warning.startsWith("Opengrep SAST coverage partial")),
            `unexpected coverage warning: ${JSON.stringify(result.warnings)}`);
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // M4 perf fix: Opengrep skips a file that holds none of a rule's identifiers only while it can derive that
      // file prefilter from the rule. The precision-pass DOM-XSS rule grew past that analysis's limit and ran
      // every pattern on every JS/TS file (baseline Opengrep time x2.7 on the field repos, no warning). With
      // --time, Opengrep lists a rule under a file's match_times only when it ran there.
      id: "E136 [engine] no baseline Opengrep rule runs on a JS/TS file that holds none of its identifiers",
      engineDep: "opengrep",
      fn: async () => {
        const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e136-"));
        try {
          const target = join(root, "target");
          const scratch = join(root, "scratch");
          await mkdir(target);
          await mkdir(scratch);
          await writeFile(join(target, "plain.js"), "const total = [1, 2, 3].reduce((sum, value) => sum + value, 0);\nmodule.exports = total;\n", "utf8");
          await writeFile(join(target, "sink.js"), 'document.getElementById("o").innerHTML = location.hash;\n', "utf8");
          await writeFile(join(scratch, OPENGREP_EFFECTIVE_IGNORE_NAME), effectiveOpengrepIgnoreList(await readFile(OPENGREP_IGNORE_FILE, "utf8")), "utf8");
          const bin = await resolveEngine("opengrep");
          const report = join(scratch, "report.json");
          const args = buildOpengrepArgs(target, join(scratch, "report.sarif"), report, (await opengrepRuleSets()).baseline);
          args.splice(args.length - 1, 0, "--time");
          await execBinary(bin.path, args, { cwd: target, offline: true, env: opengrepExecEnvironment(scratch) });
          const timing = JSON.parse(await readFile(report, "utf8")).time;
          const ran = (file: string): string[] => (timing.targets.find((entry: any) => entry.path.endsWith(file))?.match_times ?? [])
            .map(([rule]: [string, number]) => rule.split(".").pop());
          if (process.platform === "win32" && timing.targets.every((entry: any) => !entry.match_times?.length)) {
            // CI 2026-11-05: Opengrep's Windows build lists the targets but no per-rule match times, so the
            // prefilter cannot be observed here. The rules are the same files on every platform; Linux and macOS prove it.
            for (const file of ["sink.js", "plain.js"]) {
              assert(timing.targets.some((entry: any) => entry.path.endsWith(file)), `the Windows timing report does not list ${file}`);
            }
            return;
          }
          assert(ran("sink.js").includes("ci-baseline-dom-xss-innerhtml"), `the timing report does not list rules that ran: ${JSON.stringify(ran("sink.js"))}`);
          assertExactJson(ran("plain.js"), [], "baseline rules ran on a file holding none of their identifiers (lost file prefilter)");
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    },
    {
      // Design 4.7: list_rules shows per-language rule counts, read from the rule files Opengrep loads.
      id: "E102 list_rules counts Synvoya PHP rules per language",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_list_rules", {})).structuredContent;
        const php = result.sast_rule_languages?.find((entry: any) => entry.language === "php");
        assert(php && php.rule_count > 0 && php.rulesets.includes("synvoya-php"), `no PHP rule count: ${JSON.stringify(result.sast_rule_languages)}`);
        const text = (await client.callTool("codeinspectus_list_rules", {})).content?.[0]?.text ?? "";
        assert(/Opengrep rules by language: .*php \d+/.test(text), "the list_rules summary does not name the PHP rule count");
        assert(result.custom_rules.filter((rule: any) => rule.id.startsWith("syn-php-")).every((rule: any) => rule.engine_family === "synvoya"),
          "a syn-php rule is not in the Synvoya family");
      },
    },
    {
      // M3 stream B: every shipped syn-node-* rule has a fixture folder named by its id; tp/ files must
      // fire that rule, fp/ files must stay quiet for every syn-node rule, nothing may fail to parse,
      // and each finding is a Synvoya-family Opengrep finding. Experimental rules are never loaded.
      id: "E110 [engine] every Synvoya Node.js rule fires on its TP fixtures and stays quiet on its FP fixtures",
      engineDep: "opengrep",
      fn: async () => {
        const rulesDir = resolve(process.cwd(), "detection-db/opengrep-rules/synvoya-node");
        const ruleIds: string[] = [];
        for (const name of (await readdir(rulesDir)).filter((x) => x.endsWith(".yaml"))) {
          for (const match of (await readFile(join(rulesDir, name), "utf8")).matchAll(/^ {2}- id: (\S+)$/gm)) ruleIds.push(match[1] ?? "");
        }
        assert(ruleIds.length > 0 && ruleIds.every((id) => id.startsWith("syn-node-")), `unexpected rule ids: ${ruleIds.join(", ")}`);
        const folders = await readdir(SYNVOYA_NODE_FIXTURE);
        assertExactJson([...folders].sort(), [...ruleIds].sort(), "fixture folders and synvoya-node rule ids differ");
        const result = (await client.callTool("codeinspectus_scan", {
          path: SYNVOYA_NODE_FIXTURE, scanners: ["sast"], max_findings: 1000,
        })).structuredContent;
        assert(result.engine_details.some((engine: any) => engine.engine === "opengrep" && engine.ran), "Opengrep did not run");
        assert(!result.truncated, "the fixture scan was truncated");
        const partial = result.warnings.filter((warning: string) => warning.startsWith("Opengrep SAST coverage partial"));
        assert(partial.length === 0, `Opengrep reported skipped or failed files: ${JSON.stringify(partial)}`);
        assert(!result.coverage_gaps?.some((gap: any) => gap.id === "sast-parse-errors"), "Opengrep could not parse a rule fixture");
        const hits = new Set<string>();
        for (const finding of result.findings.filter((x: any) => x.rule_id.startsWith("syn-node-"))) {
          const [folder, kind] = finding.location.file.split("/");
          assert(folder === finding.rule_id && kind === "tp", `${finding.rule_id} fired at ${finding.location.file}:${finding.location.start_line}`);
          assert(finding.engine === "opengrep" && finding.engine_family === "synvoya", `${finding.rule_id} is not a Synvoya-family Opengrep finding`);
          hits.add(finding.location.file);
        }
        for (const id of ruleIds) {
          for (const file of await readdir(join(SYNVOYA_NODE_FIXTURE, id, "tp"))) {
            assert(hits.has(`${id}/tp/${file}`), `${id} missed ${id}/tp/${file}`);
          }
        }
      },
    },
    {
      // Opengrep 1.33.1 matches rule `paths` against the absolute target path, so a folder-name exclude
      // would silently switch a rule off for every project under such a parent folder (review F1).
      id: "E111 [engine] Synvoya Node.js rules still fire for a project under vendors/, third_party/, assets/js/ and example-template/ parents",
      engineDep: "opengrep",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e111-"));
        try {
          const target = join(temporaryRoot, "vendors", "third_party", "assets", "js", "templates", "example-template", "app");
          await mkdir(join(target, "src"), { recursive: true });
          await cp(join(SYNVOYA_NODE_FIXTURE, "syn-node-command-injection", "tp", "01_exec_indirect.js"), join(target, "src", "server.js"));
          await cp(join(SYNVOYA_NODE_FIXTURE, "syn-node-jwt-verify-no-algorithms", "tp", "01_require.js"), join(target, "src", "auth.js"));
          await cp(join(SYNVOYA_NODE_FIXTURE, "syn-node-placeholder-secret-deploy", "tp", "docker-compose.yml"), join(target, "docker-compose.yml"));
          const result = (await client.callTool("codeinspectus_scan", { path: target, scanners: ["sast"] })).structuredContent;
          assert(result.engine_details.some((engine: any) => engine.engine === "opengrep" && engine.ran), "Opengrep did not run");
          for (const [rule, file] of [
            ["syn-node-command-injection", "src/server.js"],
            ["syn-node-jwt-verify-no-algorithms", "src/auth.js"],
            ["syn-node-placeholder-secret-deploy", "docker-compose.yml"],
          ]) {
            assert(result.findings.some((x: any) => x.rule_id === rule && x.location.file === file),
              `${rule} did not fire on ${file} under a vendors/third_party/assets/js/templates/example-template parent`);
          }
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // Design §10.6 (field precision pass): Opengrep hits in vendored or minified libraries
      // (CKEditor, jQuery, Freemius) are not the project's code; secrets there are still reported.
      id: "E120 [engine] inferred third-party scripts (minified, UMD, vendors/) are reported low; padded own code stays high",
      engineDep: "opengrep",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e120-"));
        try {
          const sink = "module.exports = (code) => eval(code);\n";
          const umd = "(function (global, factory) {\n  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :\n" +
            "  typeof define === 'function' && define.amd ? define(factory) : global.widget = factory();\n}(this, function () {\n" +
            "  return function run(code) { return eval(code); };\n}));\n";
          const minified = `${"if(a){b(c);}".repeat(120)}function r(c){return eval(c)}\n`;
          await mkdir(join(temporaryRoot, "public", "js"), { recursive: true });
          await mkdir(join(temporaryRoot, "includes", "vendors", "lib"), { recursive: true });
          await mkdir(join(temporaryRoot, "src"), { recursive: true });
          await writeFile(join(temporaryRoot, "public", "js", "widget.js"), umd, "utf8");
          await writeFile(join(temporaryRoot, "public", "js", "bundle.js"), minified, "utf8");
          await writeFile(join(temporaryRoot, "includes", "vendors", "lib", "lib.js"), sink, "utf8");
          await writeFile(join(temporaryRoot, "src", "app.js"), sink, "utf8");
          await writeFile(join(temporaryRoot, "src", "app.test.js"), sink, "utf8");
          // Re-triage 2: one appended comment line of 20,000 ";" must not make the project's own code third-party.
          await writeFile(join(temporaryRoot, "src", "padded.js"), `${sink}//${";".repeat(20_000)}\n`, "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: temporaryRoot, scanners: ["sast"] })).structuredContent;
          const evals = result.findings.filter((x: any) => x.rule_id === "ci-baseline-dangerous-eval");
          const byFile = Object.fromEntries(evals.map((x: any) => [x.location.file, x]));
          for (const file of ["src/app.js", "src/padded.js"]) {
            assert(byFile[file]?.severity === "high", `the project's own eval() in ${file} was not reported high: ${JSON.stringify(evals)}`);
          }
          // Content or folder-name evidence (minified body, UMD wrapper, vendors/) lowers a finding, never removes it.
          for (const file of ["public/js/bundle.js", "public/js/widget.js", "includes/vendors/lib/lib.js"]) {
            assert(byFile[file]?.severity === "low" && byFile[file].title.startsWith("Third-party code"),
              `the finding in inferred third-party ${file} was not reported low: ${JSON.stringify(byFile[file])}`);
          }
          // Design 4.6: the same sink in a test file is lowered with its context, never dropped.
          assert(byFile["src/app.test.js"]?.severity === "low" && byFile["src/app.test.js"].title.startsWith("Test/example context"),
            `the eval() in a test file was not reported low with its context: ${JSON.stringify(byFile["src/app.test.js"])}`);
          assert((result.coverage_notes ?? []).some((x: any) => x.component === "routing:test-example-context"), "no test/example routing note");
          const lowered = (result.coverage_notes ?? []).find((x: any) => x.component === "routing:third-party-lowered");
          assert(lowered && ["public/js/bundle.js", "public/js/widget.js", "includes/vendors/lib/lib.js"].every((file) => lowered.detail.includes(file)),
            `the lowered third-party note is missing or incomplete: ${JSON.stringify(result.coverage_notes)}`);
          assert(!result.warnings.some((warning: string) => /dropped/i.test(warning)), `routing reported a drop: ${JSON.stringify(result.warnings)}`);
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // Dedup keys on file + line range + CWE and keeps one finding by fingerprint order at equal
      // severity/confidence, so a pack finding on a baseline finding's line could replace the existing
      // fingerprint (review F2). Raw Opengrep output, before dedup, must never put both on one line.
      id: "E112 [engine] no line carries both a ci-baseline-* and a syn-node-* Opengrep finding (existing fingerprints stay)",
      engineDep: "opengrep",
      fn: async () => {
        for (const corpus of [OPENGREP_RULES_FIXTURE, SYNVOYA_NODE_FIXTURE]) {
          const managedTmp = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e112-"));
          try {
            const output = await runOpengrep(corpus, managedTmp);
            assert(output.ran, `Opengrep did not run on ${corpus}: ${output.note ?? "no note"}`);
            const byLine = new Map<string, Set<string>>();
            for (const finding of normalizeEngineOutput(output, corpus)) {
              const key = `${finding.location.file}:${finding.location.start_line}`;
              byLine.set(key, (byLine.get(key) ?? new Set()).add(finding.rule_id));
            }
            for (const [key, rules] of byLine) {
              const ids = [...rules];
              assert(!(ids.some((id) => id.startsWith("ci-baseline-")) && ids.some((id) => id.startsWith("syn-node-"))),
                `${key} carries ${ids.join(" + ")}`);
            }
          } finally {
            await rm(managedTmp, { recursive: true, force: true });
          }
        }
      },
    },
    {
      // Design §10.6: field Gitleaks hits on identifiers and public-by-design values (Doctrine index
      // names, conda pins, OAuth client/tenant ids, reCAPTCHA site keys and Google's test keys, QStash
      // dev-server defaults, Firebase config keys) are allowlisted per class; real secrets still fire.
      // Values are assembled at run time so this source file holds no secret-shaped literal.
      id: "E121 [engine] Gitleaks precision allowlists silence identifier classes and keep real secrets",
      engineDep: "gitleaks",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e121-"));
        const j = (...parts: string[]) => parts.join("");
        const files: Record<string, string> = {
          "migrations/Version1.php": `$this->renameIndex('oauth2_access_tokens', '${j("IDX_368A4209", "A76ED395")}', 'user_id');\n`,
          "ml/env.yaml": `dependencies:\n  - aws-c-auth=0.7.3=${j("h28f75", "89_1")}\n  - tokenizers=0.14.1=${j("py310h32", "0607d_2")}\n`,
          "deploy/config.yml": `env:\n  OAUTH_CLIENT_ID: "${j("f508c1d2-0b1e-4a6f-9c3d-", "7e2a1b9c4d5e")}"\n  OAUTH_TENANT_ID: "${j("c687a1b2-3c4d-4e5f-8a9b-", "0c1d2e3f4a5b")}"\n`,
          "config/site.yml": `emailOctopusSiteKey: ${j("6LdYxAcTAAAAAJ", "cZVRqyHh71UMIEGNQ_MXjiZKh0")}\n`,
          "src/Captcha.tsx": `const CAPTCHA_TEST_KEY = '${j("6LeIxAcTAAAAAJcZVRqyHh71", "UMIEGNQ_MXjiZKhI")}'\n`,
          ".github/workflows/e2e.yaml": `env:\n  QSTASH_TOKEN: "${j("eyJVc2VySUQiOiJkZWZhdWx0VXNlciIsIlBhc3N3b3Jk", "IjoiZGVmYXVsdFBhc3N3b3JkIn0=")}"\n` +
            `  QSTASH_CURRENT_SIGNING_KEY: "${j("sig_7kYjw48mhY7k", "AjqNGcy6cr29RJ6r")}"\n`,
          "android/app/google-services.json": `{"api_key": [{"current_key": "${j("AIzaSyA1b2C3d4E5f6G7h8", "I9j0K1l2M3n4O5p6Q")}"}]}\n`,
          "services/spotify.js": `const CLIENT_SECRET = '${j("4395a1c7e2b94f0d", "8a6c3e1f5b7d9a20")}'\n`,
          "config/recaptcha.php": `'secret_key' => env('RECAPTCHA_SECRET_KEY', '${j("6LcJq8Zt2Vb7Nx4Rk1Pm", "9Wd3Hy6Lc0Ts5Gf8Ja2x")}'),\n`,
          "ios/AppConfig.json": `{"api_key": "${j("AIzaSyA1b2C3d4E5f6G7h8", "I9j0K1l2M3n4O5p6Q")}"}\n`,
          // Review round 2: a client secret inside google-services.json is still a secret.
          "android/other/google-services.json": `{"client_secret": "${j("4c1e9a7b2d8f6e0a", "3b5c7d9e1f2a4b6c")}"}\n`,
        };
        try {
          for (const [file, text] of Object.entries(files)) {
            await mkdir(dirname(join(temporaryRoot, file)), { recursive: true });
            await writeFile(join(temporaryRoot, file), text, "utf8");
          }
          const result = (await client.callTool("codeinspectus_scan", { path: temporaryRoot, scanners: ["secret"] })).structuredContent;
          const reported = new Set(result.findings.filter((x: any) => x.engines.includes("gitleaks")).map((x: any) => x.location.file));
          const real = ["services/spotify.js", "config/recaptcha.php", "ios/AppConfig.json", "android/other/google-services.json"];
          for (const file of real) assert(reported.has(file), `Gitleaks no longer reports the secret in ${file}: ${JSON.stringify([...reported])}`);
          const silent = Object.keys(files).filter((file) => !real.includes(file));
          for (const file of silent) assert(!reported.has(file), `Gitleaks still reports the allowlisted class in ${file}`);
          assert(result.secret_coverage === "verified", `secret coverage read ${result.secret_coverage}`);
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
    {
      // Design 4.6 with real Gitleaks output (--redact=100, so the SARIF never carries the value): a generic
      // secret in a test file that is also used in application code keeps its severity; a test-only one is
      // lowered. Values are assembled at run time so this source file holds no secret-shaped literal.
      id: "E137 [engine] a generic secret shared by src/ and tests/ keeps its severity in both; a test-only copy is lowered",
      engineDep: "gitleaks",
      fn: async () => {
        const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-e137-"));
        const shared = ["Qm7ZpX2kL9vR4tY8", "wB3nC6dF1gH5jK0s"].join("");
        const testOnly = ["Zt5YbN8cV2xK7mQ4", "pL1wR9sD3fG6hJ0a"].join("");
        try {
          await mkdir(join(temporaryRoot, "src"), { recursive: true });
          await mkdir(join(temporaryRoot, "tests"), { recursive: true });
          await writeFile(join(temporaryRoot, "src", "keys.ts"), `export const config = { api_key: "${shared}" };\n`, "utf8");
          await writeFile(join(temporaryRoot, "tests", "keys.test.ts"), `// fixture\nconst apiKey = "${shared}";\n`, "utf8");
          await writeFile(join(temporaryRoot, "tests", "only.test.ts"), `const apiKey = "${testOnly}";\n`, "utf8");
          const result = (await client.callTool("codeinspectus_scan", { path: temporaryRoot, scanners: ["secret"] })).structuredContent;
          const generic = result.findings.filter((x: any) => x.engines.includes("gitleaks") && x.rule_id === "generic-api-key");
          const byFile = Object.fromEntries(generic.map((x: any) => [x.location.file, x]));
          const app = byFile["src/keys.ts"];
          const reused = byFile["tests/keys.test.ts"];
          const only = byFile["tests/only.test.ts"];
          assert(app && reused && only, `Gitleaks did not report all three generic secrets: ${JSON.stringify(Object.keys(byFile))}`);
          assert(app.severity !== "low" && reused.severity === app.severity,
            `the shared test copy did not keep its severity: src ${app.severity}, tests ${reused.severity}`);
          assert(reused.message.includes("same value also found in 1 non-test file(s): src/keys.ts"), `no reuse note: ${reused.message}`);
          assert(only.severity === "low" && only.title.startsWith("Test/example context"), `the test-only copy was not lowered: ${JSON.stringify(only)}`);
          // Routing-only: the key is never written to a finding, and the values never leave the scan.
          const text = JSON.stringify(result);
          assert(generic.every((x: any) => x.secret_value_hash === undefined), "a routing key was written as secret_value_hash");
          assert(!text.includes(shared) && !text.includes(testOnly), "a secret value appears in the scan result");
        } finally {
          await rm(temporaryRoot, { recursive: true, force: true });
        }
      },
    },
  ];

  for (const c of checks) {
    try {
      // Engine-dependency gating for stable runs.
      if (c.engineDep === "opengrep" && !engineRan("opengrep")) {
        record(c.id, "skip", "opengrep did not run (repair-engines)");
        continue;
      }
      if (c.engineDep === "gitleaks" && !engineRan("gitleaks")) {
        record(c.id, "skip", "gitleaks did not run (repair-engines)");
        continue;
      }
      if (c.engineDep === "trivy-vuln") {
        if (!engineRan("trivy")) {
          record(c.id, "skip", "trivy did not run (repair-engines)");
          continue;
        }
        if (!scan.trivy_db_date) {
          record(c.id, "skip", "trivy vuln DB not present (repair-engines populates it)");
          continue;
        }
      }
      if (c.engineDep === "osv-scanner" || c.engineDep === "osv-pypi") {
        const blocker = c.engineDep === "osv-scanner" ? await osvNotInstalled() : await osvPypiNotReady();
        if (blocker) {
          record(c.id, "skip", blocker);
          continue;
        }
      }
      await c.fn();
      record(c.id, "pass", "ok");
    } catch (err) {
      if (err instanceof EvalSkip) {
        record(c.id, "skip", err.message);
        continue;
      }
      record(c.id, "fail", err instanceof Error ? err.message : String(err));
    }
  }

  client.close();

  // Report.
  const pass = results.filter((r) => r.status === "pass").length;
  const fail = results.filter((r) => r.status === "fail").length;
  const skip = results.filter((r) => r.status === "skip").length;
  process.stdout.write("\nCodeInspectus eval results\n=========================\n");
  for (const r of results) {
    const mark = r.status === "pass" ? "PASS" : r.status === "fail" ? "FAIL" : "SKIP";
    process.stdout.write(`[${mark}] ${r.id}${r.status === "pass" ? "" : " — " + r.detail}\n`);
  }
  process.stdout.write(`\n${pass} passed, ${fail} failed, ${skip} skipped (of ${results.length}).\n`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`eval harness error: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(2);
});
