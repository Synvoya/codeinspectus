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

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { cp, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runOpengrepShadowParity } from "../src/shadow/opengrep-parity.js";

const FIXTURE = resolve(process.cwd(), "fixtures/vulnerable-app");
const CORS_FIXTURE = resolve(process.cwd(), "fixtures/cors-corpus");
const API_BOUNDARY_FIXTURE = resolve(process.cwd(), "fixtures/api-boundary-corpus");
const SECURITY_CONTROLS_FIXTURE = resolve(process.cwd(), "fixtures/security-controls-corpus");
const SUPABASE_EDGE_AUTH_FIXTURE = resolve(process.cwd(), "fixtures/supabase-edge-auth-corpus");
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
const OPENGREP_SHADOW_FIXTURE = resolve(process.cwd(), "fixtures/opengrep-shadow-corpus");
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
  "ai:flutter-supabase-privileged-key": "sha256:e6322d94cff6291ff61707b3c0753b39d9c6b125403543271ec557bdd76be002",
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
  "react-native:javascript-structural-parser": "sha256:fa67e54b2d3f6ed7a24da1817d43c2f51cde97393c1953f9cb30c84e7449a055",
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
  "The six rules cover exact Django, Flask, FastAPI, Starlette, Jinja, OpenAI, and Anthropic source shapes only; unsupported aliases, computed values, dynamic imports, spreads, and flows beyond the documented bounded aliases fail closed.",
  "Format strings and leading tab indentation are currently unsupported: Python 3.12 nested same-delimiter replacement strings and mixed tab-stop indentation are skipped and reported rather than risking literal text or conditional bindings being analyzed as executable direct scope.",
  "Generated, migration, dependency, build, test, fixture, demo, sample, and example trees and conventional test files are excluded from project-root scans unless a supported source file is scanned directly.",
  "Symbolic links, unsupported encodings, generated headers, unreadable or malformed files, files over 2 MiB, and source beyond the 50,000-entry/10,000-file/64 MiB/1,000,000-token/1,000,000-node/32-level project bounds are skipped and reported in pack coverage.",
  "The pack parses repository evidence only, never imports or executes target Python, and does not replace dependency, runtime, or penetration testing.",
] as const;

const PYTHON_AI_API_COMPONENT_SIGNATURES: Readonly<Record<string, string>> = {
  "codeinspectus:pipeline": "sha256:76b7a7b37408ced23a6511a77a757a1c058171e26eb41f842cb7203a5ca5c73d",
  "pack:python-ai-api:dispatch": "sha256:25fc9425b3ffcf2bc1f15178e39000687fb2e261d1cb938f0a77a59828a1b9dd",
  "python:lezer-structural-parser": "sha256:4abf638d02d334cd6a8e667f573179f2fbba89f11a3ce415a11ec91003b1824f",
  "ai:python-hardcoded-signing-secret": "sha256:9381fb56d3598c1f478fba84a9b0db960f879d0b6aa8bda021a57c016d601c3a",
  "ai:python-credentialed-cors": "sha256:46477b8b3f9abff6ce4e771aaf3830721e26c31481ccce82751278930b584adf",
  "ai:python-untrusted-file-response": "sha256:f77122fe93de07f380fca77b64f72cd7860c61c5a5255e48e928cb269e186d54",
  "ai:python-untrusted-redirect": "sha256:ab6e8662a4039b7138c0468d779db948a1ef40271b0d6d700fb569166275b3b5",
  "ai:python-untrusted-template-source": "sha256:0592921975193cdb4ca77cf885051efad80b327bc78fc2cbaa90c19e4524806e",
  "ai:python-llm-output-dangerous-html": "sha256:c0ad9bab6d078faf4f2946b384ad8ce31c44729fee65049d38d41d26271da1d4",
};

// ── Minimal MCP stdio client ────────────────────────────────────────────────
class McpClient {
  private child: ChildProcessWithoutNullStreams;
  private buf = "";
  private pending = new Map<number, (v: any) => void>();
  private nextId = 1;

  constructor() {
    this.child = spawn("node", ["dist/index.js"], { stdio: ["pipe", "pipe", "pipe"] });
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
    javascript.analyzers.registered === 7 && javascript.analyzers.ran === 7,
    `${label}: JavaScript/TypeScript analyzer coverage was not 7/7`,
  );
  assert(
    javascript.rules.registered === 21 && javascript.rules.ran === 21,
    `${label}: JavaScript/TypeScript rule coverage was not 21/21`,
  );

  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter(
    (engine: any) => engine.engine === "codeinspectus-ai",
  );
  assert(aiEngines.length === 1, `${label}: expected exactly one AI engine run record`);
  assert(
    aiEngines[0].ran === true && aiEngines[0].version === "5.0.0",
    `${label}: expected codeinspectus-ai@5.0.0 to run`,
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
      javascript.analyzers.ran === 7 &&
      javascript.rules.ran === 21,
    `${label}: unconditional JavaScript/TypeScript pack coverage changed`,
  );
  if (!expectEngineDetails) return;
  const aiEngines = (result.engine_details ?? []).filter(
    (engine: any) => engine.engine === "codeinspectus-ai",
  );
  assert(
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.0.0",
    `${label}: expected exactly one codeinspectus-ai@5.0.0 run`,
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
      javascript.analyzers.ran === 7 &&
      javascript.rules.ran === 21,
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
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.0.0",
    `${label}: expected exactly one codeinspectus-ai@5.0.0 run`,
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
    "python", "fastapi", "starlette", "flask", "django", "jinja2", "openai", "anthropic",
  ]) assert(technologies.has(technology), `${label}: ${technology} technology detection missing`);

  const pack = result.pack_coverage?.find((candidate: any) => candidate.pack_id === "python-ai-api");
  assert(pack?.state === "ran", `${label}: Python AI/API pack did not report ran`);
  assert(
    pack.analyzers.registered === 6 && pack.analyzers.ran === 6,
    `${label}: Python AI/API analyzer coverage was not 6/6`,
  );
  assert(
    pack.rules.registered === 6 && pack.rules.ran === 6,
    `${label}: Python AI/API rule coverage was not 6/6`,
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
    aiEngines.length === 1 && aiEngines[0].ran === true && aiEngines[0].version === "5.0.0",
    `${label}: expected exactly one codeinspectus-ai@5.0.0 run`,
  );
  assert(
    (result.engine_details ?? []).every((engine: any) => engine.engine === "codeinspectus-ai"),
    `${label}: AI-only scan unexpectedly ran an external engine`,
  );
}

function assertExactPythonAiApiRuleIds(findings: any[], label: string): void {
  assert(findings.length === 6, `${label}: expected six Python AI/API findings, got ${findings.length}`);
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
    result.summary?.total === 6 && result.summary.high === 5 && result.summary.medium === 1 &&
      result.summary.critical === 0 && result.summary.low === 0 && result.summary.info === 0,
    `${label}: expected severity totals 5 high / 1 medium`,
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

async function replaceFixtureDirectory(source: string, target: string): Promise<void> {
  await rm(target, { recursive: true, force: true });
  await cp(source, target, { recursive: true });
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
    coverage.packages.resolved === 9 && coverage.packages.eligible === 5 && coverage.packages.skipped === 4,
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
        assert(nativePack.analyzers.registered === 7 && nativePack.analyzers.ran === 7, "native analyzer execution counts are wrong");
        assert(nativePack.rules.registered === 21 && nativePack.rules.ran === 21, "native rule execution counts are wrong");
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
      id: "E08 prompt-injection sink + excessive agency (LLM01+LLM06, CWE-1426)",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-prompt-injection-sink");
        assert(!!f, "prompt-injection sink not detected");
        assert(f.cwe.includes("CWE-1426"), "expected CWE-1426");
        assert(f.owasp_llm?.includes("LLM01:2025") && f.owasp_llm?.includes("LLM06:2025"), "expected LLM01 + LLM06");
        assert(f.confidence === "medium", "prompt-injection must be medium confidence (honest scope)");
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
        assert(coverage?.state === "ran" && coverage.rules.ran === 21, "rescan lost native-pack execution coverage");
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
        assert(lr.custom_rule_count === 70, `expected 70 custom rules, got ${lr.custom_rule_count}`);
        assert(lr.detection_db_version === "1.0.0", `expected detection DB 1.0.0, got ${lr.detection_db_version}`);
        assert(lr.detection_db_date === "2026-07-27", `unexpected detection DB date ${lr.detection_db_date}`);
        assert(lr.custom_rules.some((r: any) => r.id === "ci-ai-rls-using-true"), "missing ci-ai-rls-using-true in list_rules");
        const boundary = lr.custom_rules.find((r: any) => r.id === "ci-ai-client-error-leak");
        assert(boundary?.owasp_web?.includes("A05:2021") && boundary?.owasp_api?.includes("API8:2023"), "new rules must expose OWASP Web/API mappings");
        const nativeRules = lr.custom_rules.filter((rule: any) => rule.engine === "codeinspectus-ai");
        assert(nativeRules.length === 49, `expected 49 native rules, got ${nativeRules.length}`);
        assert(nativeRules.filter((rule: any) => rule.pack_id === "javascript-typescript").length === 21, "JavaScript/TypeScript native rule ownership is wrong");
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
        assert(nativePack?.analyzer_count === 7 && nativePack.rule_count === 21, "list_rules JavaScript/TypeScript pack inventory is wrong");
        const baselinePack = lr.native_packs.find((pack: any) => pack.id === "javascript-baseline");
        assert(baselinePack?.scanner_kind === "sast" && baselinePack.analyzer_count === 1 && baselinePack.rule_count === 2, "list_rules JavaScript baseline pack inventory is wrong");
        const promotedRules = nativeRules.filter((rule: any) => rule.pack_id === "javascript-baseline");
        assert(promotedRules.length === 2 && promotedRules.every((rule: any) => rule.kind === "sast" && rule.fallback_engine === "opengrep"), "promoted rule ownership/fallback is wrong");
        const flutterPack = lr.native_packs.find((pack: any) => pack.id === "flutter");
        assert(flutterPack?.analyzer_count === 6 && flutterPack.rule_count === 6, "list_rules Flutter pack inventory is wrong");
        assert(flutterPack.version === "1.0.0", `expected Flutter pack 1.0.0, got ${flutterPack.version}`);
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
          assert(pack?.version === "1.0.0", `expected ${packId} pack 1.0.0`);
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
        assert(pythonPack?.version === "1.0.0", "expected Python AI/API pack 1.0.0");
        assert(
          pythonPack.analyzer_count === 6 && pythonPack.rule_count === 6,
          "list_rules Python AI/API pack inventory is wrong",
        );
        assertExactJson(pythonPack.languages, ["python"], "list_rules Python languages changed");
        assertExactJson(
          pythonPack.frameworks,
          ["fastapi", "starlette", "flask", "django", "jinja2", "openai", "anthropic"],
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
        const pubEngine = lr.engines.find((engine: any) => engine.engine === "codeinspectus-pub");
        assert(pubEngine?.version === "1.0.0" && pubEngine.available === true, "native Pub engine inventory is unavailable");
        const pubDb = lr.advisory_databases?.find((database: any) => database.engine === "codeinspectus-pub");
        assert(["current", "stale"].includes(pubDb?.state), `unexpected Pub database state ${pubDb?.state}`);
        assert(pubDb.active_advisories === 11 && pubDb.affected_packages === 10, "Pub database inventory changed");
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
        assert(nativeCoverage.length === 8, `SAST-filtered scan must inventory all eight installed native packs, got ${nativeCoverage.length}`);
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
        assert(boundaryScan.engine_details.some((x: any) => x.engine === "codeinspectus-ai" && x.version === "5.0.0"), "AI engine version was not bumped for expanded multi-pack coverage");
      },
    },
    {
      id: "E20 Enhancement 2 explicit header/CSP/cookie/CAPTCHA configurations emit only evidence-gated findings",
      fn: async () => {
        const scenarios = [
          ["tp/headers-next", "ci-ai-security-header-disabled", 1, "http.header.strict-transport-security"],
          ["tp/headers-route-mixed", "ci-ai-security-header-disabled", 1, "http.header.strict-transport-security"],
          ["tp/csp-vercel", "ci-ai-unsafe-production-csp", 1, "http.header.content-security-policy"],
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
      id: "E22 Supabase Edge Function auth runs without SQL project signals",
      fn: async () => {
        const result = (await client.callTool("codeinspectus_scan", {
          path: SUPABASE_EDGE_AUTH_FIXTURE,
          scanners: ["ai"],
        })).structuredContent;
        const findings = result.findings.filter((x: any) => x.rule_id === "ci-ai-edge-fn-no-auth");
        assert(findings.length === 1, `expected one unauthenticated Edge Function finding, got ${findings.length}`);
        assert(findings[0].location.file === "tp/supabase/functions/public-handler/index.ts", "Edge auth finding came from the wrong fixture");
        assert(findings[0].producer_components?.includes("ai:supabase-edge-auth"), "Edge auth provenance component missing");
        assert(!result.findings.some((x: any) => x.location.file.startsWith("fp/")), "authenticated/non-edge fixture produced a finding");
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
          assert(coverage?.state === "partial", `Pub ${label} scan lost explicit exclusions`);
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
            resolved.summary.resolved === 6 &&
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
              introduced.summary.introduced === 6 &&
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
  ];

  for (const c of checks) {
    try {
      // Engine-dependency gating for stable runs.
      if (c.engineDep === "opengrep" && !engineRan("opengrep")) {
        record(c.id, "skip", "opengrep did not run (repair-engines)");
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
      await c.fn();
      record(c.id, "pass", "ok");
    } catch (err) {
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
