import { describe, expect, test } from "vitest";

import type { Finding } from "../../types.js";
import { parseDartSource } from "./dart.js";
import type { FlutterProject, FlutterProjectInput } from "./project.js";
import { createFlutterAnalyzers } from "./index.js";
import { runFlutterTlsVerificationDisabled } from "./tls.js";
import { runFlutterSensitiveSharedPreferences } from "./preferences.js";
import { runFlutterWebViewUntrustedContent } from "./webview.js";
import { runFlutterSensitiveLog } from "./logs.js";
import { runFlutterSupabasePrivilegedKeyClient } from "./supabase.js";
import { runFlutterCleartextNetwork } from "./cleartext.js";

function project(source: string, path = "lib/main.dart"): FlutterProject {
  return {
    target: "/virtual/flutter",
    root: "/virtual/flutter",
    files: [parseDartSource(path, source)],
  };
}

async function findings(
  runner: (input: FlutterProjectInput) => Promise<Finding[]>,
  source: string,
): Promise<Finding[]> {
  return runner(project(source));
}

describe("Flutter TLS verification rule", () => {
  test("flags only an unconditional true badCertificateCallback", async () => {
    const result = await findings(runFlutterTlsVerificationDisabled, `
      final client = HttpClient();
      client.badCertificateCallback = (cert, host, port) => true; // password=hunter2
      final text = 'badCertificateCallback = (_) => true';
      // client.badCertificateCallback = (_) => true;
    `);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      rule_id: "ci-flutter-tls-verification-disabled",
      severity: "high",
      confidence: "high",
      cwe: ["CWE-295"],
    });
    expect(result[0]?.location.snippet).not.toContain("hunter2");
  });

  test("keeps host-scoped and named callbacks silent", async () => {
    await expect(findings(runFlutterTlsVerificationDisabled, `
      client.badCertificateCallback = (cert, host, port) => host == 'localhost';
      other.badCertificateCallback = validateDevelopmentCertificate;
      third.badCertificateCallback = (cert, host, port) { if (host == 'dev') return true; return false; };
    `)).resolves.toHaveLength(0);
  });

  test("flags an otherwise empty block callback that always returns true", async () => {
    await expect(findings(runFlutterTlsVerificationDisabled, `
      client.badCertificateCallback = (cert, host, port) { return true; };
    `)).resolves.toHaveLength(1);
  });
});

describe("Flutter SharedPreferences credential rule", () => {
  test("tracks legacy, Async, WithCache, typed receivers, and const key aliases", async () => {
    const result = await findings(runFlutterSensitiveSharedPreferences, `
      const tokenKey = 'access_token';
      Future<void> legacy(String value) async {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('refresh_token', value);
      }
      Future<void> modern(String password) async {
        final asyncPrefs = SharedPreferencesAsync();
        await asyncPrefs.setString('password', password);
      }
      Future<void> cached(String value) async {
        final cachedPrefs = await SharedPreferencesWithCache.create(cacheOptions: options);
        await cachedPrefs.setString(tokenKey, value);
      }
      Future<void> injected(SharedPreferences prefs, String apiKey) async {
        await prefs.setString('api_key', apiKey);
      }
    `);
    expect(result).toHaveLength(4);
    expect(result.every((item) => item.severity === "high" && item.confidence === "high")).toBe(true);
    expect(result[0]?.cwe).toEqual(["CWE-312"]);
  });

  test("excludes device messaging tokens, transformed values, and unproven receivers", async () => {
    await expect(findings(runFlutterSensitiveSharedPreferences, `
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('fcm_token', fcmToken);
      await prefs.setString('device_token', deviceToken);
      await prefs.setString('push_token', pushToken);
      await prefs.setString('access_token_hash', hash(accessToken));
      fakePrefs.setString('access_token', accessToken);
    `)).resolves.toHaveLength(0);
  });
});

describe("Flutter WebView route/deep-link rule", () => {
  test("flags unrestricted JavaScript with medium severity and bridge access with high severity", async () => {
    const withoutBridge = await findings(runFlutterWebViewUntrustedContent, `
      final deepLink = Uri.base.queryParameters['target'];
      final controller = WebViewController();
      controller.setJavaScriptMode(JavaScriptMode.unrestricted);
      controller.loadRequest(Uri.parse(deepLink!));
    `);
    const withBridge = await findings(runFlutterWebViewUntrustedContent, `
      final incomingUri = Uri.base.queryParameters['target'];
      final controller = WebViewController();
      controller.setJavaScriptMode(JavascriptMode.unrestricted);
      controller.addJavaScriptChannel('NativeBridge', onMessageReceived: onMessage);
      controller.loadRequest(incomingUri);
    `);
    expect(withoutBridge).toHaveLength(1);
    expect(withoutBridge[0]).toMatchObject({
      severity: "medium",
      confidence: "high",
      cwe: ["CWE-20", "CWE-346"],
    });
    expect(withBridge).toHaveLength(1);
    expect(withBridge[0]?.severity).toBe("high");
  });

  test("accepts exact HTTPS and host equality allowlists in either comparison order", async () => {
    await expect(findings(runFlutterWebViewUntrustedContent, `
      final deepLink = Uri.base.queryParameters['target'];
      final incomingUri = Uri.parse(deepLink!);
      final controller = WebViewController();
      controller.setJavaScriptMode(JavaScriptMode.unrestricted);
      if (incomingUri.scheme == 'https' && incomingUri.host == 'trusted.example') {
        controller.loadRequest(incomingUri);
      }
      if ('https' == incomingUri.scheme && 'trusted.example' == incomingUri.host) {
        controller.loadRequest(incomingUri);
      }
    `)).resolves.toHaveLength(0);
  });

  test("accepts an exact HTTPS/host reject guard before navigation", async () => {
    await expect(findings(runFlutterWebViewUntrustedContent, `
      final deepLink = Uri.base.queryParameters['target'];
      final incomingUri = Uri.parse(deepLink!);
      final controller = WebViewController();
      controller.setJavaScriptMode(JavaScriptMode.unrestricted);
      if (incomingUri.scheme != 'https' || incomingUri.host != 'trusted.example') return;
      controller.loadRequest(incomingUri);
    `)).resolves.toHaveLength(0);
  });

  test("does not treat host prefix checks as an exact allowlist", async () => {
    await expect(findings(runFlutterWebViewUntrustedContent, `
      final deepLink = Uri.base.queryParameters['target'];
      final incomingUri = Uri.parse(deepLink!);
      final controller = WebViewController();
      controller.setJavaScriptMode(JavaScriptMode.unrestricted);
      if (incomingUri.scheme == 'https' && incomingUri.host.startsWith('trusted.example')) {
        controller.loadRequest(incomingUri);
      }
    `)).resolves.toHaveLength(1);
  });

  test("keeps trusted constants and JavaScript-disabled WebViews silent", async () => {
    await expect(findings(runFlutterWebViewUntrustedContent, `
      final controller = WebViewController();
      controller.setJavaScriptMode(JavaScriptMode.disabled);
      controller.loadRequest(Uri.parse(deepLink));
      WebView(initialUrl: 'https://trusted.example', javascriptMode: JavascriptMode.unrestricted);
    `)).resolves.toHaveLength(0);
  });
});

describe("Flutter sensitive log rule", () => {
  test("flags explicit credential values and authorization selectors in recognized sinks", async () => {
    const result = await findings(runFlutterSensitiveLog, `
      import 'dart:developer' as developer;
      final logger = Logger();
      debugPrint(headers['Authorization']);
      logger.info('access token: $accessToken');
      developer.log(password);
    `);
    expect(result).toHaveLength(3);
    expect(result.every((item) => item.severity === "medium" && item.confidence === "high")).toBe(true);
    expect(result[0]?.cwe).toEqual(["CWE-532"]);
  });

  test("excludes redacted/hashed/length/debug-only values and non-logger lookalikes", async () => {
    const result = await findings(runFlutterSensitiveLog, `
      if (kDebugMode) debugPrint(accessToken);
      print(accessToken.length);
      print(hash(accessToken));
      print('accessToken example');
      catalog.info(accessToken);
    `);
    expect(result).toHaveLength(0);
  });

  test("does not treat kDebugMode == false as a debug-only guard", async () => {
    await expect(findings(runFlutterSensitiveLog, `
      if (kDebugMode == false) debugPrint(accessToken);
      if (kDebugMode || allowProductionLogs) debugPrint(refreshToken);
      if (kDebugMode != true) debugPrint(password);
      if (true != kDebugMode) debugPrint(apiKey);
    `)).resolves.toHaveLength(4);
  });
});

describe("Flutter Supabase privileged-key rule", () => {
  test("tracks service-role/secret sources into both client initializers", async () => {
    const legacyPayload = Buffer.from(JSON.stringify({ role: "service_role" })).toString("base64url");
    const opaqueSecret = "sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS";
    const result = await findings(runFlutterSupabasePrivilegedKeyClient, `
      final serviceRoleKey = String.fromEnvironment('SUPABASE_SERVICE_ROLE_KEY');
      await Supabase.initialize(url: 'https://project.supabase.co', anonKey: serviceRoleKey);
      final client = SupabaseClient('https://project.supabase.co', '${opaqueSecret}');
      final legacy = SupabaseClient('https://project.supabase.co', 'header.${legacyPayload}.signature');
    `);
    expect(result).toHaveLength(3);
    expect(result[0]).toMatchObject({
      severity: "critical",
      confidence: "high",
      cwe: ["CWE-798", "CWE-312", "CWE-285"],
    });
    expect(result.every((item) => item.is_secret !== true)).toBe(true);
    expect(result.every((item) => !(item.location.snippet ?? "").includes(opaqueSecret))).toBe(true);
  });

  test("keeps anon/publishable/invalid opaque keys and unused privileged sources silent", async () => {
    await expect(findings(runFlutterSupabasePrivilegedKeyClient, `
      final anonKey = String.fromEnvironment('SUPABASE_ANON_KEY');
      await Supabase.initialize(url: 'https://project.supabase.co', anonKey: anonKey);
      final client = SupabaseClient('https://project.supabase.co', 'sb_publishable_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS');
      final invalid = SupabaseClient('https://project.supabase.co', 'sb_secret_testvalue123');
      final unusedServiceRoleKey = String.fromEnvironment('SUPABASE_SERVICE_ROLE_KEY');
    `)).resolves.toHaveLength(0);
  });
});

describe("Flutter cleartext network rule", () => {
  test("flags Dio base configuration and direct network calls with endpoint-aware severity", async () => {
    const base = await findings(runFlutterCleartextNetwork, `
      final dio = Dio(BaseOptions(baseUrl: 'http://api.real-service.tld/v1'));
    `);
    const auth = await findings(runFlutterCleartextNetwork, `
      Dio().get('http://api.real-service.tld/auth/token');
    `);
    const assignedDio = await findings(runFlutterCleartextNetwork, `
      final client = Dio();
      client.get('http://api.real-service.tld/health');
    `);
    const packageHttp = await findings(runFlutterCleartextNetwork, `
      import 'package:http/http.dart';
      get(Uri.parse('http://api.real-service.tld/health'));
    `);
    const aliasedHttp = await findings(runFlutterCleartextNetwork, `
      import 'package:http/http.dart' as http;
      http.get(Uri.parse('http://api.real-service.tld/health'));
    `);
    expect(base).toHaveLength(1);
    expect(base[0]?.severity).toBe("medium");
    expect(auth).toHaveLength(1);
    expect(auth[0]?.severity).toBe("high");
    expect(assignedDio).toHaveLength(1);
    expect(packageHttp).toHaveLength(1);
    expect(packageHttp[0]).toMatchObject({ cwe: ["CWE-319"], confidence: "high" });
    expect(aliasedHttp).toHaveLength(1);
  });

  test("excludes HTTPS, loopback/emulator, namespace/example, external-browser, and unproven calls", async () => {
    await expect(findings(runFlutterCleartextNetwork, `
      final secureClient = Dio(BaseOptions(baseUrl: 'https://api.real-service.tld'));
      secureClient.get('http://localhost:8080/auth');
      secureClient.get('http://127.0.0.1/auth');
      secureClient.get('http://10.0.2.2/auth');
      WebView(initialUrl: 'http://schemas.android.com/apk/res/android');
      WebView(initialUrl: 'http://example.com/demo');
      launchUrl(Uri.parse('http://api.real-service.tld/auth'));
      get(Uri.parse('http://api.real-service.tld/health'));
      http.get(Uri.parse('http://api.real-service.tld/health'));
      dio.get('http://api.real-service.tld/auth');
      final documentation = 'http://api.real-service.tld/not-a-sink';
    `)).resolves.toHaveLength(0);
  });
});

describe("Flutter analyzer factory", () => {
  test("exports six independent analyzers with common and rule-specific components", () => {
    const analyzers = createFlutterAnalyzers("/does/not/exist");
    expect(analyzers).toHaveLength(6);
    expect(new Set(analyzers.map((analyzer) => analyzer.id)).size).toBe(6);
    for (const analyzer of analyzers) {
      expect(analyzer.components.slice(0, 2)).toEqual([
        "pack:flutter:dispatch",
        "flutter:dart-structural-parser",
      ]);
      expect(analyzer.components).toHaveLength(3);
      expect(analyzer.ruleIds).toHaveLength(1);
    }
    expect(analyzers.map((analyzer) => analyzer.components[2])).toEqual([
      "ai:flutter-tls-verification",
      "ai:flutter-sensitive-preferences",
      "ai:flutter-webview-untrusted-content",
      "ai:flutter-sensitive-log",
      "ai:flutter-supabase-privileged-key",
      "ai:flutter-cleartext-network",
    ]);
  });
});
