import { describe, expect, test } from "vitest";

import {
  dartCalls,
  expressionFromTokens,
  parseDartSource,
} from "./dart.js";
import { deepLinkSeedNames, sensitiveCredentialLabels } from "./analysis.js";
import type { FlutterProject } from "./project.js";
import { runFlutterSensitiveSharedPreferences } from "./preferences.js";
import { runFlutterSupabasePrivilegedKeyClient } from "./supabase.js";

function project(source: string): FlutterProject {
  return {
    target: "/virtual/flutter",
    root: "/virtual/flutter",
    files: [parseDartSource("lib/main.dart", source)],
  };
}

describe("scope-aware Dart definitions", () => {
  test("does not seed a trusted constant only because its variable is named deepLink", () => {
    const document = parseDartSource(
      "lib/main.dart",
      "const deepLink = 'https://trusted.example/help';",
    );
    expect(deepLinkSeedNames(document)).toEqual(new Set());
  });

  test("retains receivers across postfix null assertions and null-aware calls", () => {
    const document = parseDartSource(
      "lib/main.dart",
      "prefs!.setString('access_token', value); logger?.info(accessToken);",
    );
    expect(dartCalls(document).filter((call) => call.name === "setString")[0]?.receiver).toBe("prefs");
    expect(dartCalls(document).filter((call) => call.name === "info")[0]?.receiver).toBe("logger");
  });

  test("does not let a receiver definition leak across sibling functions or a local shadow", async () => {
    const result = await runFlutterSensitiveSharedPreferences(project(`
      Future<void> obtain() async {
        final prefs = await SharedPreferences.getInstance();
      }
      Future<void> safe(SecureStore prefs, String accessToken) async {
        await prefs!.setString('access_token', accessToken);
      }
      final outerPrefs = await SharedPreferences.getInstance();
      Future<void> shadow(SecureStore outerPrefs, String password) async {
        await outerPrefs.setString('password', password);
      }
    `));
    expect(result).toHaveLength(0);
  });

  test("bounds a typed method parameter to its own following body", async () => {
    const result = await runFlutterSensitiveSharedPreferences(project(`
      class StorageService {
        final SecureStore prefs;
        void first(SharedPreferences prefs) {}
        void second(String accessToken) {
          prefs.setString('access_token', accessToken);
        }
      }
    `));
    expect(result).toHaveLength(0);
  });

  test("uses the nearest preceding receiver definition and supports nullable typed injection", async () => {
    const result = await runFlutterSensitiveSharedPreferences(project(`
      Future<void> ordered(String value) async {
        var prefs = SecureStore();
        await prefs.setString('access_token', value);
        prefs = await SharedPreferences.getInstance();
        await prefs.setString('access_token', value);
      }
      Future<void> injected(SharedPreferences? prefs, String value) async {
        await prefs!.setString('refresh_token', value);
      }
    `));
    expect(result).toHaveLength(2);
    expect(result.every((finding) => finding.cwe.length === 1 && finding.cwe[0] === "CWE-312"))
      .toBe(true);
  });
});

describe("SharedPreferences key/value precision", () => {
  test("suppresses metadata keys unless the value is independently sensitive", async () => {
    const result = await runFlutterSensitiveSharedPreferences(project(`
      final prefs = SharedPreferencesAsync();
      await prefs.setString('access_token_expiry', expiry);
      await prefs.setString('show_password', showPassword);
      await prefs.setString('token_status', status);
      await prefs.setString('token_type', type);
      await prefs.setString('token_status', accessToken);
    `));
    expect(result).toHaveLength(1);
  });

  test("resolves string key aliases only through the visible reaching definition", async () => {
    const result = await runFlutterSensitiveSharedPreferences(project(`
      Future<void> messaging(String value) async {
        const tokenKey = 'fcm_token';
        final prefs = SharedPreferencesAsync();
        await prefs.setString(tokenKey, value);
      }
      Future<void> auth(String value) async {
        const tokenKey = 'access_token';
        final prefs = SharedPreferencesAsync();
        await prefs.setString(tokenKey, value);
      }
    `));
    expect(result).toHaveLength(1);
  });

  test("suppresses only wholly safe projections and uses interpolation context for device tokens", () => {
    const document = parseDartSource("lib/main.dart", `
      print('password=$password; hash=$hash');
      print('FCM token: $token');
      print('auth token: $token');
      print(accessToken.length);
      print(hash(accessToken));
      print(hash(accessToken) + password);
    `);
    const labels = dartCalls(document)
      .filter((call) => call.name === "print")
      .map((call) => sensitiveCredentialLabels(expressionFromTokens(call.arguments[0]?.tokens ?? [])));
    expect(labels[0]).toContain("password");
    expect(labels[1]).toEqual([]);
    expect(labels[2]).toContain("token");
    expect(labels[3]).toEqual([]);
    expect(labels[4]).toEqual([]);
    expect(labels[5]).toContain("password");
  });
});

describe("scope-aware Supabase privileged-key flow", () => {
  test("does not leak privileged taint across functions or past a newer public definition", async () => {
    const result = await runFlutterSupabasePrivilegedKeyClient(project(`
      void sourceOnly() {
        final key = String.fromEnvironment('SUPABASE_SERVICE_ROLE_KEY');
      }
      Future<void> safeParameter(String key) async {
        await Supabase.initialize(url: projectUrl, anonKey: key);
      }
      Future<void> overwritten(bool usePublic) async {
        var selected = String.fromEnvironment('SUPABASE_SERVICE_ROLE_KEY');
        selected = String.fromEnvironment('SUPABASE_ANON_KEY');
        await Supabase.initialize(url: projectUrl, anonKey: selected);
      }
    `));
    expect(result).toHaveLength(0);
  });

  test("lets privileged evidence dominate mixed public/privileged expressions", async () => {
    const result = await runFlutterSupabasePrivilegedKeyClient(project(`
      final anonKey = String.fromEnvironment('SUPABASE_ANON_KEY');
      final serviceRoleKey = String.fromEnvironment('SUPABASE_SERVICE_ROLE_KEY');
      final selected = usePublic ? anonKey : serviceRoleKey;
      await Supabase.initialize(
        url: projectUrl,
        anonKey: useOther
          ? 'sb_publishable_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS'
          : 'sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS',
      );
      final client = SupabaseClient(projectUrl, selected);
    `));
    expect(result).toHaveLength(2);
  });

  test("recognizes an import-alias suffix for Supabase.initialize", async () => {
    const result = await runFlutterSupabasePrivilegedKeyClient(project(`
      import 'package:supabase_flutter/supabase_flutter.dart' as supa;
      final key = String.fromEnvironment('SUPABASE_SERVICE_ROLE_KEY');
      await supa.Supabase.initialize(url: projectUrl, anonKey: key);
    `));
    expect(result).toHaveLength(1);
  });
});
