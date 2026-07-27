import type { NativeAnalyzer } from "../types.js";
import type { Finding } from "../../types.js";

import {
  createCachedFlutterProjectLoader,
  type FlutterProject,
  type FlutterProjectInput,
} from "./project.js";
import {
  FLUTTER_TLS_RULE_ID,
  runFlutterTlsVerificationDisabled,
} from "./tls.js";
import {
  FLUTTER_PREFERENCES_RULE_ID,
  runFlutterSensitiveSharedPreferences,
} from "./preferences.js";
import {
  FLUTTER_WEBVIEW_RULE_ID,
  runFlutterWebViewUntrustedContent,
} from "./webview.js";
import { FLUTTER_LOG_RULE_ID, runFlutterSensitiveLog } from "./logs.js";
import {
  FLUTTER_SUPABASE_KEY_RULE_ID,
  runFlutterSupabasePrivilegedKeyClient,
} from "./supabase.js";
import { FLUTTER_CLEARTEXT_RULE_ID, runFlutterCleartextNetwork } from "./cleartext.js";

const COMMON_COMPONENTS = ["pack:flutter:dispatch", "flutter:dart-structural-parser"] as const;

type FlutterRuleRunner = (input: FlutterProjectInput) => Promise<Finding[]>;

function analyzerRun(
  loadProject: () => Promise<FlutterProject>,
  runner: FlutterRuleRunner,
): NativeAnalyzer["run"] {
  return async () => {
    const project = await loadProject();
    return {
      findings: await runner(project),
      ...(project.limitations?.length ? { notes: project.limitations } : {}),
    };
  };
}

/** Six independent analyzers sharing one lazy, per-pack project parse. */
export function createFlutterAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedFlutterProjectLoader(target);
  return [
    {
      id: "flutter-tls-verification",
      components: [...COMMON_COMPONENTS, "ai:flutter-tls-verification"],
      ruleIds: [FLUTTER_TLS_RULE_ID],
      run: analyzerRun(loadProject, runFlutterTlsVerificationDisabled),
    },
    {
      id: "flutter-sensitive-preferences",
      components: [...COMMON_COMPONENTS, "ai:flutter-sensitive-preferences"],
      ruleIds: [FLUTTER_PREFERENCES_RULE_ID],
      run: analyzerRun(loadProject, runFlutterSensitiveSharedPreferences),
    },
    {
      id: "flutter-webview-untrusted-content",
      components: [...COMMON_COMPONENTS, "ai:flutter-webview-untrusted-content"],
      ruleIds: [FLUTTER_WEBVIEW_RULE_ID],
      run: analyzerRun(loadProject, runFlutterWebViewUntrustedContent),
    },
    {
      id: "flutter-sensitive-log",
      components: [...COMMON_COMPONENTS, "ai:flutter-sensitive-log"],
      ruleIds: [FLUTTER_LOG_RULE_ID],
      run: analyzerRun(loadProject, runFlutterSensitiveLog),
    },
    {
      id: "flutter-supabase-privileged-key",
      components: [...COMMON_COMPONENTS, "ai:flutter-supabase-privileged-key"],
      ruleIds: [FLUTTER_SUPABASE_KEY_RULE_ID],
      run: analyzerRun(loadProject, runFlutterSupabasePrivilegedKeyClient),
    },
    {
      id: "flutter-cleartext-network",
      components: [...COMMON_COMPONENTS, "ai:flutter-cleartext-network"],
      ruleIds: [FLUTTER_CLEARTEXT_RULE_ID],
      run: analyzerRun(loadProject, runFlutterCleartextNetwork),
    },
  ];
}

export * from "./dart.js";
export * from "./project.js";
export * from "./tls.js";
export * from "./preferences.js";
export * from "./webview.js";
export * from "./logs.js";
export * from "./supabase.js";
export * from "./cleartext.js";
