import type { Finding } from "../../types.js";
import type { NativeAnalyzer } from "../types.js";

import {
  createCachedReactNativeProjectLoader,
  type ReactNativeProject,
  type ReactNativeProjectInput,
} from "./project.js";
import {
  REACT_NATIVE_ASYNC_STORAGE_RULE_ID,
  runReactNativeSensitiveAsyncStorage,
} from "./async-storage.js";
import {
  REACT_NATIVE_WEBVIEW_UNTRUSTED_RULE_ID,
  runReactNativeWebViewUntrustedContent,
} from "./webview-untrusted.js";
import {
  REACT_NATIVE_WEBVIEW_MIXED_CONTENT_RULE_ID,
  runReactNativeWebViewMixedContent,
} from "./webview-mixed-content.js";
import {
  REACT_NATIVE_WEBVIEW_UNIVERSAL_FILE_ACCESS_RULE_ID,
  runReactNativeWebViewUniversalFileAccess,
} from "./webview-universal-file-access.js";

const COMMON_COMPONENTS = [
  "pack:react-native:dispatch",
  "react-native:javascript-structural-parser",
] as const;

type ReactNativeRuleRunner = (input: ReactNativeProjectInput) => Promise<Finding[]>;

function analyzerRun(
  loadProject: () => Promise<ReactNativeProject>,
  runner: ReactNativeRuleRunner,
): NativeAnalyzer["run"] {
  return async () => {
    const project = await loadProject();
    return {
      findings: await runner(project),
      ...(project.limitations?.length ? { notes: project.limitations } : {}),
    };
  };
}

/** Four independently-failable analyzers sharing one lazy project parse. */
export function createReactNativeAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedReactNativeProjectLoader(target);
  return [
    {
      id: "react-native-sensitive-async-storage",
      components: [...COMMON_COMPONENTS, "ai:react-native-sensitive-async-storage"],
      ruleIds: [REACT_NATIVE_ASYNC_STORAGE_RULE_ID],
      run: analyzerRun(loadProject, runReactNativeSensitiveAsyncStorage),
    },
    {
      id: "react-native-webview-untrusted-content",
      components: [...COMMON_COMPONENTS, "ai:react-native-webview-untrusted-content"],
      ruleIds: [REACT_NATIVE_WEBVIEW_UNTRUSTED_RULE_ID],
      run: analyzerRun(loadProject, runReactNativeWebViewUntrustedContent),
    },
    {
      id: "react-native-webview-mixed-content",
      components: [...COMMON_COMPONENTS, "ai:react-native-webview-mixed-content"],
      ruleIds: [REACT_NATIVE_WEBVIEW_MIXED_CONTENT_RULE_ID],
      run: analyzerRun(loadProject, runReactNativeWebViewMixedContent),
    },
    {
      id: "react-native-webview-universal-file-access",
      components: [...COMMON_COMPONENTS, "ai:react-native-webview-universal-file-access"],
      ruleIds: [REACT_NATIVE_WEBVIEW_UNIVERSAL_FILE_ACCESS_RULE_ID],
      run: analyzerRun(loadProject, runReactNativeWebViewUniversalFileAccess),
    },
  ];
}

export * from "./javascript.js";
export * from "./project.js";
export * from "./async-storage.js";
export * from "./webview-untrusted.js";
export * from "./webview-mixed-content.js";
export * from "./webview-universal-file-access.js";
