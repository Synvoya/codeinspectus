import type { NativeAnalyzer } from "../types.js";

import {
  createCachedExpoConfigLoader,
  EXPO_SECRET_PUBLIC_CONFIG_RULE_ID,
  EXPO_UNSIGNED_CLEARTEXT_UPDATES_RULE_ID,
  runExpoSecretInPublicConfig,
  runExpoUnsignedCleartextUpdates,
} from "./config.js";

const COMMON_COMPONENTS = ["pack:expo:dispatch", "expo:static-config-parser"] as const;

/** Two independently-failable Expo analyzers sharing one bounded static parse. */
export function createExpoAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadConfig = createCachedExpoConfigLoader(target);
  return [
    {
      id: "expo-secret-in-public-config",
      components: [...COMMON_COMPONENTS, "ai:expo-secret-in-public-config"],
      ruleIds: [EXPO_SECRET_PUBLIC_CONFIG_RULE_ID],
      run: () => runExpoSecretInPublicConfig(loadConfig()),
    },
    {
      id: "expo-unsigned-cleartext-updates",
      components: [...COMMON_COMPONENTS, "ai:expo-unsigned-cleartext-updates"],
      ruleIds: [EXPO_UNSIGNED_CLEARTEXT_UPDATES_RULE_ID],
      run: () => runExpoUnsignedCleartextUpdates(loadConfig()),
    },
  ];
}

export * from "./config.js";
