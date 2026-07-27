import type { NativeAnalyzer } from "../types.js";

import { IOS_CONFIG_RULE_IDS, runIosConfig } from "./config.js";
import { createCachedIosConfigurationLoader } from "./project.js";

/** One independently-accounted iOS repository-configuration analyzer. */
export function createIosAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedIosConfigurationLoader(target);
  return [{
    id: "ios-configuration",
    components: [
      "pack:ios:dispatch",
      "ios:xml-plist-parser",
      "ai:ios-ats-global-arbitrary-loads",
      "ai:ios-ats-insecure-domain-exception",
      "ai:ios-ats-weak-tls",
      "ai:ios-data-protection",
    ],
    ruleIds: [...IOS_CONFIG_RULE_IDS],
    run: () => runIosConfig(loadProject()),
  }];
}

export * from "./config.js";
export * from "./plist.js";
export * from "./project.js";
