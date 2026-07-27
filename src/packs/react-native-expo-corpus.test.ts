import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { runAiChecks } from "../ai-checks/index.js";
import { detectTechnologies } from "../technology-detection.js";

const CORPUS = resolve(process.cwd(), "fixtures/react-native-expo-corpus");
const EXPECTED_RULE_IDS = [
  "ci-react-native-sensitive-async-storage",
  "ci-react-native-webview-untrusted-content",
  "ci-react-native-webview-mixed-content",
  "ci-react-native-webview-universal-file-access",
  "ci-expo-secret-in-public-config",
  "ci-expo-unsigned-cleartext-updates",
].sort();

async function scan(state: "tp" | "fp" | "fixed") {
  const target = resolve(CORPUS, state);
  const technology = await detectTechnologies(target);
  const result = await runAiChecks(target, {
    detectedTechnologies: technology.detected_technologies,
  });
  return { technology, result };
}

describe("React Native and Expo corpus", () => {
  it("produces exactly one finding per owned rule in the TP project", async () => {
    const { technology, result } = await scan("tp");
    expect(technology.detected_technologies.map((item) => item.id)).toEqual(
      expect.arrayContaining(["typescript", "react-native", "expo"]),
    );
    expect(result.findings.map((finding) => finding.rule_id).sort()).toEqual(EXPECTED_RULE_IDS);
    expect(result.findings).toHaveLength(6);
    expect(result.findings.every((finding) => finding.confidence === "high")).toBe(true);
    expect(JSON.stringify(result)).not.toContain("CI_RN_EXPO_REDACTION_SENTINEL");

    const reactNative = result.packCoverage.find((pack) => pack.pack_id === "react-native");
    const expo = result.packCoverage.find((pack) => pack.pack_id === "expo");
    expect(reactNative).toMatchObject({
      state: "ran",
      analyzers: { registered: 4, ran: 4 },
      rules: { registered: 4, ran: 4 },
    });
    expect(expo).toMatchObject({
      state: "ran",
      analyzers: { registered: 2, ran: 2 },
      rules: { registered: 2, ran: 2 },
    });
  });

  it.each(["fp", "fixed"] as const)("keeps the %s project finding-free", async (state) => {
    const { result } = await scan(state);
    expect(result.findings).toEqual([]);
    expect(result.packCoverage.find((pack) => pack.pack_id === "react-native")?.state).toBe("ran");
    expect(result.packCoverage.find((pack) => pack.pack_id === "expo")?.state).toBe("ran");
  });
});
