import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  arrayItems,
  jsCalls,
  type JsDocument,
  type JsExpression,
} from "./javascript.js";
import {
  expressionIsSafeCredentialDerivative,
  expressionIsStaticEmptyOrBoolean,
  isAsyncStorageReceiver,
  sensitiveContextWords,
} from "./analysis.js";
import { resolveReactNativeProject, type ReactNativeProjectInput } from "./project.js";

export const REACT_NATIVE_ASYNC_STORAGE_RULE_ID = "ci-react-native-sensitive-async-storage";

const CREDENTIAL_WORDS = [
  "password", "passwd", "accesstoken", "refreshtoken", "authtoken", "authorization",
  "bearer", "jwt", "sessiontoken", "apikey", "privatekey", "servicerole", "clientsecret",
  "cookie", "credential", "credentials", "secret", "token",
] as const;
const DEVICE_TOKEN_WORDS = ["fcm", "device", "push", "notification", "messaging", "apns"];

function credentialLabel(word: string): string | undefined {
  const parts = word
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  if (parts.length === 0) return undefined;
  const joined = parts.join("");
  if (
    /^(?:show|has|is|remember|save)(?:password|token|secret)$/.test(joined) ||
    /(?:token|password|secret)(?:hash|hashed|expiry|expires|expiration|status|type|length|digest|fingerprint)$/.test(joined)
  ) return undefined;
  return CREDENTIAL_WORDS.find((candidate) => {
    if (parts.includes(candidate)) return true;
    return parts.some((_part, start) =>
      parts.some((_end, end) => end >= start && parts.slice(start, end + 1).join("") === candidate)
    );
  });
}

function sensitiveLabels(
  document: JsDocument,
  key: JsExpression | undefined,
  value: JsExpression | undefined,
  useIndex: number,
): string[] {
  if (
    expressionIsStaticEmptyOrBoolean(document, value, useIndex) ||
    expressionIsSafeCredentialDerivative(document, value)
  ) {
    return [];
  }
  const context = sensitiveContextWords(key, value);
  const labels = new Set(context.map(credentialLabel).filter((label): label is string => Boolean(label)));
  if (
    labels.size === 1 && labels.has("token") &&
    DEVICE_TOKEN_WORDS.some((safe) => context.some((word) => word.toLowerCase().includes(safe)))
  ) return [];
  return [...labels].sort();
}

function pairLabels(
  document: JsDocument,
  pair: JsExpression,
  useIndex: number,
): string[] {
  const items = arrayItems(document, pair);
  if (items.length < 2) return [];
  return sensitiveLabels(document, items[0], items[1], useIndex);
}

function finding(file: string, line: number, labels: readonly string[]): Finding {
  return makeAiFinding({
    ruleId: REACT_NATIVE_ASYNC_STORAGE_RULE_ID,
    title: "Sensitive credential stored in React Native AsyncStorage",
    severity: "high",
    cwe: ["CWE-312"],
    owasp_web: ["A02:2021"],
    file,
    startLine: line,
    snippet: `AsyncStorage write stores credential-labelled data: ${labels.join(", ")} [VALUE REDACTED]`,
    message:
      "A receiver proven to be React Native AsyncStorage stores credential-labelled data. AsyncStorage is unencrypted persistent storage and is not appropriate for tokens, passwords, or private keys.",
    remediation: {
      summary: "Move credentials to platform-backed secure storage and remove the AsyncStorage copy.",
      steps: [
        "Store credentials in Keychain/Keystore-backed storage such as react-native-keychain or Expo SecureStore.",
        "Delete the old AsyncStorage entry during migration and rotate exposed long-lived credentials where appropriate.",
        "Add a regression test proving credential-labelled values never reach AsyncStorage writes.",
      ],
      references: [
        "CWE-312",
        "https://reactnative.dev/docs/security#storing-sensitive-info",
        "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/",
      ],
    },
    confidence: "high",
  });
}

export async function runReactNativeSensitiveAsyncStorage(
  input: ReactNativeProjectInput,
): Promise<Finding[]> {
  const project = await resolveReactNativeProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    if (!document.balanced) continue;
    for (const call of jsCalls(document)) {
      if (!isAsyncStorageReceiver(document, call)) continue;
      const labels = new Set<string>();
      if (call.callee === "setItem" || call.callee === "mergeItem") {
        sensitiveLabels(document, call.arguments[0], call.arguments[1], call.tokenIndex)
          .forEach((label) => labels.add(label));
      } else if (call.callee === "multiSet") {
        for (const pair of arrayItems(document, call.arguments[0])) {
          pairLabels(document, pair, call.tokenIndex).forEach((label) => labels.add(label));
        }
      } else continue;
      if (labels.size) findings.push(finding(document.path, call.line, [...labels].sort()));
    }
  }
  return findings;
}
