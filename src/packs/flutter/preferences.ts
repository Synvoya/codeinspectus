import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  argumentFor,
  dartCalls,
  decodedString,
  nearestReachingDefinition,
  type DartDocument,
  type DartExpression,
} from "./dart.js";
import {
  identifiers,
  isSafeDerivedValue,
  normalizedWord,
  sensitiveCredentialLabels,
} from "./analysis.js";
import { resolveFlutterProject, type FlutterProjectInput } from "./project.js";

export const FLUTTER_PREFERENCES_RULE_ID = "ci-flutter-sensitive-shared-preferences";

const CREDENTIAL_NAMES = [
  "password",
  "passwd",
  "accesstoken",
  "refreshtoken",
  "authtoken",
  "authorization",
  "bearer",
  "jwt",
  "sessiontoken",
  "apikey",
  "privatekey",
  "servicerole",
  "clientsecret",
  "credential",
  "secret",
  "token",
];
const DEVICE_TOKEN_NAMES = ["fcm", "device", "push", "notification", "messaging"];

function sharedPreferencesFactory(expression: DartExpression): boolean {
  const values = expression.tokens.map((token) => token.value);
  return values.some((value, index) =>
    value === "SharedPreferences" && values[index + 1] === "." && values[index + 2] === "getInstance"
  ) || values.some((value, index) =>
    value === "SharedPreferencesAsync" && (values[index + 1] === "(" || values[index + 1] === ".")
  ) || values.some((value, index) =>
    value === "SharedPreferencesWithCache" && (values[index + 1] === "(" || values[index + 1] === ".")
  );
}

function trackedSharedPreferencesReceiver(
  document: DartDocument,
  name: string,
  useIndex: number,
  seen = new Set<string>(),
): boolean {
  const definition = nearestReachingDefinition(document, name, useIndex);
  if (!definition) return false;
  const key = `${definition.tokenIndex}:${definition.name}`;
  if (seen.has(key)) return false;
  seen.add(key);
  if (/^SharedPreferences(?:Async|WithCache)?$/.test(definition.declaredType ?? "")) return true;
  if (!definition.expression) return false;
  if (sharedPreferencesFactory(definition.expression)) return true;
  return identifiers(definition.expression).some((identifier) =>
    trackedSharedPreferencesReceiver(document, identifier, definition.tokenIndex, seen)
  );
}

function resolveStringConstant(
  document: DartDocument,
  name: string,
  useIndex: number,
  seen = new Set<string>(),
): string | undefined {
  const definition = nearestReachingDefinition(document, name, useIndex);
  if (!definition?.expression) return undefined;
  const key = `${definition.tokenIndex}:${definition.name}`;
  if (seen.has(key)) return undefined;
  seen.add(key);
  const literals = definition.expression.tokens.filter((token) => token.kind === "string");
  if (literals.length === 1 && definition.expression.tokens.every((token) => token.kind === "string")) {
    return decodedString(literals[0]!);
  }
  const alias = definition.expression.tokens.find((token) => token.kind === "identifier");
  return alias ? resolveStringConstant(document, alias.value, definition.tokenIndex, seen) : undefined;
}

function literalCredentialLabel(value: string): string | undefined {
  const word = normalizedWord(value);
  if (
    /^(?:show|has|is|remember|save)password$/.test(word) ||
    /(?:token|password)(?:expiry|expires|expiration|status|type|length|hash|digest|fingerprint)$/.test(word)
  ) return undefined;
  const label = CREDENTIAL_NAMES.find((candidate) => word === candidate || word.includes(candidate));
  if (!label) return undefined;
  if (label === "token" && DEVICE_TOKEN_NAMES.some((candidate) => word.includes(candidate))) return undefined;
  return label;
}

function credentialLabels(
  key: ReturnType<typeof argumentFor>,
  value: ReturnType<typeof argumentFor>,
  document: DartDocument,
  useIndex: number,
): string[] {
  if (!value || isSafeDerivedValue(value)) return [];
  const valueLabels = sensitiveCredentialLabels(value);
  const labels = new Set(valueLabels);
  if (key) {
    for (const token of key.tokens) {
      if (token.kind === "string") {
        const label = literalCredentialLabel(decodedString(token));
        if (label) labels.add(label);
      } else if (token.kind === "identifier") {
        const label = literalCredentialLabel(
          resolveStringConstant(document, token.value, useIndex) ?? token.value,
        );
        if (label) labels.add(label);
      }
    }
  }
  const context = [...(key?.tokens ?? []), ...value.tokens]
    .map((token) => normalizedWord(token.value))
    .join(" ");
  if (
    labels.size === 1 &&
    labels.has("token") &&
    DEVICE_TOKEN_NAMES.some((candidate) => context.includes(candidate))
  ) return [];
  return [...labels].sort();
}

function finding(file: string, line: number, labels: string[]): Finding {
  return makeAiFinding({
    ruleId: FLUTTER_PREFERENCES_RULE_ID,
    title: "Sensitive credential stored in SharedPreferences",
    severity: "high",
    cwe: ["CWE-312"],
    file,
    startLine: line,
    snippet: `SharedPreferences write stores sensitive credential data: ${labels.join(", ")} [VALUE REDACTED]`,
    message:
      "A receiver proven to come from SharedPreferences stores explicit credential material. SharedPreferences is convenience storage, not encrypted credential storage.",
    remediation: {
      summary: "Store credentials in platform-backed secure storage and keep only non-sensitive preferences here.",
      steps: [
        "Move tokens, passwords, API keys, and session credentials to Keychain/Keystore-backed storage such as flutter_secure_storage.",
        "Delete the old SharedPreferences value during migration and invalidate exposed credentials where appropriate.",
        "Add a regression test proving credential keys are never written to SharedPreferences.",
      ],
      references: [
        "CWE-312",
        "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/",
        "https://pub.dev/packages/flutter_secure_storage",
      ],
    },
    confidence: "high",
  });
}

export async function runFlutterSensitiveSharedPreferences(
  input: FlutterProjectInput,
): Promise<Finding[]> {
  const project = await resolveFlutterProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    for (const call of dartCalls(document)) {
      if (
        !call.receiver ||
        !trackedSharedPreferencesReceiver(document, call.receiver, call.tokenIndex)
      ) continue;
      if (call.name !== "setString" && call.name !== "setStringList") continue;
      const key = argumentFor(call, "key", 0);
      const value = argumentFor(call, "value", 1);
      const labels = credentialLabels(key, value, document, call.tokenIndex);
      if (labels.length) findings.push(finding(document.path, call.line, labels));
    }
  }
  return findings;
}
