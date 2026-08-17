import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";
import { isSupabaseSecretKey } from "../../redact.js";

import { argumentFor, dartCalls, decodedString, expressionFromTokens } from "./dart.js";
import {
  expressionReachesSource,
  normalizedWord,
} from "./analysis.js";
import { resolveFlutterProject, type FlutterProjectInput } from "./project.js";

export const FLUTTER_SUPABASE_KEY_RULE_ID = "ci-flutter-supabase-privileged-key-client";

function legacyServiceRoleJwt(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 3 || !parts[1]) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as {
      role?: unknown;
    };
    return payload.role === "service_role";
  } catch {
    return false;
  }
}

function privilegedKeySource(expression: ReturnType<typeof expressionFromTokens>): boolean {
  const strings = expression.tokens
    .filter((token) => token.kind === "string")
    .map(decodedString);
  const explicitlyPrivileged = strings.map(normalizedWord).some((value) =>
    value.includes("servicerole") ||
    value.includes("supabasesecret") ||
    value.includes("privilegedkey") ||
    value.includes("secretkey")
  ) || strings.some((value) => isSupabaseSecretKey(value) || legacyServiceRoleJwt(value));
  return explicitlyPrivileged;
}

function privilegedIdentifier(identifier: string): boolean {
  const value = normalizedWord(identifier);
  if (value.includes("anon") || value.includes("publishable")) return false;
  return value.includes("servicerole") ||
    value.includes("supabasesecret") ||
    value.includes("privilegedkey") ||
    value.includes("secretkey");
}

function sinkKeyExpression(call: ReturnType<typeof dartCalls>[number]) {
  if (call.callee === "Supabase.initialize" || call.callee.endsWith(".Supabase.initialize")) {
    return argumentFor(call, "anonKey", 1) ?? argumentFor(call, "supabaseKey", 1);
  }
  if (call.name === "SupabaseClient") {
    return argumentFor(call, "supabaseKey", 1) ?? argumentFor(call, "key", 1);
  }
  return undefined;
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: FLUTTER_SUPABASE_KEY_RULE_ID,
    title: "Supabase privileged key reaches a Flutter client initializer",
    severity: "critical",
    cwe: ["CWE-798", "CWE-312", "CWE-285"],
    file,
    startLine: line,
    snippet: "Supabase client initialization receives a service-role or secret key [VALUE REDACTED]",
    message:
      "A source identified as a Supabase service-role/secret key reaches client initialization. Privileged keys bypass normal client authorization boundaries and must never ship in a Flutter application.",
    remediation: {
      summary: "Remove the privileged key from the client and move privileged operations behind a trusted server boundary.",
      steps: [
        "Rotate the exposed service-role/secret key immediately.",
        "Initialize the Flutter client only with the project anon or publishable key.",
        "Move service-role operations to a server or Edge Function that authenticates and authorizes each request.",
      ],
      references: [
        "CWE-798",
        "CWE-312",
        "CWE-285",
        "https://supabase.com/docs/guides/api/api-keys",
      ],
    },
    confidence: "high",
  });
}

export async function runFlutterSupabasePrivilegedKeyClient(
  input: FlutterProjectInput,
): Promise<Finding[]> {
  const project = await resolveFlutterProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    for (const call of dartCalls(document)) {
      const key = sinkKeyExpression(call);
      if (!key) continue;
      const expression = expressionFromTokens(key.tokens);
      if (!expressionReachesSource(document, expression, call.tokenIndex, {
        expressionSource: privilegedKeySource,
        unresolvedIdentifierSource: privilegedIdentifier,
      })) continue;
      findings.push(finding(document.path, call.line));
    }
  }
  return findings;
}
