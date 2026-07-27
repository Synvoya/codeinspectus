import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import { expressionUntilStatementEnd, type DartExpression } from "./dart.js";
import { isKDebugModeGuarded } from "./analysis.js";
import { resolveFlutterProject, type FlutterProjectInput } from "./project.js";

export const FLUTTER_TLS_RULE_ID = "ci-flutter-tls-verification-disabled";

function unconditionalTrueCallback(expression: DartExpression): boolean {
  const values = expression.tokens.map((token) => token.value);
  const arrow = values.indexOf("=>");
  if (arrow >= 0) {
    const body = values.slice(arrow + 1).filter((value) =>
      value !== ";" && value !== "(" && value !== ")"
    );
    return body.length === 1 && body[0] === "true";
  }

  const bodyOpen = values.lastIndexOf("{");
  const bodyClose = values.lastIndexOf("}");
  if (bodyOpen < 0 || bodyClose <= bodyOpen) return false;
  const body = values.slice(bodyOpen + 1, bodyClose);
  if (body.includes("throw") || body.filter((value) => value === "return").length !== 1) {
    return false;
  }
  const finalReturn = body.lastIndexOf("return");
  const returned = body.slice(finalReturn + 1).filter((value) =>
    value !== ";" && value !== "(" && value !== ")"
  );
  return returned.length === 1 && returned[0] === "true";
}

function finding(file: string, line: number, snippet: string): Finding {
  return makeAiFinding({
    ruleId: FLUTTER_TLS_RULE_ID,
    title: "Flutter TLS certificate verification is unconditionally disabled",
    severity: "high",
    cwe: ["CWE-295"],
    file,
    startLine: line,
    snippet,
    message:
      "badCertificateCallback unconditionally returns true, so the client accepts certificates that fail trust validation and is vulnerable to machine-in-the-middle interception.",
    remediation: {
      summary: "Remove the permissive callback and rely on platform certificate validation.",
      steps: [
        "Delete the unconditional badCertificateCallback override.",
        "If development certificates are required, trust a scoped development CA outside production code instead of bypassing validation.",
        "Test that invalid, expired, and wrong-host certificates are rejected in release builds.",
      ],
      references: [
        "CWE-295",
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://api.dart.dev/dart-io/HttpClient/badCertificateCallback.html",
      ],
    },
    confidence: "high",
  });
}

export async function runFlutterTlsVerificationDisabled(
  input: FlutterProjectInput,
): Promise<Finding[]> {
  const project = await resolveFlutterProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    for (let index = 0; index < document.tokens.length - 2; index++) {
      const token = document.tokens[index]!;
      if (token.value !== "badCertificateCallback" || document.tokens[index + 1]?.value !== "=") {
        continue;
      }
      const expression = expressionUntilStatementEnd(document, index + 2);
      if (
        !unconditionalTrueCallback(expression) ||
        isKDebugModeGuarded(document, index)
      ) continue;
      findings.push(finding(
        document.path,
        token.line,
        "badCertificateCallback unconditionally returns true [CALLBACK BODY REDACTED]",
      ));
    }
  }
  return findings;
}
