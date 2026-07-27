import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import { dartAssignments, dartCalls, expressionFromTokens, type DartDocument } from "./dart.js";
import {
  isKDebugModeGuarded,
  normalizedWord,
  sensitiveCredentialLabels,
} from "./analysis.js";
import { resolveFlutterProject, type FlutterProjectInput } from "./project.js";

export const FLUTTER_LOG_RULE_ID = "ci-flutter-sensitive-log";

const LOGGER_METHODS = new Set([
  "trace",
  "debug",
  "info",
  "warn",
  "warning",
  "error",
  "fatal",
  "log",
  "v",
  "d",
  "i",
  "w",
  "e",
  "wtf",
]);

function loggerIdentifier(value: string): boolean {
  const normalized = normalizedWord(value);
  return normalized === "log" || normalized === "logger" || normalized.endsWith("logger");
}

function developerAliases(document: DartDocument): { aliases: Set<string>; directLog: boolean } {
  const aliases = new Set<string>();
  let directLog = false;
  for (let index = 0; index < document.tokens.length - 1; index++) {
    if (document.tokens[index]!.value !== "import") continue;
    const uri = document.tokens[index + 1];
    if (uri?.kind !== "string" || uri.value !== "dart:developer") continue;
    let cursor = index + 2;
    let alias: string | undefined;
    while (cursor < document.tokens.length && document.tokens[cursor]!.value !== ";") {
      if (document.tokens[cursor]!.value === "as" && document.tokens[cursor + 1]?.kind === "identifier") {
        alias = document.tokens[cursor + 1]!.value;
      }
      cursor++;
    }
    if (alias) aliases.add(alias);
    else directLog = true;
  }
  return { aliases, directLog };
}

function loggerReceivers(document: DartDocument): Set<string> {
  const receivers = new Set<string>();
  for (const assignment of dartAssignments(document)) {
    const factory = assignment.tokens.some((token) =>
      token.kind === "identifier" && /^(?:Logger|Talker|FLogger|Loggy|PrettyPrinter)$/i.test(token.value)
    );
    if (factory || loggerIdentifier(assignment.name)) receivers.add(assignment.name);
  }
  return receivers;
}

function recognizedLogCall(
  call: ReturnType<typeof dartCalls>[number],
  trackedLoggers: ReadonlySet<string>,
  aliases: ReadonlySet<string>,
  directLog: boolean,
): boolean {
  if (call.name === "print" || call.name === "debugPrint") return true;
  if (call.name === "log" && call.receiver && aliases.has(call.receiver)) return true;
  if (call.name === "log" && !call.receiver && directLog) return true;
  if (!LOGGER_METHODS.has(call.name)) return false;
  if (!call.receiver) return false;
  return trackedLoggers.has(call.receiver) || loggerIdentifier(call.receiver);
}

function finding(file: string, line: number, labels: string[]): Finding {
  return makeAiFinding({
    ruleId: FLUTTER_LOG_RULE_ID,
    title: "Sensitive credential written to Flutter application logs",
    severity: "medium",
    cwe: ["CWE-532"],
    file,
    startLine: line,
    snippet: `Logging call receives sensitive data: ${labels.join(", ")} [VALUE REDACTED]`,
    message:
      "A recognized Flutter/Dart logging sink receives an explicit credential expression. Device, crash, and remote logs can outlive the session and be accessible to more systems than the secret itself.",
    remediation: {
      summary: "Remove credentials from logs and emit only allow-listed operational metadata.",
      steps: [
        "Delete the sensitive log argument or replace it with a non-sensitive event identifier.",
        "Configure structured logger redaction for token, password, authorization, cookie, and secret fields.",
        "Review retained logs and rotate credentials if real values may already have been recorded.",
      ],
      references: [
        "CWE-532",
        "https://cwe.mitre.org/data/definitions/532.html",
        "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/",
      ],
    },
    confidence: "high",
  });
}

export async function runFlutterSensitiveLog(input: FlutterProjectInput): Promise<Finding[]> {
  const project = await resolveFlutterProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const { aliases, directLog } = developerAliases(document);
    const trackedLoggers = loggerReceivers(document);
    for (const call of dartCalls(document)) {
      if (!recognizedLogCall(call, trackedLoggers, aliases, directLog)) continue;
      if (isKDebugModeGuarded(document, call.tokenIndex)) continue;
      const labels = new Set<string>();
      for (const argument of call.arguments) {
        for (const label of sensitiveCredentialLabels(expressionFromTokens(argument.tokens))) {
          labels.add(label);
        }
      }
      if (labels.size) findings.push(finding(document.path, call.line, [...labels].sort()));
    }
  }
  return findings;
}
