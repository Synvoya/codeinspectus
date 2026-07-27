import type { Finding, Severity } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  argumentFor,
  dartAssignments,
  dartCalls,
  decodedString,
  expressionFromTokens,
  type DartDocument,
  type DartExpression,
} from "./dart.js";
import { identifiers, isKDebugModeGuarded } from "./analysis.js";
import { resolveFlutterProject, type FlutterProjectInput } from "./project.js";

export const FLUTTER_CLEARTEXT_RULE_ID = "ci-flutter-cleartext-network";

const NETWORK_METHODS = new Set([
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "head",
  "read",
  "readBytes",
  "send",
  "request",
  "openUrl",
  "getUrl",
  "postUrl",
  "putUrl",
  "deleteUrl",
  "patchUrl",
  "loadRequest",
  "loadUrl",
]);
const WEBVIEW_CONSTRUCTORS = new Set(["WebView", "InAppWebView"]);
const CLIENT_FACTORIES = new Set(["Dio", "Client", "IOClient", "HttpClient", "GraphQLClient"]);

function excludedHttpUrl(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return true;
  }
  if (parsed.protocol !== "http:") return true;
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "0.0.0.0" ||
    host === "10.0.2.2" ||
    host === "10.0.3.2"
  ) return true;
  if (
    host === "example.com" ||
    host.endsWith(".example.com") ||
    host === "example.org" ||
    host.endsWith(".example.org") ||
    host === "example.net" ||
    host.endsWith(".example.net") ||
    host.endsWith(".example") ||
    host.endsWith(".test") ||
    host.endsWith(".invalid")
  ) return true;
  if (
    host === "schemas.android.com" ||
    host === "www.w3.org" ||
    host === "purl.org" ||
    (host === "www.apple.com" && /\/DTDs\//i.test(parsed.pathname))
  ) return true;
  return false;
}

function httpUrls(expression: DartExpression): string[] {
  const urls = new Set<string>();
  for (const token of expression.tokens) {
    if (token.kind !== "string" || token.value.includes("$")) continue;
    const value = decodedString(token).trim();
    if (!/^http:\/\//i.test(value) || excludedHttpUrl(value)) continue;
    urls.add(value);
  }
  return [...urls];
}

function urlAssignments(document: DartDocument): Map<string, string[]> {
  const assigned = new Map<string, string[]>();
  const assignments = dartAssignments(document);
  let changed = true;
  let pass = 0;
  while (changed && pass++ < 8) {
    changed = false;
    for (const assignment of assignments) {
      if (assigned.has(assignment.name)) continue;
      const urls = new Set(httpUrls(assignment));
      for (const name of identifiers(assignment)) {
        for (const url of assigned.get(name) ?? []) urls.add(url);
      }
      if (urls.size) {
        assigned.set(assignment.name, [...urls]);
        changed = true;
      }
    }
  }
  return assigned;
}

function packageHttpImports(document: DartDocument): { aliases: Set<string>; direct: boolean } {
  const aliases = new Set<string>();
  let direct = false;
  for (let index = 0; index < document.tokens.length - 1; index++) {
    if (document.tokens[index]!.value !== "import") continue;
    const uri = document.tokens[index + 1];
    if (uri?.kind !== "string" || uri.value !== "package:http/http.dart") continue;
    let cursor = index + 2;
    let alias: string | undefined;
    while (cursor < document.tokens.length && document.tokens[cursor]!.value !== ";") {
      if (document.tokens[cursor]!.value === "as" && document.tokens[cursor + 1]?.kind === "identifier") {
        alias = document.tokens[cursor + 1]!.value;
      }
      cursor++;
    }
    if (alias) aliases.add(alias);
    else direct = true;
  }
  return { aliases, direct };
}

function trackedClients(document: DartDocument, importAliases: ReadonlySet<string>): Set<string> {
  const tracked = new Set<string>(importAliases);
  for (const assignment of dartAssignments(document)) {
    if (
      assignment.tokens.some((token) => token.kind === "identifier" && CLIENT_FACTORIES.has(token.value))
    ) tracked.add(assignment.name);
  }
  return tracked;
}

function directDioChain(document: DartDocument, call: ReturnType<typeof dartCalls>[number]): boolean {
  const dot = call.tokenIndex - 1;
  const close = call.tokenIndex - 2;
  if (document.tokens[dot]?.value !== "." || document.tokens[close]?.value !== ")") return false;
  const open = document.pairs.get(close);
  return open !== undefined && document.tokens[open - 1]?.value === "Dio";
}

function recognizedSink(
  document: DartDocument,
  call: ReturnType<typeof dartCalls>[number],
  clients: ReadonlySet<string>,
  directPackageHttp: boolean,
): boolean {
  if (WEBVIEW_CONSTRUCTORS.has(call.name)) return true;
  if (call.name === "BaseOptions") return true;
  if (!NETWORK_METHODS.has(call.name)) return false;
  if (["loadRequest", "loadUrl"].includes(call.name)) return true;
  if (directDioChain(document, call)) return true;
  if (!call.receiver) return directPackageHttp;
  return clients.has(call.receiver);
}

function sinkExpression(call: ReturnType<typeof dartCalls>[number]): DartExpression {
  const preferred = argumentFor(call, "initialUrl", 0) ??
    argumentFor(call, "initialUrlRequest", 0) ??
    argumentFor(call, "baseUrl", 0) ??
    argumentFor(call, "url", 0) ??
    argumentFor(call, "uri", 0);
  return expressionFromTokens(preferred?.tokens ?? call.arguments.flatMap((argument) => argument.tokens));
}

function urlsAtSink(expression: DartExpression, assigned: ReadonlyMap<string, string[]>): string[] {
  const urls = new Set(httpUrls(expression));
  for (const name of identifiers(expression)) {
    for (const url of assigned.get(name) ?? []) urls.add(url);
  }
  return [...urls];
}

function endpointSeverity(urls: readonly string[]): Severity {
  return urls.some((value) => {
    try {
      const url = new URL(value);
      return /(?:^|[/_.-])(?:auth|login|signin|signup|oauth|token|session|password|payment|checkout|billing|card|secret)(?:[/_.-]|$)/i
        .test(`${url.pathname}/${url.searchParams.toString()}`);
    } catch {
      return false;
    }
  }) ? "high" : "medium";
}

function finding(file: string, line: number, severity: Severity): Finding {
  return makeAiFinding({
    ruleId: FLUTTER_CLEARTEXT_RULE_ID,
    title: "Flutter network or WebView sink uses a cleartext production URL",
    severity,
    cwe: ["CWE-319"],
    file,
    startLine: line,
    snippet: "Network/WebView call receives an http:// production endpoint [URL REDACTED]",
    message:
      "A literal cleartext production URL reaches a recognized network or WebView sink. Traffic and response content can be observed or modified in transit.",
    remediation: {
      summary: "Use HTTPS with valid certificate verification for every production endpoint.",
      steps: [
        "Replace the http:// endpoint with its https:// equivalent.",
        "Reject non-HTTPS runtime URLs before passing them to the network client or WebView.",
        "Keep Android and iOS cleartext-traffic exceptions disabled in release builds.",
      ],
      references: [
        "CWE-319",
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/",
      ],
    },
    confidence: "high",
  });
}

export async function runFlutterCleartextNetwork(input: FlutterProjectInput): Promise<Finding[]> {
  const project = await resolveFlutterProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const assigned = urlAssignments(document);
    const imports = packageHttpImports(document);
    const clients = trackedClients(document, imports.aliases);
    for (const call of dartCalls(document)) {
      if (
        !recognizedSink(document, call, clients, imports.direct) ||
        isKDebugModeGuarded(document, call.tokenIndex)
      ) continue;
      const urls = urlsAtSink(sinkExpression(call), assigned);
      if (urls.length) findings.push(finding(document.path, call.line, endpointSeverity(urls)));
    }
  }
  return findings;
}
