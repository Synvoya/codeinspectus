import type { Finding, Severity } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  argumentFor,
  dartAssignments,
  dartCalls,
  expressionFromTokens,
  expressionReferences,
  type DartAssignment,
  type DartCall,
  type DartDocument,
  type DartExpression,
} from "./dart.js";
import {
  hasExactHttpsHostAllowlist,
  isDeepLinkSource,
} from "./analysis.js";
import { resolveFlutterProject, type FlutterProjectInput } from "./project.js";

export const FLUTTER_WEBVIEW_RULE_ID = "ci-flutter-webview-untrusted-content";

interface ControllerState {
  unrestricted: boolean;
  bridge: boolean;
}

type ScopePath = readonly number[];

interface AnalysisContext {
  assignments: DartAssignment[];
  calls: DartCall[];
  scopes: ScopePath[];
}

function tokenValues(expression: DartExpression): string[] {
  return expression.tokens.map((token) => token.value);
}

function hasUnrestrictedJavaScript(expression: DartExpression): boolean {
  const values = tokenValues(expression);
  return values.some((value, index) =>
    (value === "JavaScriptMode" || value === "JavascriptMode") &&
    values[index + 1] === "." &&
    values[index + 2] === "unrestricted"
  ) || values.some((value, index) =>
    normalized(value) === "javascriptenabled" && values[index + 1] === ":" && values[index + 2] === "true"
  );
}

function hasRestrictedJavaScript(expression: DartExpression): boolean {
  const values = tokenValues(expression);
  return values.some((value, index) =>
    (value === "JavaScriptMode" || value === "JavascriptMode") &&
    values[index + 1] === "." &&
    values[index + 2] === "disabled"
  ) || values.some((value, index) =>
    normalized(value) === "javascriptenabled" && values[index + 1] === ":" && values[index + 2] === "false"
  );
}

function hasJavaScriptBridge(expression: DartExpression): boolean {
  return expression.tokens.some((token) =>
    token.kind === "identifier" &&
    /^(?:JavaScriptChannel|JavascriptChannel|javascriptChannels|addJavaScriptChannel|addJavaScriptHandler|registerJavaScriptHandler|onMessageReceived)$/i
      .test(token.value)
  );
}

function normalized(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

function containingAssignment(assignments: readonly DartAssignment[], tokenIndex: number): DartAssignment | undefined {
  return assignments.find((assignment) => tokenIndex >= assignment.start && tokenIndex < assignment.end);
}

function lexicalScopePaths(document: DartDocument): ScopePath[] {
  const paths: ScopePath[] = [];
  const stack: number[] = [];
  for (let index = 0; index < document.tokens.length; index++) {
    const value = document.tokens[index]!.value;
    if (value === "}") {
      const open = document.pairs.get(index);
      const position = open === undefined ? -1 : stack.lastIndexOf(open);
      if (position >= 0) stack.splice(position);
    }
    paths[index] = [...stack];
    if (value === "{" && (document.pairs.get(index) ?? -1) > index) stack.push(index);
  }
  return paths;
}

function scopeVisibleAt(eventScope: ScopePath, sinkScope: ScopePath): boolean {
  return eventScope.length <= sinkScope.length &&
    eventScope.every((open, index) => sinkScope[index] === open);
}

function controllerAssignment(assignment: DartAssignment): boolean {
  return assignment.tokens.some((token) =>
    token.kind === "identifier" && /^(?:WebViewController|InAppWebViewController)$/i.test(token.value)
  );
}

function controllerStateAt(
  document: DartDocument,
  sink: DartCall,
  context: AnalysisContext,
): ControllerState {
  if (sink.name === "WebView" || sink.name === "InAppWebView") {
    const expression = expressionFromTokens(document.tokens.slice(sink.tokenIndex, sink.closeIndex + 1));
    return {
      unrestricted: hasUnrestrictedJavaScript(expression),
      bridge: hasJavaScriptBridge(expression),
    };
  }

  const sinkScope = context.scopes[sink.tokenIndex] ?? [];
  const states = new Map<string, ControllerState>();
  const events = [
    ...context.assignments.map((assignment) => ({
      kind: "assignment" as const,
      tokenIndex: assignment.tokenIndex,
      assignment,
    })),
    ...context.calls.map((call) => ({
      kind: "call" as const,
      tokenIndex: call.tokenIndex,
      call,
    })),
  ].sort((left, right) => left.tokenIndex - right.tokenIndex ||
    (left.kind === "assignment" ? -1 : 1));

  for (const event of events) {
    if (event.tokenIndex >= sink.tokenIndex) break;
    if (!scopeVisibleAt(context.scopes[event.tokenIndex] ?? [], sinkScope)) continue;

    if (event.kind === "assignment") {
      const assignment = event.assignment;
      if (controllerAssignment(assignment)) {
        states.set(assignment.name, { unrestricted: false, bridge: false });
        continue;
      }
      const referenced = [...states.entries()].filter(([name]) =>
        expressionReferences(assignment, new Set([name]))
      );
      if (referenced.length === 1) states.set(assignment.name, referenced[0]![1]);
      else states.delete(assignment.name);
      continue;
    }

    const call = event.call;
    const assignment = containingAssignment(context.assignments, call.tokenIndex);
    const receiver = call.receiver ?? assignment?.name;
    if (!receiver) continue;
    const expression = expressionFromTokens(document.tokens.slice(call.tokenIndex, call.closeIndex + 1));
    const changesJavaScript = call.name === "setJavaScriptMode" || call.name === "setSettings";
    const enablesBridge = call.name === "addJavaScriptChannel" ||
      call.name === "addJavaScriptHandler" ||
      call.name === "registerJavaScriptHandler" ||
      hasJavaScriptBridge(expression);
    if (!changesJavaScript && !enablesBridge) continue;

    const state = states.get(receiver) ?? { unrestricted: false, bridge: false };
    if (changesJavaScript && hasUnrestrictedJavaScript(expression)) state.unrestricted = true;
    if (changesJavaScript && hasRestrictedJavaScript(expression)) state.unrestricted = false;
    if (enablesBridge) state.bridge = true;
    states.set(receiver, state);
  }

  const receiver = sink.receiver ?? containingAssignment(context.assignments, sink.tokenIndex)?.name;
  return receiver ? states.get(receiver) ?? { unrestricted: false, bridge: false } : {
    unrestricted: false,
    bridge: false,
  };
}

function webViewSink(call: DartCall): boolean {
  return call.name === "WebView" ||
    call.name === "InAppWebView" ||
    call.name === "loadRequest" ||
    call.name === "loadUrl" ||
    call.name === "loadUrlRequest";
}

function sinkInput(call: DartCall): DartExpression {
  const preferred = argumentFor(call, "initialUrl", 0) ??
    argumentFor(call, "initialUrlRequest", 0) ??
    argumentFor(call, "urlRequest", 0) ??
    argumentFor(call, "url", 0) ??
    argumentFor(call, "uri", 0);
  return expressionFromTokens(preferred?.tokens ?? call.arguments.flatMap((argument) => argument.tokens));
}

function provenWebInputSource(expression: DartExpression): boolean {
  if (isDeepLinkSource(expression)) return true;
  const values = tokenValues(expression);
  return values.some((value, index) =>
    value === "Uri" && values[index + 1] === "." && values[index + 2] === "base"
  );
}

interface CallbackSeed {
  name: string;
  start: number;
  end: number;
}

function callbackParameter(expression: DartExpression): string | undefined {
  const open = expression.tokens.findIndex((token) => token.value === "(");
  if (open < 0) return undefined;
  for (let index = open + 1; index < expression.tokens.length && expression.tokens[index]!.value !== ")"; index++) {
    const token = expression.tokens[index]!;
    if (token.kind !== "identifier") continue;
    const next = expression.tokens[index + 1]?.value;
    if (next === "," || next === ")" || expression.tokens[index + 1]?.kind === undefined) return token.value;
  }
  return undefined;
}

function callbackSeeds(calls: readonly DartCall[]): CallbackSeed[] {
  const seeds: CallbackSeed[] = [];
  for (const call of calls) {
    const callee = normalized(call.callee);
    const callbackLike = /(?:link|uri|route)/.test(callee) && /(?:listen|handler|callback|link)/.test(callee);
    for (const argument of call.arguments) {
      if (!callbackLike && !/(?:link|route|redirect|navigation)/i.test(argument.name ?? "")) continue;
      const name = callbackParameter(argument);
      if (name) seeds.push({ name, start: argument.start, end: argument.end });
    }
  }
  return seeds;
}

function taintedNamesAt(
  sink: DartCall,
  context: AnalysisContext,
  seeds: readonly CallbackSeed[],
): Set<string> {
  const sinkScope = context.scopes[sink.tokenIndex] ?? [];
  const tainted = new Set(
    seeds
      .filter((seed) => sink.tokenIndex >= seed.start && sink.tokenIndex < seed.end)
      .map((seed) => seed.name),
  );
  for (const assignment of context.assignments) {
    if (assignment.tokenIndex >= sink.tokenIndex) break;
    if (!scopeVisibleAt(context.scopes[assignment.tokenIndex] ?? [], sinkScope)) continue;
    if (provenWebInputSource(assignment) || expressionReferences(assignment, tainted)) {
      tainted.add(assignment.name);
    } else {
      tainted.delete(assignment.name);
    }
  }
  return tainted;
}

function finding(file: string, line: number, severity: Severity, bridge: boolean): Finding {
  return makeAiFinding({
    ruleId: FLUTTER_WEBVIEW_RULE_ID,
    title: "Untrusted route or deep-link content reaches a JavaScript-enabled WebView",
    severity,
    cwe: ["CWE-20", "CWE-346"],
    file,
    startLine: line,
    snippet: "Untrusted route/deep-link value reaches unrestricted WebView navigation [VALUE REDACTED]",
    message:
      `A recognized route, query, or deep-link source reaches a WebView with unrestricted JavaScript and no visible exact HTTPS scheme plus host equality allowlist.${bridge ? " A JavaScript bridge increases impact by exposing native capabilities to loaded content." : ""}`,
    remediation: {
      summary: "Allow only exact trusted HTTPS origins before WebView navigation and disable unnecessary JavaScript/bridges.",
      steps: [
        "Parse the candidate URI and require scheme == 'https' plus an exact host equality match against a fixed allowlist.",
        "Reject userinfo, unexpected ports, redirects to untrusted origins, and non-HTTPS schemes.",
        "Disable unrestricted JavaScript and remove JavaScript bridges unless the loaded content strictly requires them.",
      ],
      references: [
        "CWE-20",
        "CWE-346",
        "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/",
        "https://pub.dev/packages/webview_flutter",
      ],
    },
    confidence: "high",
  });
}

export async function runFlutterWebViewUntrustedContent(
  input: FlutterProjectInput,
): Promise<Finding[]> {
  const project = await resolveFlutterProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const assignments = dartAssignments(document);
    const calls = dartCalls(document);
    const context: AnalysisContext = {
      assignments,
      calls,
      scopes: lexicalScopePaths(document),
    };
    const seeds = callbackSeeds(calls);
    for (const call of calls) {
      if (!webViewSink(call)) continue;
      const state = controllerStateAt(document, call, context);
      if (!state.unrestricted) continue;
      const inputExpression = sinkInput(call);
      const tainted = taintedNamesAt(call, context, seeds);
      if (!provenWebInputSource(inputExpression) && !expressionReferences(inputExpression, tainted)) continue;
      if (hasExactHttpsHostAllowlist(document, call.tokenIndex, tainted)) continue;
      findings.push(finding(document.path, call.line, state.bridge ? "high" : "medium", state.bridge));
    }
  }
  return findings;
}
