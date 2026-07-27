import type { Finding, Severity } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  jsxElements,
  jsxProp,
  staticBoolean,
  type JsDocument,
  type JsExpression,
  type JsxElement,
  type JsxProp,
} from "./javascript.js";
import {
  expressionReachesUntrustedNavigation,
  hasExactHttpsHostGuard,
  hasFixedHttpsOriginWhitelist,
  isReactNativeWebView,
  isSafeNavigationCallback,
  isSanitizedHtml,
  likelyBridgePropName,
  sourceProperty,
} from "./analysis.js";
import { resolveReactNativeProject, type ReactNativeProjectInput } from "./project.js";

export const REACT_NATIVE_WEBVIEW_UNTRUSTED_RULE_ID = "ci-react-native-webview-untrusted-content";

function dynamicBoolean(document: JsDocument, prop: JsxProp | undefined, useIndex: number): boolean | undefined {
  if (!prop) return true;
  return staticBoolean(document, prop.expression, useIndex);
}

function activeBridge(element: JsxElement): boolean {
  return element.props.some((prop) => {
    if (!likelyBridgePropName(prop.name)) return false;
    if (prop.name === "onMessage") return prop.expression.tokens.some((token) =>
      !["false", "null", "undefined"].includes(token.value)
    );
    return prop.expression.tokens.length > 0 && !(
      prop.expression.tokens.length === 1 && ["false", "null", "undefined", ""].includes(
        prop.expression.tokens[0]?.staticValue ?? prop.expression.tokens[0]?.value ?? "",
      )
    );
  });
}

function safePolicy(
  document: JsDocument,
  element: JsxElement,
  kind: "uri" | "html",
  value: JsExpression,
): boolean {
  // URL navigation policy cannot make attacker-controlled initial HTML safe.
  if (kind === "html") return false;
  if (hasExactHttpsHostGuard(document, value, element.tokenIndex)) return true;
  const origins = jsxProp(element, "originWhitelist");
  if (hasFixedHttpsOriginWhitelist(document, origins?.expression, element.tokenIndex)) return true;
  const callback = jsxProp(element, "onShouldStartLoadWithRequest");
  return isSafeNavigationCallback(document, callback?.expression);
}

function taintedSource(
  document: JsDocument,
  element: JsxElement,
): { tainted: boolean; kind?: "uri" | "html"; value?: JsExpression } {
  const source = jsxProp(element, "source");
  if (!source) return { tainted: false };
  const uri = sourceProperty(document, source.expression, "uri", element.tokenIndex);
  if (expressionReachesUntrustedNavigation(document, uri, uri?.start ?? element.tokenIndex)) {
    return { tainted: true, kind: "uri", value: uri };
  }
  const html = sourceProperty(document, source.expression, "html", element.tokenIndex);
  if (
    expressionReachesUntrustedNavigation(document, html, html?.start ?? element.tokenIndex) &&
    !isSanitizedHtml(document, html, html?.start ?? element.tokenIndex)
  ) return { tainted: true, kind: "html", value: html };
  return { tainted: false };
}

function finding(
  file: string,
  line: number,
  severity: Severity,
  kind: "uri" | "html",
  bridge: boolean,
): Finding {
  return makeAiFinding({
    ruleId: REACT_NATIVE_WEBVIEW_UNTRUSTED_RULE_ID,
    title: "Untrusted navigation content reaches a JavaScript-enabled React Native WebView",
    severity,
    cwe: ["CWE-20", "CWE-346"],
    owasp_web: ["A08:2021"],
    file,
    startLine: line,
    snippet: `React Native WebView ${kind} receives untrusted navigation content [VALUE REDACTED]`,
    message:
      `A route, Expo Router search parameter, or Linking URL reaches WebView source.${kind} while JavaScript is enabled and no exact HTTPS origin gate is visible.${bridge ? " A message or injected-JavaScript bridge increases the impact." : ""}`,
    remediation: {
      summary: "Allow only exact trusted HTTPS origins before loading untrusted navigation content.",
      steps: [
        "Parse candidate URLs and require an exact HTTPS scheme plus hostname match against a fixed allowlist.",
        "Use a fixed originWhitelist or an onShouldStartLoadWithRequest callback that rejects every non-allowlisted navigation.",
        "Disable JavaScript and remove onMessage/injected JavaScript unless the trusted content strictly requires them.",
      ],
      references: [
        "CWE-20",
        "CWE-346",
        "https://github.com/react-native-webview/react-native-webview/blob/master/docs/Reference.md",
        "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/",
      ],
    },
    confidence: "high",
  });
}

export async function runReactNativeWebViewUntrustedContent(
  input: ReactNativeProjectInput,
): Promise<Finding[]> {
  const project = await resolveReactNativeProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    if (!document.balanced) continue;
    for (const element of jsxElements(document)) {
      if (!isReactNativeWebView(document, element) || element.hasSpread) continue;
      const javaScript = dynamicBoolean(document, jsxProp(element, "javaScriptEnabled"), element.tokenIndex);
      if (javaScript !== true) continue;
      const source = taintedSource(document, element);
      if (
        !source.tainted || !source.kind || !source.value ||
        safePolicy(document, element, source.kind, source.value)
      ) continue;
      const bridge = activeBridge(element);
      findings.push(finding(document.path, element.line, bridge ? "high" : "medium", source.kind, bridge));
    }
  }
  return findings;
}
