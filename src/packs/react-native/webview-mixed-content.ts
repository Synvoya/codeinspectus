import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import { jsxElements, jsxProp } from "./javascript.js";
import {
  isProductionHttpsUrl,
  isReactNativeWebView,
  sourceLiteral,
} from "./analysis.js";
import { resolveReactNativeProject, type ReactNativeProjectInput } from "./project.js";

export const REACT_NATIVE_WEBVIEW_MIXED_CONTENT_RULE_ID = "ci-react-native-webview-mixed-content";

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: REACT_NATIVE_WEBVIEW_MIXED_CONTENT_RULE_ID,
    title: "React Native WebView permits active mixed content",
    severity: "medium",
    cwe: ["CWE-319"],
    owasp_web: ["A02:2021"],
    file,
    startLine: line,
    snippet: "Production HTTPS WebView uses mixedContentMode=always [SOURCE URL REDACTED]",
    message:
      "An imported react-native-webview component loads a production HTTPS origin with mixedContentMode set literally to always, allowing insecure HTTP subresources inside the secure page.",
    remediation: {
      summary: "Set mixedContentMode to never and serve every WebView resource over HTTPS.",
      steps: [
        "Change mixedContentMode from always to never.",
        "Migrate embedded images, scripts, frames, and API endpoints to HTTPS.",
        "Test the production page with HTTP subresources blocked.",
      ],
      references: [
        "CWE-319",
        "https://github.com/react-native-webview/react-native-webview/blob/master/docs/Reference.md#mixedcontentmode",
        "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/",
      ],
    },
    confidence: "high",
  });
}

export async function runReactNativeWebViewMixedContent(
  input: ReactNativeProjectInput,
): Promise<Finding[]> {
  const project = await resolveReactNativeProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    if (!document.balanced) continue;
    for (const element of jsxElements(document)) {
      if (!isReactNativeWebView(document, element) || element.hasSpread) continue;
      const mode = jsxProp(element, "mixedContentMode");
      if (
        mode?.expression.tokens.length !== 1 ||
        mode.expression.tokens[0]?.staticValue !== "always"
      ) continue;
      const source = jsxProp(element, "source");
      const uri = sourceLiteral(document, source?.expression, "uri", element.tokenIndex);
      if (!uri || !isProductionHttpsUrl(uri)) continue;
      findings.push(finding(document.path, element.line));
    }
  }
  return findings;
}
