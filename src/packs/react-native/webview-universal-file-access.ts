import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import { jsxElements, jsxProp, staticBoolean } from "./javascript.js";
import { isReactNativeWebView, sourceLiteral } from "./analysis.js";
import { resolveReactNativeProject, type ReactNativeProjectInput } from "./project.js";

export const REACT_NATIVE_WEBVIEW_UNIVERSAL_FILE_ACCESS_RULE_ID =
  "ci-react-native-webview-universal-file-access";

function fileUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    return new URL(value).protocol === "file:";
  } catch {
    return /^file:\/\//i.test(value);
  }
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: REACT_NATIVE_WEBVIEW_UNIVERSAL_FILE_ACCESS_RULE_ID,
    title: "File-backed React Native WebView permits universal URL access",
    severity: "high",
    cwe: ["CWE-200", "CWE-942"],
    owasp_web: ["A01:2021"],
    file,
    startLine: line,
    snippet: "File-backed WebView enables allowUniversalAccessFromFileURLs [LOCAL PATH REDACTED]",
    message:
      "A JavaScript-enabled file:// WebView sets allowUniversalAccessFromFileURLs literally to true, allowing file-origin content to access content from arbitrary origins.",
    remediation: {
      summary: "Disable universal file-origin access and avoid loading privileged local content into a JavaScript-enabled WebView.",
      steps: [
        "Set allowUniversalAccessFromFileURLs to false.",
        "Serve required content from an exact trusted HTTPS origin or use a narrowly scoped native resource handler.",
        "Disable JavaScript for local content and test that file-origin pages cannot read remote or private resources.",
      ],
      references: [
        "CWE-200",
        "CWE-942",
        "https://github.com/react-native-webview/react-native-webview/blob/master/docs/Reference.md#allowuniversalaccessfromfileurls",
        "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/",
      ],
    },
    confidence: "high",
  });
}

export async function runReactNativeWebViewUniversalFileAccess(
  input: ReactNativeProjectInput,
): Promise<Finding[]> {
  const project = await resolveReactNativeProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    if (!document.balanced) continue;
    for (const element of jsxElements(document)) {
      if (!isReactNativeWebView(document, element) || element.hasSpread) continue;
      const universal = jsxProp(element, "allowUniversalAccessFromFileURLs");
      if (staticBoolean(document, universal?.expression, element.tokenIndex) !== true) continue;
      const javaScript = jsxProp(element, "javaScriptEnabled");
      // JavaScript defaults to enabled. A dynamic override is not proven insecure.
      const javaScriptState = javaScript
        ? staticBoolean(document, javaScript.expression, element.tokenIndex)
        : true;
      if (javaScriptState !== true) continue;
      const source = jsxProp(element, "source");
      const uri = sourceLiteral(document, source?.expression, "uri", element.tokenIndex);
      const sourceBase = sourceLiteral(document, source?.expression, "baseUrl", element.tokenIndex);
      if (!fileUrl(uri) && !fileUrl(sourceBase)) continue;
      findings.push(finding(document.path, element.line));
    }
  }
  return findings;
}
