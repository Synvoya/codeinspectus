import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  directCallExpression,
  expressionReachesRequest,
  functionAt,
  hasSpreadArgument,
  reachingAssignments,
  resolveCallOrigin,
  uniqueFindingsByLocation,
  type PythonAnalysisContext,
} from "./analysis.js";
import type { PythonCall } from "../python/python.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_LANGCHAIN_WEB_LOADER_SSRF_RULE_ID =
  "ci-python-langchain-web-loader-ssrf";

const WEB_LOADER_ORIGINS = new Set([
  "langchain_community.document_loaders.WebBaseLoader",
  "langchain_community.document_loaders.web_base.WebBaseLoader",
  "langchain.document_loaders.WebBaseLoader",
  "langchain.document_loaders.web_base.WebBaseLoader",
]);

const FETCH_METHODS = new Set([
  "load",
  "aload",
  "lazy_load",
  "alazy_load",
  "load_and_split",
]);

function directChainedFetch(context: PythonAnalysisContext, builder: PythonCall): boolean {
  const tokens = context.document.tokens;
  return tokens[builder.closeIndex + 1]?.value === "." &&
    FETCH_METHODS.has(tokens[builder.closeIndex + 2]?.value ?? "") &&
    tokens[builder.closeIndex + 3]?.value === "(";
}

function laterFetch(context: PythonAnalysisContext, builder: PythonCall): boolean {
  if (directChainedFetch(context, builder)) return true;
  const assignment = context.assignments.find((candidate) => {
    const direct = directCallExpression(context, candidate.expression);
    return candidate.name !== undefined && direct?.startIndex === builder.startIndex &&
      direct.closeIndex === builder.closeIndex;
  });
  if (!assignment?.name) return false;
  return context.calls.some((call) =>
    call.startIndex > builder.closeIndex &&
    call.reference[0] === assignment.name &&
    FETCH_METHODS.has(call.reference.at(-1) ?? "") &&
    functionAt(context, call.startIndex)?.id === assignment.scopeId &&
    reachingAssignments(context, assignment.name!, call.startIndex).includes(assignment)
  );
}

function vulnerable(context: PythonAnalysisContext, builder: PythonCall): boolean {
  if (hasSpreadArgument(builder)) return false;
  const origin = resolveCallOrigin(context, builder)?.join(".") ?? "";
  if (!WEB_LOADER_ORIGINS.has(origin)) return false;
  const target = argument(builder, 0, "web_path", "web_paths")?.expression;
  if (!expressionReachesRequest(context, target, builder.startIndex)) return false;
  return laterFetch(context, builder);
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PYTHON_LANGCHAIN_WEB_LOADER_SSRF_RULE_ID,
    title: "Request input controls a LangChain web loader",
    severity: "high",
    cwe: ["CWE-918"],
    owasp_web: ["A10:2021"],
    file,
    startLine: line,
    snippet: "LangChain WebBaseLoader fetches a request-controlled URL [VALUE REDACTED]",
    message:
      "A proven LangChain WebBaseLoader fetches a complete URL derived from web request input without a statically proven destination boundary.",
    remediation: {
      summary: "Map request input to trusted destinations instead of fetching an arbitrary URL.",
      steps: [
        "Prefer a server-owned identifier-to-URL map or an exact allowlist of HTTPS origins.",
        "Resolve DNS and reject loopback, link-local, private, multicast, and cloud metadata address ranges before every request and redirect.",
        "Disable redirects or revalidate every redirect target, and enforce outbound network controls as a second boundary.",
      ],
      references: [
        "CWE-918",
        "https://docs.langchain.com/oss/python/integrations/document_loaders/web_base",
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
      ],
    },
    confidence: "high",
  });
}

/** Detect a request-controlled URL fetched by a proven LangChain WebBaseLoader. */
export async function runPythonLangChainWebLoaderSsrf(
  input: PythonProjectInput,
): Promise<Finding[]> {
  const project = await resolvePythonProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const context = analyzePythonDocument(document);
    for (const call of context.calls) {
      if (vulnerable(context, call)) findings.push(finding(document.path, call.line));
    }
  }
  return uniqueFindingsByLocation(findings);
}
