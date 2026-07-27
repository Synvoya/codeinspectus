import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  directArgumentReference,
  hasSpreadArgument,
  originEquals,
  resolveCallOrigin,
  resolveReferenceOrigin,
  staticBoolean,
  staticString,
  staticStringList,
  topLevelAssignment,
  uniqueFindingsByLocation,
  type PythonAnalysisContext,
} from "./analysis.js";
import { pythonStaticBoolean } from "../python/analysis.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_CREDENTIALED_CORS_RULE_ID = "ci-python-credentialed-cors-all-origins";

function universal(argumentValue: ReturnType<typeof argument>): boolean {
  const literal = staticString(argumentValue);
  if (literal === "*") return true;
  const list = staticStringList(argumentValue);
  return Boolean(list?.includes("*"));
}

function universalRegex(argumentValue: ReturnType<typeof argument>): boolean {
  return [".*", "^.*$"].includes(staticString(argumentValue) ?? "");
}

function starletteCorsCall(context: PythonAnalysisContext, callIndex: number): boolean {
  const call = context.calls[callIndex];
  if (!call || hasSpreadArgument(call)) return false;
  const origin = resolveCallOrigin(context, call);
  if (
    originEquals(origin, "starlette.middleware.cors.CORSMiddleware") ||
    originEquals(origin, "fastapi.middleware.cors.CORSMiddleware")
  ) return true;
  if (![
    "fastapi.FastAPI.add_middleware",
    "fastapi.applications.FastAPI.add_middleware",
    "fastapi.APIRouter.add_middleware",
    "fastapi.routing.APIRouter.add_middleware",
    "starlette.applications.Starlette.add_middleware",
    "starlette.middleware.Middleware",
  ].some((expected) => originEquals(origin, expected))) return false;
  const middleware = directArgumentReference(argument(call, 0));
  if (!middleware) return false;
  const middlewareOrigin = resolveReferenceOrigin(context, middleware, call.startIndex);
  return originEquals(middlewareOrigin, "starlette.middleware.cors.CORSMiddleware") ||
    originEquals(middlewareOrigin, "fastapi.middleware.cors.CORSMiddleware");
}

function callVulnerable(context: PythonAnalysisContext, callIndex: number): boolean {
  const call = context.calls[callIndex];
  if (!call || hasSpreadArgument(call)) return false;
  const origin = resolveCallOrigin(context, call);
  if (starletteCorsCall(context, callIndex)) {
    return staticBoolean(argument(call, -1, "allow_credentials")) === true &&
      (universal(argument(call, -1, "allow_origins")) || universalRegex(argument(call, -1, "allow_origin_regex")));
  }
  if (![
    "flask_cors.CORS",
    "flask_cors.cross_origin",
    "flask_cors.decorator.cross_origin",
    "flask_cors.extension.CORS",
  ].some((expected) => originEquals(origin, expected))) return false;
  return staticBoolean(argument(call, -1, "supports_credentials")) === true &&
    universal(argument(call, -1, "origins"));
}

function djangoCorsLine(context: PythonAnalysisContext): number | undefined {
  if (!/(?:^|\/)settings(?:\.pyw?$|\/)/.test(context.document.path)) return undefined;
  const allOrigins = topLevelAssignment(context, "CORS_ALLOW_ALL_ORIGINS") ??
    topLevelAssignment(context, "CORS_ORIGIN_ALLOW_ALL");
  const credentials = topLevelAssignment(context, "CORS_ALLOW_CREDENTIALS");
  if (!allOrigins || !credentials) return undefined;
  return pythonStaticBoolean(allOrigins.expression) === true && pythonStaticBoolean(credentials.expression) === true
    ? credentials.line
    : undefined;
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PYTHON_CREDENTIALED_CORS_RULE_ID,
    title: "Credentialed CORS allows every origin",
    severity: "high",
    cwe: ["CWE-942", "CWE-346"],
    owasp_web: ["A05:2021"],
    owasp_api: ["API8:2023"],
    file,
    startLine: line,
    snippet: "Credentialed CORS is configured with a universal origin policy",
    message: "A proven Python CORS middleware enables credentials while accepting every origin.",
    remediation: {
      summary: "Replace the universal origin policy with an exact trusted-origin allowlist.",
      steps: [
        "List the exact HTTPS origins that may make credentialed browser requests.",
        "Keep wildcard origins and universal origin regexes disabled whenever credentials are enabled.",
        "Verify preflight and credential behavior for each deployed frontend origin.",
      ],
      references: [
        "CWE-942",
        "CWE-346",
        "https://fastapi.tiangolo.com/tutorial/cors/",
        "https://www.starlette.io/middleware/",
        "https://pypi.org/project/django-cors-headers/4.9.0/",
      ],
    },
    confidence: "high",
  });
}

export async function runPythonCredentialedCorsAllOrigins(
  input: PythonProjectInput,
): Promise<Finding[]> {
  const project = await resolvePythonProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const context = analyzePythonDocument(document);
    context.calls.forEach((call, index) => {
      if (callVulnerable(context, index)) findings.push(finding(document.path, call.line));
    });
    const djangoLine = djangoCorsLine(context);
    if (djangoLine !== undefined) findings.push(finding(document.path, djangoLine));
  }
  return uniqueFindingsByLocation(findings);
}
