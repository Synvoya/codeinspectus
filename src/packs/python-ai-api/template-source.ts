import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  directCallExpression,
  expressionContainsRequest,
  functionAt,
  hasSpreadArgument,
  reachingAssignments,
  resolveCallOrigin,
  uniqueFindingsByLocation,
  type PythonAnalysisContext,
} from "./analysis.js";
import type { PythonCall, PythonExpression } from "../python/python.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_UNTRUSTED_TEMPLATE_SOURCE_RULE_ID = "ci-python-untrusted-template-source";

const IMMEDIATE_SINKS = new Set([
  "flask.render_template_string",
  "flask.templating.render_template_string",
  "flask.stream_template_string",
  "flask.templating.stream_template_string",
]);

const TEMPLATE_BUILDERS = new Set([
  "jinja2.Template",
  "jinja2.environment.Template",
  "jinja2.Environment.from_string",
  "jinja2.environment.Environment.from_string",
  "django.template.Template",
  "django.template.base.Template",
  "django.template.Engine.from_string",
  "django.template.engine.Engine.from_string",
]);

function sourceArgument(
  context: PythonAnalysisContext,
  call: PythonCall,
): { source: PythonExpression; needsRender: boolean } | undefined {
  const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
  if (origin.includes("SandboxedEnvironment")) return undefined;
  if (IMMEDIATE_SINKS.has(origin)) {
    const source = argument(call, 0, "source")?.expression;
    return source ? { source, needsRender: false } : undefined;
  }
  if (!TEMPLATE_BUILDERS.has(origin)) return undefined;
  const source = argument(call, 0, "source")?.expression;
  return source ? { source, needsRender: true } : undefined;
}

function directChainedRender(context: PythonAnalysisContext, builder: PythonCall): boolean {
  const tokens = context.document.tokens;
  return tokens[builder.closeIndex + 1]?.value === "." &&
    ["render", "generate", "stream"].includes(tokens[builder.closeIndex + 2]?.value ?? "") &&
    tokens[builder.closeIndex + 3]?.value === "(";
}

function laterRender(context: PythonAnalysisContext, builder: PythonCall): boolean {
  if (directChainedRender(context, builder)) return true;
  const assignment = context.assignments.find((candidate) => {
    const direct = directCallExpression(context, candidate.expression);
    return candidate.name !== undefined && direct?.startIndex === builder.startIndex && direct.closeIndex === builder.closeIndex;
  });
  if (!assignment?.name) return false;
  return context.calls.some((call) => {
    if (call.startIndex <= builder.closeIndex || call.reference[0] !== assignment.name) return false;
    if (functionAt(context, call.startIndex)?.id !== assignment.scopeId) return false;
    if (!reachingAssignments(context, assignment.name!, call.startIndex).includes(assignment)) return false;
    const method = call.reference.at(-1);
    if (!["render", "generate", "stream"].includes(method ?? "")) return false;
    const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
    return origin.includes("Template") ||
      origin.includes("Environment.from_string") ||
      origin.includes("Engine.from_string");
  });
}

function vulnerable(context: PythonAnalysisContext, call: PythonCall): boolean {
  if (hasSpreadArgument(call)) return false;
  const sink = sourceArgument(context, call);
  if (!sink || !expressionContainsRequest(context, sink.source, call.startIndex)) return false;
  return !sink.needsRender || laterRender(context, call);
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PYTHON_UNTRUSTED_TEMPLATE_SOURCE_RULE_ID,
    title: "Request input controls template source",
    severity: "high",
    cwe: ["CWE-1336", "CWE-94"],
    owasp_web: ["A03:2021"],
    file,
    startLine: line,
    snippet: "Template source is derived from request input [VALUE REDACTED]",
    message: "Request-controlled text is compiled by a proven Python template-string API and rendered without a sandbox boundary.",
    remediation: {
      summary: "Render a fixed template and pass untrusted data only as template context.",
      steps: [
        "Move template syntax into a trusted template file controlled by the application.",
        "Pass request values as context variables so the template engine can escape them according to output context.",
        "If user-authored templates are an explicit product feature, isolate them and enforce a restricted sandbox plus resource limits.",
      ],
      references: [
        "CWE-1336",
        "CWE-94",
        "https://jinja.palletsprojects.com/en/stable/sandbox/",
        "https://flask.palletsprojects.com/en/stable/api/#flask.render_template_string",
        "https://docs.djangoproject.com/en/5.2/topics/templates/",
      ],
    },
    confidence: "high",
  });
}

export async function runPythonUntrustedTemplateSource(
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
