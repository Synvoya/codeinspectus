import type { Finding } from "../../types.js";
import type { NativeAnalyzer } from "../types.js";

import {
  createCachedPythonProjectLoader,
  type PythonProject,
  type PythonProjectInput,
} from "../python/project.js";
import {
  PYTHON_HARDCODED_SIGNING_SECRET_RULE_ID,
  runPythonHardcodedSigningSecret,
} from "./hardcoded-signing-secret.js";
import {
  PYTHON_CREDENTIALED_CORS_RULE_ID,
  runPythonCredentialedCorsAllOrigins,
} from "./credentialed-cors.js";
import {
  PYTHON_UNTRUSTED_FILE_RESPONSE_RULE_ID,
  runPythonUntrustedFileResponse,
} from "./file-response.js";
import {
  PYTHON_UNTRUSTED_REDIRECT_RULE_ID,
  runPythonUntrustedRedirect,
} from "./redirect.js";
import {
  PYTHON_UNTRUSTED_TEMPLATE_SOURCE_RULE_ID,
  runPythonUntrustedTemplateSource,
} from "./template-source.js";
import {
  PYTHON_LLM_OUTPUT_DANGEROUS_HTML_RULE_ID,
  runPythonLlmOutputDangerousHtml,
} from "./llm-html.js";

const COMMON_COMPONENTS = [
  "pack:python-ai-api:dispatch",
  "python:lezer-structural-parser",
] as const;

type PythonRuleRunner = (input: PythonProjectInput) => Promise<Finding[]>;

function analyzerRun(
  loadProject: () => Promise<PythonProject>,
  runner: PythonRuleRunner,
): NativeAnalyzer["run"] {
  return async () => {
    const project = await loadProject();
    return {
      findings: await runner(project),
      ...(project.limitations?.length ? { notes: project.limitations } : {}),
    };
  };
}

/** Six independently-failable Python API/AI analyzers sharing one bounded parse. */
export function createPythonAiApiAnalyzers(target: string): readonly NativeAnalyzer[] {
  const loadProject = createCachedPythonProjectLoader(target);
  return [
    {
      id: "python-hardcoded-signing-secret",
      components: [...COMMON_COMPONENTS, "ai:python-hardcoded-signing-secret"],
      ruleIds: [PYTHON_HARDCODED_SIGNING_SECRET_RULE_ID],
      run: analyzerRun(loadProject, runPythonHardcodedSigningSecret),
    },
    {
      id: "python-credentialed-cors",
      components: [...COMMON_COMPONENTS, "ai:python-credentialed-cors"],
      ruleIds: [PYTHON_CREDENTIALED_CORS_RULE_ID],
      run: analyzerRun(loadProject, runPythonCredentialedCorsAllOrigins),
    },
    {
      id: "python-untrusted-file-response",
      components: [...COMMON_COMPONENTS, "ai:python-untrusted-file-response"],
      ruleIds: [PYTHON_UNTRUSTED_FILE_RESPONSE_RULE_ID],
      run: analyzerRun(loadProject, runPythonUntrustedFileResponse),
    },
    {
      id: "python-untrusted-redirect",
      components: [...COMMON_COMPONENTS, "ai:python-untrusted-redirect"],
      ruleIds: [PYTHON_UNTRUSTED_REDIRECT_RULE_ID],
      run: analyzerRun(loadProject, runPythonUntrustedRedirect),
    },
    {
      id: "python-untrusted-template-source",
      components: [...COMMON_COMPONENTS, "ai:python-untrusted-template-source"],
      ruleIds: [PYTHON_UNTRUSTED_TEMPLATE_SOURCE_RULE_ID],
      run: analyzerRun(loadProject, runPythonUntrustedTemplateSource),
    },
    {
      id: "python-llm-output-dangerous-html",
      components: [...COMMON_COMPONENTS, "ai:python-llm-output-dangerous-html"],
      ruleIds: [PYTHON_LLM_OUTPUT_DANGEROUS_HTML_RULE_ID],
      run: analyzerRun(loadProject, runPythonLlmOutputDangerousHtml),
    },
  ];
}

export * from "./analysis.js";
export * from "./hardcoded-signing-secret.js";
export * from "./credentialed-cors.js";
export * from "./file-response.js";
export * from "./redirect.js";
export * from "./template-source.js";
export * from "./llm-html.js";
