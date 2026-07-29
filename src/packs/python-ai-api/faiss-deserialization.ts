import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";

import {
  analyzePythonDocument,
  argument,
  hasSpreadArgument,
  originEquals,
  resolveCallOrigin,
  staticBoolean,
  uniqueFindingsByLocation,
} from "./analysis.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_FAISS_DANGEROUS_DESERIALIZATION_RULE_ID =
  "ci-python-faiss-dangerous-deserialization";

const FAISS_LOAD_ORIGINS = [
  "langchain_community.vectorstores.FAISS.load_local",
  "langchain_community.vectorstores.faiss.FAISS.load_local",
  "langchain.vectorstores.FAISS.load_local",
  "langchain.vectorstores.faiss.FAISS.load_local",
] as const;

function dangerousFaissLoad(
  context: ReturnType<typeof analyzePythonDocument>,
  callIndex: number,
): boolean {
  const call = context.calls[callIndex];
  if (!call || hasSpreadArgument(call)) return false;
  const origin = resolveCallOrigin(context, call);
  if (!FAISS_LOAD_ORIGINS.some((expected) => originEquals(origin, expected))) return false;
  return staticBoolean(argument(call, -1, "allow_dangerous_deserialization")) === true;
}

function finding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: PYTHON_FAISS_DANGEROUS_DESERIALIZATION_RULE_ID,
    title: "LangChain FAISS dangerous deserialization enabled",
    severity: "high",
    cwe: ["CWE-502"],
    owasp_web: ["A08:2021"],
    file,
    startLine: line,
    snippet: "FAISS.load_local(..., allow_dangerous_deserialization=True)",
    message:
      "A proven LangChain FAISS load explicitly enables pickle deserialization, which can execute arbitrary code if the stored index is malicious or has been modified.",
    remediation: {
      summary: "Do not deserialize FAISS pickle data unless its origin and integrity are guaranteed.",
      steps: [
        "Prefer rebuilding the FAISS index and document store from trusted source documents instead of loading pickle state.",
        "If loading is unavoidable, keep the artifact read-only and outside user-controlled or shared writable storage.",
        "Verify an authenticated digest or signature before loading, and document the trusted artifact producer.",
      ],
      references: [
        "CWE-502",
        "https://python.langchain.com/docs/integrations/vectorstores/faiss/#saving-and-loading",
        "https://docs.python.org/3/library/pickle.html",
      ],
    },
    confidence: "high",
  });
}

/** Detect an explicit LangChain FAISS pickle-deserialization opt-in without executing target code. */
export async function runPythonFaissDangerousDeserialization(
  input: PythonProjectInput,
): Promise<Finding[]> {
  const project = await resolvePythonProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const context = analyzePythonDocument(document);
    context.calls.forEach((call, index) => {
      if (dangerousFaissLoad(context, index)) findings.push(finding(document.path, call.line));
    });
  }
  return uniqueFindingsByLocation(findings);
}
