import { describe, expect, test } from "vitest";

import { parsePythonSource } from "../python/python.js";
import type { PythonProject } from "../python/project.js";
import { runPythonFaissDangerousDeserialization } from "./faiss-deserialization.js";

function project(source: string): PythonProject {
  return {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/rag.py", source)],
  };
}

describe("Python LangChain FAISS dangerous-deserialization rule", () => {
  test("flags proven current and legacy LangChain FAISS loads with the literal opt-in", async () => {
    const findings = await runPythonFaissDangerousDeserialization(project(`
from langchain_community.vectorstores import FAISS
from langchain_community.vectorstores.faiss import FAISS as CommunityFaiss
from langchain.vectorstores import FAISS as LegacyFaiss

FAISS.load_local("index-one", embeddings, allow_dangerous_deserialization=True)
CommunityFaiss.load_local("index-two", embeddings, allow_dangerous_deserialization=True)
LegacyFaiss.load_local("index-three", embeddings, allow_dangerous_deserialization=True)
`));

    expect(findings).toHaveLength(3);
    expect(findings.every((finding) =>
      finding.rule_id === "ci-python-faiss-dangerous-deserialization" &&
      finding.severity === "high" &&
      finding.confidence === "high" &&
      finding.cwe.join(",") === "CWE-502"
    )).toBe(true);
  });

  test("flags module-qualified and source-ordered aliases", async () => {
    const findings = await runPythonFaissDangerousDeserialization(project(`
import langchain_community.vectorstores as stores
from langchain_community.vectorstores import FAISS

stores.FAISS.load_local("index-one", embeddings, allow_dangerous_deserialization=True)
VectorStore = FAISS
VectorStore.load_local("index-two", embeddings, allow_dangerous_deserialization=True)
`));

    expect(findings).toHaveLength(2);
  });

  test("stays silent for safe, omitted, dynamic, spread, lookalike, and shadowed calls", async () => {
    const findings = await runPythonFaissDangerousDeserialization(project(`
from langchain_community.vectorstores import FAISS

FAISS.load_local("safe", embeddings, allow_dangerous_deserialization=False)
FAISS.load_local("default", embeddings)
FAISS.load_local("dynamic", embeddings, allow_dangerous_deserialization=trusted)
FAISS.load_local("spread", embeddings, allow_dangerous_deserialization=True, **options)

from internal.vectorstores import FAISS as InternalFaiss
InternalFaiss.load_local("lookalike", embeddings, allow_dangerous_deserialization=True)

class FAISS:
    @classmethod
    def load_local(cls, *args, **kwargs):
        return None

FAISS.load_local("shadowed", embeddings, allow_dangerous_deserialization=True)
`));

    expect(findings).toEqual([]);
  });

  test("fails closed for conditional imports and parser-invalid source", async () => {
    const conditional = await runPythonFaissDangerousDeserialization(project(`
if enabled:
    from langchain_community.vectorstores import FAISS
FAISS.load_local("conditional", embeddings, allow_dangerous_deserialization=True)
`));
    const malformed = await runPythonFaissDangerousDeserialization(project(`
from langchain_community.vectorstores import FAISS
FAISS.load_local("broken", embeddings, allow_dangerous_deserialization=True
`));

    expect(conditional).toEqual([]);
    expect(malformed).toEqual([]);
  });
});
