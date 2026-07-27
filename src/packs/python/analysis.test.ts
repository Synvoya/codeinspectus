import { describe, expect, test } from "vitest";

import {
  pythonAssignments,
  pythonCallOrigin,
  pythonDirectCall,
  pythonImports,
  pythonKeywordArgument,
  pythonReferenceOrigin,
  pythonStaticBoolean,
  pythonStaticString,
  pythonStaticStringList,
  pythonTopLevelAssignment,
} from "./analysis.js";
import { parsePythonSource, pythonCalls } from "./python.js";

describe("Python import and literal analysis", () => {
  test("resolves direct, aliased, parenthesized, and module imports", () => {
    const document = parsePythonSource("app.py", `
from langchain_community.vectorstores import (FAISS as VectorStore, Chroma)
import starlette.middleware.cors as cors
import flask
VectorStore.load_local("index", allow_dangerous_deserialization=True)
cors.CORSMiddleware(app, allow_origins=["*"])
flask.Flask(__name__)
`);
    const calls = pythonCalls(document);

    expect(pythonImports(document)).toHaveLength(4);
    expect(pythonCallOrigin(document, calls.find((call) => call.reference.includes("VectorStore"))!)).toEqual([
      "langchain_community", "vectorstores", "FAISS", "load_local",
    ]);
    expect(pythonCallOrigin(document, calls.find((call) => call.reference.includes("CORSMiddleware"))!)).toEqual([
      "starlette", "middleware", "cors", "CORSMiddleware",
    ]);
    expect(pythonCallOrigin(document, calls.find((call) => call.reference[0] === "flask")!)).toEqual([
      "flask", "Flask",
    ]);
  });

  test("fails closed after an imported name is rebound", () => {
    const document = parsePythonSource("app.py", `
from flask import Flask
Flask = fake_factory
app = Flask(__name__)
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "Flask")!;

    expect(pythonReferenceOrigin(document, call.reference, call.startIndex)).toBeUndefined();
  });

  test("parses simple and annotated assignments without treating attributes as names", () => {
    const document = parsePythonSource("settings.py", `
DEBUG: bool = True
ALLOWED_HOSTS = ["*", "api.example.com"]
app.debug = True
`);

    expect(pythonAssignments(document).map((assignment) => assignment.name)).toEqual(["DEBUG", "ALLOWED_HOSTS"]);
    expect(pythonStaticBoolean(pythonTopLevelAssignment(document, "DEBUG")?.expression)).toBe(true);
    expect(pythonStaticStringList(pythonTopLevelAssignment(document, "ALLOWED_HOSTS")?.expression)).toEqual([
      "*", "api.example.com",
    ]);
  });

  test("extracts exact keyword literals and a direct constructor assignment", () => {
    const document = parsePythonSource("app.py", `
from flask import Flask
app = Flask(__name__)
app.run(debug=True, host="0.0.0.0")
`);
    const assignment = pythonTopLevelAssignment(document, "app")!;
    const constructor = pythonDirectCall(document, assignment.expression)!;
    const run = pythonCalls(document).find((call) => call.reference.join(".") === "app.run")!;

    expect(pythonCallOrigin(document, constructor)).toEqual(["flask", "Flask"]);
    expect(pythonStaticBoolean(pythonKeywordArgument(run, "debug")?.expression)).toBe(true);
    expect(pythonStaticString(pythonKeywordArgument(run, "host")?.expression)).toBe("0.0.0.0");
  });

  test("resolves a direct function-local import in its lexical scope", () => {
    const document = parsePythonSource("app.py", `
def build():
    from flask import Flask
    return Flask(__name__)
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "Flask")!;

    expect(pythonImports(document)).toHaveLength(1);
    expect(pythonCallOrigin(document, call)).toEqual(["flask", "Flask"]);
  });

  test("does not resolve an imported origin through lexical shadowing", () => {
    const document = parsePythonSource("app.py", `
from openai import OpenAI

def parameter_shadow(OpenAI):
    return OpenAI()

def local_import_shadow():
    from fake import OpenAI
    return OpenAI()

def unrelated_assignment():
    OpenAI = fake_factory
    return OpenAI()

def genuine():
    return OpenAI()
`);
    const calls = pythonCalls(document).filter((call) => call.reference[0] === "OpenAI");

    expect(calls).toHaveLength(4);
    expect(pythonCallOrigin(document, calls[0]!)).toBeUndefined();
    expect(pythonCallOrigin(document, calls[1]!)).toEqual(["fake", "OpenAI"]);
    expect(pythonCallOrigin(document, calls[2]!)).toBeUndefined();
    expect(pythonCallOrigin(document, calls[3]!)).toEqual(["openai", "OpenAI"]);
  });

  test("module declarations shadow earlier imports without leaking function locals", () => {
    const document = parsePythonSource("app.py", `
from openai import OpenAI

def OpenAI(value):
    return value

OpenAI("local")
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "OpenAI")!;

    expect(pythonCallOrigin(document, call)).toBeUndefined();
  });

  test("handles global and nonlocal declarations conservatively", () => {
    const document = parsePythonSource("app.py", `
from openai import OpenAI

def global_reader():
    global OpenAI
    return OpenAI()

def outer():
    from fake import OpenAI
    def inner():
        nonlocal OpenAI
        return OpenAI()
    return inner
`);
    const calls = pythonCalls(document).filter((call) => call.reference[0] === "OpenAI");

    expect(pythonCallOrigin(document, calls[0]!)).toEqual(["openai", "OpenAI"]);
    expect(pythonCallOrigin(document, calls[1]!)).toEqual(["fake", "OpenAI"]);
  });

  test.each([
    ["for target", "for OpenAI in factories:\n        pass"],
    ["with alias", "with resource() as OpenAI:\n        pass"],
    ["except alias", "try:\n        pass\n    except Error as OpenAI:\n        pass"],
    ["deleted local", "del OpenAI"],
  ])("treats a %s as a function-local binding for the whole scope", (_label, binding) => {
    const document = parsePythonSource("app.py", `
from openai import OpenAI

def build():
    OpenAI()
    ${binding}
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "OpenAI")!;

    expect(pythonCallOrigin(document, call)).toBeUndefined();
  });

  test("does not prove a control-flow-conditional import", () => {
    const document = parsePythonSource("app.py", `
def build(enabled):
    if enabled:
        from openai import OpenAI
    return OpenAI()
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "OpenAI")!;

    expect(pythonCallOrigin(document, call)).toBeUndefined();
  });

  test.each([
    ["augmented assignment", `def build(app):\n    CORS(app, origins="*", supports_credentials=True)\n    CORS += replacement`],
    ["annotation-only target", `def build(app):\n    CORS(app, origins="*", supports_credentials=True)\n    CORS: object`],
    ["destructuring target", `def build(app):\n    CORS(app, origins="*", supports_credentials=True)\n    CORS, other = factories`],
    ["walrus target", `def build(app):\n    CORS(app, origins="*", supports_credentials=True)\n    if (CORS := replacement):\n        pass`],
    ["lambda parameter", `build = lambda CORS: CORS(app, origins="*", supports_credentials=True)`],
    ["comprehension target", `values = [CORS(app, origins="*", supports_credentials=True) for CORS in factories]`],
    ["inline del", `def build(app):\n    CORS(app, origins="*", supports_credentials=True)\n    if flag: del CORS`],
    ["inline assignment", `def build(app):\n    CORS(app, origins="*", supports_credentials=True)\n    if flag: CORS = fake`],
    ["inline augmented assignment", `def build(app):\n    CORS(app, origins="*", supports_credentials=True)\n    while flag: CORS += fake`],
  ])("fails closed when an imported name has a %s", (_label, body) => {
    const document = parsePythonSource("app.py", `from flask_cors import CORS\n${body}\n`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "CORS")!;

    expect(document.balanced).toBe(true);
    expect(pythonCallOrigin(document, call)).toBeUndefined();
  });

  test.each([
    ["assignment", "CORS = fake_cors"],
    ["definition", "def CORS(*args, **kwargs): return None"],
    ["later import", "from fake import CORS"],
  ])("does not treat a module import as stable across a function when followed by %s", (_label, rebound) => {
    const document = parsePythonSource("app.py", `
from flask_cors import CORS
def build(app):
    CORS(app, origins="*", supports_credentials=True)
${rebound}
build(app)
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "CORS")!;

    expect(document.balanced).toBe(true);
    expect(pythonCallOrigin(document, call)).toBeUndefined();
  });

  test("applies stable-module provenance to explicit global lookups", () => {
    const document = parsePythonSource("app.py", `
from flask_cors import CORS
def build(app):
    global CORS
    CORS(app, origins="*", supports_credentials=True)
CORS = fake_cors
build(app)
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "CORS")!;

    expect(pythonCallOrigin(document, call)).toBeUndefined();
  });

  test.each([
    ["ordinary lookup", ""],
    ["explicit global lookup", "    global CORS\n"],
  ])("does not resolve an import written after a function's %s", (_label, declaration) => {
    const document = parsePythonSource("app.py", `
def build(app):
${declaration}    CORS(app, origins="*", supports_credentials=True)
build(app)
from flask_cors import CORS
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference[0] === "CORS")!;

    expect(document.balanced).toBe(true);
    expect(pythonCallOrigin(document, call)).toBeUndefined();
  });
});
