import { describe, expect, test } from "vitest";

import {
  parsePythonSource,
  pythonCalls,
  pythonExpressionReference,
  pythonStatements,
  splitPythonTopLevel,
} from "./python.js";

describe("bounded Python structural lexer", () => {
  test("keeps comments and string contents out of the call stream", () => {
    const document = parsePythonSource("app.py", `
# RequestsToolkit(allow_dangerous_requests=True)
message = "FAISS.load_local('index', allow_dangerous_deserialization=True)"
doc = '''app.run(debug=True, host="0.0.0.0")'''
actual(value="safe")
`);

    expect(document.balanced).toBe(true);
    expect(pythonCalls(document).map((call) => call.reference.join("."))).toEqual(["actual"]);
  });

  test("marks escaped strings as non-static", () => {
    const document = parsePythonSource("app.py", `values = ["*", r"raw\\value", "line\\n"]`);
    const strings = document.tokens.filter((token) => token.kind === "string");

    expect(strings.map((token) => token.staticString)).toEqual(["*", "raw\\value", undefined]);
  });

  test.each([
    ["PEP 701 same-delimiter string", `from openai import OpenAI\nx = f"{ "OpenAI(http_client=transport)" }"`],
    ["same-delimiter triple string", `from openai import OpenAI\nx = f'''{ '''OpenAI(http_client=transport)''' }'''`],
    ["nested format expression", `from openai import OpenAI\nx = f"{f'{OpenAI(http_client=transport)}'}"`],
  ])("fails closed for %s", (_label, source) => {
    const document = parsePythonSource("app.py", source);

    expect(document.balanced).toBe(false);
    expect(document.formatStringUnsupported).toBe(true);
    expect(pythonCalls(document)).toEqual([]);
  });

  test("fails closed for leading tab indentation", () => {
    const document = parsePythonSource("app.py", `
def build(flag, app):
    if flag:
\t\tfrom flask_cors import CORS
    return CORS(app, origins="*", supports_credentials=True)
`);

    expect(document.balanced).toBe(false);
    expect(document.tabIndentationUnsupported).toBe(true);
    expect(pythonCalls(document)).toEqual([]);
  });

  test("parses direct attribute calls, keyword arguments, and nested expressions", () => {
    const document = parsePythonSource("app.py", `
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    **options,
)
`);
    const call = pythonCalls(document).find((candidate) => candidate.reference.join(".") === "app.add_middleware");

    expect(call).toBeDefined();
    expect(call?.arguments.map((argument) => ({ name: argument.name, spread: argument.spread }))).toEqual([
      { name: undefined, spread: false },
      { name: "allow_origins", spread: false },
      { name: "allow_credentials", spread: false },
      { name: undefined, spread: true },
    ]);
    expect(pythonExpressionReference(call?.arguments[0]?.expression)).toEqual(["CORSMiddleware"]);
  });

  test("does not classify function and class declarations as calls", () => {
    const document = parsePythonSource("app.py", `
def handler(request):
    return service.run(request)
class Service(Base):
    pass
`);

    expect(pythonCalls(document).map((call) => call.reference.join("."))).toEqual(["service.run"]);
  });

  test("splits logical statements and top-level comma expressions", () => {
    const document = parsePythonSource("app.py", `
first = call(
    one,
    nested(two, three),
)
second = True; third = ["a", "b"]
`);

    expect(pythonStatements(document)).toHaveLength(3);
    const outer = pythonCalls(document).find((call) => call.reference[0] === "call");
    expect(outer?.arguments).toHaveLength(2);
    expect(splitPythonTopLevel(outer?.arguments[1]?.expression.tokens ?? [])).toHaveLength(1);
  });

  test.each([
    ["unterminated string", `value = "unterminated`],
    ["mismatched delimiters", "value = ([)]"],
    ["parser-invalid statement", "value = if True"],
    ["excessive nesting", `${"(".repeat(65)}True${")".repeat(65)}`],
  ])("fails closed for %s", (_label, source) => {
    const document = parsePythonSource("broken.py", source);

    expect(document.balanced).toBe(false);
    expect(pythonCalls(document)).toEqual([]);
  });
});
