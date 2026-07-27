import { describe, expect, test } from "vitest";

import { parsePythonSource } from "../python/python.js";
import type { PythonProject } from "../python/project.js";
import { runPythonLlmOutputDangerousHtml } from "./llm-html.js";

function findings(source: string) {
  const project: PythonProject = {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/responses.py", source)],
  };
  return runPythonLlmOutputDangerousHtml(project);
}

const prelude = `
from flask import Flask
from openai import OpenAI
app = Flask(__name__)
client = OpenAI()
`;

describe("Python LLM-to-HTML response regressions", () => {
  test("honors exact Flask make_response content types", async () => {
    const plain = await findings(`${prelude}
from flask import make_response
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return make_response(output, {"Content-Type": "text/plain; charset=utf-8"})
`);
    const html = await findings(`${prelude}
from flask import make_response
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return make_response(output, {"Content-Type": "text/html; charset=utf-8"})
`);
    expect({ plain: plain.length, html: html.length }).toEqual({ plain: 0, html: 1 });
  });

  test("honors exact Flask tuple content types", async () => {
    const plain = await findings(`${prelude}
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return output, {"Content-Type": "text/plain"}
`);
    const html = await findings(`${prelude}
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return output, 200, {"Content-Type": "text/html"}
`);
    expect({ plain: plain.length, html: html.length }).toEqual({ plain: 0, html: 1 });
  });

  test("excludes exact Flask jsonify and leaves local lookalike wrappers opaque", async () => {
    const exact = await findings(`${prelude}
from flask import jsonify
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return jsonify(output=output)
`);
    const lookalike = await findings(`${prelude}
def jsonify(value):
    return {"value": value}
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return jsonify(output)
`);
    expect({ exact: exact.length, lookalike: lookalike.length }).toEqual({ exact: 0, lookalike: 0 });
  });

  test("excludes Flask automatic JSON collections but retains bare string responses", async () => {
    const json = await findings(`${prelude}
@app.get("/dict")
def dictionary():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return {"output": output}
@app.get("/list")
def list_response():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return [output]
`);
    const string = await findings(`${prelude}
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return output
`);
    expect({ json: json.length, string: string.length }).toEqual({ json: 0, string: 1 });
  });

  test("does not propagate through arbitrary wrappers but retains exact HTML transforms", async () => {
    const wrapper = await findings(`${prelude}
def plain_text(value):
    return value
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return plain_text(output)
`);
    const markdownResult = await findings(`${prelude}
import markdown
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return markdown.markdown(output)
`);
    expect({ wrapper: wrapper.length, markdown: markdownResult.length }).toEqual({ wrapper: 0, markdown: 1 });
  });

  test("accepts only the default one-content sanitizer contract", async () => {
    const defaultPolicy = await findings(`${prelude}
import bleach
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return bleach.clean(output)
`);
    const configured = await findings(`${prelude}
import bleach
@app.get("/answer")
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return bleach.clean(output, tags=allowed_tags)
`);
    expect({ defaultPolicy: defaultPolicy.length, configured: configured.length }).toEqual({
      defaultPolicy: 0,
      configured: 1,
    });
  });
});
