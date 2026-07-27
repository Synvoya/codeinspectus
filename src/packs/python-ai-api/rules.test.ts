import { resolve } from "node:path";

import { describe, expect, test } from "vitest";

import type { Finding } from "../../types.js";
import { parsePythonSource } from "../python/python.js";
import type { PythonProject, PythonProjectInput } from "../python/project.js";
import { createPythonAiApiAnalyzers } from "./index.js";
import { runPythonHardcodedSigningSecret } from "./hardcoded-signing-secret.js";
import { runPythonCredentialedCorsAllOrigins } from "./credentialed-cors.js";
import { runPythonUntrustedFileResponse } from "./file-response.js";
import { runPythonUntrustedRedirect } from "./redirect.js";
import { runPythonUntrustedTemplateSource } from "./template-source.js";
import { runPythonLlmOutputDangerousHtml } from "./llm-html.js";

function project(source: string, path = "src/app.py"): PythonProject {
  return {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource(path, source)],
  };
}

function findings(
  runner: (input: PythonProjectInput) => Promise<Finding[]>,
  source: string,
  path?: string,
): Promise<Finding[]> {
  return runner(project(source, path));
}

describe("Python AI/API analyzer contract", () => {
  test("registers six independent analyzers with exact rule components", () => {
    const analyzers = createPythonAiApiAnalyzers("/virtual/python");
    expect(analyzers).toHaveLength(6);
    expect(analyzers.map((analyzer) => analyzer.components.at(-1))).toEqual([
      "ai:python-hardcoded-signing-secret",
      "ai:python-credentialed-cors",
      "ai:python-untrusted-file-response",
      "ai:python-untrusted-redirect",
      "ai:python-untrusted-template-source",
      "ai:python-llm-output-dangerous-html",
    ]);
    expect(analyzers.every((analyzer) =>
      analyzer.components.includes("pack:python-ai-api:dispatch") &&
      analyzer.components.includes("python:lezer-structural-parser") &&
      analyzer.ruleIds.length === 1
    )).toBe(true);
  });

  test("locks the checked-in TP, FP, and fixed corpus contract", async () => {
    const corpus = resolve(process.cwd(), "fixtures/python-ai-api-corpus");
    const run = async (variant: string): Promise<Finding[]> => {
      const results = await Promise.all(
        createPythonAiApiAnalyzers(resolve(corpus, variant)).map((analyzer) => analyzer.run()),
      );
      return results.flatMap((result) => result.findings);
    };
    const tp = await run("tp");
    expect(tp.map((finding) => finding.rule_id).sort()).toEqual([
      "ci-python-credentialed-cors-all-origins",
      "ci-python-hardcoded-signing-secret",
      "ci-python-llm-output-dangerous-html",
      "ci-python-untrusted-file-response",
      "ci-python-untrusted-redirect",
      "ci-python-untrusted-template-source",
    ]);
    expect(tp.every((finding) => !finding.location.file.includes("tests/") && !finding.location.file.includes("examples/"))).toBe(true);
    expect(JSON.stringify(tp)).not.toContain("CI_PYTHON_REDACTION_SENTINEL");
    await expect(run("fp")).resolves.toEqual([]);
    await expect(run("fixed")).resolves.toEqual([]);
  });

  test("fails closed for parser-invalid input and imported-name shadowing", async () => {
    await expect(findings(runPythonHardcodedSigningSecret, `
SECRET_KEY = "literal"
if (
`, "config/settings.py")).resolves.toEqual([]);
    await expect(findings(runPythonCredentialedCorsAllOrigins, `
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
class CORSMiddleware:
    pass
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
`)).resolves.toEqual([]);
  });
});

describe("Python signing-secret rule", () => {
  test("flags Django literal defaults, Flask config, and Starlette sessions without retaining values", async () => {
    const django = await findings(runPythonHardcodedSigningSecret, `
import os
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "sentinel-secret")
`, "config/settings.py");
    const flask = await findings(runPythonHardcodedSigningSecret, `
from flask import Flask
app = Flask(__name__)
app.config["SECRET_KEY"] = "flask-secret"
`);
    const starlette = await findings(runPythonHardcodedSigningSecret, `
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="session-secret")
`);
    expect([...django, ...flask, ...starlette]).toHaveLength(3);
    for (const finding of [...django, ...flask, ...starlette]) {
      expect(finding).toMatchObject({
        severity: "high",
        confidence: "high",
        is_secret: true,
        cwe: ["CWE-798", "CWE-321"],
      });
      expect(finding.secret_value_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(JSON.stringify(finding)).not.toMatch(/sentinel-secret|flask-secret|session-secret/);
    }
  });

  test("excludes runtime-only, empty, dynamic, and lookalike settings", async () => {
    await expect(findings(runPythonHardcodedSigningSecret, `
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
SECRET_KEY_FALLBACKS = [make_secret()]
`, "config/settings.py")).resolves.toEqual([]);
    await expect(findings(runPythonHardcodedSigningSecret, `
from flask import Flask
app = Flask(__name__)
app.secret_key = ""
fake = object()
fake.secret_key = "lookalike"
`)).resolves.toEqual([]);
  });
});

describe("Python credentialed-CORS rule", () => {
  test("flags proven FastAPI, Flask-CORS, and Django universal credential policies", async () => {
    const fastapi = await findings(runPythonCredentialedCorsAllOrigins, `
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
`);
    const flask = await findings(runPythonCredentialedCorsAllOrigins, `
from flask_cors import CORS
CORS(app, origins="*", supports_credentials=True)
`);
    const django = await findings(runPythonCredentialedCorsAllOrigins, `
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
`, "config/settings.py");
    expect([...fastapi, ...flask, ...django]).toHaveLength(3);
  });

  test("fails closed for trusted, non-credentialed, dynamic, spread, and lookalike policies", async () => {
    await expect(findings(runPythonCredentialedCorsAllOrigins, `
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example"], allow_credentials=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False)
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True)
app.add_middleware(CORSMiddleware, **options)
CORSMiddleware(app, allow_origins=["*"], allow_credentials=enabled)
`)).resolves.toEqual([]);
  });
});

describe("Python file-response rule", () => {
  test("tracks route/request aliases and unsafe path composition", async () => {
    const result = await findings(runPythonUntrustedFileResponse, `
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
app = FastAPI()
BASE = Path("/srv/files")
@app.get("/files/{name}")
def download(name: str):
    selected = (BASE / name).resolve()
    return FileResponse(selected)
`);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ severity: "high", cwe: ["CWE-22", "CWE-73"] });
  });

  test("accepts fixed send_from_directory roots, sanitizers, and dominating containment guards", async () => {
    await expect(findings(runPythonUntrustedFileResponse, `
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from flask import send_from_directory, request
from werkzeug.utils import secure_filename
app = FastAPI()
BASE = Path("/srv/files")
def flask_download():
    return send_from_directory(BASE, request.args.get("name"))
@app.get("/files/{name}")
def guarded(name: str):
    selected = (BASE / name).resolve()
    if not selected.is_relative_to(BASE):
        raise ValueError("outside root")
    return FileResponse(selected)
@app.get("/safe/{name}")
def sanitized(name: str):
    return FileResponse(BASE / secure_filename(name))
`)).resolves.toEqual([]);
  });

  test("enforces the two-assignment request-flow bound", async () => {
    await expect(findings(runPythonUntrustedFileResponse, `
from fastapi import FastAPI
from fastapi.responses import FileResponse
app = FastAPI()
@app.get("/files/{name}")
def download(name: str):
    first = name
    second = first
    third = second
    return FileResponse(third)
`)).resolves.toEqual([]);
  });
});

describe("Python redirect rule", () => {
  test("flags complete request-controlled redirect targets but not local suffixes", async () => {
    const unsafe = await findings(runPythonUntrustedRedirect, `
from flask import Flask, redirect, request
app = Flask(__name__)
@app.get("/continue")
def go():
    target = request.args.get("next")
    return redirect(target)
`);
    const local = await findings(runPythonUntrustedRedirect, `
from flask import Flask, redirect, request
app = Flask(__name__)
@app.get("/continue")
def go():
    value = request.args.get("value")
    return redirect("/search?q=" + value)
`);
    expect(unsafe).toHaveLength(1);
    expect(local).toHaveLength(0);
  });

  test("accepts route reversal, relative-URL rejection, and exact HTTPS origin guards", async () => {
    await expect(findings(runPythonUntrustedRedirect, `
from urllib.parse import urlsplit
from flask import Flask, abort, redirect, request, url_for
app = Flask(__name__)
@app.get("/one")
def one():
    return redirect(url_for("index"))
@app.get("/two")
def two():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or "\\\\" in target:
        abort(400)
    return redirect(target)
@app.get("/three")
def three():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme == "https" and parsed.netloc == "login.example.com":
        return redirect(target)
`)).resolves.toEqual([]);
  });
});

describe("Python template-source rule", () => {
  test("flags Flask and rendered Jinja source including concatenated request fragments", async () => {
    const flask = await findings(runPythonUntrustedTemplateSource, `
from flask import render_template_string, request
def preview():
    source = "Hello " + request.form["template"]
    return render_template_string(source)
`);
    const jinja = await findings(runPythonUntrustedTemplateSource, `
from flask import request
from jinja2 import Template
def preview():
    source = request.form["template"]
    template = Template(source)
    return template.render()
`);
    expect(flask).toHaveLength(1);
    expect(jinja).toHaveLength(1);
  });

  test("excludes fixed templates, context-only input, sandboxed builders, and unrendered builders", async () => {
    await expect(findings(runPythonUntrustedTemplateSource, `
from flask import render_template, request
from jinja2 import Template
from jinja2.sandbox import SandboxedEnvironment
def preview():
    source = request.form["template"]
    render_template("preview.html", content=source)
    Template(source)
    sandbox = SandboxedEnvironment()
    template = sandbox.from_string(source)
    return template.render()
`)).resolves.toEqual([]);
  });
});

describe("Python LLM-to-HTML rule", () => {
  test("tracks OpenAI Responses, chat completions, and Anthropic message text", async () => {
    const responses = await findings(runPythonLlmOutputDangerousHtml, `
from openai import OpenAI
from fastapi.responses import HTMLResponse
client = OpenAI()
def answer():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    return HTMLResponse(output)
`);
    const chat = await findings(runPythonLlmOutputDangerousHtml, `
from openai import AsyncOpenAI
from starlette.responses import Response
client = AsyncOpenAI()
async def answer():
    response = await client.chat.completions.create(model="gpt-5-mini", messages=[])
    return Response(response.choices[0].message.content, media_type="text/html")
`);
    const anthropic = await findings(runPythonLlmOutputDangerousHtml, `
from anthropic import Anthropic
from django.http import HttpResponse
client = Anthropic()
def answer():
    response = client.messages.create(model="claude", messages=[], max_tokens=10)
    return HttpResponse(response.content[0].text)
`);
    expect([...responses, ...chat, ...anthropic]).toHaveLength(3);
    expect([...responses, ...chat, ...anthropic].every((item) => item.confidence === "high")).toBe(true);
  });

  test("excludes JSON/plain responses, proven sanitizers, lookalikes, and flows beyond two aliases", async () => {
    await expect(findings(runPythonLlmOutputDangerousHtml, `
from bleach import clean
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from openai import OpenAI
client = OpenAI()
def safe():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    JSONResponse({"output": output})
    PlainTextResponse(output)
    return HTMLResponse(clean(output))
def bounded():
    response = client.responses.create(model="gpt-5-mini", input="hello")
    output = response.output_text
    alias = output
    return HTMLResponse(alias)
def HTMLResponse(value):
    return value
`)).resolves.toEqual([]);
  });
});
