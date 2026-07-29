import { describe, expect, test } from "vitest";

import { parsePythonSource } from "../python/python.js";
import type { PythonProject } from "../python/project.js";
import { runPythonLangChainWebLoaderSsrf } from "./langchain-web-loader-ssrf.js";

function project(source: string): PythonProject {
  return {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/web.py", source)],
  };
}

describe("Python LangChain web-loader SSRF rule", () => {
  test("flags proven FastAPI, Flask, and Django request URLs that a LangChain loader fetches", async () => {
    const findings = await runPythonLangChainWebLoaderSsrf(project(`
from fastapi import FastAPI
from flask import request
from django.http import HttpRequest
from langchain_community.document_loaders import WebBaseLoader
from langchain.document_loaders import WebBaseLoader as LegacyWebBaseLoader

app = FastAPI()

@app.post("/ingest")
def ingest(request: IngestRequest):
    loader = WebBaseLoader(request.url)
    return loader.load()

def flask_ingest():
    return WebBaseLoader(request.args.get("url")).load()

def django_ingest(request: HttpRequest):
    loader = LegacyWebBaseLoader(web_paths=request.GET["url"])
    return loader.lazy_load()
`));

    expect(findings).toHaveLength(3);
    expect(findings.every((finding) =>
      finding.rule_id === "ci-python-langchain-web-loader-ssrf" &&
      finding.severity === "high" &&
      finding.confidence === "high" &&
      finding.cwe.join(",") === "CWE-918"
    )).toBe(true);
  });

  test("supports module-qualified imports and a two-assignment request alias", async () => {
    const findings = await runPythonLangChainWebLoaderSsrf(project(`
import langchain_community.document_loaders as loaders
from fastapi import FastAPI

app = FastAPI()

@app.post("/ingest")
def ingest(payload: IngestRequest):
    first = payload.url
    target = first
    loader = loaders.WebBaseLoader(target)
    return loader.load_and_split()
`));

    expect(findings).toHaveLength(1);
  });

  test("stays silent for fixed destinations, partial paths, unused loaders, spreads, lookalikes, and overwritten receivers", async () => {
    const findings = await runPythonLangChainWebLoaderSsrf(project(`
from fastapi import FastAPI
from langchain_community.document_loaders import WebBaseLoader

app = FastAPI()

@app.get("/profile/{name}")
def profile(name: str, payload: IngestRequest, options):
    WebBaseLoader("https://docs.example/security").load()
    WebBaseLoader("https://api.example/users/" + name).load()
    unused = WebBaseLoader(payload.url)
    spread = WebBaseLoader(payload.url, **options)
    spread.load()
    overwritten = WebBaseLoader(payload.url)
    overwritten = object()
    overwritten.load()

class WebBaseLoader:
    def __init__(self, value):
        pass
    def load(self):
        return []

WebBaseLoader(payload.url).load()
`));

    expect(findings).toEqual([]);
  });

  test("fails closed for ordinary helper parameters, conditional imports, and malformed source", async () => {
    const helper = await runPythonLangChainWebLoaderSsrf(project(`
from langchain_community.document_loaders import WebBaseLoader

def offline_job(url: str):
    loader = WebBaseLoader(url)
    return loader.load()
`));
    const conditional = await runPythonLangChainWebLoaderSsrf(project(`
if enabled:
    from langchain_community.document_loaders import WebBaseLoader

@app.post("/ingest")
def ingest(request: IngestRequest):
    return WebBaseLoader(request.url).load()
`));
    const malformed = await runPythonLangChainWebLoaderSsrf(project(`
from langchain_community.document_loaders import WebBaseLoader
WebBaseLoader(request.url).load(
`));

    expect(helper).toEqual([]);
    expect(conditional).toEqual([]);
    expect(malformed).toEqual([]);
  });
});
