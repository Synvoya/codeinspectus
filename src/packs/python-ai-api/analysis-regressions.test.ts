import { describe, expect, test } from "vitest";

import type { Finding } from "../../types.js";
import { parsePythonSource } from "../python/python.js";
import type { PythonProject, PythonProjectInput } from "../python/project.js";
import { runPythonCredentialedCorsAllOrigins } from "./credentialed-cors.js";
import { runPythonUntrustedFileResponse } from "./file-response.js";
import { runPythonUntrustedRedirect } from "./redirect.js";
import { runPythonUntrustedTemplateSource } from "./template-source.js";

function project(source: string): PythonProject {
  return {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/app.py", source)],
  };
}

function findings(
  runner: (input: PythonProjectInput) => Promise<Finding[]>,
  source: string,
): Promise<Finding[]> {
  return runner(project(source));
}

describe("Python shared-analysis regressions", () => {
  test("does not retain stale FastAPI receiver provenance after a completed branch", async () => {
    const result = await findings(runPythonCredentialedCorsAllOrigins, `
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
class Dummy:
    def add_middleware(self, *args, **kwargs):
        pass
app = FastAPI()
if use_dummy:
    app = Dummy()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
`);
    expect(result).toEqual([]);
  });

  test("excludes Depends and Annotated Security parameters but keeps ordinary route parameters tainted", async () => {
    const injected = await findings(runPythonUntrustedFileResponse, `
from pathlib import Path
from typing import Annotated
from fastapi import Depends, FastAPI, Security
from fastapi.responses import FileResponse
app = FastAPI()
BASE = Path("/srv/files")
def supplied_name():
    return "fixed.txt"
@app.get("/default")
def default_dependency(name: str = Depends(supplied_name)):
    return FileResponse(BASE / name)
@app.get("/annotated")
def annotated_dependency(name: Annotated[str, Security(supplied_name)]):
    return FileResponse(BASE / name)
`);
    const ordinary = await findings(runPythonUntrustedFileResponse, `
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
app = FastAPI()
BASE = Path("/srv/files")
@app.get("/files/{name}")
def download(name: str):
    return FileResponse(BASE / name)
`);
    expect({ injected: injected.length, ordinary: ordinary.length }).toEqual({
      injected: 0,
      ordinary: 1,
    });
  });

  test("requires proven Django request annotations outside decorated views", async () => {
    const unannotated = await findings(runPythonUntrustedRedirect, `
from django.http import HttpResponseRedirect
def helper(request):
    return HttpResponseRedirect(request.GET.get("next"))
`);
    const annotated = await findings(runPythonUntrustedRedirect, `
from django.http import HttpRequest, HttpResponseRedirect
def helper(request: HttpRequest):
    return HttpResponseRedirect(request.GET.get("next"))
`);
    expect({ unannotated: unannotated.length, annotated: annotated.length }).toEqual({
      unannotated: 0,
      annotated: 1,
    });
  });

  test("does not bind a later render to a template object that was overwritten", async () => {
    const result = await findings(runPythonUntrustedTemplateSource, `
from flask import request
from jinja2 import Template
def preview():
    template = Template(request.form["template"])
    template = Template("<p>{{ value }}</p>")
    return template.render(value="safe")
`);
    expect(result).toEqual([]);
  });
});
