import { describe, expect, test } from "vitest";

import { parsePythonSource } from "../python/python.js";
import type { PythonProject } from "../python/project.js";
import { runPythonUntrustedRedirect } from "./redirect.js";

function findings(source: string) {
  const project: PythonProject = {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/redirects.py", source)],
  };
  return runPythonUntrustedRedirect(project);
}

describe("Python redirect guard regressions", () => {
  test("requires HTTPException to be raised", async () => {
    const bare = await findings(`
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
app = FastAPI()
@app.get("/go")
def go(next_url: str):
    parsed = urlsplit(next_url)
    if parsed.scheme or parsed.netloc:
        HTTPException(status_code=400)
    return RedirectResponse(next_url)
`);
    const raised = await findings(`
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
app = FastAPI()
@app.get("/go")
def go(next_url: str):
    parsed = urlsplit(next_url)
    if parsed.scheme or parsed.netloc or "\\\\" in next_url:
        raise HTTPException(status_code=400)
    return RedirectResponse(next_url)
`);
    expect({ bare: bare.length, raised: raised.length }).toEqual({ bare: 1, raised: 0 });
  });

  test("keeps completed-branch request assignments in the reaching set", async () => {
    const result = await findings(`
from flask import Flask, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = "/"
    if True:
        target = request.args.get("next")
    return redirect(target)
`);
    expect(result).toHaveLength(1);
  });

  test("binds scheme and host proofs to the parsed redirect target", async () => {
    const result = await findings(`
from urllib.parse import urlsplit
from flask import Flask, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    trusted = urlsplit("https://login.example.com")
    if target and trusted.scheme == "https" and trusted.netloc == "login.example.com":
        return redirect(target)
`);
    expect(result).toHaveLength(1);
  });

  test("does not accept an unrelated netloc check as a safe fallback", async () => {
    const result = await findings(`
from urllib.parse import urlsplit
from flask import Flask, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    trusted = urlsplit("/local")
    if target and trusted.netloc:
        target = "/"
    return redirect(target)
`);
    expect(result).toHaveLength(1);
  });

  test("requires both empty scheme and netloc for a relative redirect", async () => {
    const netlocOnly = await findings(`
from urllib.parse import urlsplit
from flask import Flask, abort, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    if urlsplit(target).netloc:
        abort(400)
    return redirect(target)
`);
    const complete = await findings(`
from urllib.parse import urlsplit
from flask import Flask, abort, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or "\\\\" in target:
        abort(400)
    return redirect(target)
`);
    expect({ netlocOnly: netlocOnly.length, complete: complete.length }).toEqual({ netlocOnly: 1, complete: 0 });
  });

  test("does not confuse negated or AND-combined parser properties for rejection", async () => {
    const negatedScheme = await findings(`
from urllib.parse import urlsplit
from flask import Flask, abort, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if not parsed.scheme or parsed.netloc or "\\\\" in target:
        abort(400)
    return redirect(target)
`);
    const combined = await findings(`
from urllib.parse import urlsplit
from flask import Flask, abort, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc or "\\\\" in target:
        abort(400)
    return redirect(target)
`);
    expect({ negatedScheme: negatedScheme.length, combined: combined.length }).toEqual({
      negatedScheme: 1,
      combined: 1,
    });
  });

  test("rejects browser-normalized backslashes before accepting relative redirects", async () => {
    const bypass = await findings(`
from urllib.parse import urlsplit
from flask import Flask, abort, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        abort(400)
    return redirect(target)
`);
    const slashRelative = await findings(`
from urllib.parse import urlsplit
from flask import Flask, abort, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or "\\\\" in target or not target.startswith("/"):
        abort(400)
    return redirect(target)
`);
    expect({ bypass: bypass.length, slashRelative: slashRelative.length }).toEqual({
      bypass: 1,
      slashRelative: 0,
    });
  });

  test("requires port policy with hostname allowlists but accepts exact netloc", async () => {
    const hostnameOnly = await findings(`
from urllib.parse import urlsplit
from flask import Flask, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme == "https" and parsed.hostname == "login.example.com":
        return redirect(target)
`);
    const withPort = await findings(`
from urllib.parse import urlsplit
from flask import Flask, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme == "https" and parsed.hostname == "login.example.com" and parsed.port == 443:
        return redirect(target)
`);
    const netloc = await findings(`
from urllib.parse import urlsplit
from flask import Flask, redirect, request
app = Flask(__name__)
@app.get("/go")
def go():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if parsed.scheme == "https" and parsed.netloc == "login.example.com":
        return redirect(target)
`);
    expect({ hostnameOnly: hostnameOnly.length, withPort: withPort.length, netloc: netloc.length }).toEqual({
      hostnameOnly: 1,
      withPort: 0,
      netloc: 0,
    });
  });

  test("requires a static HTTPS Django helper policy", async () => {
    const dynamic = await findings(`
from urllib.parse import urlsplit
from django.http import HttpRequest, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
def go(request: HttpRequest):
    target = request.GET.get("next")
    attacker_host = urlsplit(target).netloc
    if url_has_allowed_host_and_scheme(target, allowed_hosts={attacker_host}, require_https=True):
        return HttpResponseRedirect(target)
`);
    const strict = await findings(`
from django.http import HttpRequest, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
def go(request: HttpRequest):
    target = request.GET.get("next")
    if url_has_allowed_host_and_scheme(target, allowed_hosts={"login.example.com"}, require_https=True):
        return HttpResponseRedirect(target)
`);
    const unrelatedNegation = await findings(`
from django.http import HttpRequest, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
def go(request: HttpRequest):
    target = request.GET.get("next")
    if not feature_enabled and url_has_allowed_host_and_scheme(
        target,
        allowed_hosts={"login.example.com"},
        require_https=True,
    ):
        raise ValueError("disabled")
    return HttpResponseRedirect(target)
`);
    const falseComparison = await findings(`
from django.http import HttpRequest, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
def go(request: HttpRequest):
    target = request.GET.get("next")
    if url_has_allowed_host_and_scheme(
        target,
        allowed_hosts={"login.example.com"},
        require_https=True,
    ) == False:
        return HttpResponseRedirect(target)
`);
    expect({
      dynamic: dynamic.length,
      strict: strict.length,
      unrelatedNegation: unrelatedNegation.length,
      falseComparison: falseComparison.length,
    }).toEqual({ dynamic: 1, strict: 0, unrelatedNegation: 1, falseComparison: 1 });
  });
});
