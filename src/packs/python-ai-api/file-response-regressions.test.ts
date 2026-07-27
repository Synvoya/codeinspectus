import { describe, expect, test } from "vitest";

import type { Finding } from "../../types.js";
import { parsePythonSource } from "../python/python.js";
import type { PythonProject, PythonProjectInput } from "../python/project.js";
import { runPythonUntrustedFileResponse } from "./file-response.js";

function project(source: string): PythonProject {
  return {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/downloads.py", source)],
  };
}

function findings(source: string): Promise<Finding[]> {
  return runPythonUntrustedFileResponse(project(source) satisfies PythonProjectInput);
}

describe("Python file-response guard regressions", () => {
  test("does not treat a bare HTTPException constructor as terminating", async () => {
    const bare = await findings(`
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    candidate = (BASE / request.args.get("name")).resolve()
    if not candidate.is_relative_to(BASE):
        HTTPException(status_code=404)
    return FileResponse(candidate)
`);
    const raised = await findings(`
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    candidate = (BASE / request.args.get("name")).resolve()
    if not candidate.is_relative_to(BASE):
        raise HTTPException(status_code=404)
    return FileResponse(candidate)
`);

    expect({ bare: bare.length, raised: raised.length }).toEqual({ bare: 1, raised: 0 });
  });

  test("does not accept a string token that merely spells is_relative_to", async () => {
    const result = await findings(`
from pathlib import Path
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    candidate = (BASE / request.args.get("name")).resolve()
    if candidate and "is_relative_to":
        return FileResponse(candidate)
`);

    expect(result).toHaveLength(1);
  });

  test("binds a containment guard to the value passed to FileResponse", async () => {
    const unrelated = await findings(`
from pathlib import Path
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    candidate = (BASE / request.args.get("name")).resolve()
    trusted = BASE.resolve()
    if trusted.is_relative_to(BASE) and candidate:
        return FileResponse(candidate)
`);
    const sameValue = await findings(`
from pathlib import Path
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    candidate = (BASE / request.args.get("name")).resolve()
    if candidate.is_relative_to(BASE):
    return FileResponse(candidate)
`);
    const earlierOperand = await findings(`
from pathlib import Path
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    candidate = (BASE / request.args.get("name")).resolve()
    trusted = BASE.resolve()
    if candidate == trusted.is_relative_to(BASE):
        return FileResponse(candidate)
`);

    expect({ unrelated: unrelated.length, sameValue: sameValue.length, earlierOperand: earlierOperand.length }).toEqual({
      unrelated: 1,
      sameValue: 0,
      earlierOperand: 1,
    });
  });

  test("requires canonicalization before an is_relative_to containment check", async () => {
    const lexical = await findings(`
from pathlib import Path
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    candidate = BASE / request.args.get("name")
    if candidate.is_relative_to(BASE):
        return FileResponse(candidate)
`);
    const canonical = await findings(`
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    base = BASE.resolve()
    candidate = (base / request.args.get("name")).resolve()
    if not candidate.is_relative_to(base):
        raise HTTPException(status_code=404)
    return FileResponse(candidate)
`);

    expect({ lexical: lexical.length, canonical: canonical.length }).toEqual({
      lexical: 1,
      canonical: 0,
    });
  });

  test("does not accept an arbitrary lookalike resolve method as path canonicalization", async () => {
    const local = await findings(`
from pathlib import Path
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

class UnsafePath:
    def __init__(self, value):
        self.value = value
    def resolve(self):
        return self
    def is_relative_to(self, base):
        return True

def download():
    candidate = UnsafePath(request.args.get("name")).resolve()
    if candidate.is_relative_to(BASE):
        return FileResponse(candidate)
`);
    const imported = await findings(`
from badpaths import UnsafePath
from fastapi import HTTPException
from fastapi.responses import FileResponse
from flask import request

def download():
    base = UnsafePath("/srv/files").resolve()
    candidate = (base / request.args.get("name")).resolve()
    if not candidate.is_relative_to(base):
        raise HTTPException(status_code=404)
    return FileResponse(candidate)
`);

    expect({ local: local.length, imported: imported.length }).toEqual({ local: 1, imported: 1 });
  });

  test("requires a server-controlled containment base", async () => {
    const result = await findings(`
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import FileResponse
from flask import request

def download():
    base = Path(request.args.get("base")).resolve()
    candidate = (base / request.args.get("name")).resolve()
    if not candidate.is_relative_to(base):
        raise HTTPException(status_code=404)
    return FileResponse(candidate)
`);

    expect(result).toHaveLength(1);
  });

  test("requires canonicalization before an os.path.commonpath containment check", async () => {
    const lexical = await findings(`
import os
from fastapi import HTTPException
from fastapi.responses import FileResponse
from flask import request

BASE = "/srv/files"

def download():
    candidate = os.path.join(BASE, request.args.get("name"))
    if os.path.commonpath([BASE, candidate]) != BASE:
        raise HTTPException(status_code=404)
    return FileResponse(candidate)
`);
    const canonical = await findings(`
import os
from fastapi import HTTPException
from fastapi.responses import FileResponse
from flask import request

BASE = "/srv/files"

def download():
    base = os.path.realpath(BASE)
    candidate = os.path.realpath(os.path.join(base, request.args.get("name")))
    if os.path.commonpath([base, candidate]) != base:
        raise HTTPException(status_code=404)
    return FileResponse(candidate)
`);

    expect({ lexical: lexical.length, canonical: canonical.length }).toEqual({
      lexical: 1,
      canonical: 0,
    });
  });
});

describe("Python file-response sanitizer regressions", () => {
  test("does not trust POSIX-only basename handling for a cross-platform path", async () => {
    const posixBasename = await findings(`
import posixpath
from pathlib import Path
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    return FileResponse(BASE / posixpath.basename(request.args.get("name")))
`);
    const purePosixPath = await findings(`
from pathlib import Path, PurePosixPath
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def download():
    return FileResponse(BASE / PurePosixPath(request.args.get("name")).name)
`);

    expect({ posixBasename: posixBasename.length, purePosixPath: purePosixPath.length }).toEqual({
      posixBasename: 1,
      purePosixPath: 1,
    });
  });

  test("keeps runtime-native and separator-agnostic basename controls silent", async () => {
    const result = await findings(`
import ntpath
import os
from pathlib import Path, PurePath
from fastapi.responses import FileResponse
from flask import request

BASE = Path("/srv/files")

def os_native():
    return FileResponse(BASE / os.path.basename(request.args.get("name")))

def both_separators():
    return FileResponse(BASE / ntpath.basename(request.args.get("name")))

def runtime_path_flavour():
    return FileResponse(BASE / PurePath(request.args.get("name")).name)
`);

    expect(result).toEqual([]);
  });

  test("requires a server-controlled safe_join base", async () => {
    const controlledBase = await findings(`
from flask import request, send_file
from werkzeug.security import safe_join

def download():
    return send_file(safe_join(
        request.args.get("base"),
        request.args.get("name"),
    ))
`);
    const fixedBase = await findings(`
from flask import request, send_file
from werkzeug.security import safe_join

BASE = "/srv/files"

def download():
    return send_file(safe_join(BASE, request.args.get("name")))
`);

    expect({ controlledBase: controlledBase.length, fixedBase: fixedBase.length }).toEqual({
      controlledBase: 1,
      fixedBase: 0,
    });
  });
});
