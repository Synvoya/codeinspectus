import { describe, expect, test } from "vitest";

import {
  isPythonDependencyManifest,
  normalizePythonPackageName,
  parsePythonDependencyManifest,
} from "./dependencies.js";

describe("Python dependency manifest parsing", () => {
  test("normalizes PEP 503 package names and recognizes bounded manifest names", () => {
    expect(normalizePythonPackageName("LangChain_Community")).toBe("langchain-community");
    expect(isPythonDependencyManifest("requirements-prod.txt")).toBe(true);
    expect(isPythonDependencyManifest("requirements.in")).toBe(true);
    expect(isPythonDependencyManifest("constraints.txt")).toBe(false);
  });

  test("extracts exact requirement names without treating URLs and directives as packages", () => {
    const parsed = parsePythonDependencyManifest("requirements.txt", `
fastapi[standard]>=0.110  # API server
langchain_community==0.3.0
openai @ https://example.invalid/openai.whl
-r common.txt
git+https://example.invalid/flask.git
not-fastapi==1.0
`);

    expect([...parsed.names].sort()).toEqual([
      "fastapi", "langchain-community", "not-fastapi", "openai",
    ]);
  });

  test("extracts PEP 621 and Poetry dependencies only from dependency sections", () => {
    const parsed = parsePythonDependencyManifest("pyproject.toml", `
[project]
name = "fastapi-is-not-a-dependency"
dependencies = [
  "FastAPI>=0.110", # exact dependency
  'Anthropic~=0.40',
]
[project.optional-dependencies]
ai = ["langchain-experimental>=0.3"]
[tool.poetry.dependencies]
python = "^3.11"
Django = "^5"
[tool.poetry.group.dev.dependencies]
Flask = "^3"
[tool.unrelated]
starlette = "not dependency evidence"
`);

    expect(parsed.valid).toBe(true);
    expect([...parsed.names].sort()).toEqual([
      "anthropic", "django", "fastapi", "flask", "langchain-experimental",
    ]);
  });

  test("extracts Pipfile and setup.cfg dependency declarations", () => {
    const pipfile = parsePythonDependencyManifest("Pipfile", `
[packages]
Flask = "*"
[dev-packages]
pytest = "*"
[scripts]
django = "python manage.py"
`);
    const setup = parsePythonDependencyManifest("setup.cfg", `
[metadata]
name = sample
[options]
install_requires =
    starlette>=0.40
    openai>=1.0
python_requires = >=3.11
`);

    expect([...pipfile.names].sort()).toEqual(["flask", "pytest"]);
    expect([...setup.names].sort()).toEqual(["openai", "starlette"]);
  });

  test("accepts bounded inline-table dependency values", () => {
    const poetry = parsePythonDependencyManifest("pyproject.toml", `
[tool.poetry.dependencies]
FastAPI = { version = "^0.116", optional = true }
`);
    const pipfile = parsePythonDependencyManifest("Pipfile", `
[packages]
OpenAI = { version = ">=1", extras = ["aiohttp"] }
`);

    expect(poetry).toEqual({ names: new Set(["fastapi"]), valid: true });
    expect(pipfile).toEqual({ names: new Set(["openai"]), valid: true });
  });

  test.each([
    ["empty Poetry value", "pyproject.toml", "[tool.poetry.dependencies]\nFastAPI =\n"],
    ["malformed Poetry value", "pyproject.toml", "[tool.poetry.dependencies]\nFastAPI = { version = \"^1\"\n"],
    ["empty Pipfile value", "Pipfile", "[packages]\nOpenAI =\n"],
    ["malformed Pipfile value", "Pipfile", "[packages]\nOpenAI = \"unterminated\n"],
    ["empty unrelated value", "pyproject.toml", "[project]\ndependencies=[\"fastapi\"]\nbroken =\n"],
    ["trailing array tokens", "pyproject.toml", "[project]\ndependencies=[\"fastapi\"] trailing\n"],
    ["non-string PEP 621 item", "pyproject.toml", "[project]\ndependencies=[\"fastapi\", nonsense]\n"],
    ["inline table without assignment", "pyproject.toml", "[tool.poetry.dependencies]\nFastAPI={ broken }\n"],
    ["duplicate dependency keys", "pyproject.toml", "[tool.poetry.dependencies]\nFastAPI=\"*\"\nFastAPI=\"^1\"\n"],
    ["PEP 621 table item", "pyproject.toml", "[project]\ndependencies=[{note=\"fastapi\"}]\n"],
  ])("marks %s invalid without retaining a dependency", (_label, baseName, content) => {
    const parsed = parsePythonDependencyManifest(baseName, content);

    expect(parsed.valid).toBe(false);
    expect(parsed.names).toEqual(new Set());
  });

  test("discards earlier dependency names when later TOML is malformed", () => {
    const parsed = parsePythonDependencyManifest("pyproject.toml", `
[project]
dependencies = ["fastapi"]
[broken
`);

    expect(parsed.valid).toBe(false);
    expect(parsed.names).toEqual(new Set());
  });

  test("marks a targeted unterminated dependency array invalid", () => {
    const parsed = parsePythonDependencyManifest("pyproject.toml", `
[project]
dependencies = ["fastapi"
`);

    expect(parsed.valid).toBe(false);
    expect(parsed.names).toEqual(new Set());
  });
});
