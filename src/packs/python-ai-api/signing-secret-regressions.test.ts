import { describe, expect, test } from "vitest";

import { parsePythonSource } from "../python/python.js";
import type { PythonProject } from "../python/project.js";
import { runPythonHardcodedSigningSecret } from "./hardcoded-signing-secret.js";

function findings(source: string) {
  const project: PythonProject = {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/config.py", source)],
  };
  return runPythonHardcodedSigningSecret(project);
}

const prelude = `
import os
from flask import Flask
app = Flask(__name__)
`;

describe("Python signing-secret overwrite regressions", () => {
  test("respects straight-line app config and secret_key overwrites", async () => {
    const result = await findings(`${prelude}
app.config["SECRET_KEY"] = "temporary-config-secret"
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.secret_key = "temporary-member-secret"
app.secret_key = os.environ["SECRET_KEY"]
`);
    expect(result).toEqual([]);
  });

  test("respects config update and from_mapping overwrites", async () => {
    const result = await findings(`${prelude}
app.config.update(SECRET_KEY="temporary-keyword-secret")
app.config.update(SECRET_KEY=os.environ["SECRET_KEY"])
app.config.from_mapping({"SECRET_KEY_FALLBACKS": ["temporary-fallback"]})
app.config.from_mapping({"SECRET_KEY_FALLBACKS": make_fallbacks()})
`);
    expect(result).toEqual([]);
  });

  test("flags the final literal after an earlier dynamic value", async () => {
    const result = await findings(`${prelude}
app.config.update({"SECRET_KEY": os.environ["SECRET_KEY"]})
app.config["SECRET_KEY"] = "final-literal-secret"
`);
    expect(result).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain("final-literal-secret");
  });

  test("does not claim an active literal when branch writes make the final value ambiguous", async () => {
    const result = await findings(`${prelude}
app.config["SECRET_KEY"] = "conditional-literal-secret"
if use_runtime_secret:
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
`);
    expect(result).toEqual([]);
  });
});
