import { describe, expect, test } from "vitest";

import { parsePythonSource } from "../python/python.js";
import type { PythonProject } from "../python/project.js";
import { runPythonUnsafeToolExecution } from "./unsafe-tool-execution.js";

function project(source: string): PythonProject {
  return {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/agent.py", source)],
  };
}

describe("Python model-tool shell execution", () => {
  test("flags direct and one-wrapper OpenAI/Anthropic tool argument flows", async () => {
    const direct = await runPythonUnsafeToolExecution(project(`
import json
import os
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
tool_call = response.choices[0].message.tool_calls[0]
args = json.loads(tool_call.function.arguments)
os.system(args["command"])
`));
    const wrapper = await runPythonUnsafeToolExecution(project(`
import subprocess
from anthropic import Anthropic

def execute_tool(name, arguments):
    if name == "run_bash":
        return subprocess.run(arguments["command"], shell=True, capture_output=True)

client = Anthropic()
response = client.messages.create(model="claude-sonnet-4-5", messages=[], tools=TOOLS)
tool_calls = [item for item in response.content if item.type == "tool_use"]
for call in tool_calls:
    execute_tool(call.name, call.input)
`));

    for (const finding of [...direct, ...wrapper]) {
      expect(finding).toMatchObject({
        rule_id: "ci-python-llm-tool-argument-command-execution",
        severity: "high",
        confidence: "medium",
        cwe: ["CWE-78", "CWE-1426"],
        owasp_llm: ["LLM05:2025", "LLM06:2025"],
      });
    }
    expect(direct).toHaveLength(1);
    expect(wrapper).toHaveLength(1);
  });

  test("supports imported shell aliases and rejects approval/allowlist guarded flows", async () => {
    const unsafe = await runPythonUnsafeToolExecution(project(`
import json
from subprocess import run as shell_run
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
call = response.choices[0].message.tool_calls[0]
arguments = json.loads(call.function.arguments)
shell_run(arguments["command"], shell=True)
`));
    const guarded = await runPythonUnsafeToolExecution(project(`
import json
import subprocess
from openai import OpenAI

def execute():
    client = OpenAI()
    response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
    call = response.choices[0].message.tool_calls[0]
    arguments = json.loads(call.function.arguments)
    approved = confirm_command(arguments["command"])
    if not approved:
        return
    subprocess.run(arguments["command"], shell=True)
`));

    expect(unsafe).toHaveLength(1);
    expect(guarded).toEqual([]);
  });

  test("stays silent for validation, shell=False, static commands, lookalikes, and non-model data", async () => {
    const findings = await runPythonUnsafeToolExecution(project(`
import json
import subprocess
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
call = response.choices[0].message.tool_calls[0]
safe_args = CommandArgs.model_validate(json.loads(call.function.arguments))
subprocess.run(["git", safe_args.action], shell=False)
subprocess.run("git status", shell=True)

class subprocess:
    @staticmethod
    def run(value, shell=False):
        return value

subprocess.run(request.command, shell=True)
`));
    expect(findings).toEqual([]);
  });

  test("fails closed for generic dynamic dispatch, deeper/cross-module flow, spreads, and invalid syntax", async () => {
    const dynamic = await runPythonUnsafeToolExecution(project(`
import json
import subprocess
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
tool_call = response.choices[0].message.tool_calls[0]
args = json.loads(tool_call.function.arguments)
TOOLS_BY_NAME[tool_call.function.name](**args)
`));
    const spread = await runPythonUnsafeToolExecution(project(`
import json
import subprocess
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
tool_call = response.choices[0].message.tool_calls[0]
args = json.loads(tool_call.function.arguments)
subprocess.run(args["command"], **options)
`));
    const malformed = await runPythonUnsafeToolExecution(project(`
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(
`));
    expect(dynamic).toEqual([]);
    expect(spread).toEqual([]);
    expect(malformed).toEqual([]);
  });
});
