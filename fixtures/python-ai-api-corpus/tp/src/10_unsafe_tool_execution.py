import json
import subprocess

from openai import OpenAI


def execute_tool(name, arguments):
    if name == "run_command":
        return subprocess.run(arguments["command"], shell=True, capture_output=True)


def run_agent():
    client = OpenAI()
    response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
    tool_calls = response.choices[0].message.tool_calls
    for tool_call in tool_calls:
        execute_tool(tool_call.function.name, json.loads(tool_call.function.arguments))
