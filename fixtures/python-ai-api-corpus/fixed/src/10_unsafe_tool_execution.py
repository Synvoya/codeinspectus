import json
import subprocess

from openai import OpenAI


def run_agent():
    client = OpenAI()
    response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
    tool_call = response.choices[0].message.tool_calls[0]
    arguments = CommandArgs.model_validate(json.loads(tool_call.function.arguments))
    command = ["git", "status", "--short"] if arguments.action == "status" else ["git", "diff", "--stat"]
    return subprocess.run(command, shell=False, capture_output=True)
