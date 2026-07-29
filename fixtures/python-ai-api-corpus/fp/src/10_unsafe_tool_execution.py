import json
import subprocess

from openai import OpenAI


def run_agent():
    client = OpenAI()
    response = client.chat.completions.create(model="gpt-4.1", messages=[], tools=TOOLS)
    tool_call = response.choices[0].message.tool_calls[0]
    arguments = json.loads(tool_call.function.arguments)
    approved = confirm_command(arguments["command"])
    if not approved:
        return None
    return subprocess.run(arguments["command"], shell=True, capture_output=True)
