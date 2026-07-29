// FIXTURE — planted unsafe agent/tool execution. A model-produced function argument
// reaches a Node shell string through one local wrapper with no approval or allowlist.
import { exec } from "node:child_process";
import OpenAI from "openai";

const openai = new OpenAI();

function runToolCommand(command: string) {
  return exec(command);
}

export async function runAgent() {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: "Inspect this repository" }],
    tools: [{ type: "function", function: { name: "run_command", parameters: {} } }],
  });
  const toolCall = completion.choices[0].message.tool_calls[0];
  const args = JSON.parse(toolCall.function.arguments);
  return runToolCommand(args.command);
}
