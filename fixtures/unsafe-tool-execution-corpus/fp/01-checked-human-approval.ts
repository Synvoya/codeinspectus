import { exec } from "node:child_process";

export async function runApprovedTool() {
  const response = await openai.chat.completions.create({ tools });
  const toolCall = response.choices[0].message.tool_calls[0];
  const args = JSON.parse(toolCall.function.arguments);
  const approved = await confirmCommand(args.command);
  if (!approved) return;
  exec(args.command);
}
