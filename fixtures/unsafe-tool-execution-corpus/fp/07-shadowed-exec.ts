import { exec } from "node:child_process";

const response = await openai.chat.completions.create({ tools });
const toolCall = response.choices[0].message.tool_calls[0];
const args = JSON.parse(toolCall.function.arguments);

function preview(exec: (value: string) => void) {
  exec(args.command);
}
