import { execSync } from "node:child_process";

const response = await openai.chat.completions.create({ tools });
const toolCall = response.choices[0].message.tool_calls[0];
const args = JSON.parse(toolCall.function.arguments);
console.log(args.command);
execSync("git status");
