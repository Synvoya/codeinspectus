import { exec } from "node:child_process";

const response = await openai.chat.completions.create({ tools });
const toolCall = response.choices[0].message.tool_calls[0];
const safeArgs = CommandSchema.parse(JSON.parse(toolCall.function.arguments));
exec(safeArgs.command);
