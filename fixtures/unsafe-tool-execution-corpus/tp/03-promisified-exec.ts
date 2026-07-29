import { exec as rawExec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(rawExec);
const response = await anthropic.messages.create({ tools, messages: [] });
const toolUse = response.content.find((block) => block.type === "tool_use");
const input = toolUse.input;

await execAsync(input.command);
