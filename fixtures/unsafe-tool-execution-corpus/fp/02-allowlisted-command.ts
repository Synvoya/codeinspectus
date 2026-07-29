const { execSync } = require("child_process");

const response = await openai.responses.create({ tools });
const toolCall = response.output.find((item) => item.type === "function_call");
const args = JSON.parse(toolCall.arguments);
if (!allowedCommands.has(args.command)) throw new Error("command denied");
execSync(args.command);
