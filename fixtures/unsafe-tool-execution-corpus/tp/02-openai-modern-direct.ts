import * as childProcess from "node:child_process";

const response = await openai.chat.completions.create({ tools });
const toolCall = response.choices[0].message.tool_calls[0];
const rawArguments = toolCall.function.arguments;
const parsed = JSON.parse(rawArguments);

// childProcess.exec(parsed.command) in a comment must not create a duplicate.
childProcess.execSync(parsed.command);
