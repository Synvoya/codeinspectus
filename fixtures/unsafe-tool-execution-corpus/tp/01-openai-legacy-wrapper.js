import { exec } from "child_process";

function runCommand(command) {
  return exec(command);
}

const response = await openai.createChatCompletion({ functions: [] });
const functionCall = response.data.choices[0].message.function_call;
const args = JSON.parse(functionCall.arguments);
await runCommand(args.command);
