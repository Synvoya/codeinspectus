function exec(command: string) {
  return command;
}

const response = await openai.chat.completions.create({ tools });
const toolCall = response.choices[0].message.tool_calls[0];
const args = JSON.parse(toolCall.function.arguments);
exec(args.command);
