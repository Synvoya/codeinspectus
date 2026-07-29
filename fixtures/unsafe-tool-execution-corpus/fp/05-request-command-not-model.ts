import { exec } from "node:child_process";

await openai.chat.completions.create({ messages: [] });
const command = request.body.command;
exec(command);
