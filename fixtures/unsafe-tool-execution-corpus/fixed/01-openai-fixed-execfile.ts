import { execFile } from "node:child_process";
import { z } from "zod";

const Args = z.object({ target: z.enum(["status", "diff"]) }).strict();
const response = await openai.chat.completions.create({ tools });
const toolCall = response.choices[0].message.tool_calls[0];
const args = Args.parse(JSON.parse(toolCall.function.arguments));
const argv = args.target === "status" ? ["status", "--short"] : ["diff", "--stat"];
await execFile("git", argv);
