import { generateText } from "ai";
import { execaCommand } from "execa";

export async function run(prompt: string) {
  const { text } = await generateText({ model: "provider/model", prompt });
  await execaCommand(text);
}
