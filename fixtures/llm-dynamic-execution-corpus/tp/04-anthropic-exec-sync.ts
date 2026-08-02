import { execSync as shell } from "child_process";
import Anthropic from "@anthropic-ai/sdk";
const anthropic = new Anthropic();

export async function run(prompt: string) {
  const response = await anthropic.messages.create({ model: "claude-sonnet-4-5", messages: [] });
  const command = response.content[0].text;
  shell(command);
}
