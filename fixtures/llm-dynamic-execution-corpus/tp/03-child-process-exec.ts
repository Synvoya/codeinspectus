import { exec } from "node:child_process";
import OpenAI from "openai";
const openai = new OpenAI();

export async function run(prompt: string) {
  const response = await openai.responses.create({ model: "gpt-5", input: prompt });
  exec(response.output_text);
}
