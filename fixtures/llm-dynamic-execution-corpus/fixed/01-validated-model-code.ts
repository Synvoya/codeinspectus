import OpenAI from "openai";
const openai = new OpenAI();

declare function validateModelCode(value: string): string;
export async function run(prompt: string) {
  const response = await openai.responses.create({ model: "gpt-5", input: prompt });
  const validated = validateModelCode(response.output_text);
  return eval(validated);
}
