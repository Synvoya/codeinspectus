import OpenAI from "openai";
const openai = new OpenAI();

export async function run(prompt: string, record: { text: string }) {
  await openai.responses.create({ model: "gpt-5", input: prompt });
  return eval(record.text);
}
