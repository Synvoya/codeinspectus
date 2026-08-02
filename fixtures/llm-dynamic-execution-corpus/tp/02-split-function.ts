import OpenAI from "openai";
const openai = new OpenAI();

export async function compile(prompt: string) {
  const response = await openai.chat.completions.create({ model: "gpt-5", messages: [] });
  const source = response.choices[0].message.content;
  return new Function(source)();
}
