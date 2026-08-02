import OpenAI from "openai";
const openai = new OpenAI();

const tools = { status: () => "ok", version: () => "1" } as const;
export async function run(prompt: string) {
  const response = await openai.responses.create({ model: "gpt-5", input: prompt });
  const requested = response.output_text;
  if (!(requested in tools)) throw new Error("unsupported tool");
  return tools[requested as keyof typeof tools]();
}
