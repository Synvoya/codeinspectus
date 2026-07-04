// TP arm B (model output -> LLM05): an OpenAI completion rendered as raw HTML inline. Expect: FIRE (LLM05).
import OpenAI from "openai";
const openai = new OpenAI();
export async function Answer({ prompt }: { prompt: string }) {
  const completion = await openai.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: prompt }] });
  return <div dangerouslySetInnerHTML={{ __html: completion.choices[0].message.content }} />;
}
