// TP arm B split: a model completion pulled to a var, then rendered as raw HTML. Expect: FIRE (taint, LLM05).
import OpenAI from "openai";
const openai = new OpenAI();
export async function Summary({ messages }: { messages: any[] }) {
  const completion = await openai.chat.completions.create({ model: "gpt-4o", messages });
  const html = completion.choices[0].message.content;
  return <article dangerouslySetInnerHTML={{ __html: html }} />;
}
