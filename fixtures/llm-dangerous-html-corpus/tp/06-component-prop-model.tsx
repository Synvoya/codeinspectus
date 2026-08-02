// TP component prop: model output crosses one local JSX component prop into __html. Expect: FIRE (LLM05).
import OpenAI from "openai";
const openai = new OpenAI();

function Preview({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export async function Page({ prompt }: { prompt: string }) {
  const answer = await openai.responses.create({ model: "gpt-5", input: prompt });
  return <Preview html={answer.output_text} />;
}
