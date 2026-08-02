// FP component prop: model output is sanitized before it crosses the prop boundary. Expect: SILENT.
import DOMPurify from "dompurify";
import OpenAI from "openai";
const openai = new OpenAI();

function Preview({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export async function Page({ prompt }: { prompt: string }) {
  const answer = await openai.responses.create({ model: "gpt-5", input: prompt });
  return <Preview html={DOMPurify.sanitize(answer.output_text)} />;
}
