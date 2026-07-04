// FP plain-text render: model output and untrusted input rendered as TEXT (React escapes it), no __html.
// A single constant __html sink lets the prefilter pass; everything must stay SILENT. Expect: SILENT.
import OpenAI from "openai";
const openai = new OpenAI();
export async function Plain({ req, messages }: { req: any; messages: any[] }) {
  const completion = await openai.chat.completions.create({ model: "gpt-4o", messages });
  const model = completion.choices[0].message.content;
  return (
    <div>
      <div>{model}</div>
      <p>{req.query.bio}</p>
      <span dangerouslySetInnerHTML={{ __html: "<hr/>" }} />
    </div>
  );
}
