// FP sanitized: BOTH an untrusted source AND a model source, each wrapped in DOMPurify.sanitize.
// A sanitized sink is safe even if the inner source is tainted. Expect: SILENT.
import DOMPurify from "dompurify";
import OpenAI from "openai";
const openai = new OpenAI();
export async function Safe({ req, messages }: { req: any; messages: any[] }) {
  const completion = await openai.chat.completions.create({ model: "gpt-4o", messages });
  const model = completion.choices[0].message.content;
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(req.query.bio) }} />
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(model) }} />
    </div>
  );
}
