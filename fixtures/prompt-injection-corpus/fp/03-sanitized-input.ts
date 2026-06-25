// FP: untrusted input is validated/sanitized (zod) before it reaches the system prompt.
// Expect: SILENT.
import OpenAI from "openai";
import { z } from "zod";

const openai = new OpenAI();
const schema = z.object({ topic: z.string().max(80) });

export async function POST(req: Request) {
  const body = await req.json();
  const { topic } = schema.parse(body); // sanitized — derived var is not tainted
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "system", content: `Write a short note about ${topic}.` }],
  });
  return Response.json(completion);
}
