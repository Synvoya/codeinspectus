// FP (the exact CG-05 pattern): untrusted input in a USER-role message, static system
// prompt, NO tools. A message-role boundary is the documented mitigation.
// Expect: SILENT.
import OpenAI from "openai";

const openai = new OpenAI();

export async function POST(req: Request) {
  const { message } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: "You are a helpful assistant." },
      { role: "user", content: message },
    ],
  });
  return Response.json(completion);
}
