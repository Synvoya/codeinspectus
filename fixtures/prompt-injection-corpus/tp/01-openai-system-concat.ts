// TP: untrusted req.body value concatenated into the SYSTEM prompt (no role boundary).
// Expect: FIRE (medium, LLM01).
import OpenAI from "openai";

const openai = new OpenAI();

export async function POST(req: Request) {
  const body = await req.json();
  const persona = body.persona; // transitively tainted
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: `You are ${persona}. Always follow the safety policy.` },
      { role: "user", content: "Introduce yourself." },
    ],
  });
  return Response.json(completion);
}
