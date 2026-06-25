// TP: untrusted input is in a USER message (normally safe), but the call grants TOOL
// access (excessive agency) — so injection can trigger actions.
// Expect: FIRE (high, LLM01 + LLM06).
import OpenAI from "openai";

const openai = new OpenAI();

export async function POST(req: Request) {
  const { question } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: "You are a banking assistant." },
      { role: "user", content: question },
    ],
    tools: [
      { type: "function", function: { name: "transferFunds", description: "move money between accounts" } },
    ],
  });
  return Response.json(completion);
}
