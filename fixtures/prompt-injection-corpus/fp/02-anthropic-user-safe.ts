// FP: Anthropic — untrusted input in a user message, static `system`, no tools.
// Expect: SILENT.
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

export async function POST(req: Request) {
  const { userText } = await req.json();
  const msg = await client.messages.create({
    model: "claude-3-5-sonnet",
    max_tokens: 256,
    system: "You are concise.",
    messages: [{ role: "user", content: userText }],
  });
  return Response.json(msg);
}
