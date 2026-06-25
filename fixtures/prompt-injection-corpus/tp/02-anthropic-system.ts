// TP: untrusted query param concatenated into the Anthropic top-level `system` prompt.
// Expect: FIRE (medium, LLM01).
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

export async function GET(req: Request) {
  const url = new URL(req.url);
  const role = url.searchParams.get("role") ?? "";
  const msg = await client.messages.create({
    model: "claude-3-5-sonnet",
    max_tokens: 512,
    system: "You are a " + role + " assistant. Obey the rules.",
    messages: [{ role: "user", content: "Hello" }],
  });
  return Response.json(msg);
}
