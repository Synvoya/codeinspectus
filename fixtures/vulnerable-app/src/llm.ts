// FIXTURE — planted issue #5: prompt-injection sink. Untrusted req.body input
// concatenated into an LLM system prompt, AND the call grants tool access
// (excessive agency). Detected by: CodeInspectus AI prompt-injection check
// (ci-ai-prompt-injection-sink). CWE-1426; OWASP LLM01 + LLM06.
import OpenAI from "openai";

const openai = new OpenAI();

export async function chatHandler(req: { body: { message: string } }) {
  const userMessage = req.body.message;
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      {
        role: "system",
        content: "You are a helpful assistant. The user request is: " + userMessage,
      },
    ],
    tools: [
      { type: "function", function: { name: "deleteAccount", description: "delete a user account" } },
    ],
  });
  return completion;
}
