// TP arm B, other SDK: an Anthropic message rendered as raw HTML. Expect: FIRE (LLM05).
import Anthropic from "@anthropic-ai/sdk";
const anthropic = new Anthropic();
export async function Reply({ messages }: { messages: any[] }) {
  const message = await anthropic.messages.create({ model: "claude-3-5-sonnet-latest", max_tokens: 1024, messages });
  const rendered = message.content[0].text;
  return <section dangerouslySetInnerHTML={{ __html: rendered }} />;
}
