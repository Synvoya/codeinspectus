// FP: fully static prompt, no untrusted data anywhere. Expect: SILENT.
import OpenAI from "openai";

const openai = new OpenAI();

export async function summarize() {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: "You summarize text." },
      { role: "user", content: "Summarize the quarterly report." },
    ],
  });
  return completion;
}
