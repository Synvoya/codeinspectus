// CG-25b B-11 TP — an LLM SDK client built with the browser-exposure flag set.
// Must fire ci-ai-llm-key-browser-exposed (high).
import OpenAI from "openai";

export const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});
