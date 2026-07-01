// CG-25b B-11 FP — none of these must fire ci-ai-llm-key-browser-exposed:
//  - no flag (server-only client)
//  - the flag set to false
//  - the literal mentioned only in a comment: dangerouslyAllowBrowser: true
import OpenAI from "openai";

export const serverClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export const alsoSafe = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  dangerouslyAllowBrowser: false,
});
