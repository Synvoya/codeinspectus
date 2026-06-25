// TP: untrusted req.body value concatenated into a @google/genai systemInstruction.
// Expect: FIRE (medium, LLM01).
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({});

export async function POST(req: Request) {
  const body = await req.json();
  const domain = body.domain;
  const result = await ai.models.generateContent({
    model: "gemini-2.0-flash",
    config: { systemInstruction: "You are an expert in " + domain + ". Stay on topic." },
    contents: "Summarize the field.",
  });
  return Response.json(result);
}
