// FP: @google/genai — untrusted input as the user `contents`, static systemInstruction,
// no tools. Expect: SILENT.
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({});

export async function POST(req: Request) {
  const body = await req.json();
  const question = body.question;
  const result = await ai.models.generateContent({
    model: "gemini-2.0-flash",
    config: { systemInstruction: "You are a helpful tutor." },
    contents: question,
  });
  return Response.json(result);
}
