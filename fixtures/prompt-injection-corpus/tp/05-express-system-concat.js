// TP (Express shape): untrusted req.body value concatenated into the SYSTEM prompt.
// Expect: FIRE (medium, LLM01).
const OpenAI = require("openai");

const openai = new OpenAI();

app.post("/chat", async (req, res) => {
  const instructions = req.body.instructions;
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: "Base rules apply. Additional instructions: " + instructions },
      { role: "user", content: "Go" },
    ],
  });
  res.json(completion);
});
