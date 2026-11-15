import express from "express";

declare function buildUrl(parts: { base: string; token: string }): string;
declare function loadUser(id: string): Promise<{ id: string; resetToken: string }>;

export const resets = express.Router();

resets.get("/:id/reset-link", async (req, res) => {
  const user = await loadUser(req.params.id);
  res.json({ resetUrl: buildUrl({ base: "x", token: user.resetToken }) });
});
