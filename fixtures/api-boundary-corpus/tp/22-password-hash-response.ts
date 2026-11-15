import express from "express";

declare function findAccount(id: string): Promise<{ id: string; email: string; passwordHash: string }>;

export const accounts = express.Router();

accounts.get("/:id", async (req, res) => {
  const user = await findAccount(req.params.id);
  res.json({ id: user.id, email: user.email, passwordHash: user.passwordHash });
});
