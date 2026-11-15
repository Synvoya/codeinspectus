import express from "express";

declare function serialize<T>(value: T): T;
declare function loadAccount(id: string): Promise<{ id: string; passwordHash: string }>;

export const accounts = express.Router();

accounts.get("/:id", async (req, res) => {
  const { id, passwordHash } = await loadAccount(req.params.id);
  res.json({ data: serialize({ id, passwordHash }) });
});
