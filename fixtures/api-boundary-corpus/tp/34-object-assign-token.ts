import express from "express";

declare function loadAccount(id: string): Promise<{ id: string; storedToken: string }>;

export const accounts = express.Router();

accounts.get("/:id", async (req, res) => {
  const account = await loadAccount(req.params.id);
  res.json(Object.assign({}, { id: account.id }, { token: account.storedToken }));
});
