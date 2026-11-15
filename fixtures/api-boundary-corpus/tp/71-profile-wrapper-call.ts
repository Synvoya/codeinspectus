import express from "express";

declare function toDTO<T>(value: T): T;
declare function loadUser(id: string): Promise<{ id: string; passwordHash: string }>;

export const profiles = express.Router();

profiles.get("/:id", async (req, res) => {
  const user = await loadUser(req.params.id);
  res.json({ profile: toDTO({ id: user.id, passwordHash: user.passwordHash }) });
});
