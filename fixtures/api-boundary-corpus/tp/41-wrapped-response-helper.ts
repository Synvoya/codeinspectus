import express from "express";

declare function ok<T>(body: T): { status: "ok"; data: T };
declare function loadUser(id: string): Promise<{ apiToken: string; passwordHash: string }>;

export const users = express.Router();

users.get("/:id", async (req, res) => {
  const user = await loadUser(req.params.id);
  res.json(ok({ token: user.apiToken, passwordHash: user.passwordHash }));
});
