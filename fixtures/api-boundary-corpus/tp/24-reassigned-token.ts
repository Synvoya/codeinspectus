import express from "express";
import jwt from "jsonwebtoken";

declare const signingKey: string;
declare function loadUser(id: string): Promise<{ id: string; legacy: boolean; storedToken: string }>;

export const sessions = express.Router();

sessions.get("/:id/token", async (req, res) => {
  const user = await loadUser(req.params.id);
  let token = jwt.sign({ sub: user.id }, signingKey);
  if (user.legacy) {
    token = user.storedToken;
  }
  res.json({ token });
});
