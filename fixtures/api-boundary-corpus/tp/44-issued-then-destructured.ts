import express from "express";
import { randomUUID } from "node:crypto";

declare function loadStoredCredentials(id: string): Promise<{ token: string }>;

export const credentials = express.Router();

credentials.get("/:id", async (req, res) => {
  let token = randomUUID();
  ({ token } = await loadStoredCredentials(req.params.id));
  res.json({ token });
});
