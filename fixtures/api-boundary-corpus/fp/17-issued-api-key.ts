import { randomBytes } from "node:crypto";
import express from "express";

declare function saveKeyHash(userId: string, key: string): Promise<void>;

export const router = express.Router();

router.post("/keys", async (req, res) => {
  const apiKey = randomBytes(32).toString("hex");
  await saveKeyHash(String(req.query.user), apiKey);
  // Shown once to the caller who created it.
  res.status(201).json({ apiKey });
});

router.post("/keys/inline", async (req, res) => {
  res.status(201).json({ token: randomBytes(24).toString("base64url") });
});
