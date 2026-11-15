import express from "express";

declare function createAccessToken(userId: string): string;
declare function sendWelcome(token: string): void;
declare function withStoredToken(userId: string, use: (token: string) => void): void;

export const sessions = express.Router();

sessions.get("/:id", (req, res) => {
  const token = createAccessToken(req.params.id);
  sendWelcome(token);
  withStoredToken(req.params.id, (token) => res.json({ token }));
});
