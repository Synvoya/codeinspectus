import express from "express";

declare function createAccessToken(userId: string): string;
declare function audit(value: string): void;
declare function storedTokenFor(userId: string): string;

export const tokens = express.Router();

tokens.get("/:id", (req, res) => {
  let token = storedTokenFor(req.params.id);
  if (req.query.audit) {
    const token = createAccessToken(req.params.id);
    audit(token);
  }
  res.json({ token });
});
