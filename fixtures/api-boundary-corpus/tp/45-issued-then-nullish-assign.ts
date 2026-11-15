import express from "express";

declare function generateApiToken(): string | undefined;
declare function storedTokenFor(id: string): string;

export const keys = express.Router();

keys.get("/:id", (req, res) => {
  let token = generateApiToken();
  token ??= storedTokenFor(req.params.id);
  res.json({ token });
});
