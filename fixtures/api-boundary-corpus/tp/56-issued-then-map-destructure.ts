import express from "express";

declare function createAccessToken(userId: string): string;
declare function audit(value: string): void;
declare function listUsers(): Promise<Array<{ id: string; token: string }>>;

export const users = express.Router();

users.get("/", async (req, res) => {
  const token = createAccessToken(String(req.query.admin));
  audit(token);
  const rows = await listUsers();
  res.json(rows.map(({ token }) => ({ token })));
});
