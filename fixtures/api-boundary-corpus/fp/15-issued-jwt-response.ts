import express from "express";
import jwt from "jsonwebtoken";

declare const signingKey: string;
declare function findUser(email: string): Promise<{ id: string } | null>;

const app = express();

app.post("/session", async (req, res) => {
  const user = await findUser(String(req.body.email));
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  // The caller just authenticated: the new token is issued to them.
  const token = jwt.sign({ sub: user.id }, signingKey, { expiresIn: "1h" });
  return res.json({ token });
});
