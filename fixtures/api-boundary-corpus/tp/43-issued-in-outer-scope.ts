import express from "express";
import jwt from "jsonwebtoken";

declare const signingKey: string;

// One service token, minted at start-up and handed to every caller.
const token = jwt.sign({ service: "reports", scope: "admin" }, signingKey);

export const reports = express.Router();

reports.get("/token", (req, res) => {
  res.json({ token });
});
