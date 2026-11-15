import express from "express";

export const debug = express.Router();

debug.get("/whoami", (req, res) => {
  res.json({ token: req.headers.authorization });
});
