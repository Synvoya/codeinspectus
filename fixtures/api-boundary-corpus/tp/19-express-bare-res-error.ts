import express from "express";

declare function loadReport(id: string): Promise<unknown>;

export const reports = express.Router();

reports.get("/:id", async (req, res) => {
  try {
    res.json(await loadReport(req.params.id));
  } catch (err: any) {
    res.json({ error: err.message });
  }
});
