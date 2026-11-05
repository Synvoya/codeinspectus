const express = require("express");
const app = express();
app.get("/run", (req, res) => {
  const out = eval(req.query.code); // café — planted true positive
  res.send(String(out));
});
module.exports = app;
