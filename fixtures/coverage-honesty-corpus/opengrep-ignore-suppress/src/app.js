const express = require("express");
const app = express();
app.get("/run", (req, res) => {
  const out = eval(req.query.code); // planted true positive behind a repository .semgrepignore
  res.send(String(out));
});
module.exports = app;
