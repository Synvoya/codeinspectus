const express = require("express");
const app = express();
app.set("trust proxy", 1);
app.set("trust proxy", "loopback");
if (process.env.TRUST_PROXY === "true") {
  app.set("trust proxy", true);
}
module.exports = app;
