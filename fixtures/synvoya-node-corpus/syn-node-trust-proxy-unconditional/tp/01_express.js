const express = require("express");
const app = express();
app.set("trust proxy", true);
module.exports = app;
