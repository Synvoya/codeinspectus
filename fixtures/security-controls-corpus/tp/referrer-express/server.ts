import express from "express";

const app = express();
app.get("/", (_request, response) => {
  response.setHeader("Referrer-Policy", "strict-origin, unsafe-url");
  response.send("ok");
});
