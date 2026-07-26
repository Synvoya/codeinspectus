import express from "express";
import helmet from "helmet";

const app = express();

app.use(
  helmet({
    xContentTypeOptions: false,
  }),
);

app.get("/", (_request, response) => response.send("ok"));
