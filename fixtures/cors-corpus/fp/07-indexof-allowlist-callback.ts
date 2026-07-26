import cors from "cors";

const whitelist = ["https://app.example.com"];
export const safeIndexOfCallback = cors({
  origin(origin, callback) {
    if (whitelist.indexOf(origin) === -1) {
      callback(new Error("Not allowed by CORS"));
      return;
    }
    callback(null, true);
  },
  credentials: true,
});
